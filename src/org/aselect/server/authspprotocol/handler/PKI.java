/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 */

/* 
 * $Id: PKI.java,v 1.3 2005/07/25 10:51:48 peter Exp $ 
 *
 * Changelog:
 * $Log: PKI.java,v $
 * Revision 1.3  2005/07/25 10:51:48  peter
 * Initial A-Select 1.4.1 version.
 *
 * Revision 1.2  2005/03/29 13:45:15  erwin
 * Fixed error handling for init() and computeAuthenticateRequest() partly.
 *
 *
 */
package org.aselect.server.authspprotocol.handler;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthSPException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.utils.BASE64Decoder;

/**
 * The PKI AuthSP Handler.
 * <br><br>
 * <b>Description:</b><br>
 * The PKI AuthSP Handler communicates with the PKI AuthSP by redirecting
 * the client.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * None
 * <br><br>
 * <b>Protocol Desciption</b>
 * <br>
 * <br>
 * <i><a name="outgoing">Outgoing request going to the PKI AuthSP:</a></i>
 * <br>
 * <table border="1" cellspacing="0" cellpadding="3">
 * 	<tr>
 * 		<td style="" bgcolor="#EEEEFF"><b>name</b></td>
 * 		<td style="" bgcolor="#EEEEFF"><b>value</b></td>
 * 	</tr>  
 * 	<tr><td>rid</td><td>A-Select Server request id</td></tr>
 * 	<tr><td>as_url</td><td>A-Select Server url</td></tr>
 * 	<tr><td>user_attribute</td><td>ASelectPkiUserAttributes (dn or blob)</td></tr>
 * 	<tr><td>a-select-server</td><td>A-Select Server ID</td></tr>
 * 	<tr><td>tf_authsp*</td><td>Two factor AuthSP</td></tr>
 * 	<tr><td>tf_url*</td><td>url of the two factor AuthSP</td></tr>
 * 	<tr><td>tf_retries*</td><td>allowed retries for the two factor AuthSP</td></tr>
 * 	<tr><td>tf_uid*</td><td>userid for the two factor AuthSP</td></tr>
 * 	<tr>
 * 		<td>signature</td>
 * 		<td>signature of all paramaters in the above sequence</td>
 * 	</tr>
 * </table>
 * * Optional and only filled if <code>two_factor_authentication</code>
 * is configured.<br>
 * <br>
 * <i><a name="incoming">
 * 	Incoming response, which is returned by the Ldap AuthSP:
 * </a></i>
 * <br>
 * <table border="1" cellspacing="0" cellpadding="3">
 * <tr>
 * 	<td style="" bgcolor="#EEEEFF"><b>name</b></td>
 * 	<td style="" bgcolor="#EEEEFF"><b>value</b></td>
 * </tr>
 * <tr><td>rid</td><td>A-Select Server request id</td></tr>
 * <tr><td>result_code</td><td>AuthSP result code</td></tr>
 * <tr><td>a-select-server</td><td>A-Select Server ID</td></tr>
 * <tr>
 * 	<td>signature</td>
 * 	<td>Signature over the following data: 
 * 		<ol>
 * 			<li>rid</li>
 * 			<li>The URL that was created in 
 * 				<code>computeAuthenticationRequest()</code>
 * 			<li>result_code</li>
 * 			<li>a-select-server</li>
 * 		</ol> 
 * 	</td>
 *	</tr>
 * </table>
 * 
 * @author Alfa & Ariss
 * @version 1.0
 * 
 * 
 * 14-11-2007 - Changes:
 * - Receive and process PKI attributes Subject DN and Issuer DN from the AuthSP server
 * 
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright UMC Nijmegen (http://www.umcn.nl)
 * 
 */
public class PKI implements IAuthSPProtocolHandler
{
	/** The module name. */
	private final static String MODULE = "PKI";

	/* Specific PKI AuthSP error codes */
	private final static String PKI_NO_ERROR = "000";
	private final static String PKI_INVALID_REQUEST = "009";
	private final static String PKI_INTERNAL_SERVER_ERROR = "010";
	private final static String PKI_ERROR_PREFIX = "PKI";

	private ASelectConfigManager _oConfigManager;
	private SessionManager _oSessionManager;
	private ASelectSystemLogger _systemLogger;
	private ASelectAuthenticationLogger _authenticationLogger;
	private String _sAuthsp;
	private String _sAuthspUrl;
	private String _sTwoFactorAuthSp;
	private String _sTwoFactorAuthSpUrl;
	private String _sTwoFactorAuthSpRetries;

	/** The A-Select Server server id */
	//    private String _sServerId;
	/**
	 * Initialize the <code>PKI</code> AuthSP Handler.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Performs the following steps:
	 * <ul>
	 * 	<li>Retrieve handles to required managers and loggers</li>
	 * 	<li>Retrieve AuthSP ID from configuration</li>
	 * 	<li>Retrieve AuthSP URL from configuration</li>
	 *  <li>Retrieve optional Two-Factor Authentication configuration</li>
	 * </ul>
	 * <br>
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
	 */
	public void init(Object oAuthSpConfig, Object oAuthSpResource)
		throws ASelectAuthSPException
	{
		String sMethod = "init()";
		Object oASelectConfig = null;
		try {
			//retrieve handles
			_oConfigManager = ASelectConfigManager.getHandle();
			_oSessionManager = SessionManager.getHandle();
			_authenticationLogger = ASelectAuthenticationLogger.getHandle();
			_systemLogger = ASelectSystemLogger.getHandle();

			//log start
			StringBuffer sbInfo = new StringBuffer("Starting : ");
			sbInfo.append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			try {
				_sAuthsp = _oConfigManager.getParam(oAuthSpConfig, "id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'id' config item found in authsp section");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
			try {
				_sAuthspUrl = _oConfigManager.getParam(oAuthSpResource, "url");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'id' config item found in authsp resource section");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			try {
				oASelectConfig = _oConfigManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No main 'aselect' config section found", e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			try {
				Object oTwoFactorConfig = _oConfigManager.getSection(oAuthSpConfig, "two_factor_authentication");
				_sTwoFactorAuthSp = _oConfigManager.getParam(oTwoFactorConfig, "id");
				_sTwoFactorAuthSpUrl = _oConfigManager.getParam(oTwoFactorConfig, "url");
				_sTwoFactorAuthSpRetries = _oConfigManager.getParam(oTwoFactorConfig, "retries");
			}
			catch (ASelectConfigException e) //no two factor authentication used.
			{
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid two factor configuration found; two factor authentication disabled.");
			}
		}
		catch (ASelectAuthSPException eAA) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", eAA);
			throw eAA;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize due to internal error", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Computes the request which will be sent to the PKI AuthSP.
	 * <br><br> 
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#computeAuthenticationRequest(java.lang.String)
	 */
	public HashMap computeAuthenticationRequest(String sRid)
	{
		String sMethod = "computeAuthenticationRequest()";

		String sSignature = null;
		String sServerId = null;
		StringBuffer sbTemp = null;
		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);

		try {
			HashMap htSessionContext = _oSessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				sbTemp = new StringBuffer("Could not fetch session context for rid='");
				sbTemp.append(sRid).append("'.");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbTemp.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			HashMap htAllowedAuthsps = (HashMap) htSessionContext.get("allowed_user_authsps");
			if (htAllowedAuthsps == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Allowed user AuthSPs missing in session context.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			String sTwoFactorUserAttributes = null;
			if (_sTwoFactorAuthSp != null && _sTwoFactorAuthSpUrl != null) {
				sTwoFactorUserAttributes = (String) htAllowedAuthsps.get(_sTwoFactorAuthSp);
			}
			String sPkiUserAttributes = (String) htAllowedAuthsps.get(_sAuthsp);

			sbTemp = new StringBuffer((String) htSessionContext.get("my_url"));
			sbTemp.append("?authsp=").append(_sAuthsp);
			String sAsUrl = sbTemp.toString();

			try {
				sServerId = _oConfigManager.getParam(_oConfigManager.getSection(null, "aselect"), "server_id");
			}
			catch (ASelectConfigException e) {
				sbTemp = new StringBuffer(sMethod);
				sbTemp.append(e.getMessage());
				_systemLogger.log(Level.SEVERE, sbTemp.toString(), e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			sbTemp = new StringBuffer(sRid).append(sAsUrl).append(sPkiUserAttributes).append(sServerId);
			if (_sTwoFactorAuthSp != null && _sTwoFactorAuthSpUrl != null && _sTwoFactorAuthSpRetries != null
					&& sTwoFactorUserAttributes != null) {
				sbTemp.append(_sTwoFactorAuthSp);
				sbTemp.append(_sTwoFactorAuthSpUrl);
				sbTemp.append(_sTwoFactorAuthSpRetries);
				sbTemp.append(sTwoFactorUserAttributes);
			}
			sSignature = CryptoEngine.getHandle().generateSignature(_sAuthsp, sbTemp.toString());

			if (sSignature == null) {
				htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
				return htResponse;
			}
			try {
				sSignature = URLEncoder.encode(sSignature, "UTF-8");
				sPkiUserAttributes = URLEncoder.encode(sPkiUserAttributes, "UTF-8");
				sAsUrl = URLEncoder.encode(sAsUrl, "UTF-8");
				if (_sTwoFactorAuthSp != null && _sTwoFactorAuthSpUrl != null && sTwoFactorUserAttributes != null) {
					_sTwoFactorAuthSp = URLEncoder.encode(_sTwoFactorAuthSp, "UTF-8");
					_sTwoFactorAuthSpUrl = URLEncoder.encode(_sTwoFactorAuthSpUrl, "UTF-8");
					sTwoFactorUserAttributes = URLEncoder.encode(sTwoFactorUserAttributes, "UTF-8");
				}
			}
			catch (UnsupportedEncodingException e) {
				sbTemp = new StringBuffer(sMethod);
				sbTemp.append(e.getMessage());
				_systemLogger.log(Level.SEVERE, sbTemp.toString(), e);
			}
			sbTemp = new StringBuffer(_sAuthspUrl);
			sbTemp.append("?as_url=").append(sAsUrl);
			sbTemp.append("&rid=").append(sRid);
			sbTemp.append("&user_attribute=").append(sPkiUserAttributes);
			sbTemp.append("&a-select-server=").append(sServerId);
			if (_sTwoFactorAuthSp != null && _sTwoFactorAuthSpUrl != null && sTwoFactorUserAttributes != null
					&& _sTwoFactorAuthSpRetries != null) {
				sbTemp.append("&tf_authsp=").append(_sTwoFactorAuthSp);
				sbTemp.append("&tf_url=").append(_sTwoFactorAuthSpUrl);
				sbTemp.append("&tf_retries=").append(_sTwoFactorAuthSpRetries);
				sbTemp.append("&tf_uid=").append(sTwoFactorUserAttributes);
			}
			sbTemp.append("&signature=").append(sSignature);

			htResponse.put("redirect_url", sbTemp.toString());
		}
		catch (ASelectAuthSPException eAA) {
			//allready logged
			htResponse.put("result", eAA.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not compute authentication request due to internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}

	/**
	 * Verifies the response comming from the PKI AuthSP <br>
	 * <br>
	 * 
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#verifyAuthenticationResponse(java.util.HashMap)
	 */
	public HashMap verifyAuthenticationResponse(HashMap htAuthspResponse)
	{
		String sMethod = "verifyAuthenticationResponse";
		StringBuffer sbTemp;
		_systemLogger.log(Level.INFO, sMethod + " htAuthspResponse=" + htAuthspResponse);

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		try {
			String sRid = (String) htAuthspResponse.get("rid");
			String sAsUrl = (String) htAuthspResponse.get("my_url");
			String sResultCode = (String) htAuthspResponse.get("result_code");
			String sAsId = (String) htAuthspResponse.get("a-select-server");
			String sSubjectDN = (String) htAuthspResponse.get("pki_subject_dn"); // Bauke: optional attributes
			String sIssuerDN = (String) htAuthspResponse.get("pki_issuer_dn"); // Bauke: optional attributes
			String sSubjectId = (String) htAuthspResponse.get("pki_subject_id"); // Bauke: optional attributes
			String sSignature = (String) htAuthspResponse.get("signature");

			if ((sRid == null) || (sResultCode == null) || (sSignature == null) || (sAsId == null)) {
				sbTemp = new StringBuffer(sMethod);
				sbTemp.append("incorrect AuthSP response");
				_systemLogger.log(Level.WARNING, sbTemp.toString());

				htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
				return htResponse;
			}
			sbTemp = new StringBuffer(sAsUrl);
			sbTemp.append("?authsp=");
			sbTemp.append(_sAuthsp);
			sAsUrl = sbTemp.toString();
			HashMap htSessionContext = _oSessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				//Session is expired or never existed.
				sbTemp = new StringBuffer(sMethod);
				sbTemp.append("session for RID: " + sRid + " is invalid.");
				htResponse.put("result", Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
				_systemLogger.log(Level.WARNING, sbTemp.toString());
				return htResponse;
			}
			String sUserId = (String)htSessionContext.get("user_id");
			String sOrg = (String)htSessionContext.get("organization");

			sSignature = URLDecoder.decode(sSignature, "UTF-8");
			sbTemp = new StringBuffer(sRid);
			sbTemp.append(sAsUrl).append(sResultCode).append(sAsId);
			
			_systemLogger.log(Level.INFO, "Coded sSubjectDN="+sSubjectDN);
            if (sSubjectDN != null)	sbTemp.append(sSubjectDN); // Bauke: added
            if (sIssuerDN != null) sbTemp.append(sIssuerDN); // Bauke: added
			if (sSubjectId != null) sbTemp.append(sSubjectId); // Bauke: added
			
			boolean bVerifies = false;
			_systemLogger.log(Level.INFO, "Verify["+sbTemp+"]");
			bVerifies = CryptoEngine.getHandle().verifySignature(_sAuthsp, sbTemp.toString(), sSignature);
//			bVerifies = CryptoEngine.getHandle().verifySignature(_sAuthsp,
//					URLDecoder.decode(sbTemp.toString(), "UTF-8"), sSignature);
			if (!bVerifies) {
				sbTemp = new StringBuffer(sMethod);
				sbTemp.append("invalid signature in response from AuthSP:" + _sAuthsp);
				_systemLogger.log(Level.INFO, sbTemp.toString());

				htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
				return htResponse;
			}

			BASE64Decoder base64Decoder = new BASE64Decoder();
            if (sSubjectDN != null) sSubjectDN = new String(base64Decoder.decodeBuffer(sSubjectDN));
			if (sIssuerDN != null) sIssuerDN = new String(base64Decoder.decodeBuffer(sIssuerDN));
			if (sSubjectId != null) sSubjectId = new String(base64Decoder.decodeBuffer(sSubjectId));
			_systemLogger.log(Level.INFO, "Decoded sSubjectDN="+sSubjectDN);

			// 20090224, Bauke: When 'forced_uid' is used change the 'uid' to a more discriminating value
			String sForcedUid = (String)htSessionContext.get("forced_uid");
			if (sForcedUid != null && sForcedUid.equals(sUserId) && sSubjectDN != null) {
				sUserId = sSubjectDN;
				htResponse.put("uid", sUserId);
			}
			// Log the user authentication
			if (sResultCode.equalsIgnoreCase(PKI_NO_ERROR)) {
				_authenticationLogger.log(new Object[] {
					MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg,
					(String) htSessionContext.get("app_id"), "granted"
				});

				htResponse.put("rid", sRid);
				// Bauke: transfer additional attributes to caller
				_systemLogger.log(Level.INFO, "to Response: sSubjectDN="+sSubjectDN);
				if (sSubjectDN != null) htResponse.put("pki_subject_dn", sSubjectDN); // Bauke: added
				if (sIssuerDN != null) htResponse.put("pki_issuer_dn", sIssuerDN); // Bauke: added
				if (sSubjectId != null) htResponse.put("pki_subject_id", sSubjectId); // Bauke: added
				return htResponse;
			}
			_authenticationLogger.log(new Object[] {
				MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg,
				(String)htSessionContext.get("app_id"), "denied"
			});
			if (sResultCode.equalsIgnoreCase(PKI_INVALID_REQUEST)) {
				sbTemp = new StringBuffer(sMethod);
				sbTemp.append("error from from AuthSP: ").append(sResultCode);
				htResponse.put("result", Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			else if (sResultCode.equalsIgnoreCase(PKI_INTERNAL_SERVER_ERROR)) {
				sbTemp = new StringBuffer(sMethod);
				sbTemp.append("error from from AuthSP: ").append(sResultCode);
				htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			else {
				htResponse.put("result", PKI_ERROR_PREFIX + sResultCode);
				sbTemp = new StringBuffer(sMethod);
				sbTemp.append("error from from AuthSP: ").append(sResultCode);
			}
			_systemLogger.log(Level.INFO, sbTemp.toString());
		}
		catch (Exception e) {
			sbTemp = new StringBuffer(sMethod);
			sbTemp.append(e.getMessage());
			_systemLogger.log(Level.INFO, sbTemp.toString());
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}
}