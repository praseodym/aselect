/**
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
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
 * The Delegator AuthSP Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * The Delegator AuthSP Handler communicates with the Delegator AuthSP by redirecting the client. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * <br>
 * <b>Protocol Desciption</b> <br>
 * <br>
 * <i><a name="outgoing">Outgoing request going to the Delegator AuthSP:</a></i> <br>
 * <table border="1" cellspacing="0" cellpadding="3">
 * <tr>
 * <td style="" bgcolor="#EEEEFF"><b>name</b></td>
 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
 * </tr>
 * <tr>
 * <td>rid</td>
 * <td>A-Select Server request id</td>
 * </tr>
 * <tr>
 * <td>as_url</td>
 * <td>A-Select Server url</td>
 * </tr>
 * <tr>
 * <td>user_attribute</td>
 * <td>ASelectDelegatorUserAttributes (dn or blob)</td>
 * </tr>
 * <tr>
 * <td>a-select-server</td>
 * <td>A-Select Server ID</td>
 * </tr>
 * <tr>
 * <td>tf_retries*</td>
 * <td>allowed retries for the two factor AuthSP</td>
 * </tr>
 * <tr>
 * <td>signature</td>
 * <td>signature of all paramaters in the above sequence</td>
 * </tr>
 * </table>
 * <br>
 * <i><a name="incoming"> Incoming response, which is returned by the Delegator AuthSP: </a></i> <br>
 * <table border="1" cellspacing="0" cellpadding="3">
 * <tr>
 * <td style="" bgcolor="#EEEEFF"><b>name</b></td>
 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
 * </tr>
 * <tr>
 * <td>rid</td>
 * <td>A-Select Server request id</td>
 * </tr>
 * <tr>
 * <td>result_code</td>
 * <td>AuthSP result code</td>
 * </tr>
 * <tr>
 * <td>a-select-server</td>
 * <td>A-Select Server ID</td>
 * </tr>
 * <tr>
 * <td>signature</td>
 * <td>Signature over the following data:
 * <ol>
 * <li>rid</li>
 * <li>The URL that was created in <code>computeAuthenticationRequest()</code>
 * <li>result_code</li>
 * <li>a-select-server</li>
 * </ol>
 * </td>
 * </tr>
 * </table>
 * 
 * @author Alfa & Ariss
 * @version 1.0 14-11-2007 - Changes: - Receive and process Delegator attributes Subject DN and Issuer DN from the AuthSP server
 * @author Bauke Hiemstra - www.anoigo.nl Copyright UMC Nijmegen (http://www.umcn.nl)
 */
public class DelegatorAuthSPHandler implements IAuthSPProtocolHandler
{
	/** The module name. */
	private final static String MODULE = "DelegatorAuthSPHandler";

	/* Specific Delegator AuthSP error codes */
	private final static String DELEGATOR_NO_ERROR = "000";
	private final static String DELEGATOR_INVALID_REQUEST = "009";
	private final static String DELEGATOR_INTERNAL_SERVER_ERROR = "010";
	private final static String DELEGATOR_ERROR_PREFIX = "DELEGATOR";

	private ASelectConfigManager _oConfigManager;
	private SessionManager _oSessionManager;
	private ASelectSystemLogger _systemLogger;
	private ASelectAuthenticationLogger _authenticationLogger;
	private String _sAuthsp;
	private String _sAuthspUrl;
	
	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#myRidName()
	 */
	public String getLocalRidName() { return "rid"; }

	/**
	 * The A-Select Server server id.
	 * 
	 * @param oAuthSpConfig
	 *            the o auth sp config
	 * @param oAuthSpResource
	 *            the o auth sp resource
	 * @throws ASelectAuthSPException
	 *             the a select auth sp exception
	 */
	
	/**
	 * Initialize the <code>Delegator</code> AuthSP Handler. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Performs the following steps:
	 * <ul>
	 * <li>Retrieve handles to required managers and loggers</li>
	 * <li>Retrieve AuthSP ID from configuration</li>
	 * <li>Retrieve AuthSP URL from configuration</li>
	 * <li>Retrieve optional Two-Factor Authentication configuration</li>
	 * </ul>
	 * <br>
	 * 
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
	 */
	public void init(Object oAuthSpConfig, Object oAuthSpResource)
	throws ASelectAuthSPException
	{
		String sMethod = "init";
		Object oASelectConfig = null;
		try {
			// retrieve handles
			_oConfigManager = ASelectConfigManager.getHandle();
			_oSessionManager = SessionManager.getHandle();
			_authenticationLogger = ASelectAuthenticationLogger.getHandle();
			_systemLogger = ASelectSystemLogger.getHandle();

			// log start
			StringBuffer sbInfo = new StringBuffer("Starting : ");
			sbInfo.append(MODULE);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, sbInfo.toString());

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
	 * Computes the request which will be sent to the Delegator AuthSP. <br>
	 * <br>
	 * 
	 * @param sRid
	 *            the s rid
	 * @return the hash map
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#computeAuthenticationRequest(java.lang.String)
	 */
	public HashMap computeAuthenticationRequest(String sRid, HashMap htSessionContext)
	{
		String sMethod = "computeAuthenticationRequest";

		String sSignature = null;
		String sServerId = null;
		StringBuffer sbTemp = null;
		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);

		try {
			// 20120403, Bauke: passed as parameter: HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
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

			sbTemp = new StringBuffer((String) htSessionContext.get("my_url"));
			sbTemp.append("?authsp=").append(_sAuthsp);
			String sAsUrl = sbTemp.toString();
			String sCountry = (String) htSessionContext.get("country");
			if (sCountry == null || sCountry.trim().length() < 1) {
				sCountry = null;
			}
			String sLanguage = (String) htSessionContext.get("language");
			if (sLanguage == null || sLanguage.trim().length() < 1) {
				sLanguage = null;
			}

			try {
				sServerId = _oConfigManager.getParam(_oConfigManager.getSection(null, "aselect"), "server_id");
			}
			catch (ASelectConfigException e) {
				sbTemp = new StringBuffer(sMethod);
				sbTemp.append(e.getMessage());
				_systemLogger.log(Level.SEVERE, sbTemp.toString(), e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			String sAppId= (String) htSessionContext.get("app_id");
			if (sAppId == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "AppId missing in session context.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			// for signature calculation
			sbTemp = new StringBuffer(sRid).append(sAsUrl).append(sAppId).append(sServerId);
			if (sCountry != null) {
				sbTemp.append(sCountry);
			}
			if (sLanguage != null) {
				sbTemp.append(sLanguage);
			}

			sSignature = CryptoEngine.getHandle().generateSignature(_sAuthsp, sbTemp.toString());
			if (sSignature == null) {
				htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
				return htResponse;
			}
			try {
				sSignature = URLEncoder.encode(sSignature, "UTF-8");
//				sDelegatorUserAttributes = URLEncoder.encode(sDelegatorUserAttributes, "UTF-8");
				sAsUrl = URLEncoder.encode(sAsUrl, "UTF-8");
				sAppId = URLEncoder.encode(sAppId, "UTF-8");
				sServerId = URLEncoder.encode(sServerId, "UTF-8");
				if (sCountry != null) {
					sbTemp.append(URLEncoder.encode(sCountry, "UTF-8"));
				}
				if (sLanguage != null) {
					sbTemp.append(URLEncoder.encode(sLanguage, "UTF-8"));
				}
				sbTemp = new StringBuffer(_sAuthspUrl);
				sbTemp.append("?as_url=").append(sAsUrl);
				sbTemp.append("&app_id=").append(sAppId);
				sbTemp.append("&rid=").append(sRid);
//				sbTemp.append("&user_attribute=").append(sDelegatorUserAttributes);
				sbTemp.append("&a-select-server=").append(sServerId);
				sbTemp.append("&signature=").append(sSignature);
				if (sCountry != null) {
					sbTemp.append("&country=").append(sCountry);
				}
				if (sLanguage != null) {
					sbTemp.append("&language=").append(sLanguage);
				}

				htResponse.put("redirect_url", sbTemp.toString());
			}
			catch (UnsupportedEncodingException e) {
				sbTemp = new StringBuffer(sMethod);
				sbTemp.append(e.getMessage());
				_systemLogger.log(Level.SEVERE, sbTemp.toString(), e);
			}
		}
		catch (ASelectAuthSPException eAA) {  // allready logged
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
	 * Verifies the response coming from the Delegator AuthSP.<br>
	 * <br> 
	 * @param htAuthspResponse
	 *            the authsp response
	 * @param htSessionContext
	 *            the session context, must be available
	 * @return the result hash map
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#verifyAuthenticationResponse(java.util.HashMap)
	 */
	// 20120403, Bauke: added htSessionContext
	public HashMap verifyAuthenticationResponse(HashMap htAuthspResponse, HashMap htSessionContext)
	{
		String sMethod = "verifyAuthenticationResponse";
		StringBuffer sbTemp;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "htAuthspResponse=" + htAuthspResponse);

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);	// defensive
		try {
			String sRid = (String) htAuthspResponse.get("rid");
			String sAsUrl = (String) htAuthspResponse.get("my_url");
			String sResultCode = (String) htAuthspResponse.get("result_code");
			String sAsId = (String) htAuthspResponse.get("a-select-server");
			String sDelegateSession = (String) htAuthspResponse.get("delegate_session");
			String sDelegateTimeout = (String) htAuthspResponse.get("delegate_timeout");
			String sDelegateFields = (String) htAuthspResponse.get("delegate_fields");
			String sUserId = (String) htAuthspResponse.get("user_id");
			String sSignature = (String) htAuthspResponse.get("signature");

			if ((sRid == null) || (sResultCode == null) || (sSignature == null) || (sAsId == null)) {
				sbTemp = new StringBuffer("incorrect AuthSP response");
				_systemLogger.log(Level.WARNING, MODULE, sMethod,  sbTemp.toString());
				htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
				return htResponse;
			}
			sbTemp = new StringBuffer(sAsUrl);
			sbTemp.append("?authsp=");
			sbTemp.append(_sAuthsp);
			sAsUrl = sbTemp.toString();

			// 20120403, Bauke: session is available as a parameter
			String sOrg = (String) htSessionContext.get("organization");

			sSignature = URLDecoder.decode(sSignature, "UTF-8");
			sbTemp = new StringBuffer(sRid);
			sbTemp.append(sAsUrl).append(sResultCode).append(sAsId);

			BASE64Decoder base64Decoder = new BASE64Decoder();
			if (sDelegateSession != null)
				sDelegateSession = new String(base64Decoder.decodeBuffer(URLDecoder.decode(sDelegateSession, "UTF-8")));
			if (sDelegateTimeout != null)
				sDelegateTimeout = new String(base64Decoder.decodeBuffer(URLDecoder.decode(sDelegateTimeout, "UTF-8")));
			if (sDelegateFields != null)
				sDelegateFields = new String(URLDecoder.decode(sDelegateFields, "UTF-8"));	// keep the base64 for deserialize
			

			if (sUserId != null)
				sbTemp.append(sUserId);
			if (sDelegateSession != null)
				sbTemp.append(sDelegateSession);
			if (sDelegateTimeout != null)
				sbTemp.append(sDelegateTimeout);
			if (sDelegateFields != null)
				sbTemp.append(sDelegateFields);

			boolean bVerifies = false;
			_systemLogger.log(Level.FINEST, MODULE, sMethod,  "Verify[" + sbTemp + "]");
			bVerifies = CryptoEngine.getHandle().verifySignature(_sAuthsp, sbTemp.toString(), sSignature);

			if (!bVerifies) {
				sbTemp = new StringBuffer();
				sbTemp.append(" invalid signature in response from AuthSP:" + _sAuthsp);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, sbTemp.toString());

				htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
				return htResponse;
			}


			// Log the user authentication
			if (sResultCode.equalsIgnoreCase(DELEGATOR_NO_ERROR)) {
				_authenticationLogger.log(new Object[] {
					MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg, (String) htSessionContext.get("app_id"),
					"granted"
				});

				htResponse.put("rid", sRid);
				// Bauke: transfer additional attributes to caller
				_systemLogger.log(Level.INFO, MODULE, sMethod, "to Response: sSubjectId=" + sDelegateFields);
				if (sDelegateSession != null)
					htResponse.put("delegate_session", sDelegateSession);
				if (sDelegateTimeout != null)
					htResponse.put("delegate_timeout", sDelegateTimeout);
				if (sDelegateFields != null) {
					_systemLogger.log(Level.FINER, MODULE, sMethod, "delegateFields=" + sDelegateFields);
					htResponse.put("attributes", sDelegateFields);	// use special key for adding extra attributes
				}
				htResponse.put("uid", sUserId); 
				htResponse.put("result",  Errors.ERROR_ASELECT_SUCCESS);
				
				return htResponse;
			}
			_authenticationLogger.log(new Object[] {
				MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg, (String) htSessionContext.get("app_id"),
				"denied", sResultCode
			});
			htResponse.put("authsp_type", "delegator");
			if (sResultCode.equalsIgnoreCase(DELEGATOR_INVALID_REQUEST)) {
				sbTemp = new StringBuffer();
				sbTemp.append("error from from AuthSP: ").append(sResultCode);
				htResponse.put("result", Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			else if (sResultCode.equalsIgnoreCase(DELEGATOR_INTERNAL_SERVER_ERROR)) {
				sbTemp = new StringBuffer();
				sbTemp.append("error from from AuthSP: ").append(sResultCode);
				htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			else {
				htResponse.put("result", DELEGATOR_ERROR_PREFIX + sResultCode);
				sbTemp = new StringBuffer();
				sbTemp.append("error from from AuthSP: ").append(sResultCode);
			}
			_systemLogger.log(Level.INFO,  MODULE, sMethod, sbTemp.toString());
		}
		catch (Exception e) {
			sbTemp = new StringBuffer(e.getMessage());
			_systemLogger.log(Level.INFO,  MODULE, sMethod, sbTemp.toString());
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}
}