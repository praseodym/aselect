/* 
 * @author Cristina Gavrila, BTTSD
 *
 * 14-11-2007 - Adapted to pass the SMS phone number used to the A-select server
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright UMC Nijmegen (http://www.umcn.nl)
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
import org.aselect.system.utils.Utils;

/**
 * The SMS AuthSP Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * The SMS AuthSP Handler communicates with the SMS AuthSP by redirecting the client. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * <br>
 * <b>Protocol Description</b> <br>
 * <i><a name="outgoing">Outgoing request going to the SMS AuthSP:</a></i> <br>
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
 * <td>uid</td>
 * <td>A-Select Server user ID</td>
 * </tr>
 * <tr>
 * <td>a-select-server</td>
 * <td>A-Select Server ID</td>
 * </tr>
 * <tr>
 * <td>signature</td>
 * <td>signature of all paramaters in the above sequence</td>
 * </tr>
 * </table>
 * <br>
 * <i><a name="incoming"> Incoming response, which is returned by the SMS AuthSP: </a></i> <br>
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
 */
public class SMSAuthSPHandler implements IAuthSPProtocolHandler
{
	private final String MODULE = "SMSAuthSPHandler";
	private ASelectConfigManager _configManager;
	private SessionManager _sessionManager;
	private ASelectSystemLogger _systemLogger;
	private ASelectAuthenticationLogger _authenticationLogger;
	private String _sAuthsp;
	private String _sAuthspUrl;

	private static final String ERROR_SMS_OK = "000";
	private static final String ERROR_SMS_INVALID_PHONE = "500";  // 20110718, bad phone number, redirect to selfservice
	private static final String ERROR_SMS_ACCESS_DENIED = "800";

	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
	 */
	public void init(Object oAuthSPConfig, Object oAuthSPResource)
		throws ASelectAuthSPException
	{
		String sMethod = "init()";
		_configManager = ASelectConfigManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_authenticationLogger = ASelectAuthenticationLogger.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
		try {
			try {
				_sAuthsp = _configManager.getParam(oAuthSPConfig, "id");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, "init()",
						"Parameter 'id' not found in SMS AuthSP configuration", eAC);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
			try {
				_sAuthspUrl = _configManager.getParam(oAuthSPResource, "url");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, "init()",
						"Parameter 'url' not found in SMS AuthSP configuration", eAC);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
		}
		catch (ASelectAuthSPException eAA) {
			_systemLogger.log(Level.SEVERE, MODULE, "init()", "Initialisation failed due to configuration error", eAA);
			throw eAA;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, "init()", "Initialisation failed due to internal error", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Creates the authentication request URL. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method creates a hashtable with the follwing contents:
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF"><b>key</b></td>
	 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
	 * </tr>
	 * <tr>
	 * <td>result</td>
	 * <td>
	 * {@link Errors#ERROR_ASELECT_SUCCESS} or an error code if creating the authentication request URL fails</td>
	 * </tr>
	 * <tr>
	 * <td>redirect_url</td>
	 * <td>The URL to the AuthSP including the protocol parameters as specified if the <a href="#outgoing">class
	 * description</a>.</td>
	 * </tr>
	 * </table>
	 * 
	 * @param sRid
	 *            the s rid
	 * @return the hash map
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#computeAuthenticationRequest(java.lang.String)
	 */
	public HashMap computeAuthenticationRequest(String sRid)
	{
		String sMethod = "computeAuthenticationRequest";
		StringBuffer sbBuffer = null;
		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "sRid=" + sRid);

		try {
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Context=" + htSessionContext);
			if (htSessionContext == null) {
				sbBuffer = new StringBuffer("Could not fetch session context for rid='");
				sbBuffer.append(sRid).append("'.");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			HashMap htAllowedAuthsps = (HashMap) htSessionContext.get("allowed_user_authsps");
			if (htAllowedAuthsps == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Allowed_user_authsps missing in session context.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			String sUserId = (String) htAllowedAuthsps.get(_sAuthsp);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Allowed=" + htAllowedAuthsps + " sUserId=" + sUserId);
			if (Utils.hasValue(sUserId)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing SMS user attributes.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			sbBuffer = new StringBuffer((String) htSessionContext.get("my_url"));
			sbBuffer.append("?authsp=").append(_sAuthsp);
			String sAsUrl = sbBuffer.toString();
			String sCountry = (String) htSessionContext.get("country");
			if (sCountry == null || sCountry.trim().length() < 1) {
				sCountry = null;
			}
			String sLanguage = (String) htSessionContext.get("language");
			if (sLanguage == null || sLanguage.trim().length() < 1) {
				sLanguage = null;
			}
			String sServerId = _configManager.getParam(_configManager.getSection(null, "aselect"), "server_id");
			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sAsUrl);
			sbSignature.append(sUserId);
			sbSignature.append(sServerId);
			if (sCountry != null) {
				sbSignature.append(sCountry);
			}
			if (sLanguage != null) {
				sbSignature.append(sLanguage);
			}
			String sSignature = CryptoEngine.getHandle().generateSignature(_sAuthsp, sbSignature.toString());
			if (sSignature == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not sign SMS AuthSP request.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			// Bauke: store additional sms attribute
			htSessionContext.put("sms_phone", sUserId);
			_sessionManager.put(sRid, htSessionContext);

			sSignature = URLEncoder.encode(sSignature, "UTF-8");
			sUserId = URLEncoder.encode(sUserId, "UTF-8");
			sAsUrl = URLEncoder.encode(sAsUrl, "UTF-8");
			StringBuffer sbRedirect = new StringBuffer(_sAuthspUrl);
			sbRedirect.append("?as_url=").append(sAsUrl);
			sbRedirect.append("&rid=").append(sRid);
			sbRedirect.append("&uid=").append(sUserId);
			sbRedirect.append("&a-select-server=").append(sServerId);
			if (sCountry != null) {
				sbRedirect.append("&country=").append(sCountry);
			}
			if (sLanguage != null) {
				sbRedirect.append("&language=").append(sLanguage);
			}
			sbRedirect.append("&signature=").append(sSignature);
			htResponse.put("redirect_url", sbRedirect.toString());
			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectAuthSPException eAA) {
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
	 * Verifies the response from the AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method verifies the response from the AuthSP. The response parameters are placed in
	 * <code>htAuthspResponse</code> and are described in the <a href="#incoming">class description</a>. <br>
	 * <br>
	 * This method creates a hashtable with the following contents:
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF"><b>key</b></td>
	 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
	 * </tr>
	 * <tr>
	 * <td>result</td>
	 * <td>
	 * {@link Errors#ERROR_ASELECT_SUCCESS} or an error code if the authentication response was invalid or the user
	 * was not authenticated.</td>
	 * </tr>
	 * <tr>
	 * <td>rid</td>
	 * <td>The A-Select request identifier of this authentication.</td>
	 * </tr>
	 * </table>
	 * 
	 * @param htAuthspResponse
	 *            the ht authsp response
	 * @return the hash map
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#verifyAuthenticationResponse(java.util.HashMap)
	 */
	public HashMap verifyAuthenticationResponse(HashMap htAuthspResponse)
	{
		String sMethod = "verifyAuthenticationResponse";
		StringBuffer sbBuffer = null;
		HashMap htResponse = new HashMap();

		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "htAuthspRespone=" + htAuthspResponse);
		try {
			String sRid = (String) htAuthspResponse.get("rid");
			String sAsUrl = (String) htAuthspResponse.get("my_url");
			String sResultCode = (String) htAuthspResponse.get("result_code");
			String sAsId = (String) htAuthspResponse.get("a-select-server");
			String sSignature = (String) htAuthspResponse.get("signature");
			if (sRid == null || sResultCode == null || sAsId == null || sSignature == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Incorrect AuthSP response: one or more parameters missing.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}
			sbBuffer = new StringBuffer(sAsUrl);
			sbBuffer.append("?authsp=");
			sbBuffer.append(_sAuthsp);
			sAsUrl = sbBuffer.toString();
			sSignature = URLDecoder.decode(sSignature, "UTF-8");
			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sAsUrl);
			sbSignature.append(sResultCode);
			sbSignature.append(sAsId);
			boolean bVerifies = CryptoEngine.getHandle().verifySignature(_sAuthsp, sbSignature.toString(), sSignature);
			if (!bVerifies) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "invalid signature in response from AuthSP:" + _sAuthsp);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Incorrect AuthSP response: invalid Session (could be expired)");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}

			String sUserId = (String) htSessionContext.get("sel_uid");
			if (sUserId == null)
				sUserId = (String) htSessionContext.get("user_id");
			String sOrg = (String) htSessionContext.get("organization");

			// Log authentication
			if (sResultCode.equalsIgnoreCase(ERROR_SMS_ACCESS_DENIED) || sResultCode.equalsIgnoreCase(ERROR_SMS_INVALID_PHONE)) {
				_authenticationLogger.log(new Object[] {
					MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg, (String) htSessionContext.get("app_id"),
					"denied", sResultCode
				});
			}
			else if (sResultCode.equalsIgnoreCase(ERROR_SMS_OK)) {
				_authenticationLogger.log(new Object[] {
					MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg, (String) htSessionContext.get("app_id"),
					"granted"
				});
			}
			
			// Throw exceptions
			if (sResultCode.equalsIgnoreCase(ERROR_SMS_ACCESS_DENIED))
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
			
			if (!sResultCode.equalsIgnoreCase(ERROR_SMS_OK) && !sResultCode.equalsIgnoreCase(ERROR_SMS_INVALID_PHONE)) {
				StringBuffer sbError = new StringBuffer("AuthSP returned errorcode: ").append(sResultCode);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			
			// ERROR_SMS_OK or ERROR_SMS_INVALID_PHONE
			htResponse.put("rid", sRid);
			htResponse.put("authsp_type", "sms");

			// 20090223: Since we decided on the 'uid' here, pass it on as well
			htResponse.put("uid", sUserId);

			// Bauke: pass additional attribute
			String sSmsPhone = (String) htSessionContext.get("sms_phone");
			if (sSmsPhone != null)
				htResponse.put("sms_phone", sSmsPhone);
			
			htResponse.put("result", sResultCode.equalsIgnoreCase(ERROR_SMS_OK)?
							Errors.ERROR_ASELECT_SUCCESS: Errors.ERROR_ASELECT_AUTHSP_INVALID_PHONE);
		}
		catch (ASelectAuthSPException eAA) {
			htResponse.put("result", eAA.getMessage());
		}
		catch (UnsupportedEncodingException eUE) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not decode signature", eUE);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not verify authentication response due to internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}
}
