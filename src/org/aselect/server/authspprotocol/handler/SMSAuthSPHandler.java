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
import org.aselect.system.exception.ASelectException;
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
	private String _sAuthspVoice;

	private static final String ERROR_SMS_OK = "000";
	private static final String ERROR_SMS_INVALID_PHONE = "500";  // 20110718, bad phone number, redirect to selfservice
	private static final String ERROR_SMS_ACCESS_DENIED = "800";

	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#myRidName()
	 */
	public String getLocalRidName() { return "rid"; }

	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
	 */
	public void init(Object oAuthSPConfig, Object oAuthSPResource)
	throws ASelectAuthSPException
	{
		String sMethod = "init";
		_configManager = ASelectConfigManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_authenticationLogger = ASelectAuthenticationLogger.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
		try {
			try {
				_sAuthsp = _configManager.getParam(oAuthSPConfig, "id");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Parameter 'id' not found in SMS AuthSP configuration", eAC);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
			
			_sAuthspUrl = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "url", true/*mandatory*/);
			_sAuthspVoice = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "voice_url", false);
		}
		catch (ASelectAuthSPException eAA) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initialisation failed due to configuration error", eAA);
			throw eAA;
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initialisation failed due to configuration error", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initialisation failed due to internal error", e);
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
	public HashMap computeAuthenticationRequest(String sRid, HashMap htSessionContext)
	{
		String sMethod = "computeAuthenticationRequest";
		StringBuffer sbBuffer = null;
		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "sRid=" + sRid);

		try {
			// 20120403, Bauke: passes as parameter: HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
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
			
			// 20111013, Bauke: added absent phonenumber handling
			String sCF = (String)htSessionContext.get("sms_correction_facility");
			
			// 20121124, Bauke: added SMS by Voice
			// sPhoneNr will contain the phone number without the possible trailing "v"
			// sUserId contains the combination.
			// For an SMS by Voice a different url is used.
			String sPhoneNr = sUserId;
			boolean isVoice = false;
			if (Utils.hasValue(sUserId) && sUserId.endsWith("v")) {
				sPhoneNr = sUserId.substring(0, sUserId.length()-1);
				isVoice = true;
			}
			if (!Utils.hasValue(sPhoneNr)) {  // no phone number
				sPhoneNr = "";
				if ("true".equals(sCF)) {  // let the sms AuthSP take care of bad phone numbers
					sUserId = isVoice? "v": "";
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing SMS user attributes, but sms_correction_facility="+sCF);
				}
				else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing SMS user attributes.");
					throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
				}
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
			sbSignature.append(sPhoneNr);  //sUserId);
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
			htSessionContext.put("sms_phone", sPhoneNr);  // sUserId);  // from aselectSmsUserAttributes
			_sessionManager.setUpdateSession(htSessionContext, _systemLogger);  // 20120403, Bauke: was updateSession

			// Build the AuthSP url
			sSignature = URLEncoder.encode(sSignature, "UTF-8");
			//sUserId = URLEncoder.encode(sUserId, "UTF-8");
			sPhoneNr = URLEncoder.encode(sPhoneNr, "UTF-8");
			sAsUrl = URLEncoder.encode(sAsUrl, "UTF-8");
			StringBuffer sbRedirect = new StringBuffer(isVoice? _sAuthspVoice: _sAuthspUrl);  // here's the voice switch
			sbRedirect.append("?as_url=").append(sAsUrl);
			sbRedirect.append("&rid=").append(sRid);
			//sbRedirect.append("&uid=").append(sUserId);
			sbRedirect.append("&uid=").append(sPhoneNr);
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
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not compute authentication request due to internal error", e);
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
			
			// 20120403, Bauke: session context is available as a parameter
			String sUserId = (String) htSessionContext.get("sel_uid");
			if (sUserId == null)
				sUserId = (String) htSessionContext.get("user_id");
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sUserId="+sUserId);
			
			// 20130618, Bauke: no don't, this is not the phonenumber as it is in the SMS authspserver
			// 20121124, Bauke: strip trailing voice indicator
			//if (Utils.hasValue(sUserId) && sUserId.endsWith("v"))
			//	sUserId = sUserId.substring(0, sUserId.length()-1);
			
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
