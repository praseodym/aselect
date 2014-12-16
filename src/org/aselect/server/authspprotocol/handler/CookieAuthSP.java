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

/* 
*/

package org.aselect.server.authspprotocol.handler;

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

/**
 * The CookieAuthSP handler. <br>
 * <br>
 * <b>Description:</b><br>
 * The CookieAuthSP handler communicates with the CookieAuthSP by using redirects.
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 */
public class CookieAuthSP implements IAuthSPProtocolHandler
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private final static String MODULE = "CookieAuthSP";

	public final static String ERROR_NO_ERROR = "000";
	public final static String ERROR_ACCESS_DENIED = "800";

	/**
	 * The A-Select config manager
	 */
	private ASelectConfigManager _configManager;
	/**
	 * The A-Select session manager
	 */
	private SessionManager _sessionManager;
	/**
	 * The A-Select crypto engine
	 */
	private CryptoEngine _cryptoEngine;
	/**
	 * The logger that logs system information
	 */
	private ASelectSystemLogger _systemLogger;
	/**
	 * The logger that logs authentication information
	 */
	private ASelectAuthenticationLogger _authenticationLogger;
	/**
	 * The AuthSP ID
	 */
	private String _sAuthSP;
	/**
	 * The url to the authsp
	 */
	private String _sAuthSPUrl;
	/**
	 * The A-Select Server server id
	 */
	private String _sServerId;
	/**name of the cookie to be obtained for authentication
	 */
	private String _sCookiename;
	
	
	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#myRidName()
	 */
	public String getLocalRidName() { return "rid"; }

	/**
	 * Initializes the CookieAuthSP handler. <br>
	 * Resolves the following config items:<br>
	 * - The AuthSP id<br>
	 * - The url to the authsp (from the resource)<br>
	 * - The server id from the A-Select main config<br>
	 * <br>
	 * <br>
	 * 
	 * @param oAuthSPConfig
	 *            the o auth sp config
	 * @param oAuthSPResource
	 *            the o auth sp resource
	 * @throws ASelectAuthSPException
	 *             the a select auth sp exception
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
	 */
	public void init(Object oAuthSPConfig, Object oAuthSPResource)
	throws ASelectAuthSPException
	{
		String sMethod = "init";

		Object oASelectConfig = null;

		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			_authenticationLogger = ASelectAuthenticationLogger.getHandle();
			_configManager = ASelectConfigManager.getHandle();
			_sessionManager = SessionManager.getHandle();
			_cryptoEngine = CryptoEngine.getHandle();

			try {
				_sAuthSP = _configManager.getParam(oAuthSPConfig, "id");
			}
			catch (Exception e) {
				throw new ASelectAuthSPException("No valid 'id' config item found in authsp section", e);
			}

			try {
				_sAuthSPUrl = _configManager.getParam(oAuthSPResource, "url");
			}
			catch (Exception e) {
				StringBuffer sbFailed = new StringBuffer(
						"No valid 'url' config item found in resource section of authsp with id='");
				sbFailed.append(_sAuthSP);
				sbFailed.append("'");
				throw new ASelectAuthSPException(sbFailed.toString(), e);
			}

			_sCookiename = _configManager.getPreviousSessionCookieName();
			if (_sCookiename == null ) {
				throw new ASelectAuthSPException("No valid 'previous_session' cookiename config item found in config section");
			}
			
			
			try {
				oASelectConfig = _configManager.getSection(null, "aselect");
			}
			catch (Exception e) {
				throw new ASelectAuthSPException("No main 'aselect' config section found", e);
			}

			try {
				_sServerId = _configManager.getParam(oASelectConfig, "server_id");
			}
			catch (Exception e) {
				throw new ASelectAuthSPException("No valid 'server_id' config item found in main 'aselect' section", e);
			}
		}
		catch (ASelectAuthSPException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Sends an authentication request to the authsp. <br>
	 * The response must contain the following parameters:<br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">name</td>
	 * <td style="" bgcolor="#EEEEFF">value</td>
	 * <td style="" bgcolor="#EEEEFF">encoded</td>
	 * </tr>
	 * <tr>
	 * <td>as_url</td>
	 * <td>A-Select Server url</td>
	 * <td>yes</td>
	 * </tr>
	 * <tr>
	 * <td>rid</td>
	 * <td>A-Select Server request id</td>
	 * <td>no</td>
	 * </tr>
	 * <tr>
	 * <td>cookiename</td>
	 * <td>Cookie name to look for</td>
	 * <td>yes</td>
	 * </tr>
	 * <tr>
	 * <td>a-select-server</td>
	 * <td>A-Select Server ID</td>
	 * <td>no</td>
	 * </tr>
	 * <tr>
	 * <td>signature</td>
	 * <td>signature of all paramaters in the above sequence</td>
	 * <td>yes</td>
	 * </tr>
	 * </table>
	 * <br>
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

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		try {
			// 20120403, Bauke: passes as parameter: HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				StringBuffer sbBuffer = new StringBuffer("Could not fetch session context for rid: ");
				sbBuffer.append(sRid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			StringBuffer sbMyUrl = new StringBuffer((String) htSessionContext.get("my_url"));
			sbMyUrl.append("?authsp=").append(_sAuthSP);
			String sAsUrl = sbMyUrl.toString();

			HashMap htAllowedAuthsps = (HashMap) htSessionContext.get("allowed_user_authsps");
			if (htAllowedAuthsps == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "allowed_user_authsps missing in session context");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
//			String sUserId = (String) htAllowedAuthsps.get(_sAuthSP);
//			if (sUserId == null) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "missing NullAuthSP user attributes ");
//				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
//			}

			
			String sCountry = (String) htSessionContext.get("country");
			if (sCountry == null || sCountry.trim().length() < 1) {
				sCountry = null;
			}

			String sLanguage = (String) htSessionContext.get("language");
			if (sLanguage == null || sLanguage.trim().length() < 1) {
				sLanguage = null;
			}

			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sAsUrl);
			sbSignature.append(_sCookiename);
			sbSignature.append(_sServerId);

			if (sCountry != null)
				sbSignature.append(sCountry);

			if (sLanguage != null)
				sbSignature.append(sLanguage);

			String sSignature = _cryptoEngine.generateSignature(_sAuthSP, sbSignature.toString());
			if (sSignature == null) {
				StringBuffer sbBuffer = new StringBuffer("Could not generate signature for authsp: ");
				sbBuffer.append(_sAuthSP);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			sSignature = URLEncoder.encode(sSignature, "UTF-8");
			_sCookiename = URLEncoder.encode(_sCookiename, "UTF-8");
			sAsUrl = URLEncoder.encode(sAsUrl, "UTF-8");
			// rid those not need to be url encoded by definition contains no characters to be encoded
			// a-select-server is never url encoded because of the way aselectserver handles this parameter
			
			StringBuffer sbRedirect = new StringBuffer(_sAuthSPUrl);
			sbRedirect.append("?as_url=").append(sAsUrl);
			sbRedirect.append("&rid=").append(sRid);
			sbRedirect.append("&cookiename=").append(_sCookiename);
			sbRedirect.append("&a-select-server=").append(_sServerId);

			if (sCountry != null)
				sbRedirect.append("&country=").append(sCountry);

			if (sLanguage != null)
				sbRedirect.append("&language=").append(sLanguage);

			sbRedirect.append("&signature=").append(sSignature);

			htResponse.put("redirect_url", sbRedirect.toString());
			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectAuthSPException e) {
			htResponse.put("result", e.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}

	/**
	 * Checks the response from the CookieAuthSP. <br>
	 * The response must contain the following parameters:<br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">name</td>
	 * <td style="" bgcolor="#EEEEFF">value</td>
	 * <td style="" bgcolor="#EEEEFF">encoded</td>
	 * </tr>
	 * <tr>
	 * <td>rid</td>
	 * <td>A-Select Server request id</td>
	 * <td>no</td>
	 * </tr>
	 * <tr>
	 * <td>result_code</td>
	 * <td>AuthSP result code</td>
	 * <td>no</td>
	 * </tr>
	 * <tr>
	 * <td>a-select-server</td>
	 * <td>A-Select Server ID</td>
	 * <td>no</td>
	 * </tr>
	 * <tr>
	 * <td>signature</td>
	 * <td>signature of all paramaters in the above sequence</td>
	 * <td>yes</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
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

		String sUserId = null;
		String sAppID = null;
		StringBuffer sbMessage = null;
		String sOrganization = null;
		String sLogResultCode = null;

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		try {
			String sRid = (String) htAuthspResponse.get("rid");	// rid by definition not url ecnoded
			String sAsUrl = (String) htAuthspResponse.get("my_url");	// my_url is contructed by aselectserver, no need to url decode
			String sResultCode = (String) htAuthspResponse.get("result_code");
			String uid = (String) htAuthspResponse.get("uid");
			String sAsId = (String) htAuthspResponse.get("a-select-server");	// a-select-server never url encoded
			String sSignature = (String) htAuthspResponse.get("signature");
			if ((sRid == null) || (sResultCode == null) || (sSignature == null) || (sAsId == null)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Incorrect AuthSP response, missing one or more required parameters.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			StringBuffer sbAsUrl = new StringBuffer(sAsUrl);
			sbAsUrl.append("?authsp=");
			sbAsUrl.append(_sAuthSP);
			sAsUrl = sbAsUrl.toString();

			sSignature = URLDecoder.decode(sSignature, "UTF-8");
			uid = URLDecoder.decode( ((uid == null)  ? "" : uid), "UTF-8");
			sResultCode = URLDecoder.decode(sResultCode, "UTF-8");
			
			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sResultCode);
			sbSignature.append(uid);
			sbSignature.append(sAsId);

			if (!_cryptoEngine.verifySignature(_sAuthSP, sbSignature.toString(), sSignature)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid signature in response from AuthSP:"
						+ _sAuthSP);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			// 20120403, Bauke: session is available as a parameter
			sUserId = uid == null ? (String) htSessionContext.get("user_id") : uid;
			sAppID = (String) htSessionContext.get("app_id");

			// must be retrieved from the session, because it can be an remote organtization
			sOrganization = (String) htSessionContext.get("organization");

			sbMessage = new StringBuffer(sOrganization);
			sbMessage.append(_sAuthSP).append(",");

			// check if user was authenticated successfully
			if (!sResultCode.equalsIgnoreCase(ERROR_NO_ERROR)) {
				if (sResultCode.equalsIgnoreCase(ERROR_ACCESS_DENIED)) {
					_authenticationLogger.log(new Object[] {
						MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrganization, sAppID, "denied", sResultCode
					});
					throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
				}

				StringBuffer sbError = new StringBuffer("AuthSP returned errorcode: ");
				sbError.append(sResultCode);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			_authenticationLogger.log(new Object[] {
				MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrganization, sAppID, "granted"
			});

			htResponse.put("rid", sRid);
			htResponse.put("authsp_type", _sAuthSP);
			sLogResultCode = Errors.ERROR_ASELECT_SUCCESS;
			htResponse.put("uid", sUserId);
			htResponse.put("result", sLogResultCode);
		}
		catch (ASelectAuthSPException e) {
			sLogResultCode = e.getMessage();
			htResponse.put("result", e.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR", e);
			sLogResultCode = Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
			htResponse.put("result", sLogResultCode);
		}
		return htResponse;
	}
}
