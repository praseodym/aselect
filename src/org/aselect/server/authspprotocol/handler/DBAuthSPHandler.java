package org.aselect.server.authspprotocol.handler;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Hashtable;
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
/**
 * The DB AuthSP Handler.
 * <br><br>
 * <b>Description:</b><br>
 * The DB AuthSP Handler communicates with the DB AuthSP by redirecting 
 * the client. 
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * None
 * <br><br>
 * <b>Protocol Description</b>
 * <br>
 * <i><a name="outgoing">Outgoing request going to the DB AuthSP:</a></i>
 * <br>
 * <table border="1" cellspacing="0" cellpadding="3">
 * 	<tr>
 * 		<td style="" bgcolor="#EEEEFF"><b>name</b></td>
 * 		<td style="" bgcolor="#EEEEFF"><b>value</b></td>
 * 	</tr>  
 * 	<tr><td>rid</td><td>A-Select Server request id</td></tr>
 * 	<tr><td>as_url</td><td>A-Select Server url</td></tr>
 * 	<tr><td>uid</td><td>A-Select Server user ID</td></tr>
 * 	<tr><td>a-select-server</td><td>A-Select Server ID</td></tr>
 * 	<tr>
 * 		<td>signature</td>
 * 		<td>signature of all paramaters in the above sequence</td>
 * 	</tr>
 * </table>
 * <br>
 * <i><a name="incoming">
 * 	Incoming response, which is returned by the DB AuthSP:
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
 * @author Cristina Gavrila, BTTSD
 */
public class DBAuthSPHandler implements IAuthSPProtocolHandler {

	private final String MODULE = "DBAuthSPHandler";

	private ASelectConfigManager _configManager;

	private SessionManager _sessionManager;

	private ASelectSystemLogger _systemLogger;

	private ASelectAuthenticationLogger _authenticationLogger;

	private String _sAuthsp;

	private String _sAuthspUrl;

	private static final String ERROR_DB_OK = "000";

	private static final String ERROR_DB_ACCESS_DENIED = "800";

	private static final String ERROR_DB_INVALID_CREDENTIALS = "400";

	private static final String ERROR_DB_PREFIX = "DB";

	public void init(Object oAuthSPConfig, Object oAuthSPResource)
			throws ASelectAuthSPException {
		String sMethod = "init()";
		_configManager = ASelectConfigManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_authenticationLogger = ASelectAuthenticationLogger.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
		try {
			try {
				_sAuthsp = _configManager.getParam(oAuthSPConfig, "id");
			} catch (ASelectConfigException eAC) {
				_systemLogger
						.log(
								Level.WARNING,
								"DBAuthSPHandler",
								"init()",
								"Parameter 'id' not found in DB AuthSP configuration",
								eAC);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
			try {
				_sAuthspUrl = _configManager.getParam(oAuthSPResource, "url");
			} catch (ASelectConfigException eAC) {
				_systemLogger
						.log(
								Level.WARNING,
								"DBAuthSPHandler",
								"init()",
								"Parameter 'url' not found in DB AuthSP configuration",
								eAC);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
		} catch (ASelectAuthSPException eAA) {
			_systemLogger.log(Level.SEVERE, "DBAuthSPHandler", "init()",
					"Initialisation failed due to configuration error", eAA);
			throw eAA;
		} catch (Exception e) {
			_systemLogger.log(Level.SEVERE, "DBAuthSPHandler", "init()",
					"Initialisation failed due to internal error", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}
	
    /**
     * Creates the authentication request URL.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * This method creates a hashtable with the follwing contents:
     * <table border="1" cellspacing="0" cellpadding="3">
     * <tr>
     *	<td style="" bgcolor="#EEEEFF"><b>key</b></td>
     *	<td style="" bgcolor="#EEEEFF"><b>value</b></td>
     * </tr>  
     * <tr>
     * 	<td>result</td>
     *  <td>
     * 		{@link Errors#ERROR_ASELECT_SUCCESS} or an error code 
     * 		if creating the authentication request URL fails
     * 	</td>
     * </tr>
     * <tr>
     * 	<td>redirect_url</td>
     * 	<td>
     * 		The URL to the AuthSP including the protocol parameters as specified
     * 		if the <a href="#outgoing">class description</a>.
     * </td>
     * </tr>
     * </table>
     * 
     * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#computeAuthenticationRequest(java.lang.String)
     */
	public Hashtable computeAuthenticationRequest(String sRid) {
		String sMethod = "computeAuthenticationRequest()";
		StringBuffer sbBuffer = null;
		Hashtable htResponse = new Hashtable();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
		try {
			Hashtable htSessionContext = _sessionManager
					.getSessionContext(sRid);
			if (htSessionContext == null) {
				sbBuffer = new StringBuffer(
						"Could not fetch session context for rid='");
				sbBuffer.append(sRid).append("'.");
				_systemLogger.log(Level.WARNING, "DBAuthSPHandler", sMethod,
						sbBuffer.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			Hashtable htAllowedAuthsps = (Hashtable) (Hashtable) htSessionContext
					.get("allowed_user_authsps");
			if (htAllowedAuthsps == null) {
				_systemLogger.log(Level.WARNING, "DBAuthSPHandler", sMethod,
						"Allowed_user_authsps missing in session context.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			String sUserId = (String) (String) htAllowedAuthsps.get(_sAuthsp);
			if (sUserId == null) {
				_systemLogger.log(Level.WARNING, "DBAuthSPHandler", sMethod,
						"Missing DB user attributes.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			sbBuffer = new StringBuffer((String) (String) htSessionContext
					.get("my_url"));
			sbBuffer.append("?authsp=").append(_sAuthsp);
			String sAsUrl = sbBuffer.toString();
			String sCountry = (String) (String) htSessionContext.get("country");
			if (sCountry == null || sCountry.trim().length() < 1) {
				sCountry = null;
			}
			String sLanguage = (String) (String) htSessionContext
					.get("language");
			if (sLanguage == null || sLanguage.trim().length() < 1) {
				sLanguage = null;
			}
			String sServerId = _configManager.getParam(_configManager
					.getSection(null, "aselect"), "server_id");
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
			String sSignature = CryptoEngine.getHandle().generateSignature(
					_sAuthsp, sbSignature.toString());
			if (sSignature == null) {
				_systemLogger.log(Level.WARNING, "DBAuthSPHandler", sMethod,
						"Could not sign DB AuthSP request.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
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
		} catch (ASelectAuthSPException eAA) {
			htResponse.put("result", eAA.getMessage());
		} catch (Exception e) {
			_systemLogger
					.log(
							Level.SEVERE,
							"DBAuthSPHandler",
							sMethod,
							"Could not compute authentication request due to internal error",
							e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}
    /**
     * Verifies the response from the AuthSP.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * This method verifies the response from the AuthSP. The response 
     * parameters are placed in <code>htAuthspResponse</code> and are 
     * described in the <a href="#incoming">class description</a>.
     * <br><br>
     * This method creates a hashtable with the following contents:
     * <table border="1" cellspacing="0" cellpadding="3">
     * 	<tr>
     *		<td style="" bgcolor="#EEEEFF"><b>key</b></td>
     *		<td style="" bgcolor="#EEEEFF"><b>value</b></td>
     * 	</tr>  
     * 	<tr>
     * 		<td>result</td>
     *  	<td>
     * 			{@link Errors#ERROR_ASELECT_SUCCESS} or an error code 
     * 			if the authentication response was invalid or the user was 
     * 			not authenticated.
     * 		</td>
     * 	</tr>
     * 	<tr>
     * 		<td>rid</td>
     * 		<td>The A-Select request identifier of this authentication.</td>
     * 	</tr>
     * </table>
     * 
     * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#verifyAuthenticationResponse(java.util.Hashtable)
     */
	public Hashtable verifyAuthenticationResponse(Hashtable htAuthspResponse) {
		String sMethod = "verifyAuthenticationResponse()";
		StringBuffer sbBuffer = null;
		Hashtable htResponse = new Hashtable();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
		try {
			String sRid = (String) (String) htAuthspResponse.get("rid");
			String sAsUrl = (String) (String) htAuthspResponse.get("my_url");
			String sResultCode = (String) (String) htAuthspResponse
					.get("result_code");
			String sAsId = (String) (String) htAuthspResponse
					.get("a-select-server");
			String sSignature = (String) (String) htAuthspResponse
					.get("signature");
			if (sRid == null || sResultCode == null || sAsId == null
					|| sSignature == null) {
				_systemLogger
						.log(Level.WARNING, "DBAuthSPHandler", sMethod,
								"Incorrect AuthSP response: one or more parameters missing.");
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
			boolean bVerifies = CryptoEngine.getHandle().verifySignature(
					_sAuthsp, sbSignature.toString(), sSignature);
			if (!bVerifies) {
				_systemLogger.log(Level.WARNING, "DBAuthSPHandler", sMethod,
						"invalid signature in response from AuthSP:"+_sAuthsp);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}
			Hashtable htSessionContext = _sessionManager
					.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger
						.log(Level.WARNING, "DBAuthSPHandler", sMethod,
								"Incorrect AuthSP response: invalid Session (could be expired)");
				throw new ASelectAuthSPException("0102");
			}
			String sUserId = (String) (String) htSessionContext.get("user_id");
			String sOrg = (String) (String) htSessionContext
					.get("organization");
			if (sResultCode.equalsIgnoreCase(ERROR_DB_ACCESS_DENIED)) {
				_authenticationLogger.log(new Object[] { "DBAuthSPHandler",
						sUserId, htAuthspResponse.get("client_ip"), sOrg,
						(String) (String) htSessionContext.get("app_id"),
						"denied" });
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
			}
			if (!sResultCode.equalsIgnoreCase(ERROR_DB_OK)) {
				StringBuffer sbError = new StringBuffer(
						"AuthSP returned errorcode: ");
				sbError.append(sResultCode);
				_systemLogger.log(Level.WARNING, "DBAuthSPHandler", sMethod,
						sbError.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			_authenticationLogger
					.log(new Object[] { "DBAuthSPHandler", sUserId,
							htAuthspResponse.get("client_ip"), sOrg,
							(String) (String) htSessionContext.get("app_id"),
							"granted" });
			htResponse.put("rid", sRid);
			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		} catch (ASelectAuthSPException eAA) {
			htResponse.put("result", eAA.getMessage());
		} catch (UnsupportedEncodingException eUE) {
			_systemLogger.log(Level.SEVERE, "DBAuthSPHandler", sMethod,
					"Could not decode signature", eUE);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		} catch (Exception e) {
			_systemLogger
					.log(
							Level.SEVERE,
							"DBAuthSPHandler",
							sMethod,
							"Could not verify authentication response due to internal error",
							e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}
}
