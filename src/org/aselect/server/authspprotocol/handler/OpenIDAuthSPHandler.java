/*
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

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.http.HttpServletResponse;

import org.aselect.server.authspprotocol.IAuthSPDirectLoginProtocolHandler;
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

/**
 * The OpenID AuthSP Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * The OpenID AuthSP Handler communicates with the OpenID AuthSP by redirecting the client. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * <br>
 * <b>Protocol Description</b> <br>
 * <i><a name="outgoing">Outgoing request going to the OpenID AuthSP:</a></i> <br>
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
 * <td>signature of all parameters in the above sequence</td>
 * </tr>
 * </table>
 * <br>
 * <i><a name="incoming"> Incoming response, which is returned by the OpenID AuthSP: </a></i> <br>
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
 */
public class OpenIDAuthSPHandler implements IAuthSPProtocolHandler, IAuthSPDirectLoginProtocolHandler
{
	private final String MODULE = "OpenIDAuthSPHandler";

	/** The configuration. */
	private ASelectConfigManager _configManager;
	/** The session manager. */
	private SessionManager _sessionManager;

	private AuthSPHandlerManager _authSPHandlerManager;

	/** The system logger. */
	private ASelectSystemLogger _systemLogger;

	/** The Authentication logger. */
	private ASelectAuthenticationLogger _authenticationLogger;

	/** The AuthSP name. */
	private String _sAuthsp;
	/** The AuthSP URL. */
	private String _sAuthspUrl;

	/** AuthSP success code */
	private final static String ERROR_OPENID_OK = "000";

	/** AuthsP access denied error. */
	private final static String ERROR_OPENID_ACCESS_DENIED = "800";

	private final static String ERROR_OPENID_INVALID_CREDENTIALS = "400";


	// Localization
	protected String _sUserLanguage = "";
	protected String _sUserCountry = "";

	/**
	 * Initializes the <code>OpenID</code> AuthSP handler. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Performs the following steps:
	 * <ul>
	 * <li>Retrieve handles to required managers and loggers</li>
	 * <li>Retrieve AuthSP ID from configuration</li>
	 * <li>Retrieve AuthSP URL from configuration</li>
	 * </ul>
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
		final String sMethod = "init()";
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
						"Parameter 'id' not found in OPenID" +
						" AuthSP configuration", eAC);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
			try {
				_sAuthspUrl = _configManager.getParam(oAuthSPResource, "url");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Parameter 'url' not found in OpenID AuthSP configuration", eAC);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
		}
		catch (ASelectAuthSPException eAA) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initialisation failed due to configuration error", eAA);
			throw eAA;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initialisation failed due to internal error", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * new init function. <br>
	 * <br>
	 * 
	 * @param sAuthSPId
	 *            the s auth sp id
	 * @throws ASelectAuthSPException
	 *             the a select auth sp exception
	 * @see org.aselect.server.authspprotocol.IAuthSPDirectLoginProtocolHandler#init(java.lang.String)
	 */
	public void init(String sAuthSPId)
		throws ASelectAuthSPException
	{
		final String sMethod = "init()";
		_configManager = ASelectConfigManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_authenticationLogger = ASelectAuthenticationLogger.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
		_authSPHandlerManager = AuthSPHandlerManager.getHandle();
		try {
			_sAuthsp = sAuthSPId;
			try {
				_sAuthspUrl = _authSPHandlerManager.getUrl(sAuthSPId);
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'url' retrieved", e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		catch (ASelectAuthSPException eAA) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initialisation failed due to configuration error", eAA);
			throw eAA;
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
	public HashMap computeAuthenticationRequest(String sRid)
	{
		String sMethod = "computeAuthenticationRequest";
		StringBuffer sbBuffer = null;

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		try {
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
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
			if (sUserId == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing OpenID user attributes.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Using user id: '" + sUserId + "'");

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

			if (sCountry != null)
				sbSignature.append(sCountry);

			if (sLanguage != null)
				sbSignature.append(sLanguage);

			String sSignature = CryptoEngine.getHandle().generateSignature(_sAuthsp, sbSignature.toString());
			if (sSignature == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not sign OpenID AuthSP request.");
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

			if (sCountry != null)
				sbRedirect.append("&country=").append(sCountry);

			if (sLanguage != null)
				sbRedirect.append("&language=").append(sLanguage);

			sbRedirect.append("&signature=").append(sSignature);

			htResponse.put("redirect_url", sbRedirect.toString());
			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectAuthSPException eAA) {
			// allready logged
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
		String sMethod = "verifyAuthenticationResponse()";
		StringBuffer sbBuffer = null;

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		try {
			// retrieve request parameters
			String sRid = (String) htAuthspResponse.get("rid");
			String sAsUrl = (String) htAuthspResponse.get("my_url");
			String sResultCode = (String) htAuthspResponse.get("result_code");
			String sAsId = (String) htAuthspResponse.get("a-select-server");
			String sSignature = (String) htAuthspResponse.get("signature");
			// validate request
			if ((sRid == null) || (sResultCode == null) || (sAsId == null) || (sSignature == null)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Incorrect AuthSP response: one or more parameters missing.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			// create complete as_url
			sbBuffer = new StringBuffer(sAsUrl);
			sbBuffer.append("?authsp=");
			sbBuffer.append(_sAuthsp);
			sAsUrl = sbBuffer.toString();

			// validate signature
			sSignature = URLDecoder.decode(sSignature, "UTF-8");
			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sAsUrl);
			sbSignature.append(sResultCode);
			sbSignature.append(sAsId);

			boolean bVerifies = CryptoEngine.getHandle().verifySignature(_sAuthsp, sbSignature.toString(), sSignature);
			if (!bVerifies) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "invalid signature in response from AuthSP:"
						+ _sAuthsp);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			// get parameters from session
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Incorrect AuthSP response: invalid Session (could be expired)");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}
			// OpenID returns it's own uid
//			String sUserId = (String) htSessionContext.get("user_id");
			String sUserId = (String) htAuthspResponse.get("uid");
			
			String sOrg = (String) htSessionContext.get("organization");

			// check why the user was not authenticated successfully
			if (sResultCode.equalsIgnoreCase(ERROR_OPENID_ACCESS_DENIED)) { // access denied
				// only log to authentication log
				_authenticationLogger.log(new Object[] {
					MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg,
					(String) htSessionContext.get("app_id"), "denied", sResultCode
				});
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
			}

			if (!sResultCode.equalsIgnoreCase(ERROR_OPENID_OK)) { // other error
				StringBuffer sbError = new StringBuffer("AuthSP returned errorcode: ");
				sbError.append(sResultCode);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			// everything OK -> log to authentication logger
			_authenticationLogger.log(new Object[] {
				MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg,
				(String) htSessionContext.get("app_id"), "granted"
			});
			// set response
			htResponse.put("rid", sRid);
			htResponse.put("authsp_type", "openid");
			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
			htResponse.put("uid", sUserId);
		}
		catch (ASelectAuthSPException eAA) // Error occurred
		{
			// allready logged
			htResponse.put("result", eAA.getMessage());
		}
		catch (UnsupportedEncodingException eUE) // Error while decoding signature
		{
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not decode signature", eUE);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		catch (Exception e) // internal error
		{
			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not verify authentication response due to internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);

		}
		return htResponse;
	}

	/**
	 * handles all the incoming direct login requests for the OpenID AuthSP <br>
	 * not implemented (yet) <br>
	 * <br>
	 * .
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @param sServerId
	 *            the s server id
	 * @param sLanguage
	 *            the s language
	 * @param sCountry
	 *            the s country
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.authspprotocol.IAuthSPDirectLoginProtocolHandler#handleDirectLoginRequest(java.util.HashMap,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter, java.lang.String)
	 */
	public void handleDirectLoginRequest(HashMap htServiceRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut, String sServerId, String sLanguage, String sCountry)
		throws ASelectException
	{
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);

	}

	/**
	 * Handles the directlogin1 request for the OpenID AuthSP. <br>
	 * Not implemented (yet)<br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param pwOut
	 *            the pw out
	 * @param sServerId
	 *            the s server id
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleDirectLogin1(HashMap htServiceRequest, PrintWriter pwOut, String sServerId)
		throws ASelectException
	{
		throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
	}

	/**
	 * Handles directlogin2 request for the OpenID AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Handles the <code>directlogin2</code> request for the OpenID AuthSP. Verifies the request coming from the direct
	 * login form and does an API call to the OpenID AuthSP to verify the submitted username and password. <br>
	 * <br>
	 * Not implemented (yet)<br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @param sServerId
	 *            the s server id
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleDirectLogin2(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut,
			String sServerId)
		throws ASelectException
	{
		String sMethod = "handleDirectLogin2";

		throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
	}

	/**
	 * Prints the direct Login form. <br>
	 * <br>
	 * Not implemented (yet)<br>
	 * <b>Description:</b> <br>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param pwOut
	 *            the pw out
	 * @param sServerId
	 *            the s server id
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void showDirectLoginForm(HashMap htServiceRequest, PrintWriter pwOut, String sServerId)
		throws ASelectException
	{
		String sMethod = "showDirectLoginForm()";
		throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
	}

}
