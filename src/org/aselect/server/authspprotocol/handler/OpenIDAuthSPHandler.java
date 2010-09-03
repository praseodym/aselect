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
 * $Id: Ldap.java,v 1.20 2006/05/03 09:46:50 tom Exp $ 
 * 
 * Changelog:
 * $Log: Ldap.java,v $
 * Revision 1.20  2006/05/03 09:46:50  tom
 * Removed Javadoc version
 *
 * Revision 1.19  2006/04/10 11:10:05  martijn
 * fixed showing friendly_name tags in showDirectLoginForm()
 *
 * Revision 1.18  2006/04/06 11:20:35  leon
 * gets the session in showdirectloginform for maintainer tags
 *
 * Revision 1.17  2006/04/03 12:28:59  erwin
 * HTML Tags are now replaced in case of an error.
 *
 * Revision 1.16  2006/04/03 08:44:12  erwin
 * Changed signature checking (fixed bug #165)
 *
 * Revision 1.15  2006/03/28 08:19:18  leon
 * *** empty log message ***
 *
 * Revision 1.14  2006/03/20 11:33:29  martijn
 * added optional template tag support
 *
 * Revision 1.13  2006/03/20 11:32:10  leon
 * removed some old not used functions
 *
 * Revision 1.12  2006/03/20 10:15:57  leon
 * implements now the IAuthSPDirectLoginProtocolHandler
 *
 * Revision 1.11  2005/09/08 13:06:53  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.10  2005/04/01 14:17:41  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.9  2005/03/24 15:12:43  erwin
 * fixed wrong errror into ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER
 *
 * Revision 1.8  2005/03/23 10:54:16  erwin
 * use ERROR_ASELECT_SERVER_SESSION_EXPIRED instead of invalid session
 *
 * Revision 1.7  2005/03/23 10:52:03  erwin
 * Added a session expired check
 *
 * Revision 1.6  2005/03/23 09:49:21  erwin
 * - Applied code style
 * - Added javadoc
 * - Improved error handling
 * 
 *
 */

package org.aselect.server.authspprotocol.handler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
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
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthSPException;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

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

	/** Prefix in errors.conf for LDAP specific errors */
//	private final static String ERROR_LDAP_PREFIX = "LDAP";
	// Prefix with number so integer check can be done on errors
	private final static String ERROR_OPENID_PREFIX = "11";

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
			/////// ????????????????? /////////////////
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
					MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg, (String) htSessionContext.get("app_id"),
					"denied"
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
				MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg, (String) htSessionContext.get("app_id"),
				"granted"
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
		String sMethod = "handleDirectLoginRequest()";
		String sRequest = (String) htServiceRequest.get("request");

		// Localization
		_sUserLanguage = sLanguage;
		_sUserCountry = sCountry;

		if (sRequest.equalsIgnoreCase("direct_login1")) {
			handleDirectLogin1(htServiceRequest, pwOut, sServerId);
		}
		else if (sRequest.equalsIgnoreCase("direct_login2")) {
			handleDirectLogin2(htServiceRequest, servletResponse, pwOut, sServerId);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request :'" + sRequest + "'");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

	}

	/**
	 * Handles the directlogin1 request for the OpenID AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Handles the <code>directlogin1</code> request for the OpenID AuthSP. Shows the Direct Login Form where users can
	 * submit their username and password. <br>
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
	private void handleDirectLogin1(HashMap htServiceRequest, PrintWriter pwOut, String sServerId)
		throws ASelectException
	{
		// show direct login form
		try {
			showDirectLoginForm(htServiceRequest, pwOut, sServerId);
		}
		catch (ASelectException e) {
			throw e;
		}
	}

	/**
	 * Handles directlogin2 request for the OpenID AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Handles the <code>directlogin2</code> request for the OpenID AuthSP. Verifies the request coming from the direct
	 * login form and does an API call to the OpenID AuthSP to verify the submitted username and password. <br>
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

		try {
			String sRid = null;
			String sUid = null;
			String sPassword = null;

			sRid = (String) htServiceRequest.get("rid");
			sUid = (String) htServiceRequest.get("user_id");
			sPassword = (String) htServiceRequest.get("password");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request, missing parmeter 'rid'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			if (sUid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request, missing parmeter 'user_id'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			if (sPassword == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request, missing parmeter 'password'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			// check if session is valid and not expired
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid session");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}
			String sAuthSPId = (String) htSessionContext.get("direct_authsp"); // must be set in configuration
			if (sAuthSPId == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Parameter 'direct_authsp' not found in session");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}
			String sAuthSPUrl = _authSPHandlerManager.getUrl(sAuthSPId);
			Integer intAuthSPLevel = _authSPHandlerManager.getLevel(sAuthSPId);
			String sResponse = null;
			try {
				StringBuffer sbRequest = new StringBuffer(sAuthSPUrl);
				sbRequest.append("?request=authenticate");
				sbRequest.append("&rid=").append(URLEncoder.encode(sRid, "UTF-8"));
				sbRequest.append("&user=").append(URLEncoder.encode(sUid, "UTF-8"));
				sbRequest.append("&password=").append(URLEncoder.encode(sPassword, "UTF-8"));
				_systemLogger.log(Level.INFO, MODULE, sMethod, "To AUTHSP: " + sbRequest);
				URL oServer = new URL(sbRequest.toString());
				BufferedReader oInputReader = new BufferedReader(new InputStreamReader(oServer.openStream()), 16000);
				sResponse = oInputReader.readLine();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "From AUTHSP: " + sResponse);
				oInputReader.close();
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid/No response from DirectAuthSP: '"
						+ sAuthSPId + "'", e);
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}

			HashMap htResponse = Utils.convertCGIMessage(sResponse);
			String sResponseCode = ((String) htResponse.get("status"));
			String sOrg = (String) htSessionContext.get("organization");
			if (sResponseCode == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid response from Direct AuthSP: '"+sAuthSPId+"'.");
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}
			else if (sResponseCode.equals(ERROR_OPENID_OK)) // authentication succeeded
			{
				TGTIssuer tgtIssuer = new TGTIssuer(sServerId);
				String sOldTGT = (String) htServiceRequest.get("aselect_credentials_tgt");
				htSessionContext.put("user_id", sUid);
				htSessionContext.put("authsp_level", intAuthSPLevel.toString());
				htSessionContext.put("sel_level", intAuthSPLevel.toString());  // equal to authsp_level in this case
				htSessionContext.put("authsp_type", "openid");
				_sessionManager.updateSession(sRid, htSessionContext); // store too (545)
				tgtIssuer.issueTGT(sRid, sAuthSPId, null, servletResponse, sOldTGT);

				_authenticationLogger.log(new Object[] {
					MODULE, sUid, (String) htSessionContext.get("client_ip"), sOrg,
					(String) htSessionContext.get("app_id"), "granted"
				});
			}
			else if (sResponseCode.equals(ERROR_OPENID_ACCESS_DENIED)) {
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, (String) htSessionContext.get("client_ip"), sOrg,
					(String) htSessionContext.get("app_id"), "denied"
				});

				String sErrorForm = _configManager.getForm("error", _sUserLanguage, _sUserCountry);
				sErrorForm = Utils.replaceString(sErrorForm, "[error]", ERROR_OPENID_PREFIX + ERROR_OPENID_ACCESS_DENIED);
				sErrorForm = Utils.replaceString(sErrorForm, "[error_code]", ERROR_OPENID_PREFIX + ERROR_OPENID_ACCESS_DENIED);
				String sErrorMessage = _configManager.getErrorMessage(ERROR_OPENID_PREFIX + ERROR_OPENID_ACCESS_DENIED,
						_sUserLanguage, _sUserCountry);
				sErrorForm = Utils.replaceString(sErrorForm, "[error_message]", sErrorMessage);
				sErrorForm = Utils.replaceString(sErrorForm, "[language]", _sUserLanguage);
				// RH, 20100819, sn
				//	add some extra info here
				sErrorForm = Utils.replaceString(sErrorForm, "[country]", _sUserCountry);
				sErrorForm = Utils.replaceString(sErrorForm, "[app_id]",(String) htSessionContext.get("app_id"));
				// RH, 20100819, en
				
				
				sErrorForm = Utils.replaceConditional(sErrorForm, "if_error", sErrorMessage != null && !sErrorMessage.equals(""));
				sErrorForm = _configManager.updateTemplate(sErrorForm, htSessionContext);
				pwOut.println(sErrorForm);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error response received: '" + sResponse
						+ "' from DirectAuthSP: '" + sAuthSPId + "'.");
				String sErrorMessage = _configManager.getErrorMessage(ERROR_OPENID_PREFIX
						+ ERROR_OPENID_INVALID_CREDENTIALS, _sUserLanguage, _sUserCountry);
				htServiceRequest.put("error_message", sErrorMessage);
				showDirectLoginForm(htServiceRequest, pwOut, sServerId);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Exception occured", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Prints the direct Login form. <br>
	 * <br>
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
		try {

			String sDirectLoginForm = _configManager.getForm("directlogin", _sUserLanguage, _sUserCountry);
			if (sDirectLoginForm == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "template file 'directlogin.html' not found");
				throw new ASelectException(Errors.ERROR_ASELECT_NOT_FOUND);
			}
			String sRid = (String) htServiceRequest.get("rid");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "no parameter 'rid' found in request");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not fetch session context for rid='" + sRid
						+ "'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}
			String sMyUrl = (String) htServiceRequest.get("my_url");
			if (sMyUrl == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "no parameter 'my_url' found in request");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			String sErrorMessage = (String) htServiceRequest.get("error_message");
			if (sErrorMessage == null) {
				sErrorMessage = "";
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "FORM directlogin, sServerId=" + sServerId);

			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[rid]", sRid);
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[aselect_url]", (String) htServiceRequest
					.get("my_url"));
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[a-select-server]", sServerId);
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[request]", "direct_login2");
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[cross_request]", "cross_login");

			String sUid = (String) htServiceRequest.get("user_id");
			if (sUid != null)
				sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[user_name]", sUid);
			else
				sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[user_name]", "");

			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[error_message]", sErrorMessage);
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[language]", _sUserLanguage);
			sDirectLoginForm = Utils.replaceConditional(sDirectLoginForm, "if_error", sErrorMessage != null && !sErrorMessage.equals(""));
			
			StringBuffer sbUrl = new StringBuffer(sMyUrl).append("?request=error").append("&result_code=").append(
					Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=").append(sServerId).append("&rid=")
					.append(sRid);
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[cancel]", sbUrl.toString());
			sDirectLoginForm = _configManager.updateTemplate(sDirectLoginForm, htSessionContext);
			pwOut.println(sDirectLoginForm);
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not show direct login page", e);
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not show direct login page", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

}
