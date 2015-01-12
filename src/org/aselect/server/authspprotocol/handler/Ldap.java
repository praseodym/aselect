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
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.authspprotocol.IAuthSPConditions;
import org.aselect.server.authspprotocol.IAuthSPDirectLoginProtocolHandler;
import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.server.udb.UDBConnectorFactory;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthSPException;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;

/**
 * The Ldap AuthSP Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * The Ldap AuthSP Handler communicates with the Ldap AuthSP by redirecting the client. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * <br>
 * <b>Protocol Description</b> <br>
 * <i><a name="outgoing">Outgoing request going to the Ldap AuthSP:</a></i> <br>
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
 * <i><a name="incoming"> Incoming response, which is returned by the Ldap AuthSP: </a></i> <br>
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
public class Ldap implements IAuthSPProtocolHandler, IAuthSPDirectLoginProtocolHandler, IAuthSPConditions
{
	private final String MODULE = "Ldap";

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
	private final static String ERROR_LDAP_OK = "000";

	/** AuthsP access denied error. */
	private final static String ERROR_LDAP_ACCESS_DENIED = "800";

	private final static String ERROR_LDAP_INVALID_CREDENTIALS = "400";

	/** Prefix in errors.conf for LDAP specific errors */
//	private final static String ERROR_LDAP_PREFIX = "LDAP";
	// Prefix with number so integer check can be done on errors
	private final static String ERROR_LDAP_PREFIX = "11";

	// Localization
	protected String _sUserLanguage = "";
	protected String _sUserCountry = "";
	
	protected boolean outputAvailable = true;	// We assume output available presence per default
	
	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#myRidName()
	 */
	public String getLocalRidName() { return "rid"; }
	
	/**
	 * Initializes the <code>Ldap</code> AuthSP handler. <br>
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
		final String sMethod = "init";
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
						"Parameter 'id' not found in Ldap AuthSP configuration", eAC);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
			try {
				_sAuthspUrl = _configManager.getParam(oAuthSPResource, "url");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Parameter 'url' not found in Ldap AuthSP configuration", eAC);
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
		final String sMethod = "init";
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
	public HashMap computeAuthenticationRequest(String sRid, HashMap htSessionContext)
	{
		String sMethod = "computeAuthenticationRequest";
		StringBuffer sbBuffer = null;

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		try {
			// 20120403, Bauke: passes as parameter: HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
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
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing ldap user attributes.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Using user id: '" + sUserId + "' from allowed Authsps ");
			if ("".equals(sUserId))
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Empty user id, would be nice to use "+htSessionContext.get("user_id"));

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
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not sign Ldap AuthSP request.");
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

			// 20120403, Bauke: session is available as a parameter
			String sUserId = (String) htSessionContext.get("user_id");
			String sOrg = (String) htSessionContext.get("organization");

			// check why the user was not authenticated successfully
			if (sResultCode.equalsIgnoreCase(ERROR_LDAP_ACCESS_DENIED)) { // access denied
				// only log to authentication log
				_authenticationLogger.log(new Object[] {
					MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg,
					(String) htSessionContext.get("app_id"), "denied", sResultCode
				});
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
			}

			if (!sResultCode.equalsIgnoreCase(ERROR_LDAP_OK)) { // other error
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
			htResponse.put("authsp_type", "ldap");
			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectAuthSPException eAA) {  // already logged
			htResponse.put("result", eAA.getMessage());
		}
		catch (UnsupportedEncodingException eUE) {  // Error while decoding signature
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not decode signature", eUE);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		catch (Exception e) { // internal error
			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not verify authentication response due to internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}

	/**
	 * handles all the incoming direct login requests for the LDAP AuthSP <br>
	 * <br>
	 * .
	 * 
	 * @param htServiceRequest
	 *            the service request
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @param htSessionContext
	 *            the session context
	 * @param htAdditional
	 *            the additional attributes
	 * @param pwOut
	 *            the pw output
	 * @param sServerId
	 *            the server id
	 * @param sLanguage
	 *            the language
	 * @param sCountry
	 *            the country
	 * @return true if successful
	 * @throws ASelectException
	 * @see org.aselect.server.authspprotocol.IAuthSPDirectLoginProtocolHandler#handleDirectLoginRequest(java.util.HashMap,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter,
	 *      java.lang.String)
	 */
	// 20120403, Bauke: added htSessionContext to save on session reads
	public boolean handleDirectLoginRequest(HashMap htServiceRequest, HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			HashMap htSessionContext, HashMap htAdditional, PrintWriter pwOut, String sServerId, String sLanguage, String sCountry)
	throws ASelectException
	{
		String sMethod = "handleDirectLoginRequest";
		String sRequest = (String) htServiceRequest.get("request");

		// Localization
		_sUserLanguage = sLanguage;
		_sUserCountry = sCountry;

		if (sRequest.equalsIgnoreCase("direct_login1")) {
			handleDirectLogin1(servletRequest, htServiceRequest, htSessionContext, pwOut, sServerId);
			return true;
		}
		else if (sRequest.equalsIgnoreCase("direct_login2")) {
			return handleDirectLogin2(htServiceRequest, servletRequest, servletResponse, htSessionContext, htAdditional, pwOut, sServerId);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request :'" + sRequest + "'");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}

	/**
	 * Handles the directlogin1 request for the LDAP AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Handles the <code>directlogin1</code> request for the LDAP AuthSP. Shows the Direct Login Form where users can
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
	 *            the service request
	 * @param pwOut
	 *            the pw out
	 * @param sServerId
	 *            the server id
	 * @throws ASelectException
	 *             the aselect exception
	 */
	private void handleDirectLogin1(HttpServletRequest servletRequest, HashMap htServiceRequest, HashMap htSessionContext, PrintWriter pwOut, String sServerId)
	throws ASelectException
	{
		// show direct login form
		String sMethod = "handleDirectLogin1";
		
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "htServiceRequest: '"+htServiceRequest);
		// not very useful: try {
		showDirectLoginForm(servletRequest, htServiceRequest, htSessionContext, pwOut, sServerId);  // can change the session
		//}
		//catch (ASelectException e) { throw e; }
	}

	/**
	 * Handles directlogin2 request for the LDAP AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Handles the <code>directlogin2</code> request for the LDAP AuthSP. Verifies the request coming from the direct
	 * login form and does an API call to the LDAP AuthSP to verify the submitted username and password. <br>
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
	 *            the service request
	 * @param servletResponse
	 *            the servlet response, can be null if no user browser is attached
	 * @param pwOut
	 *            the output print writer
	 * @param sServerId
	 *            the server id
	 * @return true if successful
	 * @throws ASelectException
	 */
	private boolean handleDirectLogin2(HashMap htServiceRequest, HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			HashMap htSessionContext, HashMap htAdditional, PrintWriter pwOut, String sServerId)
	throws ASelectException
	{
		String sMethod = "handleDirectLogin2";

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "servletResponse="+servletResponse);
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

			// 20120403, available as parameter: HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
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
			// RH, 20110912, moved authSPsection decl. up for reuse later
			Object authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp", "id="+sAuthSPId);

			try {
				// 20110721, Bauke: communicate with the AuthSP using the POST mechanism
				String sPostIt = null;
				if (authSPsection != null)
					sPostIt = ASelectConfigManager.getSimpleParam(authSPsection, "post_it", false);  // not mandatory
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Section id="+sAuthSPId+" post_it: " + sPostIt);

				StringBuffer sbReqArgs = new StringBuffer("request=authenticate");
				sbReqArgs.append("&rid=").append(URLEncoder.encode(sRid, "UTF-8"));
				sbReqArgs.append("&user=").append(URLEncoder.encode(sUid, "UTF-8"));
				sbReqArgs.append("&password=").append(URLEncoder.encode(sPassword, "UTF-8"));
				String sArgs = sbReqArgs.toString();
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "To AUTHSP: " + sAuthSPUrl+" Args="+sArgs);
							
				if ("true".equals(sPostIt)) {  // use POST, must also be URL encoded!!!
					
					URL oServer = new URL(sAuthSPUrl);  // 20120106, Bauke: just the url
					HttpURLConnection conn = (HttpURLConnection)oServer.openConnection();
					conn.setDoOutput(true);
					
					_systemLogger.log(Level.INFO, MODULE, sMethod, "POST Host="+oServer.getHost()+" Length="+sArgs.length());
					conn.setRequestMethod("POST");
					conn.setRequestProperty("Host", oServer.getHost());
					conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
					conn.setRequestProperty("Content-Length", Integer.toString(sArgs.length()));
					
					OutputStream oStream = conn.getOutputStream();
					BufferedWriter oOutputWriter = new BufferedWriter(new OutputStreamWriter(oStream), 16000);
					oOutputWriter.write(sArgs);
					oOutputWriter.close();
					
					// And retrieve the response
					InputStream iStream = conn.getInputStream();
					BufferedReader oInputReader = new BufferedReader(new InputStreamReader(iStream), 16000);
					sResponse = oInputReader.readLine();
					oInputReader.close();
				}
				else {
					StringBuffer sbRequest = new StringBuffer(sAuthSPUrl);
					String sRequest = sbRequest.append("?").append(sbReqArgs).toString();
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "GET request="+ sRequest);
					URL oServer = new URL(sRequest);
					URLConnection conn = oServer.openConnection();
					InputStream iStream = conn.getInputStream();
					BufferedReader oInputReader = new BufferedReader(new InputStreamReader(iStream), 16000);
					sResponse = oInputReader.readLine();
					oInputReader.close();
				}				
				_systemLogger.log(Level.INFO, MODULE, sMethod, "From AUTHSP: " + sResponse);
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid/No response from DirectAuthSP: '"
						+ sAuthSPId + "'", e);
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}

			HashMap htResponse = Utils.convertCGIMessage(sResponse, false);
			String sResponseCode = ((String) htResponse.get("status"));
			String sOrg = (String) htSessionContext.get("organization");
			if (sResponseCode == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid response from Direct AuthSP: '"+sAuthSPId+"'.");
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}
			else if (sResponseCode.equals(ERROR_LDAP_OK)) // authentication succeeded
			{
				htSessionContext.put("user_id", sUid);

				// Start sequential authsp's
				String app_id = (String)htSessionContext.get("app_id");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "app_id="+app_id+" SessionContext="+htSessionContext);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "htServiceRequest="+htServiceRequest);
				
				htSessionContext.put("authsp_level", intAuthSPLevel.toString());
				htSessionContext.put("sel_level", intAuthSPLevel.toString());  // equal to authsp_level in this case
				htSessionContext.put("authsp_type", "ldap");

				String next_authsp = _authSPHandlerManager.getNextAuthSP(sAuthSPId, app_id);
				if (next_authsp != null) {
					htSessionContext.remove("direct_authsp");	// No other direct_authsp's yet
					htSessionContext.put("forced_authsp", next_authsp);
					
					// Set allowed_user_authsps in the event of direct_authsp, 
					// would 'normally' be set by  ApplicationBrowserHandler.handleLogin2(.....).getAuthsps(....)
					HashMap htUserAuthsps = getUserAuthsps(sUid);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "next_authsp="+next_authsp+" allowed="+htUserAuthsps);
					htSessionContext.put("allowed_user_authsps", htUserAuthsps);
				}
				// Store now, issueTGTandRedirect() will read it again
				//_sessionManager.updateSession(sRid, htSessionContext);
				_sessionManager.setUpdateSession(htSessionContext, _systemLogger);  // 20120403, Bauke: changed from updateSession
				
				if (servletResponse == null) {
					// For the login_token functionality, no redirection
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No browser attached ...");
					return true;  // No browser attached
				}
				
				HandlerTools.setRequestorFriendlyCookie(servletResponse, htSessionContext, _systemLogger);  // 20130825
				TGTIssuer tgtIssuer = new TGTIssuer(sServerId);
				String sOldTGT = (String) htServiceRequest.get("aselect_credentials_tgt");
				
				setOutputAvailable(true); // Assume browser still present, 	// RH, 20130813, n
				String sTgt = tgtIssuer.issueTGTandRedirect(sRid, htSessionContext, sAuthSPId, htAdditional, servletRequest, servletResponse,
						sOldTGT, false /* no redirect */, this);	// RH, 20130813, n

				// Cookie was set on the 'servletResponse'

				// The next user redirect will set the TGT cookie, the "nextauthsp" form below will also set the cookie
				if (next_authsp != null) {
					// Direct the user to the next_authsp using the "nextauthsp" form
					String sNextauthspForm = _configManager.getHTMLForm("nextauthsp", _sUserLanguage, _sUserCountry);
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[rid]", sRid);
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[a-select-server]",  (String) htServiceRequest.get("a-select-server"));
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[user_id]", sUid);
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[authsp]", next_authsp);
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[aselect_url]", (String) htServiceRequest.get("my_url"));
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[request]", "login3");
					String sLanguage = (String) htServiceRequest.get("language");  // 20101027 _
					String sCountry = (String) htServiceRequest.get("country");  // 20101027 _
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[language]", sLanguage);
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[country]", sCountry);
					sNextauthspForm = _configManager.updateTemplate(sNextauthspForm, htSessionContext, servletRequest);
				
					Tools.pauseSensorData(_configManager, _systemLogger, htSessionContext);  //20111102 can update the session
					pwOut.println(sNextauthspForm);
					return true;
				}
				// End sequential authsp's
				
				_authenticationLogger.log(new Object[] {
						MODULE, sUid, (String) htSessionContext.get("client_ip"), sOrg, app_id, "granted"
					});

				if (isOutputAvailable()) {	// only redirect of output available // RH, 20130813, n
					String sAppUrl = (String) htSessionContext.get("app_url");
					if (htSessionContext.get("remote_session") != null)
						sAppUrl = (String) htSessionContext.get("local_as_url");
					
					// 20111101, Bauke: added Sensor
					// Finish regular authsp handling
					Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_ldp", sRid, htSessionContext, sTgt, true);
					_sessionManager.setDeleteSession(htSessionContext, _systemLogger);  // 20120403, Bauke: changed from Session
					// 20111018, Bauke: redirect is done below
	
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to: sAppUrl=" + sAppUrl);
					String sLang = (String)htSessionContext.get("language");
					tgtIssuer.sendTgtRedirect(sAppUrl, sTgt, sRid, servletResponse, sLang);  // no session changes
				}	// RH, 20130813, n
				setOutputAvailable(true);	// restore original value	// RH, 20130813, n
				return true;
			}
			else if (sResponseCode.equals(ERROR_LDAP_ACCESS_DENIED)) {
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, (String) htSessionContext.get("client_ip"), sOrg,
					(String) htSessionContext.get("app_id"), "denied", sResponseCode
				});

				if (servletResponse == null)  // no browser attached
					return false;
				
				String sErrorForm = _configManager.getHTMLForm("error", _sUserLanguage, _sUserCountry);
				sErrorForm = Utils.replaceString(sErrorForm, "[error]", ERROR_LDAP_PREFIX + ERROR_LDAP_ACCESS_DENIED);
				sErrorForm = Utils.replaceString(sErrorForm, "[error_code]", ERROR_LDAP_PREFIX + ERROR_LDAP_ACCESS_DENIED);
				String sErrorMessage = _configManager.getErrorMessage(MODULE, ERROR_LDAP_PREFIX + ERROR_LDAP_ACCESS_DENIED,
						_sUserLanguage, _sUserCountry);
				sErrorForm = Utils.replaceString(sErrorForm, "[error_message]", sErrorMessage);
				sErrorForm = Utils.replaceString(sErrorForm, "[language]", _sUserLanguage);
				// RH, 20100819, sn
				//	add some extra info here
				sErrorForm = Utils.replaceString(sErrorForm, "[country]", _sUserCountry);
				sErrorForm = Utils.replaceString(sErrorForm, "[app_id]",(String) htSessionContext.get("app_id"));
				// RH, 20100819, en
				sErrorForm = _configManager.updateTemplate(sErrorForm, htSessionContext, servletRequest);
			
				// Bauke 20100908: Extract if_cond=... from the application URL
				String sSpecials = Utils.getAselectSpecials(htSessionContext, true/*decode too*/, _systemLogger);
				sErrorForm = Utils.handleAllConditionals(sErrorForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);

				Tools.pauseSensorData(_configManager, _systemLogger, htSessionContext);  //20111102 can update the session
				pwOut.println(sErrorForm);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error response received: '" + sResponse
						+ "' from DirectAuthSP: '" + sAuthSPId + "'.");

				if (servletResponse != null) {
					String sErrorMessage = _configManager.getErrorMessage(MODULE, ERROR_LDAP_PREFIX
						+ ERROR_LDAP_INVALID_CREDENTIALS, _sUserLanguage, _sUserCountry);
					htServiceRequest.put("error_message", sErrorMessage);
					showDirectLoginForm(servletRequest, htServiceRequest, htSessionContext, pwOut, sServerId);  // can change the session
				}  // else no browser attached
			}
			return false;
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
	 * @param sMethod
	 * @param sUid
	 * @return
	 * @throws ASelectException
	 */
	private HashMap getUserAuthsps(String sUid)
	throws ASelectException
	{
		String sMethod = "getUserAuthSPs";
		HashMap htUserAuthsps = new HashMap();
		IUDBConnector oUDBConnector = null;

		try {
			oUDBConnector = UDBConnectorFactory.getUDBConnector();
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to connect with UDB.", e);
			throw e;
		}

		// Get user's attributes from the UDB
		HashMap htUserProfile = oUDBConnector.getUserProfile(sUid);
		if (!((String) htUserProfile.get("result_code")).equals(Errors.ERROR_ASELECT_SUCCESS)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get user profile.");
			throw new ASelectException((String) htUserProfile.get("result_code"));
		}
		htUserAuthsps = (HashMap) htUserProfile.get("user_authsps");
		if (htUserAuthsps == null) {
			// should never happen
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "uid=" + sUid + " profile=" + htUserProfile
				+ " user_authsps=" + htUserAuthsps);
		return htUserAuthsps;
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
	 *            the service request
	 * @param pwOut
	 *            the output writer
	 * @param sServerId
	 *            the server id
	 * @throws ASelectException
	 */
	private void showDirectLoginForm(HttpServletRequest servletRequest, HashMap htServiceRequest, HashMap htSessionContext, PrintWriter pwOut, String sServerId)
	throws ASelectException
	{
		String sMethod = "showDirectLoginForm";
		try {
			String sDirectLoginForm = _configManager.getHTMLForm("directlogin", _sUserLanguage, _sUserCountry);
			if (sDirectLoginForm == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "template file 'directlogin.html' not found");
				throw new ASelectException(Errors.ERROR_ASELECT_NOT_FOUND);
			}
			String sRid = (String) htServiceRequest.get("rid");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "no parameter 'rid' found in request");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			// 20120403, available as parameter now: HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not fetch session context for rid='"+sRid+"'");
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
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[aselect_url]", (String)htServiceRequest.get("my_url"));
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[a-select-server]", sServerId);
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[request]", "direct_login2");
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[cross_request]", "cross_login");
			String sUid = (String) htSessionContext.get("user_id");
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[user_id]", (sUid != null)? sUid: "");
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[error_message]", sErrorMessage);
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[language]", _sUserLanguage);
			
			sDirectLoginForm = _configManager.updateTemplate(sDirectLoginForm, htSessionContext, servletRequest);
			// Extract if_cond=... from the application URL
			
			// 20100908, Bauke: conditions
			String sSpecials = Utils.getAselectSpecials(htSessionContext, true/*decode too*/, _systemLogger);
			sDirectLoginForm = Utils.handleAllConditionals(sDirectLoginForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);

			StringBuffer sbUrl = new StringBuffer(sMyUrl).append("?request=error").append("&result_code=").append(
					Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=").append(sServerId).append("&rid=")
					.append(sRid);
			sDirectLoginForm = Utils.replaceString(sDirectLoginForm, "[cancel]", sbUrl.toString());
			Tools.pauseSensorData(_configManager, _systemLogger, htSessionContext);  //20111102, can update the session
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

	public synchronized boolean isOutputAvailable()
	{
		return outputAvailable;
	}

	public synchronized void setOutputAvailable(boolean outputAvailable)
	{
		this.outputAvailable = outputAvailable;
	}

}
