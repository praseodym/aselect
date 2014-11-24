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
*
 */

package org.aselect.authspserver.authsp.cookieauthsp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Properties;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.crypto.CryptoEngine;
import org.aselect.authspserver.log.AuthSPAuthenticationLogger;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.authspserver.session.AuthSPPreviousSessionManager;
import org.aselect.authspserver.session.AuthSPSessionManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.servlet.ASelectHttpServlet;
import org.aselect.system.utils.Utils;


/**
 * . <br>
 * CookieAuthSP is an AuthSP used for authentication based on previously set cookie <br>
 * <b>Description: </b> <br>
 * The CookieAuthSP uses the existence of a previously stored cookie as an access denied or access granted. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * - <br>
 * 
 */
public class CookieAuthSP extends ASelectHttpServlet
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -2996268295941444515L;
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static String MODULE = "CookieAuthSP";
	/**
	 * The Null AuthSP version string
	 */
	private static String VERSION = "A-Select CookieAuthSP " + "1.9";
	
	private final static String DEFAULT_FAILUREHANDLING = "aselect";


	/**
	 * The logger that logs authentication information
	 */
	private AuthSPAuthenticationLogger _authenticationLogger;
	/**
	 * The logger that logs system information
	 */
	private AuthSPSystemLogger _systemLogger;
	/**
	 * The config manager which contains the configuration
	 */
	private AuthSPConfigManager _configManager;

	/** The PreviousSessionmanager */
	private AuthSPPreviousSessionManager _previousSessionManager;

	/**
	 * The AuthSP crypto engine
	 */
	private CryptoEngine _cryptoEngine;
	/**
	 * The workingdir configured in the web.xml of the AuthSP Server
	 */
	private String _sWorkingDir;
	/**
	 * Error page template
	 */
	private String _sErrorHtmlTemplate;
	/**
	 * <code>Properties</code> containing the error codes with the corresponding error messages
	 */
	private Properties _propErrorMessages;
	/**
	 * The AuthSP Server user friendly name
	 */
	private String _sFriendlyName;

	/**
	 * The authentication mode that is configured
	 */
	private String _sAuthMode;

	private String _sFailureHandling;

	/**
	 * Initialization of the CookieAuthSPP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The CookieAuthSP uses the following components from the A-Select AuthSP Server<br>
	 * - the config manager<br>
	 * - the crypto engine<br>
	 * - the user friendly name<br>
	 * - the working directory<br>
	 * <br>
	 * Initialization includes:<br>
	 * - It loads the AuthSP components from the servlet context.<br>
	 * - It loads the error messages from the errors.conf file.<br>
	 * - It loads the error.html file.<br>
	 * - Sets the configured authentication_mode (default = grant all users)<br>
	 * <br>
	 * <br>
	 * <b>Preconditions:</b><br>
	 * - the AuthSPServer must be succesfully started<br>
	 * - an error config file must exist:<br>
	 * <i>workingdir/conf/cookieauthsp/errors/errors.conf</i><br>
	 * - an error template file must exist:<br>
	 * <i>workingdir/conf/cookieauthsp/html/error.html</i><br>
	 * - needs an 'authsp' config section with name='cookieauthsp' in the configuration of the AuthSP Server <br>
	 * <br>
	 * 
	 * @param oServletConfig
	 *            the o servlet config
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	@Override
	public void init(ServletConfig oServletConfig)
	throws ServletException
	{
		String sMethod = "init";

		Object _oAuthSPConfig = null;

		try {
			super.init(oServletConfig);

			_authenticationLogger = AuthSPAuthenticationLogger.getHandle();
			_systemLogger = AuthSPSystemLogger.getHandle();
			_configManager = AuthSPConfigManager.getHandle();
			_previousSessionManager = AuthSPPreviousSessionManager.getHandle();


			StringBuffer sbInfo = new StringBuffer("Starting : ");
			sbInfo.append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			String sConfigID = oServletConfig.getInitParameter("config_id");
			if (sConfigID == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No 'config_id' found as init-parameter in web.xml.");
				throw new ASelectException(Errors.ERROR_NULL_INTERNAL);
			}

			ServletContext servletContext = oServletConfig.getServletContext();
			_cryptoEngine = (CryptoEngine) servletContext.getAttribute("CryptoEngine");
			if (_cryptoEngine == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No CryptoEngine found in servlet context.");

				throw new ASelectException(Errors.ERROR_NULL_INTERNAL);
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded CryptoEngine");

			_sFriendlyName = (String) servletContext.getAttribute("friendly_name");
			if (_sFriendlyName == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No friendly_name found in servlet context.");
				throw new ASelectException(Errors.ERROR_NULL_INTERNAL);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded friendly_name");

			_sWorkingDir = (String) servletContext.getAttribute("working_dir");
			if (_sWorkingDir == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No working_dir found in servlet context.");
				throw new ASelectException(Errors.ERROR_NULL_INTERNAL);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded working_dir");

			StringBuffer sbErrorsConfig = new StringBuffer(_sWorkingDir);
			sbErrorsConfig.append(File.separator);
			sbErrorsConfig.append("conf");
			sbErrorsConfig.append(File.separator);
			sbErrorsConfig.append(MODULE.toLowerCase());
			sbErrorsConfig.append(File.separator);
			sbErrorsConfig.append("errors");
			sbErrorsConfig.append(File.separator);
			sbErrorsConfig.append("errors.conf");

			File fErrorsConfig = new File(sbErrorsConfig.toString());
			if (!fErrorsConfig.exists()) {
				StringBuffer sbFailed = new StringBuffer("The errors.conf doesn't exist: ");
				sbFailed.append(sbErrorsConfig.toString());

				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbFailed.toString());

				throw new ASelectException(Errors.ERROR_NULL_INTERNAL);
			}
			_propErrorMessages = new Properties();
			_propErrorMessages.load(new FileInputStream(sbErrorsConfig.toString()));

			sbInfo = new StringBuffer("Successfully loaded ");
			sbInfo.append(_propErrorMessages.size());
			sbInfo.append(" error messages from: ");
			sbInfo.append(sbErrorsConfig.toString());
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			_sErrorHtmlTemplate = _configManager.loadHTMLTemplate(_sWorkingDir, "error.html", sConfigID,
					_sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");

			try {
				_oAuthSPConfig = _configManager.getSection(null, "authsp", "id=" + sConfigID);
			}
			catch (ASelectConfigException eAC) {
				StringBuffer sbTemp = new StringBuffer("No valid 'authsp' config section found with id='");
				sbTemp.append(sConfigID).append("'");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbTemp.toString(), eAC);
				throw new ASelectException(Errors.ERROR_NULL_INTERNAL);
			}


			// get failure handling
			try {
				_sFailureHandling = _configManager.getParam(_oAuthSPConfig, "failure_handling");
			}
			catch (ASelectConfigException eAC) {
				_sFailureHandling = DEFAULT_FAILUREHANDLING;
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No 'failure_handling' parameter found in configuration, using default: " + DEFAULT_FAILUREHANDLING);
			}

			if (!_sFailureHandling.equalsIgnoreCase("aselect") && !_sFailureHandling.equalsIgnoreCase("local")) {
				StringBuffer sbWarning = new StringBuffer("Invalid 'failure_handling' parameter found in configuration: '");
				sbWarning.append(_sFailureHandling);
				sbWarning.append("', using default: " + DEFAULT_FAILUREHANDLING);
				_sFailureHandling = DEFAULT_FAILUREHANDLING;

				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbWarning.toString());
			}


			sbInfo = new StringBuffer("Successfully started: ");
			sbInfo.append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		catch (ASelectException ase) {
			throw new ServletException(ase);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR", e);

			StringBuffer sbError = new StringBuffer("Could not initialize ");
			sbError.append(MODULE);
			sbError.append(" : ");
			sbError.append(e.getMessage());
			throw new ServletException(sbError.toString(), e);
		}
	}

	/**
	 * Processes requests for HTTP <code>GET</code>. <br>
	 * <br>
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
	 * <td>as_url</td>
	 * <td>A-Select Server URL</td>
	 * <td>yes</td>
	 * </tr>
	 * <tr>
	 * <td>uid</td>
	 * <td>A-Select User ID</td>
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
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ServletException, java.io.IOException
	{
		String sMethod = "doGet";
		String sQueryString = "";
		String sLanguage = null;
		
		servletResponse.setContentType("text/html");
		setDisableCachingHttpHeaders(servletRequest, servletResponse);
		sQueryString = servletRequest.getQueryString();
		HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, true);  // URL decoded result

		try {
			sLanguage = (String) htServiceRequest.get("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;			
			String sCountry = (String) htServiceRequest.get("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;
			
			String sMyUrl = servletRequest.getRequestURL().toString();
			htServiceRequest.put("my_url", sMyUrl);

			String sRid = (String) htServiceRequest.get("rid");
			String sAsUrl = (String) htServiceRequest.get("as_url");
			String sCookiename = (String) htServiceRequest.get("cookiename");
			String sAsId = (String) htServiceRequest.get("a-select-server");
			String sSignature = (String) htServiceRequest.get("signature");

			if ((sRid == null) || (sAsUrl == null) || (sCookiename == null) || (sAsId == null) || (sSignature == null)) {
				_systemLogger.log(Level.FINE, MODULE, sMethod,
						"Invalid request, at least one mandatory parameter is missing.");
				throw new ASelectException(Errors.ERROR_NULL_INVALID_REQUEST);
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "GET {" + servletRequest + " --> " + sMethod + ": "
					+ sQueryString);

			// 20120110, Bauke: no longer needed, done by convertCGIMessage()
			//sAsUrl = URLDecoder.decode(sAsUrl, "UTF-8");
			//sUid = URLDecoder.decode(sUid, "UTF-8");
			//sSignature = URLDecoder.decode(sSignature, "UTF-8");

			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sAsUrl);
			sbSignature.append(sCookiename);
			sbSignature.append(sAsId);

			// optional country and language code
			if (sCountry != null) sbSignature.append(sCountry);
			if (sLanguage != null) sbSignature.append(sLanguage);

			if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
				throw new ASelectException(Errors.ERROR_NULL_INVALID_REQUEST);
			}

			// Get cookie value here and verify if we know this cookie
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Looking for cookie with name:" + sCookiename);
			
			Cookie[] cookies = servletRequest.getCookies();
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Number of cookies found= " + (cookies == null ? 0 : cookies.length));
			String v = null;
			for ( Cookie c : cookies) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found cookie: " + c.getName() + ", with value: " +  c.getValue());
				if (c.getName().equalsIgnoreCase(sCookiename)) {
					v = c.getValue();
					break;
				}
			}
			_sAuthMode = Errors.ERROR_NULL_ACCESS_DENIED;
			
			if ( v != null ) { // we found a value for our cookie
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found cookie value:" + v);
				// We verify if we know this cookie here
				Hashtable h = null;
				try {
					h = (Hashtable) _previousSessionManager.getHandle().get(v);
					// W don't use the value (yet)
				} catch (ASelectStorageException e) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Cookie value not in storage");
					h = null;
				}
				if (h != null) {
					_sAuthMode = Errors.ERROR_NULL_SUCCESS;
					_authenticationLogger.log(new Object[] {
							MODULE, sCookiename, servletRequest.getRemoteAddr(), sAsId, "granted"
					});
					
				} else {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "No cookie found with name:" + sCookiename);
					_sAuthMode = Errors.ERROR_NULL_ACCESS_DENIED;
					_authenticationLogger.log(new Object[] {
							MODULE, sCookiename, servletRequest.getRemoteAddr(), sAsId, "denied", _sAuthMode
					});
					
				}
			} else {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No cookie found with name:" + sCookiename);
				_sAuthMode = Errors.ERROR_NULL_ACCESS_DENIED;
				_authenticationLogger.log(new Object[] {
						MODULE, sCookiename, servletRequest.getRemoteAddr(), sAsId, "denied", _sAuthMode
				});
			}
			
			handleResult(htServiceRequest, servletResponse, _sAuthMode, sLanguage, _sFailureHandling);
		}
		catch (ASelectException e) {
			handleResult(htServiceRequest, servletResponse, e.getMessage(), sLanguage, _sFailureHandling);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			handleResult(htServiceRequest, servletResponse, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, sLanguage, _sFailureHandling);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "} NULL GET");
	}

	/**
	 * Private entry point of the CookieAuthSP. This will not be used, so always an error page will be shown. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ServletException, java.io.IOException
	{
		String sMethod = "doPost";

		servletResponse.setContentType("text/html");
		setDisableCachingHttpHeaders(servletRequest, servletResponse);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "CookieAuthSP POST {" + servletRequest + ", qry="
				+ servletRequest.getQueryString());

		String request = (String)servletRequest.getParameter("request");  // is URLdecoded
		String cookiename = (String)servletRequest.getParameter("cookiename");
		String tgt = (String)servletRequest.getParameter("tgt");
		
		String sAsId = (String)servletRequest.getParameter("a-select-server");
		String sSignature = (String)servletRequest.getParameter("signature");
		
		StringBuffer sbSignature = new StringBuffer(request);
		sbSignature.append(cookiename);
		sbSignature.append(tgt);
		sbSignature.append(sAsId);


		HashMap serviceRequest = new HashMap();
		// we have to get some sort of rid and AsUrl and language

		StringBuffer sbResponse = new StringBuffer("status=");
		
		if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
			sbResponse.append(Errors.ERROR_NULL_INVALID_REQUEST);
		} else {
			
			// Do the cookie save stuff here
			Hashtable htPreviousSessionContext = new Hashtable();

			htPreviousSessionContext.put(cookiename, tgt);
			try {
				_previousSessionManager.create(tgt, htPreviousSessionContext);
			}
			catch (ASelectStorageException e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Cookie already present:" + tgt);
			}
			sbResponse.append(Errors.ERROR_NULL_SUCCESS);
		}

	
		String response = sbResponse.toString();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Respond with result:" + response);
		servletResponse.setContentLength(response.length());
		servletResponse.getWriter().write(response);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "End CookieAuthSP POST");
	}

	/**
	 * Determines whether or not the CookieAuthSP is restartable. <br>
	 * <br>
	 * 
	 * @return true, if checks if is restartable servlet
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	@Override
	protected boolean isRestartableServlet()
	{
		// RM_17_01
		return false;
	}

	/**
	 * Creates a redirect url and redirects the user back to the A-Select Server. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            The servlet request
	 * @param servletResponse
	 *            The servlet response
	 * @param sResultCode
	 *            The error code that should be sent to the A-Select Server
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	private void handleResult(HashMap servletRequest, HttpServletResponse servletResponse,
								String sResultCode, String sLanguage, String failureHandling)
	throws IOException
	{
		String sMethod = "handleResult";

		PrintWriter pwOut = null;
		try {
			pwOut = servletResponse.getWriter();
			if (failureHandling.equalsIgnoreCase("aselect") || sResultCode.equals(Errors.ERROR_NULL_SUCCESS)) {
				String sRid = (String)servletRequest.get("rid");
				String sAsUrl = (String)servletRequest.get("as_url");
				String sAsId = (String)servletRequest.get("a-select-server");
				if (sRid == null || sAsUrl == null || sAsId == null) {
					showErrorPage(pwOut, _sErrorHtmlTemplate, sResultCode, _configManager.getErrorMessage(sResultCode,
							// RH, 20100621, Remove cyclic dependency system<->server
//							_propErrorMessages), sLanguage);
							_propErrorMessages), sLanguage, _systemLogger);
				}
				else {
					StringBuffer sbSignature = new StringBuffer(sRid);
					sbSignature.append(sAsUrl);
					sbSignature.append(sResultCode);
					sbSignature.append(sAsId);
					String sSignature = _cryptoEngine.generateSignature(sbSignature.toString());
					sSignature = URLEncoder.encode(sSignature, "UTF-8");

					StringBuffer sbRedirect = new StringBuffer(sAsUrl);
					sbRedirect.append("&rid=").append(sRid);
					sbRedirect.append("&result_code=").append(sResultCode);
					sbRedirect.append("&a-select-server=").append(sAsId);
					sbRedirect.append("&signature=").append(sSignature);

					_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIR " + sbRedirect);
					servletResponse.sendRedirect(sbRedirect.toString());
				}
			}
			else {
				// RH, 20100621, Remove cyclic dependency system<->server
				showErrorPage(pwOut, _sErrorHtmlTemplate, sResultCode, _configManager.getErrorMessage(sResultCode,
//						_propErrorMessages), sLanguage);
						_propErrorMessages), sLanguage, _systemLogger);
			}
		}
		catch (ASelectException eAS) // could not generate signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate CookieAuthSP signature", eAS);
			// RH, 20100621, Remove cyclic dependency system<->server
//			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _configManager
//					.getErrorMessage(Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _propErrorMessages), sLanguage);
			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _configManager
					.getErrorMessage(Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _propErrorMessages), sLanguage, _systemLogger);

		}
		catch (UnsupportedEncodingException eUE) // could not encode signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode NULL AuthSP signature", eUE);
			// RH, 20100621, Remove cyclic dependency system<->server
//			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _configManager
//					.getErrorMessage(Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _propErrorMessages), sLanguage);
			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _configManager
					.getErrorMessage(Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _propErrorMessages), sLanguage, _systemLogger);
		}
		catch (IOException eIO) // Could not write output
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "IO error while handling authentication result", eIO);
			throw eIO;
		}
		finally {
			if (pwOut != null)
				pwOut.close();
		}
	}
}