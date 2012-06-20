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
package org.aselect.authspserver.authsp.db;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.crypto.CryptoEngine;
import org.aselect.authspserver.log.AuthSPAuthenticationLogger;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.authspserver.sam.AuthSPSAMAgent;
import org.aselect.authspserver.session.AuthSPSessionManager;

import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.exception.ASelectUDBException;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.servlet.ASelectHttpServlet;
import org.aselect.system.utils.Utils;

/**
 * An A-Select AuthSP that uses a database as back-end. <br>
 * <br>
 * <b>Description:</b><br>
 * The A-Select DB AuthSP uses a database back-end to validate user/password combinations. The DB AuthSP retrieves the
 * following components and attributes from the A-Select AuthSP Server:
 * <ul>
 * <li>The configmanager</li>
 * <li>The crypto engine</li>
 * <li>The system logger</li>
 * <li>The authentication logger</li>
 * <li><code>friendly_name</code></li>
 * <li><code>working_dir</code></li>
 * </ul>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Cristina Gavrila, BTTSD
 * @author Hans Zandbelt, SURFnet
 */
public class DBAuthSP extends ASelectHttpServlet
{
	/**	 */
	private static final long serialVersionUID = 8572776954706719972L;

	/** The status parameter name for API calls. */
	private final String RESULT_CODE = "status";

	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "DBAuthSP";

	/** Default failure_handling option. */
	private final static String DEFAULT_FAILUREHANDLING = "aselect";

	/** The version. */
	public static final String VERSION = "DB AuthSP";

	private final static boolean DEFAULT_ENCRYPTION = false;

	/** The logger that logs system information. */
	private AuthSPSystemLogger _systemLogger;

	/** The logger that logs authentication information. */
	private AuthSPAuthenticationLogger _authenticationLogger;

	/** The crypto engine */
	private CryptoEngine _cryptoEngine;

	/** The configuration */
	private AuthSPConfigManager _configManager;

	/** The Sessionmanager */
	private AuthSPSessionManager _sessionManager;

	private String _sWorkingDir;

	private Object _oAuthSpConfig;

	/** HTML error templates */
	private String _sErrorHtmlTemplate;

	/** HTML error templates */
	private String _sAuthenticateHtmlTemplate;

	// failure handling properties
	private Properties _oErrorProperties;

	private String _sFailureHandling;

	private String _sFriendlyName;

	private int _iAllowedRetries;

//	// database properties
//	private String _sDriver;
//
//	private String _sUrl;
//
//	private String _sUserName;
//
//	private String _sUserPassword;
//
//	// password/query properties
//	private String _sQuery;
//
//	private String _sColumn;
//
//	private boolean _bEncrypedPassword;
	

	/**
	 * Initialization of the DB AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Performs the following steps to initialise the <code>AuthSP</code>:
	 * <ul>
	 * <li>Retrieve handles to managers and loggers</li>
	 * <li>Retrieve crypto engine from servlet context</li>
	 * <li>Retrieve friendly name from servlet context</li>
	 * <li>Load error properties</li>
	 * <li>Load HTML templates</li>
	 * <li>Get allowed retries from configuration</li>
	 * <li>Get failure handling from configuration</li>
	 * <li>Get database properties, such as driver, url, username and password initialize driver</li>
	 * </ul>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The AuthSPServer must be succesfully started</li>
	 * <li>An error config file must exist</li>
	 * <li>An error template file must exist</li>
	 * <li>An authentication template file must exist</li>
	 * <li>An DB 'authsp' config section must be available in the configuration of the AuthSP Server. The id of this
	 * section must be available as 'config_id' servlet init paramater.</li>
	 * </ul>
	 * 
	 * @param oConfig
	 *            the o config
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	public void init(ServletConfig oConfig)
	throws ServletException
	{
		String sMethod = "init()";
		StringBuffer sbTemp = null;
		try {
			// super init
			super.init(oConfig);
			// retrieve managers and loggers
			_systemLogger = AuthSPSystemLogger.getHandle();
			_authenticationLogger = AuthSPAuthenticationLogger.getHandle();
			_configManager = AuthSPConfigManager.getHandle();
			_sessionManager = AuthSPSessionManager.getHandle();
			

			// log start
			StringBuffer sbInfo = new StringBuffer("Starting : ");
			sbInfo.append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			// Retrieve crypto engine from servlet context.
			ServletContext oContext = oConfig.getServletContext();
			_cryptoEngine = (CryptoEngine) oContext.getAttribute("CryptoEngine");
			if (_cryptoEngine == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No CryptoEngine found in servlet context.");
				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded CryptoEngine.");

			// Retrieve friendly name
			_sFriendlyName = (String) oContext.getAttribute("friendly_name");
			if (_sFriendlyName == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'friendly_name' found in servlet context.");
				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'friendly_name'.");

			// Retrieve working directory
			_sWorkingDir = (String) oContext.getAttribute("working_dir");
			if (_sWorkingDir == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No working_dir found in servlet context.");
				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded working_dir");

			// Retrieve configuration
			String sConfigID = oConfig.getInitParameter("config_id");
			if (sConfigID == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'config_id' found as init-parameter in web.xml.");
				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR);
			}
			try {
				_oAuthSpConfig = _configManager.getSection(null, "authsp", "id=" + sConfigID);
			}
			catch (ASelectConfigException eAC) {
				sbTemp = new StringBuffer("No valid 'authsp' config section found with id='");
				sbTemp.append(sConfigID);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbTemp.toString(), eAC);
				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR);
			}

			// Load error properties
			StringBuffer sbErrorsConfig = new StringBuffer(_sWorkingDir);
			sbErrorsConfig.append(File.separator);
			sbErrorsConfig.append("conf");
			sbErrorsConfig.append(File.separator);
			sbErrorsConfig.append(sConfigID);
			sbErrorsConfig.append(File.separator);
			sbErrorsConfig.append("errors");
			sbErrorsConfig.append(File.separator);
			sbErrorsConfig.append("errors.conf");
			File fErrorsConfig = new File(sbErrorsConfig.toString());
			if (!fErrorsConfig.exists()) {
				StringBuffer sbFailed = new StringBuffer("The error configuration file does not exist: \"");
				sbFailed.append(sbErrorsConfig.toString()).append("\".");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString());
				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR);
			}
			_oErrorProperties = new Properties();
			_oErrorProperties.load(new FileInputStream(sbErrorsConfig.toString()));
			sbInfo = new StringBuffer("Successfully loaded ");
			sbInfo.append(_oErrorProperties.size());
			sbInfo.append(" error messages from: \"");
			sbInfo.append(sbErrorsConfig.toString()).append("\".");
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			// Load HTML templates.
			_sErrorHtmlTemplate = _configManager.loadHTMLTemplate(_sWorkingDir, "error.html", sConfigID,
					_sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");
			_sAuthenticateHtmlTemplate = _configManager.loadHTMLTemplate(_sWorkingDir, "authenticate.html", sConfigID,
					_sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'authenticate.html' template.");

			// get allowed retries
			try {
				String sAllowedRetries = _configManager.getParam(_oAuthSpConfig, "allowed_retries");
				_iAllowedRetries = Integer.parseInt(sAllowedRetries);
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'allowed_retries' parameter found in configuration", eAC);
				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, eAC);
			}
			catch (NumberFormatException eNF) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid 'allowed_retries' parameter found in configuration", eNF);
				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, eNF);
			}

			// get failure handling
			try {
				_sFailureHandling = _configManager.getParam(_oAuthSpConfig, "failure_handling");
			}
			catch (ASelectConfigException eAC) {
				_sFailureHandling = DEFAULT_FAILUREHANDLING;
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No 'failure_handling' parameter found in configuration, using default: aselect");
			}

			if (!_sFailureHandling.equalsIgnoreCase("aselect") && !_sFailureHandling.equalsIgnoreCase("local")) {
				StringBuffer sbWarning = new StringBuffer(
						"Invalid 'failure_handling' parameter found in configuration: '");
				sbWarning.append(_sFailureHandling);
				sbWarning.append("', using default: aselect");

				_sFailureHandling = DEFAULT_FAILUREHANDLING;

				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbWarning.toString());
			}

			///////////////////////////////////////////////////////////
//			// get driver
//			try {
//				_sDriver = _configManager.getParam(_oAuthSpConfig, "driver");
//			}
//			catch (ASelectConfigException eAC) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'driver' parameter found in configuration", eAC);
//				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, eAC);
//			}
//			try {
//				// initialize driver
//				Class.forName(_sDriver);
//			}
//			catch (Exception e) {
//				StringBuffer sbFailed = new StringBuffer("Can't initialize driver: ");
//				sbFailed.append(_sDriver);
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
//				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
//			}
//
//			// get url
//			try {
//				_sUrl = _configManager.getParam(_oAuthSpConfig, "url");
//			}
//			catch (Exception e) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'url' found", e);
//				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
//			}
//
//			// get user
//			try {
//				_sUserName = _configManager.getParam(_oAuthSpConfig, "user");
//			}
//			catch (Exception e) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'username' found", e);
//				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
//			}
//
//			// get password
//			try {
//				_sUserPassword = _configManager.getParam(_oAuthSpConfig, "password");
//			}
//			catch (Exception e) {
//				_sUserPassword = "";
//				_systemLogger
//						.log(
//								Level.WARNING,
//								MODULE,
//								sMethod,
//								"No or empty config item 'password' found, using empty password. Don't use this in a live production environment.",
//								e);
//				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
//			}
//
//			// get password query
//			try {
//				_sQuery = _configManager.getParam(_oAuthSpConfig, "query");
//			}
//			catch (ASelectConfigException eAC) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'query' parameter found in configuration", eAC);
//				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, eAC);
//			}
//
//			// get password column name
//			try {
//				_sColumn = _configManager.getParam(_oAuthSpConfig, "column");
//			}
//			catch (ASelectConfigException eAC) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'column' parameter found in configuration", eAC);
//				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, eAC);
//			}
//
//			try {
//				String sEncryptedPassword = _configManager.getParam(_oAuthSpConfig, "encrypted");
//				_bEncrypedPassword = Boolean.parseBoolean(sEncryptedPassword);
//			}
//			catch (ASelectConfigException eAC) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod,
//						"No 'encrypted' parameter found in configuration, taking default: " + DEFAULT_ENCRYPTION, eAC);
//				_bEncrypedPassword = DEFAULT_ENCRYPTION;
//			}
//			catch (Exception e) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod,
//						"Could not parse pasword encryption setting, taking default: " + DEFAULT_ENCRYPTION, e);
//				throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
//			}
			///////////////////////////////////////////////////////////////////////////////////////////////
			
			sbInfo = new StringBuffer("Successfully started ");
			sbInfo.append(VERSION).append(".");
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			throw new ServletException("Initializing failed");
		}
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	protected boolean isRestartableServlet()
	{
		return false;
	}

	/**
	 * Process requests for the HTTP <code>GET</code> method. <br>
	 * <br>
	 * This could be a API call, otherwise the authentication screen is displayed.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws java.io.IOException
	{
		String sMethod = "doGet()";
		PrintWriter pwOut = null;
		String sLanguage = null;

		try {
			setDisableCachingHttpHeaders(servletRequest, servletResponse);
			pwOut = servletResponse.getWriter();

			String sQueryString = servletRequest.getQueryString();
			HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, false);

			sLanguage = (String) htServiceRequest.get("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;
			String sCountry = (String) htServiceRequest.get("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;				

			// check if the request is an API call
			String sRequestName = (String) htServiceRequest.get("request");
			if (sRequestName != null) // API request
			{
				handleApiRequest(htServiceRequest, servletRequest, pwOut, servletResponse);
			}
			else
			// Browser request
			{
				String sMyUrl = servletRequest.getRequestURL().toString();
				htServiceRequest.put("my_url", sMyUrl);

				String sRid = (String) htServiceRequest.get("rid");
				String sAsUrl = (String) htServiceRequest.get("as_url");
				String sUid = (String) htServiceRequest.get("uid");
				String sAsId = (String) htServiceRequest.get("a-select-server");
				String sSignature = (String) htServiceRequest.get("signature");

				// if ((sRid == null) || (sUid == null) || (sAsId == null))
				if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sAsId == null) || (sSignature == null)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Invalid request received: one or more mandatory parameters missing.");
					throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
				}

				servletResponse.setContentType("text/html");
				// URL decode values
				sAsUrl = URLDecoder.decode(sAsUrl, "UTF-8");
				sUid = URLDecoder.decode(sUid, "UTF-8");
				sSignature = URLDecoder.decode(sSignature, "UTF-8");

				// validate signature
				StringBuffer sbSignature = new StringBuffer(sRid);
				sbSignature.append(sAsUrl);
				sbSignature.append(sUid);
				sbSignature.append(sAsId);
				// optional country code
				if (sCountry != null)
					sbSignature.append(sCountry);
				// optional language code
				if (sLanguage != null)
					sbSignature.append(sLanguage);
				if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
					StringBuffer sbWarning = new StringBuffer("Invalid signature from A-Select Server '");
					sbWarning.append(sAsId);
					sbWarning.append("' for user: ");
					sbWarning.append(sUid);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
					throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
				}
				htServiceRequest.put("as_url", sAsUrl);
				htServiceRequest.put("uid", sUid);
				htServiceRequest.put("retry_counter", "1");

				if (sCountry != null)
					htServiceRequest.put("country", sCountry);
				if (sLanguage != null)
					htServiceRequest.put("language", sLanguage);

				showAuthenticateForm(pwOut, " ", " ", htServiceRequest);
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", eAS);
			handleResult(servletRequest, servletResponse, pwOut, eAS.getMessage(), sLanguage);
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error sending response", eIO);
			if (!servletResponse.isCommitted()) {
				// send response if no headers have been written
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_COULD_NOT_AUTHENTICATE_USER, sLanguage);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}

		}
	}

	/**
	 * Process requests for the HTTP <code>POST</code> method. <br>
	 * <br>
	 * This should be the submitted authentication form.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws java.io.IOException
	{
		String sMethod = "doPost()";
		PrintWriter pwOut = null;
		String sUid = null;
		String sPassword = null;
		Connection oConnection = null;
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		String sLanguage = servletRequest.getParameter("language");  // optional language code
		if (sLanguage == null || sLanguage.trim().length() < 1)
			sLanguage = null;
		String sCountry = servletRequest.getParameter("country");  // optional country code
		if (sCountry == null || sCountry.trim().length() < 1)
			sCountry = null;

		try {
			servletResponse.setContentType("text/html");
			setDisableCachingHttpHeaders(servletRequest, servletResponse);
			pwOut = servletResponse.getWriter();

			String sMyUrl = servletRequest.getRequestURL().toString();
			String sRid = servletRequest.getParameter("rid");
			String sAsUrl = servletRequest.getParameter("as_url");
			sUid = servletRequest.getParameter("uid");
			String sAsId = servletRequest.getParameter("a-select-server");
			sPassword = servletRequest.getParameter("password");
			String sSignature = servletRequest.getParameter("signature");
			String sRetryCounter = servletRequest.getParameter("retry_counter");

			if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sPassword == null) || (sAsId == null)
					|| (sRetryCounter == null) || (sSignature == null)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid request received: one or more mandatory parameters missing.");
				throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
			}
			
			if (sPassword.trim().length() < 1) // invalid password
			{
				HashMap htServiceRequest = new HashMap();
				htServiceRequest.put("my_url", sMyUrl);
				htServiceRequest.put("as_url", sAsUrl);
				htServiceRequest.put("uid", sUid);
				htServiceRequest.put("rid", sRid);
				htServiceRequest.put("a-select-server", sAsId);
				htServiceRequest.put("retry_counter", sRetryCounter);
				htServiceRequest.put("signature", sSignature);
				if (sCountry != null)
					htServiceRequest.put("country", sCountry);
				if (sLanguage != null)
					htServiceRequest.put("language", sLanguage);
				// show authentication form once again with warning message
				showAuthenticateForm(pwOut, Errors.ERROR_DB_INVALID_PASSWORD, _configManager.getErrorMessage(
						Errors.ERROR_DB_INVALID_PASSWORD, _oErrorProperties), htServiceRequest);
			}
			else {
				// generate signature
				StringBuffer sbSignature = new StringBuffer(sRid);
				sbSignature.append(sAsUrl);
				sbSignature.append(sUid);
				sbSignature.append(sAsId);
				if (sCountry != null)
					sbSignature.append(sCountry);
				if (sLanguage != null)
					sbSignature.append(sLanguage);
				if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), URLDecoder
						.decode(sSignature, "UTF-8"))) {
					StringBuffer sbWarning = new StringBuffer("Invalid signature from A-Select Server '");
					sbWarning.append(sAsId);
					sbWarning.append("' for user: ");
					sbWarning.append(sUid);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
					throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
				}

				DBServerParms dbSParms = new DBServerParms();

				// authenticate user
//				oConnection = getConnection();
				oConnection = getConnection(dbSParms);

				try {
//					oStatement = oConnection.prepareStatement(_sQuery);
					oStatement = oConnection.prepareStatement(dbSParms.getQuery());
					oStatement.setString(1, sUid);
					oResultSet = oStatement.executeQuery();
				}
				catch (Exception e) {
//					_authenticationLogger.log("SEVERE", MODULE, sMethod, "Could not execute query: " + _sQuery, e
					_authenticationLogger.log("SEVERE", MODULE, sMethod, "Could not execute query: " + dbSParms.getQuery(), e
							.getMessage());
					throw new ASelectException(Errors.ERROR_DB_COULD_NOT_REACH_DB_SERVER, e);
				}

				if (oResultSet.next()) {
					boolean matches = false;
					try {
//						String sPwd = oResultSet.getString(_sColumn);
						String sPwd = oResultSet.getString(dbSParms.getPasswordcolumn());
//						matches = _bEncrypedPassword ? MD5Crypt.matches(sPwd, sPassword) : sPwd.equals(sPassword);
						matches = dbSParms.isEncrypedPassword() ? MD5Crypt.matches(sPwd, sPassword) : sPwd.equals(sPassword);
					}
					catch (Exception e) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not compare with database field: ", e);
						throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
					}

					if (matches) {
						_authenticationLogger.log(new Object[] {
							MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "granted"
						});
						handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_SUCCESS, sLanguage);
					}
					else {

						int iRetriesDone = Integer.parseInt(sRetryCounter);
						if (iRetriesDone < _iAllowedRetries) // try again
						{
							HashMap htServiceRequest = new HashMap();
							htServiceRequest.put("my_url", sMyUrl);
							htServiceRequest.put("as_url", sAsUrl);
							htServiceRequest.put("uid", sUid);
							htServiceRequest.put("rid", sRid);
							htServiceRequest.put("a-select-server", sAsId);
							htServiceRequest.put("retry_counter", String.valueOf(iRetriesDone + 1));
							htServiceRequest.put("signature", sSignature);
							if (sCountry != null)
								htServiceRequest.put("country", sCountry);
							if (sLanguage != null)
								htServiceRequest.put("language", sLanguage);
							// show authentication form once again with warning
							// message
							showAuthenticateForm(pwOut, Errors.ERROR_DB_INVALID_PASSWORD, _configManager
									.getErrorMessage(Errors.ERROR_DB_INVALID_PASSWORD, _oErrorProperties),
									htServiceRequest);
						}
						else {
							// authenticate failed
							_authenticationLogger.log(new Object[] {
								MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "denied", Errors.ERROR_DB_INVALID_PASSWORD
							});
							handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_INVALID_PASSWORD, sLanguage);
						}
					}
				}
				else
				// other error
				{
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error authenticating user, cause: "
							+ Errors.ERROR_DB_COULD_NOT_REACH_DB_SERVER);
					handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_COULD_NOT_REACH_DB_SERVER, sLanguage);
				}
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", eAS);
			handleResult(servletRequest, servletResponse, pwOut, eAS.getMessage(), sLanguage);
		}
		catch (IOException eIO) // could not send response
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error sending response", eIO);
			if (!servletResponse.isCommitted()) {
				// send response if no headers have been written
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}
		}
		catch (NumberFormatException eNF) // error parsing retry_counter
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Invalid request received: The retry counter parameter is invalid.");
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_INVALID_REQUEST, sLanguage);
		}
		catch (Exception e) // internal error
		{
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_COULD_NOT_AUTHENTICATE_USER, sLanguage);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();

				if (oStatement != null)
					oStatement.close();

				if (oConnection != null)
					oConnection.close();

				if (pwOut != null) {
					pwOut.close();
					pwOut = null;
				}
			}
			catch (Exception e) {
			}
			;
		}
	}

	/**
	 * Show an HTML authentication page. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Shows a authentication form with, if applicable, an error or warning message.
	 * 
	 * @param pwOut
	 *            the <code>PrintWriter</code> that is the target for displaying the html page.
	 * @param sError
	 *            The error that should be shown in the page.
	 * @param sErrorMessage
	 *            The error message that should be shown in the page.
	 * @param htServiceRequest
	 *            The request parameters.
	 */
	private void showAuthenticateForm(PrintWriter pwOut, String sError, String sErrorMessage, HashMap htServiceRequest)
	{
		String sMethod = "showAuthenticateForm()";

		
		String sAuthenticateForm = new String(_sAuthenticateHtmlTemplate);
		String sMyUrl = (String) htServiceRequest.get("my_url");
		String sRid = (String) htServiceRequest.get("rid");
		String sAsUrl = (String) htServiceRequest.get("as_url");
		String sUid = (String) htServiceRequest.get("uid");
		String sAsId = (String) htServiceRequest.get("a-select-server");
		String sSignature = (String) htServiceRequest.get("signature");
		String sRetryCounter = (String) htServiceRequest.get("retry_counter");
		String sCountry = (String) htServiceRequest.get("country");
		String sLanguage = (String) htServiceRequest.get("language");

		// RH, 20100907, sn
		String sFriendlyName = (String) htServiceRequest.get("requestorfriendlyname");
		if (sFriendlyName != null) {
			try {
				sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[requestor_friendly_name]", URLDecoder.decode(sFriendlyName, "UTF-8"));
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "UTF-8 dencoding not supported, using undecoded", e);
				sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[requestor_friendly_name]", sFriendlyName);
			}
		}
		// RH, 20100907, en
		

		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[rid]", sRid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[as_url]", sAsUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[uid]", sUid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[db_server]", sMyUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[a-select-server]", sAsId);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error]", sError);  // obsoleted 20100817
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_code]", sError);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_message]", sErrorMessage);
		if (sLanguage != null) sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[language]", sLanguage);
		if (sCountry != null) sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[country]", sCountry);
		sAuthenticateForm = Utils.replaceConditional(sAuthenticateForm, "if_error", sErrorMessage != null && !sErrorMessage.equals(""));
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[signature]", sSignature);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[retry_counter]", sRetryCounter);

		pwOut.println(sAuthenticateForm);
	}

	/**
	 * Handle result.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @param sResultCode
	 *            the s result code
	 */
	private void handleResult(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut, String sResultCode, String sLanguage)
	{
		String sMethod = "handleResult()";
		StringBuffer sbTemp = null;

		try {
			if (_sFailureHandling.equalsIgnoreCase("aselect") || sResultCode.equals(Errors.ERROR_DB_SUCCESS))
			// A-Select handles error or success
			{
				String sRid = servletRequest.getParameter("rid");
				String sAsUrl = servletRequest.getParameter("as_url");
				String sAsId = servletRequest.getParameter("a-select-server");
				if (sRid == null || sAsUrl == null || sAsId == null) {
					showErrorPage(pwOut, _sErrorHtmlTemplate, sResultCode, _configManager.getErrorMessage(sResultCode,
							// RH, 20100621, Remove cyclic dependency system<->server
//							_oErrorProperties), sLanguage);
							_oErrorProperties), sLanguage, _systemLogger);
				}
				else {

					sbTemp = new StringBuffer(sRid);
					sbTemp.append(sAsUrl).append(sResultCode);
					sbTemp.append(sAsId);
					String sSignature = _cryptoEngine.generateSignature(sbTemp.toString());

					sSignature = URLEncoder.encode(sSignature, "UTF-8");

					sbTemp = new StringBuffer(sAsUrl);
					sbTemp.append("&rid=").append(sRid);
					sbTemp.append("&result_code=").append(sResultCode);
					sbTemp.append("&a-select-server=").append(sAsId);
					sbTemp.append("&signature=").append(sSignature);

					try {
						servletResponse.sendRedirect(sbTemp.toString());
					}
					catch (IOException eIO) // could not send redirect
					{
						StringBuffer sbError = new StringBuffer("Could not send redirect to: \"");
						sbError.append(sbTemp.toString()).append("\"");
						_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), eIO);
					}
				}
			}
			else
			// Local error handling
			{
				// RH, 20100621, Remove cyclic dependency system<->server
//				showErrorPage(pwOut, _sErrorHtmlTemplate, sResultCode, _configManager.getErrorMessage(sResultCode,
//						_oErrorProperties), sLanguage);
				showErrorPage(pwOut, _sErrorHtmlTemplate, sResultCode, _configManager.getErrorMessage(sResultCode,
						_oErrorProperties), sLanguage, _systemLogger);
			}
		}
		catch (ASelectException eAS) // could not generate signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate DB AuthSP signature", eAS);
			// RH, 20100621, Remove cyclic dependency system<->server
//			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_DB_COULD_NOT_AUTHENTICATE_USER, _configManager
//					.getErrorMessage(sResultCode, _oErrorProperties), sLanguage);
			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_DB_COULD_NOT_AUTHENTICATE_USER, _configManager
					.getErrorMessage(sResultCode, _oErrorProperties), sLanguage, _systemLogger);
		}
		catch (UnsupportedEncodingException eUE) // could not encode
		// signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode DB AuthSP signature", eUE);
			// RH, 20100621, Remove cyclic dependency system<->server
//			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_DB_COULD_NOT_AUTHENTICATE_USER, _configManager
//					.getErrorMessage(sResultCode, _oErrorProperties), sLanguage);
			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_DB_COULD_NOT_AUTHENTICATE_USER, _configManager
					.getErrorMessage(sResultCode, _oErrorProperties), sLanguage, _systemLogger);

		}
	}

	/**
	 * Processes an API request to this DB AuthSP.
	 * 
	 * @param htServiceRequest
	 *            a <code>HashMap</code> containing request parameters.
	 * @param servletRequest
	 *            The request.
	 * @param servletResponse
	 *            The response.
	 * @param pwOut
	 *            The output.
	 */
	private void handleApiRequest(HashMap htServiceRequest, HttpServletRequest servletRequest, PrintWriter pwOut,
			HttpServletResponse servletResponse)
	{
		String sMethod = "handleApiRequest()";
		String sRid = (String) htServiceRequest.get("rid");
		HashMap htSessionContext = null;
		// create response HashTable
		StringBuffer sbResponse = new StringBuffer("&rid=");
		// add rid to response
		sbResponse.append(sRid);
		int iAllowedRetries = 0;
		try {
			if (htServiceRequest.get("request").equals("authenticate")) {
				// 20120401, Bauke: removed containsKey call
				//if (_sessionManager.containsKey(sRid)) {
				boolean sessionPresent = false;  // 20120401: Bauke: optimize update/create
				try {
					htSessionContext = _sessionManager.getSessionContext(sRid);
				}
				catch (ASelectException e) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Not found: "+sRid);
				}
				if (htSessionContext != null) {
					try {
						iAllowedRetries = ((Integer) htSessionContext.get("allowed_retries")).intValue();
					}
					catch (ClassCastException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to cast to Integer.", e);
						throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR);
					}
				}
				else {
					htSessionContext = new HashMap();
					//_sessionManager.createSession(sRid, htSessionContext);
					iAllowedRetries = _iAllowedRetries;
				}
				iAllowedRetries--;
				Integer intAllowedRetries = new Integer(iAllowedRetries);
				htSessionContext.put("allowed_retries", intAllowedRetries);
				// 20120401: Bauke: optimize update/create
				if (sessionPresent)
					_sessionManager.updateSession(sRid, htSessionContext); // Let's store the sucker (154)
				else
					_sessionManager.createSession(sRid, htSessionContext);
				if (iAllowedRetries < 0) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No login retries left for rid: '" + sRid + "'");
					throw new ASelectException(Errors.ERROR_DB_ACCESS_DENIED);
				}
				handleAuthenticate(htServiceRequest, servletRequest);

				sbResponse.append("&").append(RESULT_CODE);
				sbResponse.append("=").append(Errors.ERROR_DB_SUCCESS);
				_sessionManager.remove(sRid);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid API request received.");
				throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
			}
		}
		catch (ASelectException eAS) {

			// Allready logged
			sbResponse.append("&").append(RESULT_CODE);
			sbResponse.append("=").append(eAS.getMessage());
		}
		// set reponse headers
		servletResponse.setContentType("application/x-www-form-urlencoded");
		servletResponse.setContentLength(sbResponse.length());
		// respond
		pwOut.write(sbResponse.toString());
	}

	/**
	 * Handle authenticate.
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletRequest
	 *            the servlet request
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleAuthenticate(HashMap htServiceRequest, HttpServletRequest servletRequest)
	throws ASelectException
	{
		String sMethod = "handleAuthenticate()";
		String sResultCode = null;
		String sUid = (String) htServiceRequest.get("uid");
		String sPassword = (String) servletRequest.getParameter("password");
		String sAsID = (String) htServiceRequest.get("a-select-server");
		if ((sUid == null) || (sPassword == null)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Invalid request received: one or more mandatory parameters missing.");
			throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
		}

		DBServerParms dbSParms = new DBServerParms();
		// authenticate user
//		Connection oConnection = getConnection();
		Connection oConnection = getConnection(dbSParms);
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;
		try {
//			oStatement = oConnection.prepareStatement(_sQuery);
			oStatement = oConnection.prepareStatement(dbSParms.getQuery());
			oStatement.setString(1, sUid);
			oResultSet = oStatement.executeQuery();
			sResultCode = (oResultSet.next()) ? (Errors.ERROR_DB_SUCCESS) : Errors.ERROR_DB_INTERNAL_ERROR;
		}
		catch (Exception e) {
//			_authenticationLogger.log("SEVERE", MODULE, sMethod, "Could not execute query: " + _sQuery, e.getMessage());
			_authenticationLogger.log("SEVERE", MODULE, sMethod, "Could not execute query: " + dbSParms.getQuery(), e.getMessage());
			// RH, 20090605, sn
			try {
				oResultSet.close();
			}
			catch (SQLException e1) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not close resultset");
			}
			try {
				oStatement.close();
			}
			catch (SQLException e1) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not close statement");
			}
			try {
				oConnection.close();
			}
			catch (SQLException e1) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not close connection");
			}
			// RH, 20090605, en
			throw new ASelectException(Errors.ERROR_DB_COULD_NOT_REACH_DB_SERVER, e);
		}
		if (sResultCode.equals(Errors.ERROR_DB_SUCCESS)) {
			boolean matches = false;
			try {

//				String sPwd = oResultSet.getString(_sColumn);
				String sPwd = oResultSet.getString(dbSParms.getPasswordcolumn());

//				if (_bEncrypedPassword) {
				if (dbSParms.isEncrypedPassword()) {
					matches = MD5Crypt.matches(sPwd, sPassword);
				}
				else {
					matches = sPwd.equals(sPassword);
				}
			}
			catch (Exception e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could parse result: " + oResultSet);
				throw new ASelectException(Errors.ERROR_DB_COULD_NOT_REACH_DB_SERVER, e);
			}
			// RH, 20090605, sn
			finally {
				try {
					oResultSet.close();
				}
				catch (SQLException e1) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not close resultset");
				}
				try {
					oStatement.close();
				}
				catch (SQLException e1) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not close statement");
				}
				try {
					oConnection.close();
				}
				catch (SQLException e1) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not close connection");
				}
			}
			// RH, 20090605, sn

			if (matches) {
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsID, "granted"
				});
			}
			else {
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsID, "denied", Errors.ERROR_DB_INVALID_PASSWORD
				});
				throw new ASelectException(Errors.ERROR_DB_INVALID_PASSWORD);
			}
		}
		else {
			// no results for uid
			_authenticationLogger.log(new Object[] {
				MODULE, sUid, servletRequest.getRemoteAddr(), sAsID, "denied", sResultCode
			});
			throw new ASelectException(sResultCode);
		}
	}

	/**
	 * Opens a new JDBC connection to the resource that is retrieved from the authsp configuration. <br>
	 * <br>
	 * 
	 * @return <code>Connection</code> that contains the JDBC connection
	 * @throws ASelectException
	 *             if the connection could not be opened
	 */
//	private Connection getConnection()
//	throws ASelectException
//	{
//		String sMethod = "getConnection()";
//
//		Connection oConnection = null;
//
//		try {
//			// initialize driver
//			Class.forName(_sDriver);
//		}
//		catch (Exception e) {
//			StringBuffer sbFailed = new StringBuffer("Can't initialize driver: ");
//			sbFailed.append(_sDriver);
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
//			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
//		}
//
//		try {
//			oConnection = DriverManager.getConnection(_sUrl, _sUserName, _sUserPassword);
//		}
//		catch (SQLException e) {
//			StringBuffer sbFailed = new StringBuffer("Could not open connection to: ");
//			sbFailed.append(_sUrl);
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
//			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
//		}
//
//		return oConnection;
//	}
	
	/**
	 * Opens a new JDBC connection to the resource with parameters passed through serverParms. <br>
	 * <br>
	 * @param serverParms
	 * 		parameter wrapper object to active resource
	 * @return <code>Connection</code> that contains the JDBC connection
	 * @throws ASelectException
	 *             if the connection could not be opened
	 */
	private Connection getConnection(DBServerParms serverParms)
	throws ASelectException
	{
		String sMethod = "getConnection()";

		Connection oConnection = null;

		try {
			// initialize driver
			Class.forName(serverParms.getDriver());
		}
		catch (Exception e) {
			StringBuffer sbFailed = new StringBuffer("Can't initialize driver: ");
			sbFailed.append(serverParms.getDriver());
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
		}

		try {
			oConnection = DriverManager.getConnection(serverParms.getUrl(), serverParms.getUsername(), serverParms.getPassword());
		}
		catch (SQLException e) {
			StringBuffer sbFailed = new StringBuffer("Could not open connection to: ");
			sbFailed.append(serverParms.getUrl());
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
		}

		return oConnection;
	}

	
	/**
	 *	Wrapper to hold DBServer information. <br>
	 * On construction it finds active (actual) parameters either from resource group or config section
	 * <br>
	 * 
	 * @author RH
	 */
	private class DBServerParms {
		private String driver = null;
		private String username = null;
		private String password = null;
		private String url = null;
		private String query = null;
		private String passwordcolumn = null;
		private boolean encrypedPassword = DEFAULT_ENCRYPTION;
		
		
		
		
		/**
		 * Empty constructor
		 * @throws ASelectException 
		 */
		public DBServerParms() throws ASelectException {
			super();
			setActiveParameters();
		}
				
		private void  setActiveParameters() throws ASelectException
	{
		String sMethod = "setActiveParameters()";

//		SAMResource oSAMResource = null;
//		String sDriver = null;
//		String sUsername = null;
//		String sPassword = null;
//		String sUrl = null;
//		String sQuery = null;
//		String sColumn = null;
//		boolean bEncrypedPassword = DEFAULT_ENCRYPTION;
		Object oBackendServer = _oAuthSpConfig;	// use  config section as default

		
		/////////////////////////////////////////////////////////////////
		String sDBResourceGroup = null;
		SAMResource activeResource = null;
		try {
			sDBResourceGroup = _configManager.getParam(_oAuthSpConfig, "resourcegroup");
			try {
				activeResource = AuthSPSAMAgent.getHandle().getActiveResource(sDBResourceGroup);
				oBackendServer = activeResource.getAttributes();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Using back-end server from resource: "+ _configManager.getParam(oBackendServer, "id"));
			}
			catch (ASelectSAMException e) {
				// No problem, just use the "old" way (from the config section)
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No active resource found in resourcegroup: " + sDBResourceGroup + ", using   back-end server from config section");
			}
		} 	catch (ASelectConfigException e) {
			// No problem, just use the "old" way (from the config section)
			_systemLogger.log(Level.INFO, MODULE, sMethod, "No resourcegroup found for authsp: "+  _configManager.getParam(_oAuthSpConfig, "id") + ", using  back-end server config section");
		}
		////////////////////////////////////////////////////////////////////

		
		// set driver
		try {
			 setDriver(_configManager.getParam(oBackendServer, "driver"));
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'driver' parameter found in configuration", eAC);
			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, eAC);
		}
		try {
			// initialize driver
			Class.forName(getDriver());
		}
		catch (Exception e) {
			StringBuffer sbFailed = new StringBuffer("Can't initialize driver: ");
			sbFailed.append(getDriver());
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
		}

		// set url
		try {
			setUrl( _configManager.getParam(oBackendServer, "url"));
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'url' found", e);
			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
		}

		// set user
		try {
			setUsername( _configManager.getParam(oBackendServer, "user"));
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'user' found", e);
			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
		}

		// set password
		try {
			setPassword( _configManager.getParam(oBackendServer, "password"));
		}
		catch (Exception e) {
			setPassword("");
			_systemLogger
					.log(
							Level.WARNING,
							MODULE,
							sMethod,
							"No or empty config item 'password' found, using empty password. Don't use this in a live production environment.",
							e);
			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
		}

		// set password query
		try {
			setQuery(_configManager.getParam(oBackendServer, "query"));
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'query' parameter found in configuration", eAC);
			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, eAC);
		}

		// set password column name
		try {
			setPasswordcolumn( _configManager.getParam(oBackendServer, "column"));
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'column' parameter found in configuration", eAC);
			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, eAC);
		}

		try {
			String sEncryptedPassword = _configManager.getParam(oBackendServer, "encrypted");
			setEncrypedPassword(Boolean.parseBoolean(sEncryptedPassword));
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No 'encrypted' parameter found in configuration, taking default: " + DEFAULT_ENCRYPTION, eAC);
			setEncrypedPassword(DEFAULT_ENCRYPTION);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not parse pasword encryption setting, taking default: " + DEFAULT_ENCRYPTION, e);
			throw new ASelectException(Errors.ERROR_DB_INTERNAL_ERROR, e);
		}

	}
		
		/**
		 * @return the driver
		 */
		public synchronized String getDriver()
		{
			return driver;
		}
		/**
		 * @param driver the driver to set
		 */
		public synchronized void setDriver(String driver)
		{
			this.driver = driver;
		}
		/**
		 * @return the username
		 */
		public synchronized String getUsername()
		{
			return username;
		}
		/**
		 * @param username the username to set
		 */
		public synchronized void setUsername(String username)
		{
			this.username = username;
		}
		/**
		 * @return the password
		 */
		public synchronized String getPassword()
		{
			return password;
		}
		/**
		 * @param password the password to set
		 */
		public synchronized void setPassword(String password)
		{
			this.password = password;
		}
		/**
		 * @return the url
		 */
		public synchronized String getUrl()
		{
			return url;
		}
		/**
		 * @param url the url to set
		 */
		public synchronized void setUrl(String url)
		{
			this.url = url;
		}
		/**
		 * @return the query
		 */
		public synchronized String getQuery()
		{
			return query;
		}
		/**
		 * @param query the query to set
		 */
		public synchronized void setQuery(String query)
		{
			this.query = query;
		}
		/**
		 * @return the passwordcolumn
		 */
		public synchronized String getPasswordcolumn()
		{
			return passwordcolumn;
		}
		/**
		 * @param passwordcolumn the passwordcolumn to set
		 */
		public synchronized void setPasswordcolumn(String passwordcolumn)
		{
			this.passwordcolumn = passwordcolumn;
		}
		/**
		 * @return the encrypedPassword
		 */
		public synchronized boolean isEncrypedPassword()
		{
			return encrypedPassword;
		}
		/**
		 * @param encrypedPassword the encrypedPassword to set
		 */
		public synchronized void setEncrypedPassword(boolean encrypedPassword)
		{
			this.encrypedPassword = encrypedPassword;
		}

	}
}