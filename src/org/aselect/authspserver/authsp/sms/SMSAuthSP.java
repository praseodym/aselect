package org.aselect.authspserver.authsp.sms;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.DecimalFormat;
import java.text.NumberFormat;
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
import org.aselect.authspserver.session.AuthSPSessionManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.servlet.ASelectHttpServlet;
import org.aselect.system.utils.Utils;

/**
 * An A-Select AuthtSP that sends an sms with the token <br>
 * <br>
 * <b>Description:</b><br>
 * <ul>
 * <li>The configmanager</li>
 * <li>The crypto engine</li>
 * <li>The system logger</li>
 * <li>The authentication logger</li>
 * <li><code>friendly_name</code></li>
 * <li><code>working_dir</code></li>
 * </ul>
 * <br>
 * <b>Concurrency issues:</b> <br> - <br>
 * 
 * @author Cristina Gavrila, BTTSD
 */
public class SMSAuthSP extends ASelectHttpServlet
{
	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "SMSAuthSP";

	/** Default failure_handling option. */
	private final static String DEFAULT_FAILUREHANDLING = "aselect";

	/** The version. */
	public static final String VERSION = "A-Select SMS AuthSP "+"1.9";

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

	/** HTML authenticate templates */
	private String _sAuthenticateHtmlTemplate;

	// failure handling properties
	private Properties _oErrorProperties;
	private String _sFailureHandling;
	private String _sFriendlyName;
	private int _iAllowedRetries;
	private String _sSmsUrl;
	private String _sSmsUser;
	private String _sSmsPassword;
	private String _sSmsGateway;
	private int _iSmsSecretLength;
	private String _sSmsText;
	private String _sSmsFrom;
	private SmsSender _oSmsSender;

	/**
	 * Initialization of the SMS AuthSP. <br>
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
	 * </ul>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The AuthSPServer must be succesfully started</li>
	 * <li>An error config file must exist</li>
	 * <li>An error template file must exist</li>
	 * <li>An authentication template file must exist</li>
	 * <li> An SMS 'authsp' config section must be available in the
	 * configuration of the AuthSP Server. The id of this section must be
	 * available as 'config_id' servlet init paramater. </li>
	 * </ul>
	 * 
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
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded CryptoEngine.");

			// Retrieve friendly name
			_sFriendlyName = (String) oContext.getAttribute("friendly_name");
			if (_sFriendlyName == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'friendly_name' found in servlet context.");
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'friendly_name'.");

			// Retrieve working directory
			_sWorkingDir = (String) oContext.getAttribute("working_dir");
			if (_sWorkingDir == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No working_dir found in servlet context.");
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded working_dir");

			// Retrieve configuration
			String sConfigID = oConfig.getInitParameter("config_id");
			if (sConfigID == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'config_id' found as init-parameter in web.xml.");
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR);
			}
			try {
				_oAuthSpConfig = _configManager.getSection(null, "authsp", "id=" + sConfigID);
			}
			catch (ASelectConfigException eAC) {
				sbTemp = new StringBuffer("No valid 'authsp' config section found with id='");
				sbTemp.append(sConfigID).append("'");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbTemp.toString(), eAC);
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR);
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
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR);
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
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR, eAC);
			}
			catch (NumberFormatException eNF) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid 'allowed_retries' parameter found in configuration", eNF);
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR, eNF);
			}

			// get failure handling
			try {
				_sFailureHandling = _configManager.getParam(_oAuthSpConfig, "failure_handling");
			}
			catch (ASelectConfigException eAC) {
				_sFailureHandling = DEFAULT_FAILUREHANDLING;
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No 'failure_handling' parameter found in configuration, using default: aselect", eAC);
			}

			if (!_sFailureHandling.equalsIgnoreCase("aselect") && !_sFailureHandling.equalsIgnoreCase("local")) {
				StringBuffer sbWarning = new StringBuffer(
						"Invalid 'failure_handling' parameter found in configuration: '");
				sbWarning.append(_sFailureHandling);
				sbWarning.append("', using default: aselect");

				_sFailureHandling = DEFAULT_FAILUREHANDLING;

				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbWarning.toString());
			}

			try {
				_sSmsUrl = _configManager.getParam(_oAuthSpConfig, "url");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'url' parameter found in configuration", eAC);
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR, eAC);
			}

			try {
				_sSmsUser = _configManager.getParam(_oAuthSpConfig, "user");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'user' parameter found in configuration", eAC);
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR, eAC);
			}

			try {
				_sSmsPassword = _configManager.getParam(_oAuthSpConfig, "password");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'password' parameter found in configuration", eAC);
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR, eAC);
			}

			try {
				String sSmsSecretLength = _configManager.getParam(_oAuthSpConfig, "secret_length");
				_iSmsSecretLength = Integer.parseInt(sSmsSecretLength);
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'secret_length' parameter found in configuration", eAC);
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR, eAC);
			}
			catch (NumberFormatException eNF) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid 'secret_length' parameter found in configuration", eNF);
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR, eNF);
			}

			try {
				_sSmsText = _configManager.getParam(_oAuthSpConfig, "text");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'text' parameter found in configuration", eAC);
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR, eAC);
			}

			try {
				_sSmsFrom = _configManager.getParam(_oAuthSpConfig, "from");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'from' parameter found in configuration", eAC);
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR, eAC);
			}

			try {
				_sSmsGateway = _configManager.getParam(_oAuthSpConfig, "gateway");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No 'gateway' parameter found in configuration, using default of provider", eAC);
				_sSmsGateway = null; // use default gateway
			}

			// _oSmsSender = new MollieHttpSmsSender(new URL(_sSmsUrl),
			// _sSmsUser, _sSmsPassword); // RH, 20080729, o
			_oSmsSender = new MollieHttpSmsSender(new URL(_sSmsUrl), _sSmsUser, _sSmsPassword, _sSmsGateway); // RH,
																												// 20080729,
																												// n

			sbInfo = new StringBuffer("Successfully started ");
			sbInfo.append(VERSION).append(".");
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			throw new ServletException("Initializing failed");
		}
	}

	protected boolean isRestartableServlet()
	{
		return false;
	}

	/**
	 * Process requests for the HTTP <code>GET</code> method. <br>
	 * <br>
	 * This could be a API call, otherwise the authentication screen is
	 * displayed.
	 * 
	 * @see javax.servlet.http.HttpServlet#doGet(
	 *      javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
		throws java.io.IOException
	{
		String sMethod = "doGet()";
		PrintWriter pwOut = null;

		try {
			setDisableCachingHttpHeaders(servletRequest, servletResponse);
			pwOut = servletResponse.getWriter();

			String sQueryString = servletRequest.getQueryString();
			HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "GET htServiceRequest=" + htServiceRequest);

			// check if the request is an API call
			String sRequestName = (String) htServiceRequest.get("request");
			if (sRequestName != null) // API request
			{
				// handleApiRequest(htServiceRequest,servletRequest,
				// pwOut,servletResponse);
			}
			else // Browser request
			{
				String sMyUrl = servletRequest.getRequestURL().toString();
				htServiceRequest.put("my_url", sMyUrl);

				String sRid = (String) htServiceRequest.get("rid");
				String sAsUrl = (String) htServiceRequest.get("as_url");
				String sUid = (String) htServiceRequest.get("uid");
				String sAsId = (String) htServiceRequest.get("a-select-server");
				String sSignature = (String) htServiceRequest.get("signature");

				if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sAsId == null) || (sSignature == null)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Invalid request received: one or more mandatory parameters missing.");
					throw new ASelectException(Errors.ERROR_SMS_INVALID_REQUEST);
				}

				// optional country code
				String sCountry = (String) htServiceRequest.get("country");
				if (sCountry == null || sCountry.trim().length() < 1) {
					sCountry = null;
				}

				// optional language code
				String sLanguage = (String) htServiceRequest.get("language");
				if (sLanguage == null || sLanguage.trim().length() < 1) {
					sLanguage = null;
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
					throw new ASelectException(Errors.ERROR_SMS_INVALID_REQUEST);
				}
				htServiceRequest.put("as_url", sAsUrl);
				htServiceRequest.put("uid", sUid);
				htServiceRequest.put("retry_counter", "1");

				if (sCountry != null)
					htServiceRequest.put("country", sCountry);
				if (sLanguage != null)
					htServiceRequest.put("language", sLanguage);

				_systemLogger.log(Level.INFO, MODULE, sMethod, "sUid=" + sUid);
				generateAndSend(servletRequest, sUid);

				_systemLogger.log(Level.INFO, MODULE, sMethod, "FORM htServiceRequest=" + htServiceRequest);
				showAuthenticateForm(pwOut, " ", " ", htServiceRequest);
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", eAS);
			handleResult(servletRequest, servletResponse, pwOut, eAS.getMessage());
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error sending response", eIO);
			if (!servletResponse.isCommitted()) {
				// send response if no headers have been written
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}
		}
		catch (SmsException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not send sms", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_SMS_COULD_NOT_AUTHENTICATE_USER);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_SMS_COULD_NOT_AUTHENTICATE_USER);
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

		_systemLogger.log(Level.INFO, MODULE, sMethod, "POST htServiceRequest=" + servletRequest);
		try {
			servletResponse.setContentType("text/html");
			setDisableCachingHttpHeaders(servletRequest, servletResponse);
			pwOut = servletResponse.getWriter();

			String sMyUrl = servletRequest.getRequestURL().toString();
			String sRid = servletRequest.getParameter("rid");
			String sAsUrl = servletRequest.getParameter("as_url");
			String sAsId = servletRequest.getParameter("a-select-server");
			sPassword = servletRequest.getParameter("password");
			sUid = servletRequest.getParameter("uid");
			String sSignature = servletRequest.getParameter("signature");
			String sRetryCounter = servletRequest.getParameter("retry_counter");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "uid=" + sUid + " password=" + sPassword + " rid=" + sRid);

			if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sPassword == null) || (sAsId == null)
					|| (sRetryCounter == null) || (sSignature == null)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid request received: one or more mandatory parameters missing.");
				throw new ASelectException(Errors.ERROR_SMS_INVALID_REQUEST);
			}

			// optional country code
			String sCountry = servletRequest.getParameter("country");
			if (sCountry == null || sCountry.trim().length() < 1) {
				sCountry = null;
			}

			// optional language code
			String sLanguage = servletRequest.getParameter("language");
			if (sLanguage == null || sLanguage.trim().length() < 1) {
				sLanguage = null;
			}

			if (sPassword.trim().length() < 1) // invalid password, retry
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
				showAuthenticateForm(pwOut, Errors.ERROR_SMS_INVALID_PASSWORD, _configManager.getErrorMessage(
						Errors.ERROR_SMS_INVALID_PASSWORD, _oErrorProperties), htServiceRequest);
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
					throw new ASelectException(Errors.ERROR_SMS_INVALID_REQUEST);
				}

				// authenticate user
				String generatedPass = (String) servletRequest.getSession().getAttribute("generated_secret");
				String sResultCode = (sPassword.compareTo(generatedPass) == 0) ? (Errors.ERROR_SMS_SUCCESS)
						: Errors.ERROR_SMS_INVALID_PASSWORD;

				if (sResultCode.equals(Errors.ERROR_SMS_INVALID_PASSWORD))  // invalid password
				{
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Invalid password, retry=" + sRetryCounter + " < "
							+ _iAllowedRetries);
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
						// show authentication form once again with warning message
						showAuthenticateForm(pwOut, Errors.ERROR_SMS_INVALID_PASSWORD, _configManager.getErrorMessage(
								Errors.ERROR_SMS_INVALID_PASSWORD, _oErrorProperties), htServiceRequest);
					}
					else {  // authenticate failed
						_authenticationLogger.log(new Object[] {
							MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "denied"
						});
						handleResult(servletRequest, servletResponse, pwOut, sResultCode);
					}
				}
				else if (sResultCode.equals(Errors.ERROR_SMS_SUCCESS)) // success
				{
					// Authentication successfull
					_authenticationLogger.log(new Object[] {
						MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "granted"
					});

					_systemLogger.log(Level.INFO, MODULE, sMethod, "Success");
					handleResult(servletRequest, servletResponse, pwOut, sResultCode);
				}
				else  // other error
				{
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error authenticating user, cause: "
							+ sResultCode);
					handleResult(servletRequest, servletResponse, pwOut, sResultCode);
				}
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", eAS);
			handleResult(servletRequest, servletResponse, pwOut, eAS.getMessage());
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
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_SMS_INVALID_REQUEST);
		}
		catch (Exception e) // internal error
		{
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_SMS_COULD_NOT_AUTHENTICATE_USER);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
		}
	}

	/**
	 * Show an HTML authentication page. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Shows a authentication form with, if applicable, an error or warning
	 * message.
	 * 
	 * @param pwOut
	 *            the <code>PrintWriter</code> that is the target for
	 *            displaying the html page.
	 * @param sError
	 *            The error that should be shown in the page.
	 * @param sErrorMessage
	 *            The error message that should be shown in the page.
	 * @param htServiceRequest
	 *            The request parameters.
	 */
	private void showAuthenticateForm(PrintWriter pwOut, String sError, String sErrorMessage, HashMap htServiceRequest)
	{
		String sMethod = "showAuthenticateForm";
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

		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error]", sError);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[rid]", sRid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[as_url]", sAsUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[uid]", sUid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[sms_server]", sMyUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[a-select-server]", sAsId);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_message]", sErrorMessage);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[signature]", sSignature);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[retry_counter]", sRetryCounter);

		// optional country code
		if (sCountry != null) {
			sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[country]", sCountry);
		}
		else {
			sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[country]", "");
		}

		// optional language code
		if (sLanguage != null) {
			sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[language]", sLanguage);
		}
		else {
			sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[language]", "");
		}

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Show Form");
		pwOut.println(sAuthenticateForm);
	}

	private void handleResult(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut, String sResultCode)
	{
		String sMethod = "handleResult()";
		StringBuffer sbTemp = null;

		try {
			if (_sFailureHandling.equalsIgnoreCase("aselect") || sResultCode.equals(Errors.ERROR_SMS_SUCCESS))
			// A-Select handles error or success
			{
				String sRid = servletRequest.getParameter("rid");
				String sAsUrl = servletRequest.getParameter("as_url");
				String sAsId = servletRequest.getParameter("a-select-server");
				if (sRid == null || sAsUrl == null || sAsId == null) {
					showErrorPage(pwOut, _sErrorHtmlTemplate, sResultCode, _configManager.getErrorMessage(sResultCode,
							_oErrorProperties));
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
						_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT "+sbTemp);
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
			else // Local error handling
			{
				showErrorPage(pwOut, _sErrorHtmlTemplate, sResultCode, _configManager.getErrorMessage(sResultCode,
						_oErrorProperties));
			}
		}
		catch (ASelectException eAS) // could not generate signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate SMS AuthSP signature", eAS);
			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_SMS_COULD_NOT_AUTHENTICATE_USER, _configManager
					.getErrorMessage(sResultCode, _oErrorProperties));
		}
		catch (UnsupportedEncodingException eUE) // could not encode
		// signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode SMS AuthSP signature", eUE);
			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_SMS_COULD_NOT_AUTHENTICATE_USER, _configManager
					.getErrorMessage(sResultCode, _oErrorProperties));
		}
	}

	private void generateAndSend(HttpServletRequest servRequest, String sRecipient)
		throws SmsException
	{
		String sSecret = generateSecret();
		String sText = _sSmsText.replaceAll("0", sSecret);
		// TODO: add gateway here
		_systemLogger.log(Level.INFO, MODULE, "generateAndSend", "SMS=" + sText + " Secret=" + sSecret);
		_oSmsSender.sendSms(sText, _sSmsFrom, sRecipient);
		servRequest.getSession().setAttribute("generated_secret", sSecret);
	}

	private String generateSecret()
	{
		double multiply = Math.pow(10.0D, (double) this._iSmsSecretLength);
		double secretValue = Math.random() * multiply;
		char[] secretFormat = new char[this._iSmsSecretLength];
		for (int i = 0; i < secretFormat.length; i++) {
			secretFormat[i] = '0';
		}
		NumberFormat format = new DecimalFormat(new String(secretFormat));
		return format.format(secretValue);
	}
}