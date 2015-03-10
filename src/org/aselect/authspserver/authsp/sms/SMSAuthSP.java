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
package org.aselect.authspserver.authsp.sms;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.authsp.AbstractAuthSP;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
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
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Cristina Gavrila, BTTSD
 */
public class SMSAuthSP extends AbstractAuthSP  // 20141201, Bauke: inherit goodies from AbstractAuthSP
{
	private static final long serialVersionUID = 1L;

	private static final int MAX_FIXED_SECRET_LENGTH = 50;

	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "SMSAuthSP";

	/** The version. */
	public static final String VERSION = "A-Select SMS AuthSP";

	//private Object _oAuthSpConfig;

	/** HTML error templates */
	//private String _sErrorHtmlTemplate;

	/** HTML authenticate templates */
	//private String _sAuthenticateHtmlTemplate;
	//private String _sChallengeHtmlTemplate;

	//private String _sFailureHandling;

	private String _sSmsUrl;
	private String _sSmsCustomer;  // 20140206, Bauke: added for CM
	private String _sSmsUser;
	private String _sSmsPassword;
	private String _sSmsGateway;
	private int _iSmsSecretLength;
	private String _sSmsText;
	private String _sSmsFrom;
	private GenericSmsSender _oSmsSender;
	private String _sSmsProvider;  // <gw_provider> from config
	private String _fixed_secret;		// RH, 20110913, n
	private boolean _bShow_challenge;		// RH, 20110919, n

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
	 * <li>An SMS 'authsp' config section must be available in the configuration of the AuthSP Server. The id of this
	 * section must be available as 'config_id' servlet init paramater.</li>
	 * </ul>
	 * 
	 * @param oConfig
	 *            the configuration
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	public void init(ServletConfig oConfig)
	throws ServletException
	{
		String sMethod = "init";
		try {
			// super init
			super.init(oConfig, true, Errors.ERROR_SMS_INTERNAL_ERROR);

			StringBuffer sbInfo = new StringBuffer("Starting: ").append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
			
			// get show_challenge
			try {
				String sShow_challenge = _configManager.getParam(_oAuthSpConfig, "show_challenge");
				_bShow_challenge = Boolean.parseBoolean(sShow_challenge);
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.INFO, MODULE, sMethod,
						"No or invalid 'show_challenge' parameter found in configuration, no challenge form will be presented");
				_bShow_challenge = false;
			}

			// Load HTML templates.
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "error.html", null/*language*/, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "authenticate.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'authenticate.html' template.");
			
			if (_bShow_challenge) {	// Only load form if needed
				Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "challenge.html", null, _sFriendlyName, VERSION);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'challenge.html' template.");
			}

			_iAllowedRetries = Utils.getSimpleIntParam(_configManager, _systemLogger, _oAuthSpConfig, "allowed_retries", true);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "allowed_retries="+_iAllowedRetries);

			try {
				_sSmsUrl = _configManager.getParam(_oAuthSpConfig, "url");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'url' parameter found in configuration", eAC);
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR, eAC);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "url="+_sSmsUrl);

			// For CM a Customer ID is needed
			_sSmsCustomer = Utils.getSimpleParam(_configManager, _systemLogger, _oAuthSpConfig, "customer", false/*not mandatory*/);

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
			// NOTE: getSimpleParam() can return null values

			// if gateway is nog given, use the default gateway for the provider
			_sSmsGateway = Utils.getSimpleParam(_configManager, _systemLogger, _oAuthSpConfig, "gateway", false/*not mandatory*/);

			// if _sSmsProvider is null use default provider
			_sSmsProvider = Utils.getSimpleParam(_configManager, _systemLogger, _oAuthSpConfig, "gw_provider", false/*not mandatory*/);

			_oSmsSender = SmsSenderFactory.createSmsSender(_sSmsUrl, _sSmsCustomer, _sSmsUser, _sSmsPassword, _sSmsGateway, _sSmsProvider);
			
			// RH, 20110913, sn
			try {
				_fixed_secret = _configManager.getParam(_oAuthSpConfig, "fixed_secret");
				if (_fixed_secret.length() == 0 || _fixed_secret.length() > MAX_FIXED_SECRET_LENGTH)
					throw new ASelectConfigException("Invalid _fixed_secret length");
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"There is a 'fixed_secret' parameter found in configuration, all secret codes will be the same, which is not very secret !");
			}
			catch (ASelectException eAC) {
				_systemLogger.log(Level.INFO, MODULE, sMethod,
						"No or invalid  'fixed_secret' parameter found  in configuration, random secret codes will be generated");
				_fixed_secret = null;
			}
			// RH, 20110913, en
			
			sbInfo = new StringBuffer("Successfully started ").append(VERSION);
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
		String sMethod = "doGet";
		PrintWriter pwOut = null;
		String sLanguage = null;
		
		String failureHandling = _sFailureHandling;	// Initially we use default from config, this might change if we suspect parameter tampering
		
		try {
			String sQueryString = servletRequest.getQueryString();
			HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, false);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "GET htServiceRequest=" + htServiceRequest);
			sLanguage = (String) htServiceRequest.get("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;
			String sCountry = (String) htServiceRequest.get("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;
			
			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

			// check if the request is an API call
			String sRequestName = (String) htServiceRequest.get("request");
			if (sRequestName != null) {  // API request
				// handleApiRequest(htServiceRequest,servletRequest,pwOut,servletResponse);
			}
			else {  // Browser request
				String sMyUrl = servletRequest.getRequestURL().toString();
				htServiceRequest.put("my_url", sMyUrl);

				String sRid = (String) htServiceRequest.get("rid");
				String sAsUrl = (String) htServiceRequest.get("as_url");
				String sUid = (String) htServiceRequest.get("uid");
				String sAserverId = (String) htServiceRequest.get("a-select-server");
				String sSignature = (String) htServiceRequest.get("signature");

				if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sAserverId == null) || (sSignature == null)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid request received: one or more mandatory parameters missing, handling error locally.");
					failureHandling = "local";	// RH, 20111021, n
					throw new ASelectException(Errors.ERROR_SMS_INVALID_REQUEST);
				}

				// URL decode values
				sAsUrl = URLDecoder.decode(sAsUrl, "UTF-8");
				sUid = URLDecoder.decode(sUid, "UTF-8");
				sSignature = URLDecoder.decode(sSignature, "UTF-8");

				// validate signature
				StringBuffer sbData = new StringBuffer(sRid);
				sbData.append(sAsUrl);
				sbData.append(sUid);
				sbData.append(sAserverId);
				if (sCountry != null) sbData.append(sCountry);
				if (sLanguage != null) sbData.append(sLanguage);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Verifying alias data signature:" 
						+ sAserverId + " Data=" +  sbData.toString() + " Sign=" + sSignature );

				if (!_cryptoEngine.verifySignature(sAserverId, sbData.toString(), sSignature)) {
					StringBuffer sbWarning = new StringBuffer("Invalid signature from A-Select Server '");
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid signature from A-Select Server, handling error locally.");
					failureHandling = "local";	// RH, 20111021, n
					throw new ASelectException(Errors.ERROR_SMS_INVALID_REQUEST);
				}
				htServiceRequest.put("as_url", sAsUrl);
				htServiceRequest.put("uid", sUid);  // This is the user's phone number
				
				String formtoken = newToken();
				Integer iRetryCounter = 1;	// first time
				String sRetryCounter =  String.valueOf(iRetryCounter);	// for backward compatibility  we use the retry_counter to store our formtoken
				sRetryCounter +=  ":" + formtoken;	// for backward compatibility  we use the retry_counter to store our formtoken
				HashMap sessionContext = null; 
				
				if (!_sessionManager.containsKey(sRid)) {	// We expect there is no session yet
					sessionContext = new HashMap();
				}
				else {
					sessionContext = _sessionManager.getSessionContext(sRid);
				}
				sessionContext.put("sms_formtoken", formtoken);
				sessionContext.put("sms_retry_counter", iRetryCounter);
				_sessionManager.updateSession(sRid, sessionContext);
				// RH, 20110104, add formsignature
				sRetryCounter += ":" + _cryptoEngine.generateSignature(sConcat(sAserverId, sUid, sRetryCounter));
				htServiceRequest.put("retry_counter", String.valueOf(sRetryCounter));

				if (sCountry != null)
					htServiceRequest.put("country", sCountry);
				if (sLanguage != null)
					htServiceRequest.put("language", sLanguage);
				
				_systemLogger.log(Level.INFO, MODULE, sMethod, "SMS to sUid=" + sUid);
				// sUid can have a trailing "v" to indicate a voice phone (without SMS reception)
				// Should not occur though, the SMSAuthSPHandler must take care of this
				boolean bValid = isValidPhoneNumber(sUid.replace("v", ""));  // remove voice flag, just in case
				int iReturnSend = -1;
				if (bValid)
					iReturnSend = generateAndSendSms(servletRequest, sUid);
				if (!bValid || iReturnSend == 1) {
					// Bad phone number.
					// We want to show the challenge form only the first time around,
					// therefore make sure the form contains a "challenge" input field.
					if (_bShow_challenge && htServiceRequest.get("challenge") == null ) {
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "challenge FORM htServiceRequest=" + htServiceRequest);
						
						// Challenge form should inform user about invalid phone number 
						/* 20141216, Bauke: set error_code to activate the error message in challenge.html: */
						showChallengeForm(pwOut, Errors.ERROR_SMS_INVALID_PHONE/*was null*/, null, htServiceRequest);
						return;
					}
					handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_SMS_INVALID_PHONE, sLanguage, failureHandling);
					return;
				}

				// Code sent successfully
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "FORM htServiceRequest=" + htServiceRequest);
				showAuthenticateForm(pwOut, ""/*no error*/, htServiceRequest);
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", eAS);
			handleResult(servletRequest, servletResponse, pwOut, eAS.getMessage(), sLanguage, failureHandling);
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error sending response", eIO);
			if (!servletResponse.isCommitted()) {
				// send response if no headers have been written
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}
		}
		catch (DataSendException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not send sms", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_SMS_COULD_NOT_AUTHENTICATE_USER, sLanguage, failureHandling);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_SMS_COULD_NOT_AUTHENTICATE_USER, sLanguage, failureHandling);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
		}
	}

	/**
	 * Checks if phone number is valid.
	 * Total length in Europe is 5 - 14 characters (including country code)
	 * In the Netherlands length is 11
	 * Accepted format: [+][0*]<countrycode><localphone>
	 * 
	 * @param sPhone
	 *            the phone number
	 * @return true, if successful
	 */
	private boolean isValidPhoneNumber(String sPhone)
	{
		if (sPhone.length() > 0 && sPhone.charAt(0) == '+')
			sPhone = sPhone.substring(1);
		sPhone = sPhone.replaceAll("^0*", "");
		if (sPhone.length() < 5 || sPhone.length() > 14)
			return false;
		if (sPhone.startsWith("31") && sPhone.length() != 11)
			return false;
		return true;
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
		String sMethod = "doPost";
		PrintWriter pwOut = null;
		String sUid = null;
		String sPassword = null;
		String sLanguage = null;
		String failureHandling = _sFailureHandling;	// Initially we use default from config, this might change if we suspect parameter tampering

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "POST htServiceRequest=" + servletRequest);
		try {
			sLanguage = servletRequest.getParameter("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;
			String sCountry = servletRequest.getParameter("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;
			
			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

			String sMyUrl = servletRequest.getRequestURL().toString();
			String sRid = servletRequest.getParameter("rid");
			String sAsUrl = servletRequest.getParameter("as_url");
			String sAserverId = servletRequest.getParameter("a-select-server");
			sPassword = servletRequest.getParameter("password");  // is code
			sUid = servletRequest.getParameter("uid");
			String sSignature = servletRequest.getParameter("signature");
			String sRetryCounter = servletRequest.getParameter("retry_counter");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "uid=" + sUid + " password=" + sPassword + " rid=" + sRid);
			if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sPassword == null) || (sAserverId == null)
					|| (sRetryCounter == null) || (sSignature == null)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received: one or more mandatory parameters missing, handling error locally.");
				failureHandling = "local";	// RH, 20111021, n
				throw new ASelectException(Errors.ERROR_SMS_INVALID_REQUEST);
			}

			HashMap sessionContext = _sessionManager.getSessionContext(sRid);
			String formtoken;
			Integer retry_counter;
			if ( (sessionContext == null) ||  ( (formtoken = (String)sessionContext.get("sms_formtoken")) == null)
					 ||  ( (retry_counter = (Integer)sessionContext.get("sms_retry_counter")) == null)) {
				throw new ASelectException(Errors.ERROR_SMS_INVALID_REQUEST);			
			}
			
			if (sPassword.trim().length() < 1) {  // empty password, retry
				HashMap htServiceRequest = new HashMap();
				htServiceRequest.put("my_url", sMyUrl);
				htServiceRequest.put("as_url", sAsUrl);
				htServiceRequest.put("uid", sUid);
				htServiceRequest.put("rid", sRid);
				htServiceRequest.put("a-select-server", sAserverId);
				htServiceRequest.put("retry_counter", sRetryCounter);
				htServiceRequest.put("signature", sSignature);
				if (sCountry != null)
					htServiceRequest.put("country", sCountry);
				if (sLanguage != null)
					htServiceRequest.put("language", sLanguage);
				// show authentication form once again with warning message
				showAuthenticateForm(pwOut, Errors.ERROR_SMS_INVALID_PASSWORD, htServiceRequest);
			}
			else {
				// generate signature
				StringBuffer sbData = new StringBuffer(sRid).append(sAsUrl).append(sUid);
				sbData.append(sAserverId);
				if (sCountry != null) sbData.append(sCountry);
				if (sLanguage != null) sbData.append(sLanguage);
				
				if (!_cryptoEngine.verifySignature(sAserverId, sbData.toString(), URLDecoder.decode(sSignature, "UTF-8"))) {
					StringBuffer sbWarning = new StringBuffer("Invalid signature from A-Select Server '");
					sbWarning.append(sAserverId).append("' for user: ").append(sUid);
					sbWarning.append(" , handling error locally. Data=").append(sbData.toString());	// RH, 20111021, n
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
					failureHandling = "local";	// RH, 20111021, n
					throw new ASelectException(Errors.ERROR_SMS_INVALID_REQUEST);
				}

				// RH, 20110104, sn
				// verify form signature
				// formSignature is stored as part of the retryCounter
				String[] sa = sRetryCounter.split(":");
				String formSignature = sa[2];
				sRetryCounter = sa[0] + ":" + sa[1]; // now also contains formtoken
				String signedParms = sConcat(sAserverId, sUid, sRetryCounter);
//				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sRetryCounter:" +sa[1] + ", formtoken:" + formtoken);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sRetryCounter:" + sRetryCounter + ", formtoken:" + formtoken);
				if ( !_cryptoEngine.verifyMySignature(signedParms, formSignature) || !sa[1].equals(formtoken) ) {
					StringBuffer sbWarning = new StringBuffer("Invalid signature from User form '");
					sbWarning.append(sAserverId).append("' for user: ").append(sUid);
					sbWarning.append(" , handling error locally. Data=").append(sbData.toString());	// RH, 20111021, n
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
					failureHandling = "local";	// RH, 20111021, n
					throw new ASelectException(Errors.ERROR_SMS_INVALID_REQUEST);
				}
				// RH, 20110104, en

				// authenticate user
				// RM_20_01
				String generatedPass = (String) servletRequest.getSession(true).getAttribute("generated_secret");
				String sResultCode = (sPassword.compareTo(generatedPass) == 0) ? (Errors.ERROR_SMS_SUCCESS)
						: Errors.ERROR_SMS_INVALID_PASSWORD;

				if (sResultCode.equals(Errors.ERROR_SMS_INVALID_PASSWORD)) // invalid password
				{
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Invalid password, retry=" + retry_counter + " < " + _iAllowedRetries);
					int iRetriesDone = retry_counter;
					if (iRetriesDone < _iAllowedRetries) // try again
					{
						HashMap htServiceRequest = new HashMap();
						htServiceRequest.put("my_url", sMyUrl);
						htServiceRequest.put("as_url", sAsUrl);
						htServiceRequest.put("uid", sUid);
						htServiceRequest.put("rid", sRid);
						htServiceRequest.put("a-select-server", sAserverId);

						// add formsignature
						sRetryCounter =  String.valueOf(iRetriesDone + 1);
						sessionContext.put("sms_retry_counter", iRetriesDone+1);
						formtoken = newToken(); 
						sessionContext.put("sms_formtoken", formtoken);
						_sessionManager.updateSession(sRid, sessionContext);

						sRetryCounter +=  ":" + formtoken;	// for backward compatibility we use sRetryCounter to store the formtoken
						
						sRetryCounter += ":" + _cryptoEngine.generateSignature( sConcat(sAserverId, sUid, sRetryCounter));
						htServiceRequest.put("retry_counter", sRetryCounter);	// RH, 20110104, n
						htServiceRequest.put("signature", sSignature);
						if (sCountry != null)
							htServiceRequest.put("country", sCountry);
						if (sLanguage != null)
							htServiceRequest.put("language", sLanguage);
						
						// show authentication form once again with warning message
						showAuthenticateForm(pwOut, Errors.ERROR_SMS_INVALID_PASSWORD, htServiceRequest);
					}
					else { // authenticate failed
						_authenticationLogger.log(new Object[] {
							MODULE, sUid, servletRequest.getRemoteAddr(), sAserverId, "denied", Errors.ERROR_SMS_INVALID_PASSWORD
						});
						handleResult(servletRequest, servletResponse, pwOut, sResultCode, sLanguage, failureHandling);
					}
				}
				else if (sResultCode.equals(Errors.ERROR_SMS_SUCCESS)) {  // success
					// Authentication successfull
					_authenticationLogger.log(new Object[] {
						MODULE, sUid, servletRequest.getRemoteAddr(), sAserverId, "granted"
					});

					_systemLogger.log(Level.INFO, MODULE, sMethod, "Success");
					handleResult(servletRequest, servletResponse, pwOut, sResultCode, sLanguage, failureHandling);
				}
				else { // other error
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error authenticating user, cause: " + sResultCode);
					handleResult(servletRequest, servletResponse, pwOut, sResultCode, sLanguage, failureHandling);
				}
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", eAS);
			handleResult(servletRequest, servletResponse, pwOut, eAS.getMessage(), sLanguage, failureHandling);
		}
		catch (IOException eIO) {  // could not send response
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error sending response", eIO);
			if (!servletResponse.isCommitted()) {
				// send response if no headers have been written
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}
		}
		catch (NumberFormatException eNF) {  // error parsing retry_counter
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Invalid request received: The retry counter parameter is invalid.");
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_SMS_INVALID_REQUEST, sLanguage, failureHandling);
		}
		catch (Exception e) {  // internal error
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_SMS_COULD_NOT_AUTHENTICATE_USER, sLanguage, failureHandling);
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
	 * Shows a authentication form with, if applicable, an error or warning message.
	 * 
	 * @param pwOut
	 *            the <code>PrintWriter</code> that is the target for displaying the html page.
	 * @param sError
	 *            The error that should be shown in the page. Can be null (no errors)
	 * @param sErrorMessage
	 *            The error message that should be shown in the page.
	 * @param htServiceRequest
	 *            The request parameters.
	 * @throws ASelectException 
	 */
	private void showAuthenticateForm(PrintWriter pwOut, String sError, HashMap htServiceRequest)
	throws ASelectException
	{
		String sMethod = "showAuthenticateForm";

		String sMyUrl = (String) htServiceRequest.get("my_url");
		String sRid = (String) htServiceRequest.get("rid");
		String sAsUrl = (String) htServiceRequest.get("as_url");
		String sUid = (String) htServiceRequest.get("uid");
		String sAsId = (String) htServiceRequest.get("a-select-server");
		String sSignature = (String) htServiceRequest.get("signature");
		String sRetryCounter = (String) htServiceRequest.get("retry_counter");
		String sLanguage = (String)htServiceRequest.get("language");  // optional language code
		String sCountry = (String) htServiceRequest.get("country");
		String sAuthenticateForm = Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID,
				"authenticate.html", sLanguage, _sFriendlyName, VERSION);
		
		String sErrorMessage = null;
		if (Utils.hasValue(sError)) {  // translate error code
			Properties propErrorMessages = Utils.loadPropertiesFromFile(_systemLogger, _sWorkingDir, _sConfigID, "errors.conf", sLanguage);
			sErrorMessage = _configManager.getErrorMessage(MODULE, sError, propErrorMessages);
		}
		
		// RH, 20100907, sn
		// NOTE: friendly name is taken from the request, not the value produced by init()
		String sFriendlyName = (String) htServiceRequest.get("requestorfriendlyname");
		if (sFriendlyName != null) {
			try {
				sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[requestor_friendly_name]", URLDecoder.decode(sFriendlyName, "UTF-8"));
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "UTF-8 encoding not supported, using undecoded", e);
				sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[requestor_friendly_name]", sFriendlyName);
			}
		}
		// RH, 20100907, en

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "error_code="+sError+" message="+sErrorMessage);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[uid]", sUid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[rid]", sRid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[as_url]", sAsUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[uid]", sUid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[sms_server]", sMyUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[a-select-server]", sAsId);
		if (sError != null) {
			sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error]", sError);  // obsoleted 20100817
			sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_code]", sError);
		}
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[country]", (sCountry != null)? sCountry: "");
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[language]", (sLanguage != null)? sLanguage: "");
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[signature]", sSignature);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[retry_counter]", sRetryCounter);
		
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_message]", sErrorMessage);
		
		// Bauke 20110721: Extract if_cond=... from the application URL
		String sSpecials = Utils.getAselectSpecials(htServiceRequest, true/*decode too*/, _systemLogger);
		sAuthenticateForm = Utils.handleAllConditionals(sAuthenticateForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Show Form: "+"authenticate.html");
		pwOut.println(sAuthenticateForm);
	}

	
	/**
	 * Show an HTML challenge page. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Shows a challenge to ask for phone number form with, if applicable, an error or warning message.
	 * 
	 * @param pwOut
	 *            the <code>PrintWriter</code> that is the target for displaying the html page.
	 * @param sError
	 *            The error that should be shown in the page. Can be null (no errors)
	 * @param sErrorMessage
	 *            The error message that should be shown in the page.
	 * @param htServiceRequest
	 *            The request parameters.
	 * @throws ASelectException 
	 */
	private void showChallengeForm(PrintWriter pwOut, String sError, String sErrorMessage, HashMap htServiceRequest)
	throws ASelectException
	{
		String sMethod = "showChallengeForm";
		
		String sMyUrl = (String) htServiceRequest.get("my_url");
		String sRid = (String) htServiceRequest.get("rid");
		String sAsUrl = (String) htServiceRequest.get("as_url");
		String sUid = (String) htServiceRequest.get("uid");
		String sAsId = (String) htServiceRequest.get("a-select-server");
		String sSignature = (String) htServiceRequest.get("signature");
		String sRetryCounter = (String) htServiceRequest.get("retry_counter");
		String sCountry = (String) htServiceRequest.get("country");
		String sChallenge = (String) htServiceRequest.get("challenge");
		String sLanguage = (String) htServiceRequest.get("language");
		
		String sChallengeForm = Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID,
				"challenge.html", sLanguage, _sFriendlyName, VERSION);
		
		// RH, 20100907, sn
		String sFriendlyName = (String) htServiceRequest.get("requestorfriendlyname");
		if (sFriendlyName != null) {
			try {
				sChallengeForm = Utils.replaceString(sChallengeForm, "[requestor_friendly_name]", URLDecoder.decode(sFriendlyName, "UTF-8"));
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "UTF-8 dencoding not supported, using undecoded", e);
				sChallengeForm = Utils.replaceString(sChallengeForm, "[requestor_friendly_name]", sFriendlyName);
			}
		}
		// RH, 20100907, en

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "error_code="+sError+" message="+sErrorMessage);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[uid]", sUid);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[rid]", sRid);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[as_url]", sAsUrl);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[uid]", sUid);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[sms_server]", sMyUrl);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[a-select-server]", sAsId);
		if (sError != null) {
			sChallengeForm = Utils.replaceString(sChallengeForm, "[error]", sError);  // obsoleted 20100817
			sChallengeForm = Utils.replaceString(sChallengeForm, "[error_code]", sError);
		}
		sChallengeForm = Utils.replaceString(sChallengeForm, "[country]", (sCountry != null)? sCountry: "");
		sChallengeForm = Utils.replaceString(sChallengeForm, "[language]", (sLanguage != null)? sLanguage: "");

		// RM_20_02
		sChallengeForm = Utils.replaceString(sChallengeForm, "[challenge]", (sChallenge != null)? sChallenge: sUid );

		// RM_20_03
		// This message presents a get form, so it will url-encode field values, but the signature in our htRequest is already urlencoded
		// so we decode it here
		try {
			sChallengeForm = Utils.replaceString(sChallengeForm, "[signature]", URLDecoder.decode(sSignature, "UTF-8") );
		}
		catch (UnsupportedEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "UTF-8 url-decoding not supported, using undecoded", e);
			e.printStackTrace();
		}
		sChallengeForm = Utils.replaceString(sChallengeForm, "[retry_counter]", sRetryCounter);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[error_message]", sErrorMessage);
		
		// Bauke 20110721: Extract if_cond=... from the application URL
		String sSpecials = Utils.getAselectSpecials(htServiceRequest, true/*decode too*/, _systemLogger);
		sChallengeForm = Utils.handleAllConditionals(sChallengeForm, Utils.hasValue(sError/*20141216,Bauke:was sErrorMessage*/), sSpecials, _systemLogger);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Show Form");
		pwOut.println(sChallengeForm);
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
			PrintWriter pwOut, String sResultCode, String sLanguage, String failureHandling)
	{
		String sMethod = "handleResult";
		StringBuffer sbTemp = null;

		try {
			// Prevent tampering with request parameters, potential fishing leak
			if (failureHandling.equalsIgnoreCase(DEFAULT_FAILUREHANDLING) || sResultCode.equals(Errors.ERROR_SMS_SUCCESS) ||
								sResultCode.equals(Errors.ERROR_SMS_INVALID_PHONE)) {  // 20111020, Bauke: added
				// A-Select handles error or success
				String sRid = servletRequest.getParameter("rid");
				String sAsUrl = servletRequest.getParameter("as_url");
				String sAsId = servletRequest.getParameter("a-select-server");
				if (sRid == null || sAsUrl == null || sAsId == null) {
					getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
				}
				else {
					sbTemp = new StringBuffer(sRid);
					sbTemp.append(sAsUrl).append(sResultCode).append(sAsId);
					String sSignature = _cryptoEngine.generateSignature(sbTemp.toString());
					sSignature = URLEncoder.encode(sSignature, "UTF-8");

					sbTemp = new StringBuffer(sAsUrl);
					sbTemp.append("&rid=").append(sRid);
					sbTemp.append("&result_code=").append(sResultCode);
					sbTemp.append("&a-select-server=").append(sAsId);
					sbTemp.append("&signature=").append(sSignature);

					try {
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "REDIRECT " + sbTemp);
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
			else {  // Local error handling
				getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
			}
		}
		catch (ASelectException eAS) {  // could not generate signature
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate SMS AuthSP signature", eAS);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_SMS_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (UnsupportedEncodingException eUE) {  // could not encode signature
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode SMS AuthSP signature", eUE);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_SMS_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
	}

	/**
	 * Generate and send.
	 * 
	 * @param servRequest
	 *            the servlet request
	 * @param sRecipient
	 *            the recipient phone numbers (a comma separated list)
	 */
	private int generateAndSendSms(HttpServletRequest servRequest, String sRecipient)
	throws DataSendException
	{
		String sSecret = (_fixed_secret == null) ? generateSecret() : _fixed_secret;	// RH, 20110913, n
		// 20130502, Bauke: moved to the SmsSender driver, method assembleSmsMessage()
		//String sText = _sSmsText.replaceAll("0", sSecret);
		
		// RM_20_04
		_systemLogger.log(Level.FINEST, MODULE, "generateAndSend", "Text=" + _sSmsText+ " Secret=" + sSecret);
		int result = 0;
		if (_fixed_secret == null) {
			result = _oSmsSender.sendSms(_sSmsText, sSecret, _sSmsFrom, sRecipient);	// RH, 20110913, n
		}
		servRequest.getSession(true).setAttribute("generated_secret", sSecret);
		return result;
	}

	/**
	 * Generate secret.
	 * 
	 * @return the string
	 */
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