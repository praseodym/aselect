/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.authspserver.authsp.delegator;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.authsp.AbstractAuthSP;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;

/**
 * An A-Select AuthtSP that delegates authentication to a Delgate class <br>
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
 * @author RH
 */
public class DelegatorAuthSP extends AbstractAuthSP  // 20141201, Bauke: inherit goodies from AbstractAuthSP
{
	private static final long serialVersionUID = 1L;

	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "DelegatorAuthSP";

	/** The version. */
	public static final String VERSION = "A-Select Delegator AuthSP 1.0";

	/** The sessioncontext key for uid in the request to the delegate */
	public static final String DEFAULT_REQUEST_KEY_UID = "username";

	/** The sessioncontext key for password  to the delegate */
	public static final String DEFAULT_REQUEST_KEY_PASSWD = "password";

	/** The sessioncontext key for password  from the delegate */
	public static final String DEFAULT_RESPONSE_KEY_UID = "uid";

	/** The sessioncontext key for delegate_session */
	// Maybe make this configuration parameter
	public static final String KEY_DELEGATE_SESSION = "delegate_session";
	
	/** The parameter key for the delegate to put the additional challenge in */
	// Maybe make this configuration parameter
	public static final String KEY_DELEGATE_CHALLENGE = "delegate_challenge";

	//private Object _oAuthSPConfig;

	/** HTML authenticate templates */
	//private String _sAuthenticateHtmlTemplate;
	//private String _sChallengeHtmlTemplate;

	//private String _sFailureHandling;
	private String _sDelegateUrl;
	private String _sDelegateUser;
	private String _sDelegatePassword;
	private String _sDelegateGateway;
	private String _sAuthProvider;
	private boolean _bShow_challenge;		// RH, 20110919, n
	private boolean _bUrldecode_responseheaders;		// RH, 20131220, n
	
	// RH, 20130115, sn
	private String request_key_uid;
	private String request_key_password;
	private String response_key_uid;
	// RH, 20130115, en
	
	/**
	 * Initialization of the DELEGATOR AuthSP. <br>
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
	 * <li>A Delegator 'authsp' config section must be available in the configuration of the AuthSP Server. The id of this
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
		String sMethod = "init";
		try {
			super.init(oConfig, true, Errors.DELEGATOR_CONFIG_ERROR);

			// log start
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
			
			if (_bShow_challenge) {	// Only load form if needed
				Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "challenge.html", null, _sFriendlyName, VERSION);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'challenge.html' template.");
			}

			// Load HTML templates.
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "error.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "authenticate.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'authenticate.html' template.");

			// Get allowed retries
			_iAllowedRetries = Utils.getSimpleIntParam(_configManager, _systemLogger, _oAuthSpConfig, "allowed_retries", true);

			try {
				_sDelegateUrl = _configManager.getParam(_oAuthSpConfig, "url");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'url' parameter found in configuration", eAC);
				throw new ASelectException(Errors.DELEGATOR_CONFIG_ERROR, eAC);
			}

			try {
				_sDelegateUser = _configManager.getParam(_oAuthSpConfig, "user");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'user' parameter found in configuration, not using authentication towards delegate");
			}

			try {
				_sDelegatePassword = _configManager.getParam(_oAuthSpConfig, "password");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'password' parameter found in configuration");
			}

			catch (NumberFormatException eNF) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid 'secret_length' parameter found in configuration", eNF);
				throw new ASelectException(Errors.DELEGATOR_CONFIG_ERROR, eNF);
			}

			// NOTE: ASelectConfigException results in a stack trace.
			// Therefore non serious missing parameters should throw an ASelectException please.
			try {
				_sDelegateGateway = _configManager.getParam(_oAuthSpConfig, "gateway");
			}
			catch (ASelectException eAC) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No 'gateway' parameter found in configuration, using default of provider");
				_sDelegateGateway = null; // use default gateway
			}

			// RH, 20080729
			try {
				_sAuthProvider = _configManager.getParam(_oAuthSpConfig, "auth_provider");
			}
			catch (ASelectException eAC) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No 'provider' parameter found in configuration, using default provider");
				_sAuthProvider = DelegateFactory.HTTP_DELEGATE; // choose as default privider
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "DelegateProvider="+_sAuthProvider); 

			// RH, 20130115, sn
			try {
				request_key_uid = _configManager.getParam(_oAuthSpConfig, "request_key_uid");
			}
			catch (ASelectException eAC) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No 'request_key_uid' parameter found in configuration, using default");
				request_key_uid = DEFAULT_REQUEST_KEY_UID;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "request_key_uid="+request_key_uid); 
			
			try {
				request_key_password = _configManager.getParam(_oAuthSpConfig, "request_key_password");
			}
			catch (ASelectException eAC) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No 'request_key_password' parameter found in configuration, using default");
				request_key_password = DEFAULT_REQUEST_KEY_PASSWD;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "request_key_password="+request_key_password); 

			try {
				response_key_uid = _configManager.getParam(_oAuthSpConfig, "response_key_uid");
			}
			catch (ASelectException eAC) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No 'response_key_uid' parameter found in configuration, using default");
				response_key_uid = DEFAULT_RESPONSE_KEY_UID;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "response_key_uid="+response_key_uid); 
			// RH, 20130115, en

			// RH, 20131220, sn
			// get urldecode_responseheaders
			try {
				String sUrldecode_responseheaders = _configManager.getParam(_oAuthSpConfig, "urldecode_responseheaders");
				_bUrldecode_responseheaders = Boolean.parseBoolean(sUrldecode_responseheaders);
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.INFO, MODULE, sMethod,
						"No or invalid 'urldecode_responseheaders' parameter found in configuration, not decoding");
				_bUrldecode_responseheaders = false;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "_bUrldecode_responseheaders="+_bUrldecode_responseheaders); 
			// RH, 20131220, en
			
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
		
		// super doGet for basics, future improvement
//		super.doGet(servletRequest, servletResponse);
		try {
			String sQueryString = servletRequest.getQueryString();
			HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, false);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "GET htServiceRequest=" + htServiceRequest);
			sLanguage = (String) htServiceRequest.get("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;
			String sCountry = (String) htServiceRequest.get("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;
			
			servletResponse.setContentType("text/html");	// RH, 20111021, n			// Content type must be set (before getwriter)
			setDisableCachingHttpHeaders(servletRequest, servletResponse);
			pwOut = servletResponse.getWriter();

			// check if the request is an API call
			String sRequestName = (String) htServiceRequest.get("request");
			if (sRequestName != null) // API request
			{
				_systemLogger.log(Level.INFO, MODULE, sMethod, "API calls not supported, disallowed GET parameter found 'request' =" + sRequestName);
				throw new ASelectException(Errors.DELEGATOR_INVALID_REQUEST);
			}
			else // Browser request
			{
				String sMyUrl = servletRequest.getRequestURL().toString();
				htServiceRequest.put("my_url", sMyUrl);

				String sRid = (String) htServiceRequest.get("rid");
				String sAsUrl = (String) htServiceRequest.get("as_url");
//				String sUid = (String) htServiceRequest.get("uid");
				String sAppId = (String) htServiceRequest.get("app_id");
				String sAsId = (String) htServiceRequest.get("a-select-server");
				String sSignature = (String) htServiceRequest.get("signature");

				if ((sRid == null) || (sAsUrl == null)  || (sAppId == null) || (sAsId == null) || (sSignature == null)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid request received: one or more mandatory parameters missing, handling error locally.");
					failureHandling = "local";	// RH, 20111021, n
					throw new ASelectException(Errors.DELEGATOR_INVALID_REQUEST);
				}

				// URL decode values
				sAsUrl = URLDecoder.decode(sAsUrl, "UTF-8");
//				sUid = URLDecoder.decode(sUid, "UTF-8");
				sAppId = URLDecoder.decode(sAppId, "UTF-8");
				sAsId = URLDecoder.decode(sAsId, "UTF-8");
				
				sSignature = URLDecoder.decode(sSignature, "UTF-8");

				// validate signature
				StringBuffer sbSignature = new StringBuffer(sRid);
				sbSignature.append(sAsUrl);
//				sbSignature.append(sUid);
				
				sbSignature.append(sAppId);
				sbSignature.append(sAsId);
				// optional country code
				if (sCountry != null)
					sbSignature.append(URLDecoder.decode(sCountry, "UTF-8"));
				// optional language code
				if (sLanguage != null)
					sbSignature.append(URLDecoder.decode(sLanguage, "UTF-8"));
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Verifying alias data signature:" 
						+ sAsId + " " +  sbSignature.toString() + " " + sSignature );

				if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
					StringBuffer sbWarning = new StringBuffer("Invalid signature from A-Select Server '");
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid signature from A-Select Server, handling error locally.");
					failureHandling = "local";	// RH, 20111021, n
					throw new ASelectException(Errors.DELEGATOR_INVALID_REQUEST);
				}
				
				htServiceRequest.put("as_url", sAsUrl);
//				htServiceRequest.put("uid", sUid); 
				htServiceRequest.put("app_id", sAppId);  // This is the requested application
								
				
				String formtoken = newToken();
				Integer iRetryCounter = 1;	// first time around
				String sRetryCounter =  String.valueOf(iRetryCounter);	
				sRetryCounter +=  ":" + formtoken;	// for backward compatibility  we use the retry_counter to store our formtoken
				HashMap sessionContext = null; 
				
				if ( !_sessionManager.containsKey(sRid) ) {	// We expect there is no session yet
					sessionContext = new HashMap();
				} else  {
					sessionContext = _sessionManager.getSessionContext(sRid);
				}
				sessionContext.put(_sAuthProvider + "_formtoken", formtoken);
				sessionContext.put(_sAuthProvider + "_retry_counter", iRetryCounter);
				sessionContext.put(_sAuthProvider + "_app_id", sAppId);
				_sessionManager.updateSession(sRid, sessionContext);
				// RH, 20110104, add formsignature
				sRetryCounter += ":" + _cryptoEngine.generateSignature(sConcat(sAsId, sAppId, sRetryCounter));
				htServiceRequest.put("retry_counter", String.valueOf(sRetryCounter));

				if (sCountry != null)
					htServiceRequest.put("country", sCountry);
				if (sLanguage != null)
					htServiceRequest.put("language", sLanguage);

				_systemLogger.log(Level.INFO, MODULE, sMethod, "FORM htServiceRequest=" + htServiceRequest);
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
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.DELEGATOR_INTERNAL_SERVER_ERROR, sLanguage, failureHandling);
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
		String sMethod = "doPost";
		PrintWriter pwOut = null;
		String sUid = null;
		String sPassword = null;
		String sLanguage = null;
		String failureHandling = _sFailureHandling;	// Initially we use default from config, this might change if we suspect parameter tampering

		_systemLogger.log(Level.INFO, MODULE, sMethod, "POST htServiceRequest=" + servletRequest);
		try {
			sLanguage = servletRequest.getParameter("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;
			String sCountry = servletRequest.getParameter("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;
			
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
			String sChallenge = servletRequest.getParameter("delegate_challenge");
			String sChallengeResponse = servletRequest.getParameter("delegate_challenge_response");
			String sDelegateSession = servletRequest.getParameter("delegate_session");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "uid=" + sUid + " rid=" + sRid);

			if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sAsId == null)
					|| (sRetryCounter == null) || (sSignature == null)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received: one or more mandatory parameters missing, handling error locally.");
				failureHandling = "local";	// RH, 20111021, n
				throw new ASelectException(Errors.DELEGATOR_INVALID_REQUEST);
			}

			HashMap sessionContext = _sessionManager.getSessionContext(sRid);
			if ( sessionContext == null  ) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received, no session found for rid:" + sRid);
				throw new ASelectException(Errors.DELEGATOR_INVALID_REQUEST);			
			}
			String app_id  = (String)sessionContext.get(_sAuthProvider  + "_app_id");
			String formtoken = (String)sessionContext.get(_sAuthProvider  + "_formtoken");
			Integer retry_counter = (Integer)sessionContext.get(_sAuthProvider  + "_retry_counter");
			if ( (formtoken  == null)
					||  ( retry_counter  == null) 
					||  (app_id  == null)  ) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received, one or more of session parameters could not be retrieved" );
				throw new ASelectException(Errors.DELEGATOR_INVALID_REQUEST);			
			}

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

			if (sUid.trim().length() < 1 ) {  // empty user , retry
				// show authentication form once again with warning message
				showAuthenticateForm(pwOut, Errors.DELEGATOR_INVALID_USER_PASSWORD_FORMAT, htServiceRequest);
			}
			else {
				// generate signature
				StringBuffer sbSignature = new StringBuffer(sRid);
				sbSignature.append(sAsUrl);
				sbSignature.append(sAsId);
				if (sCountry != null)
					sbSignature.append(sCountry);
				if (sLanguage != null)
					sbSignature.append(sLanguage);

				// verify form signature
				// formSignature is stored as part of the retryCounter
				String[] sa = sRetryCounter.split(":");
				String formSignature = sa[2];
				sRetryCounter = sa[0] + ":" + sa[1]; // now also contains formtoken
				String signedParms = sConcat(sAsId, app_id, sRetryCounter);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sRetryCounter:" +sa[1] + ", formtoken:" + formtoken + ", app_id:" + app_id);
				if ( !_cryptoEngine.verifyMySignature(signedParms, formSignature) || !sa[1].equals(formtoken) ) {
					StringBuffer sbWarning = new StringBuffer("Invalid signature from User form '");
					sbWarning.append(sAsId).append("' for user: ").append(sUid);
					sbWarning.append(" , handling error locally. ").append(sUid);	// RH, 20111021, n
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
					failureHandling = "local";	// RH, 20111021, n
					throw new ASelectException(Errors.DELEGATOR_INVALID_REQUEST);
				}
				
				// authenticate user
				URL delegateURL = new URL(_sDelegateUrl.replace("*", app_id));
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "creating delegator with URL:" + delegateURL);
				Delegate _oDelegate = DelegateFactory.createDelegate(delegateURL, _sDelegateUser, _sDelegatePassword, _sDelegateGateway, _sAuthProvider);

				HashMap<String, String> requestparameters =  new HashMap<String, String>();
				HashMap<String, List<String>> responseparameters =  new HashMap<String, List<String>>();
				
				if (sessionContext.get(_sAuthProvider  + "_" + KEY_DELEGATE_SESSION) == null) {// If there is no delegate_session yet, this is a first (user/passwd) request
					requestparameters.put(request_key_uid, sUid);
					requestparameters.put(request_key_password, sPassword);
				} else {	// this is a challenge request
					sUid = (String)sessionContext.get(_sAuthProvider  + "_" + request_key_uid);	// use safed userid for this challenge
					requestparameters.put(KEY_DELEGATE_SESSION, (String)sessionContext.get(_sAuthProvider  + "_" + KEY_DELEGATE_SESSION));
					// remove old info from session context
					sessionContext.remove(_sAuthProvider  + "_" + KEY_DELEGATE_SESSION);
					sessionContext.remove(_sAuthProvider  + "_" + request_key_uid);
					_sessionManager.updateSession(sRid, sessionContext);

					requestparameters.put( sChallenge, sChallengeResponse);
				}
				// authenticate returns parameters in Map authenticate
				int iResultCode = _oDelegate.authenticate(requestparameters, responseparameters);
				
				// RH, 20131220, sn
				if ( _bUrldecode_responseheaders ) {
					// responseparameters is modifiable
					Set<String> sKeys = responseparameters.keySet();
					Iterator<String> iKeys = sKeys.iterator();
					while ( iKeys.hasNext() ) {
						String sKey = iKeys.next();
						List<String> lValues = responseparameters.get(sKey);
						Iterator<String> iValues = lValues.iterator();
						Vector<String> decoded = new Vector<String>();
						while ( iValues.hasNext() ) {
							String iValue = iValues.next();
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "responseparameter value before decode=" + iValue);
							iValue = URLDecoder.decode( iValue, "UTF-8" );
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "responseparameter value after decode=" + iValue);
							decoded.add(iValue);
						}
						responseparameters.put(sKey, decoded);
					}
				}
				// RH, 20131220, en
				
				
				switch (iResultCode) {
				case Delegate.DELEGATE_SUCCESS:
				case Delegate.DELEGATE_SUCCESS_NO_CONTENT:	// For TESTING we let fall-through
					
					// Authentication successfull
					_authenticationLogger.log(new Object[] {
						MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "granted"
					});

					_systemLogger.log(Level.INFO, MODULE, sMethod, "Success");
					_systemLogger.log(Level.INFO, MODULE, sMethod, "responseparameters:" + responseparameters);
					if (responseparameters.get(response_key_uid) == null) {
						String[] initialParms = { sUid };
						responseparameters.put(response_key_uid, Arrays.asList(initialParms));	// if no user returned from delegate, use requested user
					}
					handleResult(servletRequest, servletResponse, pwOut, Integer.toString(iResultCode), sLanguage, failureHandling, responseparameters);
					
					break;

				case Delegate.DELEGATE_INQUIRE:	// Not implemented yet at the other side
					// show challenge form
					if (!_bShow_challenge) {
						// Challenging not configured
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error communicating with delegate, challenging not configured");
						throw new ASelectException(Errors.DELEGATOR_INTERNAL_SERVER_ERROR);
					}
					String delegateSession = (String) responseparameters.get(KEY_DELEGATE_SESSION).get(0);	// Should be single valued
					// For testing give delegateSession a value
					//////	TESTING	/////	// DELEGATE_INQUIRE not implemented yet on the other side
//					if (delegateSession == null) {
//						byte[] baRandomBytes = new byte[20];
//						CryptoEngine.nextRandomBytes(baRandomBytes);
//						delegateSession = "_" + app_id + "_" + sUid + Utils.byteArrayToHexString(baRandomBytes);
//					}
					//////	TESTING	/////	// DELEGATE_INQUIRE not implemented yet on the other side

					if (delegateSession == null) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error communicating with delegate, no Session from delegate");
						throw new ASelectException(Errors.DELEGATOR_INTERNAL_SERVER_ERROR);
					}
					sChallenge =  (String) responseparameters.get(KEY_DELEGATE_CHALLENGE).get(0);	// Should be single valued
					if (sChallenge == null) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error communicating with delegate, no Challenge from delegate");
						throw new ASelectException(Errors.DELEGATOR_INTERNAL_SERVER_ERROR);
					}
					sessionContext.put(_sAuthProvider  + "_" + KEY_DELEGATE_SESSION, delegateSession);
					sessionContext.put(_sAuthProvider  + "_" + request_key_uid, sUid);	// safe userid for this challenge
					
					_sessionManager.updateSession(sRid, sessionContext);
					htServiceRequest.putAll(responseparameters);
					
					htServiceRequest.put(KEY_DELEGATE_CHALLENGE, sChallenge);
					showChallengeForm(pwOut, null, null, htServiceRequest);
					break;

				default:	// default to retry / fail
					// Handle retries
					if ( retry_counter < _iAllowedRetries ) {
						retry_counter++;	// next time around
						htServiceRequest.put("app_id", app_id);  // This is the requested application
						formtoken = newToken();

						sRetryCounter =  String.valueOf(retry_counter);	
						sRetryCounter +=  ":" + formtoken;	// for backward compatibility  we use the retry_counter to store our formtoken
						
						sessionContext.put(_sAuthProvider + "_formtoken", formtoken);
						sessionContext.put(_sAuthProvider + "_retry_counter", retry_counter);
						_sessionManager.updateSession(sRid, sessionContext);

						sRetryCounter += ":" + _cryptoEngine.generateSignature(sConcat(sAsId, app_id, sRetryCounter));
						htServiceRequest.put("retry_counter", String.valueOf(sRetryCounter));
	
						if (sCountry != null)
							htServiceRequest.put("country", sCountry);
						if (sLanguage != null)
							htServiceRequest.put("language", sLanguage);
						
						_systemLogger.log(Level.INFO, MODULE, sMethod, "FORM htServiceRequest=" + htServiceRequest);
						showAuthenticateForm(pwOut, ""/*no error*/, htServiceRequest);
					}
					else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Too many retries" );
						_authenticationLogger.log(new Object[] {
							MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "denied", Errors.DELEGATOR_DELEGATE_FAIL
							});
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Fail");
						_systemLogger.log(Level.INFO, MODULE, sMethod, "responseparameters:" + responseparameters);
						handleResult(servletRequest, servletResponse, pwOut, Integer.toString(iResultCode), sLanguage, failureHandling);
					}					
					break;
				}
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", eAS);
			handleResult(servletRequest, servletResponse, pwOut, eAS.getMessage(), sLanguage, failureHandling);
		}
		catch (IOException eIO) {  // could not send response
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error sending response", eIO);
			if (!servletResponse.isCommitted()) {  // send response if no headers have been written
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}
		}
		catch (Exception e) {  // internal error
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.DELEGATOR_INTERNAL_SERVER_ERROR, sLanguage, failureHandling);
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
	 *            the <code>PrintWriter</code> that is the target for displaying
	 *            the html page.
	 * @param sError
	 *            The error that should be shown in the page. Can be null (no
	 *            errors)
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
		
		if (sError == null)
			sError = "";
		String sMyUrl = (String) htServiceRequest.get("my_url");
		String sRid = (String) htServiceRequest.get("rid");
		String sAsUrl = (String) htServiceRequest.get("as_url");
		String sUid = (String) htServiceRequest.get("uid");
		String sAsId = (String) htServiceRequest.get("a-select-server");
		String sSignature = (String) htServiceRequest.get("signature");
		String sRetryCounter = (String) htServiceRequest.get("retry_counter");
		String sCountry = (String) htServiceRequest.get("country");
		String sLanguage = (String) htServiceRequest.get("language");
		
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
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "UTF-8 dencoding not supported, using undecoded", e);
				sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[requestor_friendly_name]", sFriendlyName);
			}
		}
		// RH, 20100907, en

		_systemLogger.log(Level.INFO, MODULE, sMethod, "error_code="+sError+" message="+sErrorMessage);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[rid]", sRid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[as_url]", sAsUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[uid]", sUid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[authsp_server]", sMyUrl);
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
		//sAuthenticateForm = Utils.replaceConditional(sAuthenticateForm, "if_error", sErrorMessage != null && !sErrorMessage.equals(""));
		
		// Bauke 20110721: Extract if_cond=... from the application URL
		String sSpecials = Utils.getAselectSpecials(htServiceRequest, true/*decode too*/, _systemLogger);
		sAuthenticateForm = Utils.handleAllConditionals(sAuthenticateForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Show Form");
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
	 */
	private void showChallengeForm(PrintWriter pwOut, String sError, String sErrorMessage, HashMap htServiceRequest)
	throws ASelectException
	{
		String sMethod = "showChallengeForm";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "htServiceRequest=" + htServiceRequest);

		String sMyUrl = (String) htServiceRequest.get("my_url");
		String sRid = (String) htServiceRequest.get("rid");
		String sAsUrl = (String) htServiceRequest.get("as_url");
		String sUid = (String) htServiceRequest.get("uid");
		String sAsId = (String) htServiceRequest.get("a-select-server");
		String sSignature = (String) htServiceRequest.get("signature");
		String sRetryCounter = (String) htServiceRequest.get("retry_counter");
		String sCountry = (String) htServiceRequest.get("country");
		String sChallenge = (String) htServiceRequest.get("delegate_challenge");
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

		_systemLogger.log(Level.INFO, MODULE, sMethod, "error_code="+sError+" message="+sErrorMessage);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[rid]", sRid);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[as_url]", sAsUrl);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[uid]", sUid);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[authsp_server]", sMyUrl);
		sChallengeForm = Utils.replaceString(sChallengeForm, "[a-select-server]", sAsId);
		if (sError != null) {
			sChallengeForm = Utils.replaceString(sChallengeForm, "[error]", sError);  // obsoleted 20100817
			sChallengeForm = Utils.replaceString(sChallengeForm, "[error_code]", sError);
		}
		sChallengeForm = Utils.replaceString(sChallengeForm, "[country]", (sCountry != null)? sCountry: "");
		sChallengeForm = Utils.replaceString(sChallengeForm, "[language]", (sLanguage != null)? sLanguage: "");
		sChallengeForm = Utils.replaceString(sChallengeForm, "[delegate_challenge]",  sChallenge );

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
		sChallengeForm = Utils.handleAllConditionals(sChallengeForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);

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
		handleResult(servletRequest, servletResponse, pwOut, sResultCode, sLanguage, failureHandling, null);
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
			PrintWriter pwOut, String sResultCode, String sLanguage, String failureHandling, Map<String, List<String>> responseParameters)
	{
		String sMethod = "handleResult";
		StringBuffer sbTemp = null;
		
		try {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sResultCode=" + sResultCode + ", failureHandling=" + failureHandling + ", responseParameters=" + responseParameters);
			sResultCode = translateResult(sResultCode);

			// Prevent tampering with request parameters, potential fishing leak
			if (failureHandling.equalsIgnoreCase(DEFAULT_FAILUREHANDLING) || sResultCode.equals(Errors.DELEGATOR_SUCCESS)) {
				// A-Select handles error or success
				String sRid = servletRequest.getParameter("rid");
				String sAsUrl = servletRequest.getParameter("as_url");
				String sAsId = servletRequest.getParameter("a-select-server");
				String sUserId, sDelegateSession, sDelegateTimeout, sDelegateFields;
				sUserId = sDelegateSession = sDelegateTimeout = sDelegateFields = null;
				 
				if (responseParameters != null) {
					sUserId = (String) responseParameters.get(response_key_uid).get(0);	// must at least have a single valued user_id
					// delegate_session and delegate_timeout not implemented by the other side (yet)
//					sDelegateSession = (String) responseParameters.get("delegate_session");
//					sDelegateTimeout = (String) responseParameters.get("delegate_timeout");
					sDelegateFields = Utils.serializeAttributes(responseParameters);	// creates base64
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "sDelegateFields=" + sDelegateFields);
				}
				if (sRid == null || sAsUrl == null || sAsId == null) {
					getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
				}
				else {
					sbTemp = new StringBuffer(sRid);
					sbTemp.append(sAsUrl).append(sResultCode);
					sbTemp.append(sAsId);
					
					if (sUserId != null)
						sbTemp.append(sUserId);
					if (sDelegateSession != null)
						sbTemp.append(sDelegateSession);
					if (sDelegateTimeout != null)
						sbTemp.append(sDelegateTimeout);
					if (sDelegateFields != null)
						sbTemp.append(sDelegateFields);

					
					String sSignature = _cryptoEngine.generateSignature(sbTemp.toString());
					sSignature = URLEncoder.encode(sSignature, "UTF-8");

					sbTemp = new StringBuffer(sAsUrl);
					sbTemp.append("&rid=").append(sRid);
					sbTemp.append("&result_code=").append(sResultCode);
					sbTemp.append("&a-select-server=").append(sAsId);
					BASE64Encoder base64encoder = new BASE64Encoder();

					if (sUserId != null)
						sbTemp.append("&user_id=").append(sUserId);
					if (sDelegateSession != null)
						sbTemp.append("&delegate_session=").append(URLEncoder.encode(base64encoder.encode(sDelegateSession.getBytes("UTF-8")), "UTF-8"));
					if (sDelegateTimeout != null)
						sbTemp.append("&delegate_timeout=").append(URLEncoder.encode(base64encoder.encode(sDelegateTimeout.getBytes("UTF-8")), "UTF-8"));	
					if (sDelegateFields != null)
						sbTemp.append("&delegate_fields=").append(URLEncoder.encode(sDelegateFields, "UTF-8"));	// Already Base64
					sbTemp.append("&signature=").append(sSignature);

					try {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT " + sbTemp);
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
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate Delegator AuthSP signature", eAS);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.DELEGATOR_DELEGATE_FAIL, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (UnsupportedEncodingException eUE) {  // could not encode signature
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode Delegator AuthSP signature", eUE);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.DELEGATOR_DELEGATE_FAIL, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
	}

	/**
	 * Translate delegator resultcode to server DelegatorAuthSPHandler resultcode.
	 * 
	 * @return the string
	 */
	private String translateResult(String resultcode)
	{
		if (Errors.DELEGATOR_DELEGATE_SUCCESS.equals(resultcode) || Errors.DELEGATOR_DELEGATE_SUCCESS_NO_CONTENT.equals(resultcode)) {	
			// For testing we allow DELEGATOR_DELEGATE_SUCCESS_NO_CONTENT
			return Errors.DELEGATOR_SUCCESS;
		}
		else {	// Default to invalid request
			return Errors.DELEGATOR_INVALID_REQUEST;
		}
	}
}