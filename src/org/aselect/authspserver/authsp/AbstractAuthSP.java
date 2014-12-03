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

package org.aselect.authspserver.authsp;

import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.aselect.authspserver.authsp.sms.Errors;
import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.crypto.CryptoEngine;
import org.aselect.authspserver.log.AuthSPAuthenticationLogger;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.authspserver.session.AuthSPSessionManager;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.servlet.ASelectHttpServlet;
import org.aselect.system.utils.Utils;

/**
 * Superclass various AuthSP's
 * Handles basics common to these AuthSP's
 * 
 * @author remy
 *
 * 20141201, Bauke: added lots of functionality in the init() method,
 *     all AuthSP's inherit from AbstractAuthSP now. Functionality moved from AuthSP's to here.
 */
public abstract class AbstractAuthSP extends ASelectHttpServlet
{
	private static final long serialVersionUID = 1L;

	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "AbstractAuthSP";

	/** Default failure_handling option. */
	protected final static String DEFAULT_FAILUREHANDLING = "aselect";
	
	/** The logger that logs system information. */
	protected AuthSPSystemLogger _systemLogger;

	/** The logger that logs authentication information. */
	protected AuthSPAuthenticationLogger _authenticationLogger;

	/** The configuration */
	protected AuthSPConfigManager _configManager;

	/** The Sessionmanager */
	protected AuthSPSessionManager _sessionManager;

	/** The crypto engine */
	protected CryptoEngine _cryptoEngine;

	// ID of this AuthSP
	protected String _sConfigID = null;
	
	// The AuthSP Config Section
	protected Object _oAuthSpConfig;// = null;

	/* The AuthSP Server user friendly name */
	protected String _sFriendlyName;
	
	/* The workingdir configured in the web.xml of the AuthSP Server */
	protected String _sWorkingDir;

	protected String _sFailureHandling = null;
	
	protected HashMap htSessionContext = null;
	
	protected int _iAllowedRetries = 0;

	protected static SecureRandom _random;
	
	private static final int TOKEN_SIZE = 16;

	/**
	 * Initialization of the Abstract AuthSP. <br>
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
	 * </ul>
	 * 
	 * @param oConfig
	 *            the configuration
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	public void init(ServletConfig oConfig, boolean needSection, String sErrorCode)
	throws ServletException
	{
		String sMethod = "init";
		try {
			super.init(oConfig);
			
			// retrieve managers and loggers
			_systemLogger = AuthSPSystemLogger.getHandle();
			_authenticationLogger = AuthSPAuthenticationLogger.getHandle();
			_configManager = AuthSPConfigManager.getHandle();
			_sessionManager = AuthSPSessionManager.getHandle();
			
			// Retrieve crypto engine from servlet context.
			ServletContext oContext = oConfig.getServletContext();
			_cryptoEngine = (CryptoEngine) oContext.getAttribute("CryptoEngine");
			if (_cryptoEngine == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No CryptoEngine found in servlet context.");
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded CryptoEngine.");

			_sFriendlyName = (String)oContext.getAttribute("friendly_name");
			if (_sFriendlyName == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No friendly_name found in servlet context.");
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded friendly_name");
			
			_sWorkingDir = (String)oContext.getAttribute("working_dir");
			if (_sWorkingDir == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No working_dir found in servlet context.");
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded working_dir");

			_sConfigID = oConfig.getInitParameter("config_id");
			if (_sConfigID == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No 'config_id' found as init-parameter in web.xml.");
				throw new ASelectException(Errors.ERROR_SMS_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "ConfigID="+_sConfigID);

			// pre load error messages
			Utils.loadPropertiesFromFile(_systemLogger, _sWorkingDir, _sConfigID, "errors.conf", null/*language*/);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully read messages from errors.conf");

			// Call before extracting _oAuthSpConfig configuration items
			getAuthSpConfigSection(needSection, sErrorCode);
			
			// _oAuthSpConfig is set now
			getFailureHandlingFromConfig();

			// Get random generator
			_random = SecureRandom.getInstance("SHA1PRNG");

			// Set allowed retries to some default
			_iAllowedRetries = 0;	// Must be set by each AuthSP
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			throw new ServletException("Initializing failed");
		}
	}

	// 20141201, Bauke: added
	/**
	 * Get the AuthSP config section.
	 * 
	 * @param needSection
	 *            is section mandatory?
	 * @throws ASelectException
	 */
	private void getAuthSpConfigSection(boolean needSection, String sErrorCode)
	throws ASelectException
	{
		String sMethod = "getAuthSpConfigSection";
		try {
			_oAuthSpConfig = _configManager.getSection(null, "authsp", "id=" + _sConfigID);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Found AuthSP config section id="+ _sConfigID+" ->"+_oAuthSpConfig);
		}
		catch (Exception e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "No valid 'authsp' config section found with id="+ _sConfigID);
			if (needSection)
				throw new ASelectException(sErrorCode);
		}
	}
		
	// 20141201, Bauke: added
	/**
	 * Get failure handling from configuration.
	 * 
	 * @param sDefaultHandling
	 *            the default handling
	 * @throws ASelectException
	 */
	protected void getFailureHandlingFromConfig()
	throws ASelectException
	{
		String sMethod = "getFailureHandlingFromConfig";
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Id="+ _sConfigID+" ->"+_oAuthSpConfig);
		_sFailureHandling = Utils.getSimpleParam(_configManager, _systemLogger, _oAuthSpConfig, "failure_handling", false);
		if (_sFailureHandling == null) {
			_sFailureHandling = DEFAULT_FAILUREHANDLING;
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
					"No 'failure_handling' parameter found in configuration, using default: "+DEFAULT_FAILUREHANDLING);
		}

		if (!_sFailureHandling.equalsIgnoreCase(DEFAULT_FAILUREHANDLING) && !_sFailureHandling.equalsIgnoreCase("local")) {
			_sFailureHandling = DEFAULT_FAILUREHANDLING;
			StringBuffer sbWarning = new StringBuffer("Invalid 'failure_handling' parameter found in configuration: '");
			sbWarning.append(_sFailureHandling).append("', using default: "+DEFAULT_FAILUREHANDLING);
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbWarning.toString());
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "failure_handling="+_sFailureHandling);
	}

	// 20141201, Bauke: added
	/**
	 * Gets the template and show error page.
	 * 
	 * @param pwOut
	 *            the output writer
	 * @param sResultCode
	 *            the result code
	 * @param sErrorCode
	 *            the error code
	 * @param sLanguage
	 *            the language
	 * @throws ASelectException
	 */
	protected void getTemplateAndShowErrorPage(PrintWriter pwOut, String sResultCode, String sErrorCode, String sLanguage, String sVersion)
	throws ASelectException
	{
		String sMethod = "getTemplateAndShowErrorPage";
		
		String sErrorHtmlTemplate = Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID,
				"error.html", sLanguage, _sFriendlyName, sVersion);
		
		String sErrorMessage = null;
		if (Utils.hasValue(sErrorCode)) {  // translate error code
			Properties propErrorMessages = Utils.loadPropertiesFromFile(_systemLogger, _sWorkingDir, _sConfigID, "errors.conf", sLanguage);
			sErrorMessage = _configManager.getErrorMessage(MODULE, sErrorCode, propErrorMessages);
		}
		
		showErrorPage(pwOut, sErrorHtmlTemplate, sResultCode, sErrorMessage, sLanguage, _systemLogger);
	}

	/**
	 * Process requests for the HTTP <code>GET</code> method. <br>
	 * <br>
	 * Retrieves or sets up htSessionContext and iAllowedRetries
	 * 
	 * @param pwOut
	 *            the pw out
	 * @param sResultCode
	 *            the s result code
	 * @param sErrorCode
	 *            the s error code
	 * @param sLanguage
	 *            the s language
	 * @param sVersion
	 *            the s version
	 * @throws ASelectException
	 *             the a select exception
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	/**
	 * For future improvement
	 */
//	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
//	throws java.io.IOException
//	{
//		String sMethod = "doGet";
//		htSessionContext = null;
//		int iAllowedRetries = 0;
//
//		String sRid = (String) servletRequest.getParameter("rid");
//
//		boolean sessionPresent = false;
//		try {
//			htSessionContext = _sessionManager.getSessionContext(sRid);
//		}
//		catch (ASelectException e) {
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "Not found: "+sRid);
//		}
//		
//		if (htSessionContext != null) {
//			sessionPresent = true;
//			try {
//				iAllowedRetries = ((Integer) htSessionContext.get("allowed_retries")).intValue();
//			}
//			catch (ClassCastException e) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to cast to Integer.", e);
//				iAllowedRetries = _iAllowedRetries;
//			}
//		}
//		else {
//			htSessionContext = new HashMap();
//			//_sessionManager.createSession(sRid, htSessionContext);
//			iAllowedRetries = _iAllowedRetries;
//		}
//
//		
//		
//	}

	/**
	 * 
	 * @return new random hexString token of TOKEN_SIZE *2 length
	 */
	protected synchronized String newToken() {
		byte[] r = new byte[TOKEN_SIZE];
		_random.nextBytes(r);
		return org.aselect.system.utils.Utils.byteArrayToHexString(r);
	}	
	
	/* (non-Javadoc)
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	@Override
	protected boolean isRestartableServlet()
	{
		return false;
	}

	/**
	 * Simple utility to concatenate strings
	 * Only not null params are concatenated
	 * @param strings
	 * 		strings to concat
	 * @return
	 * 		concated string
	 */
	protected String sConcat(String... strings)
	{
		StringBuffer sb = new StringBuffer();
	       for ( String s : strings )              
	    	   if (s != null)
	    		   sb.append(s); 
	       return sb.toString();
	}
}
