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

import java.security.SecureRandom;
import java.util.HashMap;
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

/**
 * Superclass various AuthSP's
 * Handles basics common to these AuthSP's
 * 
 * @author remy
 *
 */
public abstract class AbstractAuthSP extends ASelectHttpServlet
{
	private static final long serialVersionUID = 1L;

	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "AbstractAuthSP";

	private static SecureRandom _random;
	
	/** The logger that logs system information. */
	protected AuthSPSystemLogger _systemLogger;

	/** The logger that logs authentication information. */
	protected AuthSPAuthenticationLogger _authenticationLogger;

	/** The crypto engine */
	protected CryptoEngine _cryptoEngine;

	/** The configuration */
	protected AuthSPConfigManager _configManager;

	/** The Sessionmanager */
	protected AuthSPSessionManager _sessionManager;

	protected HashMap htSessionContext = null;
	protected int _iAllowedRetries;
	
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
	 *            the o config
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	public void init(ServletConfig oConfig)
	throws ServletException
	{
		String sMethod = "init";
//		StringBuffer sbTemp = null;
		try {
			// super init
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
			_random = SecureRandom.getInstance("SHA1PRNG");

			// set allowed retries to some default
			_iAllowedRetries = 0;	// Must be set by each AuthSP
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			throw new ServletException("Initializing failed");
		}
	}
			
	/**
	 * Process requests for the HTTP <code>GET</code> method. <br>
	 * <br>
	 * Retrieves or sets up htSessionContext and iAllowedRetries
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
