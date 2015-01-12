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
 * $Id: LDAPAuthSP.java,v 1.21 2006/05/03 10:06:47 tom Exp $ 
 *
 * Changelog:
 * $Log: LDAPAuthSP.java,v $
 * Revision 1.21  2006/05/03 10:06:47  tom
 * Removed Javadoc version
 *
 * Revision 1.20  2006/05/03 09:32:56  martijn
 * changes for version 1.5
 *
 * Revision 1.19  2006/04/12 13:29:35  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.17.2.7  2006/04/12 06:40:10  jeroen
 * Debug logging removed
 *
 * Revision 1.17.2.6  2006/04/12 06:08:09  jeroen
 * Fix in full uid check. Now also the index is checked > -1.
 *
 * Revision 1.17.2.5  2006/04/03 13:59:22  erwin
 * Fixed problem with unknown realm (bug #178)
 *
 * Revision 1.17.2.4  2006/03/30 15:10:53  leon
 * *** empty log message ***
 *
 * Revision 1.17.2.3  2006/03/30 14:49:46  leon
 * small bugfix
 *
 * Revision 1.17.2.2  2006/03/30 14:29:00  leon
 * merged changes from head in this branch
 *
 * Revision 1.18  2006/03/28 08:18:18  leon
 * Added session management for directlogin
 *
 * Revision 1.17  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.16  2005/04/29 12:08:55  martijn
 * fixed bug in failure_handling logging
 *
 * Revision 1.15  2005/04/29 11:37:58  martijn
 * fixed failure_handling bug: now checking if failure_handling is set to aselect or local. fixed bugs in logging
 *
 * Revision 1.14  2005/04/04 08:16:18  martijn
 * made country and language parameters optional (fixed small bug, to make it work)
 *
 * Revision 1.13  2005/04/04 07:49:25  martijn
 * added support for the optional attributes country and language in the authentication template
 *
 * Revision 1.12  2005/04/01 14:18:40  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.11  2005/03/29 13:10:28  martijn
 * added a default for the failure_handling config option if not configured
 *
 * Revision 1.10  2005/03/29 10:38:15  erwin
 * Removed redundant code; now extends ASelectHttpServlet and uses AuthSP configmanager functionality.
 *
 * Revision 1.9  2005/03/24 09:56:30  erwin
 * Fixed numberformat exception and problem with error handling
 *
 * Revision 1.8  2005/03/23 12:41:18  erwin
 * Improved template loading (close)
 *
 * Revision 1.7  2005/03/23 11:35:21  erwin
 * Fixed problem with nullpointer if errors are handled by A-Select.
 *
 * Revision 1.6  2005/03/23 09:48:38  erwin
 * - Applied code style
 * - Added javadoc
 * - Improved error handling
 *
 * Revision 1.5  2005/03/02 13:45:19  remco
 * Integrated new logger
 * Removed old configuration code
 *
 * Revision 1.4  2005/02/07 16:26:19  leon
 * removed importConfig from init
 *
 * Revision 1.3  2005/02/04 10:12:40  leon
 * code restyle and license added
 */
package org.aselect.authspserver.authsp.ldap;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.authsp.AbstractAuthSP;
import org.aselect.authspserver.authsp.ldap.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.servlet.ASelectHttpServlet;
import org.aselect.system.utils.Utils;

/**
 * An A-Select AuthtSP that uses LDAP as back-end. <br>
 * <br>
 * <b>Description:</b><br>
 * The A-Select LDAP AuthSP uses a LDAP back-end to validate user/password combinations. The LDAP AuthSP retrieves the
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
 * @author Alfa & Ariss
 */
public class LDAPAuthSP extends AbstractAuthSP  // 20141201, Bauke: inherit goodies from AbstractAuthSP
{
	private static final long serialVersionUID = 1L;

	/** The status parameter name for API calls. */
	private final String RESULT_CODE = "status";

	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "LDAPAuthSP";

	/** The version. */
	public static final String VERSION = "A-Select LDAP AuthSP";
	
	// failure handling properties
	//private Properties _oErrorProperties;
	
	/**
	 * Initialization of the LDAP AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Performs the following steps to initialise the <code>LDAPAuthSP</code>:
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
	 * <li>The AuthSPServer must be successfully started</li>
	 * <li>An error config file must exist</li>
	 * <li>An error template file must exist</li>
	 * <li>An authentication template file must exist</li>
	 * <li>An LDAP 'authsp' config section must be available in the configuration of the AuthSP Server. The id of this
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
			// super init
			super.init(oConfig, true, Errors.ERROR_LDAP_INTERNAL_ERROR);

			StringBuffer sbInfo = new StringBuffer("Starting: ").append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
			
			// Load HTML templates.
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "error.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "authenticate.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'authenticate.html' template.");

			// Get allowed retries
			_iAllowedRetries = Utils.getSimpleIntParam(_configManager, _systemLogger, _oAuthSpConfig, "allowed_retries", true);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "allowed_retries="+_iAllowedRetries);
			
			sbInfo = new StringBuffer("Successfully started ").append(VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			throw new ServletException("Initializing failed");
		}
	}

	/**
	 * Process requests for the HTTP <code>GET</code> method. <br>
	 * Arguments must be URL encoded.<br>
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
			// 20141208, Bauke: utf-8 added
			servletResponse.setContentType("text/html; charset=utf-8");	// RH, 20111021, n 	// contenttype must be set before getwriter

			setDisableCachingHttpHeaders(servletRequest, servletResponse);
			pwOut = servletResponse.getWriter();

			String sQueryString = servletRequest.getQueryString();  // parameters are URL encoded
			HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, true/*url decode*/);
			// In htServiceRequest values are URL decoded now
			
			sLanguage = (String) htServiceRequest.get("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;
			String sCountry = (String) htServiceRequest.get("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;

			// check if the request is an API call
			String sRequestName = (String) htServiceRequest.get("request");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "LDAP GET { query-->" + sQueryString);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "req="+sRequestName+" pwd="+(String)htServiceRequest.get("password"));

			if (sRequestName != null) {  // API request, no URL decoding done yet
				handleApiRequest(htServiceRequest, servletRequest, pwOut, servletResponse);
			}
			else { // Browser request
				String sMyUrl = servletRequest.getRequestURL().toString();
				htServiceRequest.put("my_url", sMyUrl);

				String sRid = (String) htServiceRequest.get("rid");
				String sAsUrl = (String) htServiceRequest.get("as_url");
				String sUid = (String) htServiceRequest.get("uid");
				String sAsId = (String) htServiceRequest.get("a-select-server");
				String sSignature = (String) htServiceRequest.get("signature");

				if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sAsId == null) || (sSignature == null)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid request received: one or more mandatory parameters missing, handling error locally.");
					failureHandling = "local";	// RH, 20111021, n
					throw new ASelectException(Errors.ERROR_LDAP_INVALID_REQUEST);
				}

				// validate signature
				StringBuffer sbSignature = new StringBuffer(sRid);
				sbSignature.append(sAsUrl).append(sUid).append(sAsId);

				// optional country and language code
				if (sCountry != null) sbSignature.append(sCountry);
				if (sLanguage != null) sbSignature.append(sLanguage);

				if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
					StringBuffer sbWarning = new StringBuffer("Invalid signature from A-Select Server '");
					sbWarning.append(sAsId);
					sbWarning.append("' for user: ").append(sUid).append(", handling error locally.");
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
					failureHandling = "local";	// RH, 20111021, n
					throw new ASelectException(Errors.ERROR_LDAP_INVALID_REQUEST);
				}

				// Get the User its contexts
				LDAPProtocolHandlerFactory.getContext(_oAuthSpConfig, sUid, _systemLogger);

				// show authentication form
				htServiceRequest.put("as_url", sAsUrl);
				htServiceRequest.put("uid", sUid);
				htServiceRequest.put("retry_counter", "1");
				if (sCountry != null) htServiceRequest.put("country", sCountry);
				if (sLanguage != null) htServiceRequest.put("language", sLanguage);

				showAuthenticateForm(pwOut, "", htServiceRequest);
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
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, sLanguage, failureHandling);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "} LDAP GET");
	}

	/**
	 * Process requests for the HTTP <code>POST</code> method. <br>
	 * Arguments must be URL encoded.<br>
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
		String sLanguage = null;
		String failureHandling = _sFailureHandling;	// Initially we use default from config, this might change if we suspect parameter tampering


		String sRequest = servletRequest.getParameter("request");
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "LDAP POST { req="+sRequest+" query-->" + servletRequest.getQueryString()+" len="+servletRequest.getContentLength());
		try {
			// 20141208, Bauke: utf-8 added
			servletResponse.setContentType("text/html; charset=utf-8");	// RH, 20111021, n	// contenttype must be set before getwriter
			pwOut = servletResponse.getWriter();

			// NOTE: getParameter() returns an URL decoded value
			sLanguage = servletRequest.getParameter("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;
			String sCountry = servletRequest.getParameter("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;

			String sMyUrl = servletRequest.getRequestURL().toString();
			String sRid = servletRequest.getParameter("rid");
			String sAsUrl = servletRequest.getParameter("as_url");
			String sUid = servletRequest.getParameter("uid");
			String sAsId = servletRequest.getParameter("a-select-server");
			String sPassword = servletRequest.getParameter("password");
			String sSignature = servletRequest.getParameter("signature");
			String sRetryCounter = servletRequest.getParameter("retry_counter");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "req="+sRequest+" pwd=["+sPassword+"]");
			
			if ("authenticate".equals(sRequest)) {
				HashMap htServiceRequest = new HashMap();

				String sUser = servletRequest.getParameter("user");
				if (sUser != null) htServiceRequest.put("user", sUser);
				if (sRequest != null) htServiceRequest.put("request", sRequest);
				if (sAsId != null) htServiceRequest.put("a-select-server", sAsId);
				if (sRid != null) htServiceRequest.put("rid", sRid);
				if (sPassword != null) htServiceRequest.put("password", sPassword);
				if (sSignature != null) htServiceRequest.put("signature", sSignature);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "htServiceRequest="+htServiceRequest);
				handleApiRequest(htServiceRequest, servletRequest, pwOut, servletResponse);
				return;
			}
			setDisableCachingHttpHeaders(servletRequest, servletResponse);

			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sRequest="+sRequest+" sRid="+sRid+" sUid="+sUid+" sPassword="+sPassword);
			if (sRid == null || sAsUrl == null || sUid == null || sPassword == null || sAsId == null ||
								sRetryCounter == null || sSignature == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received: one or more mandatory parameters missing, handling error locally.");
				failureHandling = "local";	// RH, 20111021, n
				throw new ASelectException(Errors.ERROR_LDAP_INVALID_REQUEST);
			}
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "LDAP POST " + servletRequest + " --> " + sMethod + ", "
					+ sRid + ": " + sMyUrl);

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
				if (sCountry != null) htServiceRequest.put("country", sCountry);
				if (sLanguage != null) htServiceRequest.put("language", sLanguage);
				
				// show authentication form once again with warning message
				showAuthenticateForm(pwOut, Errors.ERROR_LDAP_INVALID_PASSWORD, htServiceRequest);
			}
			else {
				// generate signature
				StringBuffer sbSignature = new StringBuffer(sRid);
				sbSignature.append(sAsUrl);
				sbSignature.append(sUid);
				sbSignature.append(sAsId);
				if (sCountry != null) sbSignature.append(sCountry);
				if (sLanguage != null) sbSignature.append(sLanguage);

				// 20120106, Bauke: already decoded
				//if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), URLDecoder.decode(sSignature, "UTF-8"))) {
				if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
					StringBuffer sbWarning = new StringBuffer("Invalid signature from A-Select Server '");
					sbWarning.append(sAsId);
					sbWarning.append("' for user: ").append(sUid).append(", handling error locally");	// RH, 20111021, n
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
					failureHandling = "local";	// RH, 20111021, n
					throw new ASelectException(Errors.ERROR_LDAP_INVALID_REQUEST);
				}

				// authenticate user
				ILDAPProtocolHandler oProtocolHandler = LDAPProtocolHandlerFactory.instantiateProtocolHandler(
						_oAuthSpConfig, sUid, _systemLogger);
				String sResultCode = oProtocolHandler.authenticate(sPassword);
				if (sResultCode.equals(Errors.ERROR_LDAP_INVALID_PASSWORD))
				// invalid password
				{
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
						if (sCountry != null) htServiceRequest.put("country", sCountry);
						if (sLanguage != null) htServiceRequest.put("language", sLanguage);
						// show authentication form once again with warning message
						showAuthenticateForm(pwOut, Errors.ERROR_LDAP_INVALID_PASSWORD, htServiceRequest);
					}
					else {
						// authenticate failed
						_authenticationLogger.log(new Object[] {
							MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "denied", Errors.ERROR_LDAP_INVALID_PASSWORD
						});
						handleResult(servletRequest, servletResponse, pwOut, sResultCode, sLanguage, failureHandling);
					}
				}
				else if (sResultCode.equals(Errors.ERROR_LDAP_SUCCESS)) // success
				{
					// Authentication successfull
					_authenticationLogger.log(new Object[] {
						MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "granted"
					});

					handleResult(servletRequest, servletResponse, pwOut, sResultCode, sLanguage, failureHandling);
				}
				else // other error
				{
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error authenticating user, cause: "
							+ sResultCode);
					handleResult(servletRequest, servletResponse, pwOut, sResultCode, sLanguage, failureHandling);
				}
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", eAS);
			handleResult(servletRequest, servletResponse, pwOut, eAS.getMessage(), sLanguage, failureHandling);
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
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_LDAP_INVALID_REQUEST, sLanguage, failureHandling);
		}
		catch (Exception e) // internal error
		{
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, sLanguage, failureHandling);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
				_systemLogger.log(Level.INFO, MODULE, sMethod, "} LDAP POST");
			}
		}
	}

	/**
	 * Determines whether or not the LDAP AuthsP is restartable. <br>
	 * <br>
	 * 
	 * @return true, if checks if is restartable servlet
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	protected boolean isRestartableServlet()
	{
		return false;
	}

	/**
	 * Handle the response to the client. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a redirect url and redirects the user back to the A-Select Server. If errors are handled locally the
	 * {@link ASelectHttpServlet#showErrorPage(PrintWriter, String, String, String)} method is called in case of an
	 * error.
	 * 
	 * @param servletRequest
	 *            The servlet request.
	 * @param servletResponse
	 *            The servlet response.
	 * @param sResultCode
	 *            The error code that should be sent to the A-Select Server
	 * @param pwOut
	 *            The output that is used, when error handling is local.
	 */
	private void handleResult(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut, String sResultCode, String sLanguage, String failureHandling)
	{
		String sMethod = "handleResult";
		StringBuffer sbTemp = null;

		try {
			// Prevent tampering with request parameters, potential fishing leak
			if (failureHandling.equalsIgnoreCase(DEFAULT_FAILUREHANDLING) || sResultCode.equals(Errors.ERROR_LDAP_SUCCESS))
			// A-Select handles error or success
			{
				String sRid = servletRequest.getParameter("rid");
				String sAsUrl = servletRequest.getParameter("as_url");
				String sAsId = servletRequest.getParameter("a-select-server");
				if (sRid == null || sAsUrl == null || sAsId == null) {
					getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
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
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "REDIR " + sbTemp);
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
			else { // Local error handling
				getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
			}
		}
		catch (ASelectException eAS) // could not generate signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate LDAP AuthSP signature", eAS);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (UnsupportedEncodingException eUE) // could not encode signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode LDAP AuthSP signature", eUE);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
	}

	/**
	 * Processes an API request to this LDAP AuthSP.
	 * 
	 * @param htServiceRequest
	 *            a <code>HashMap</code> containing request parameters.
	 *            The parameters have already been URL decoded.
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
		String sMethod = "handleApiRequest";
		String sRid = (String) htServiceRequest.get("rid");
		HashMap htSessionContext = null;
		// create response HashTable
		StringBuffer sbResponse = new StringBuffer("&rid=");
		// add rid to response
		sbResponse.append(sRid);
		int iAllowedRetries = 0;
		try {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "REQ " + htServiceRequest.get("request"));
			if (!htServiceRequest.get("request").equals("authenticate") || !Utils.hasValue(sRid)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid API request received.");
				throw new ASelectException(Errors.ERROR_LDAP_INVALID_REQUEST);
			}
			
			// 20120105, Bauke: removed containsKey call
			//if (_sessionManager.containsKey(sRid)) {
			boolean sessionPresent = false;  // 20120401: Bauke: optimize update/create
			try {
				htSessionContext = _sessionManager.getSessionContext(sRid);
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Not found: "+sRid);
			}
			
			if (htSessionContext != null) {
				sessionPresent = true;
				try {
					iAllowedRetries = ((Integer) htSessionContext.get("allowed_retries")).intValue();
				}
				catch (ClassCastException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to cast to Integer.", e);
					throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR);
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
				throw new ASelectException(Errors.ERROR_LDAP_ACCESS_DENIED);
			}
			handleAuthenticate(htServiceRequest, servletRequest);

			sbResponse.append("&").append(RESULT_CODE);
			sbResponse.append("=").append(Errors.ERROR_LDAP_SUCCESS);
			_sessionManager.remove(sRid);
		}
		catch (ASelectException eAS) {  // Allready logged
			sbResponse.append("&").append(RESULT_CODE);
			sbResponse.append("=").append(eAS.getMessage());
		}
		
		// set reponse headers
		servletResponse.setContentType("application/x-www-form-urlencoded");  // must be set before getWriter()
		servletResponse.setContentLength(sbResponse.length());
		pwOut.write(sbResponse.toString());
	}

	/**
	 * Handle the API call <code>request=authenticate</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * processes a authenticate API call and sends an API reponse to the client. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            The request containing URL decoded parameters.
	 * @param servletRequest
	 *            The request parameters.
	 * @throws ASelectException
	 *             If authenticate fails.
	 */
	private void handleAuthenticate(HashMap htServiceRequest, HttpServletRequest servletRequest)
	throws ASelectException
	{
		String sMethod = "handleAuthenticate";

		String sUid = (String) htServiceRequest.get("user");
		String sPassword = (String) htServiceRequest.get("password");
		String sAsID = (String) htServiceRequest.get("a-select-server");
		if (sUid == null || sPassword == null) // missing request parameters
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Invalid API request: one or more mandatory parameters are missing.");
			throw new ASelectException(Errors.ERROR_LDAP_INVALID_REQUEST);
		}

		sPassword = sPassword.trim();
		if (sPassword.length() < 1) // password invalid
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid API request: invalid password.");
			throw new ASelectException(Errors.ERROR_LDAP_INVALID_REQUEST);
		}

		ILDAPProtocolHandler oProtocolHandler = LDAPProtocolHandlerFactory.instantiateProtocolHandler(_oAuthSpConfig, sUid, _systemLogger);
		
		// The authentication is here, handled by the actual ProtocolHandler
		String sResultCode = oProtocolHandler.authenticate(sPassword);
		if (sResultCode.equals(Errors.ERROR_LDAP_SUCCESS)) {  // Authentication successful
			_authenticationLogger.log(new Object[] {
				MODULE, sUid, servletRequest.getRemoteAddr(), sAsID, "granted"
			});
		}
		else if (sResultCode.equals(Errors.ERROR_LDAP_INVALID_PASSWORD)) {  // invalid password
			_authenticationLogger.log(new Object[] {
				MODULE, sUid, servletRequest.getRemoteAddr(), sAsID, "denied", Errors.ERROR_LDAP_INVALID_PASSWORD
			});
			throw new ASelectException(sResultCode);
		}
		else {  // other error
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not authenticate user, cause:" + sResultCode);
			throw new ASelectException(sResultCode);
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
		String sCountry = (String) htServiceRequest.get("country");
		String sLanguage = (String) htServiceRequest.get("language");
		
		String sAuthenticateForm =  Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID,
					"authenticate.html", sLanguage, _sFriendlyName, VERSION);
		
		String sErrorMessage = null;
		if (Utils.hasValue(sError)) {  // translate error code
			Properties propErrorMessages = Utils.loadPropertiesFromFile(_systemLogger, _sWorkingDir, _sConfigID, "errors.conf", sLanguage);
			sErrorMessage = _configManager.getErrorMessage(MODULE, sError, propErrorMessages);
		}
		
		String sFriendlyName = (String) htServiceRequest.get("requestorfriendlyname");
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[requestor_friendly_name]", sFriendlyName);

		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[rid]", sRid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[as_url]", sAsUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[uid]", sUid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[ldap_server]", sMyUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[a-select-server]", sAsId);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error]", sError);  // obsoleted 20100817
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_code]", sError);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_message]", sErrorMessage);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[language]", sLanguage);
		sAuthenticateForm = Utils.replaceConditional(sAuthenticateForm, "[if_error,", ",", "]", sErrorMessage != null && !sErrorMessage.equals(""), _systemLogger);
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

		pwOut.println(sAuthenticateForm);
	}
}
