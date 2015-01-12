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
 * $Id: RadiusAuthSP.java,v 1.24 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $Log: RadiusAuthSP.java,v $
 * Revision 1.24  2006/05/03 10:07:31  tom
 * Removed Javadoc version
 *
 * Revision 1.23  2006/04/12 13:29:35  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.22.2.1  2006/03/22 09:18:30  martijn
 * changed version to 1.5
 *
 * Revision 1.22  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.21  2005/07/25 10:55:32  peter
 * Missing required init parameter did not throw an exception.
 *
 * Revision 1.20  2005/04/29 12:08:55  martijn
 * fixed bug in failure_handling logging
 *
 * Revision 1.19  2005/04/29 11:42:16  martijn
 * fixed bugs in logging, failure_handling, retry_counter and disabling caching
 *
 * Revision 1.18  2005/04/04 08:16:18  martijn
 * made country and language parameters optional (fixed small bug, to make it work)
 *
 * Revision 1.17  2005/04/04 07:49:25  martijn
 * added support for the optional attributes country and language in the authentication template
 *
 * Revision 1.16  2005/04/01 14:18:40  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.15  2005/03/29 13:16:51  martijn
 * added a default for the failure_handling config option if not configured
 *
 * Revision 1.14  2005/03/29 12:39:03  erwin
 * Removed redundant code; now extends ASelectHttpServlet and uses AuthSP configmanager functionality.
 *
 * Revision 1.13  2005/03/23 11:52:07  erwin
 * Improved some error handling
 *
 * Revision 1.12  2005/03/23 11:03:37  erwin
 * Added a-select-server to signing
 *
 * Revision 1.11  2005/03/16 13:13:18  martijn
 *
 * Revision 1.10  2005/03/14 09:58:02  martijn
 * config section renamed, new config used an init-param from web.xml to retrieve the config section
 *
 * Revision 1.9  2005/03/14 07:30:54  tom
 * Minor code style changes
 *
 * Revision 1.8  2005/03/11 13:48:44  erwin
 * Improved error handling.
 *
 * Revision 1.7  2005/03/10 16:16:59  tom
 * Added new Authentication Logger
 *
 * Revision 1.6  2005/03/10 07:48:20  tom
 * Added new Logger functionality
 * Added new Configuration functionality
 * Fixed small bug in Authenticator verification
 *
 * Revision 1.5  2005/03/08 08:11:28  leon
 * nullpointer exception fixed in the RadiusAuthSP.handleResult() by checking
 * if sRid != null and sAsUrl != null
 *
 * Revision 1.4  2005/03/07 15:57:40  leon
 * - New Failure Handling
 * - Extra Javadoc
 *
 * Revision 1.3  2005/02/09 09:17:04  leon
 * added License
 * code restyle
 * 
 *
 */

package org.aselect.authspserver.authsp.radius;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.authsp.AbstractAuthSP;
import org.aselect.authspserver.authsp.radius.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * The Radius AuthSP. <br>
 * <br>
 * <b>Description: </b> <br>
 * The Radius AuthSP is able to authenticate users against a Radius Server/Back-end based on the <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * None <br>
 * <br>
 * <b>Protocol Description</b> <br>
 * <i>Incoming request from the A-Select Server (Radius Protocol Handler):</i>
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
 * <td>Generated signature of all paramaters in the above sequence</td>
 * </tr>
 * </table>
 * <br>
 * <i>Outgoing response which will be returned to the A-Select Server (Radius Protocol Handler):</i>
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
 * <td>Generated signature of all paramaters in the above sequence</td>
 * </tr>
 * </table>
 * <br>
 * <b>Note:</b> The Algorithm and the JCE Provider used to generate the signatures is configurable in the AuthSP Server
 * config and must be the same as on the A-Select Server otherwise generated signatures will never be valid. <br>
 * <br>
 * 
 * @author Alfa & Ariss
 */
public class RadiusAuthSP extends AbstractAuthSP  // 20141201, Bauke: inherit goodies from AbstractAuthSP
{
	private static final long serialVersionUID = 1L;
	
	private final String MODULE = "RadiusAuthSP";
	
	private final String VERSION = "A-Select RADIUS AuthSP 2.0";
	
	//private String _sFailureHandling;
	//private String _sErrorHtmlTemplate;
	//private String _sAuthenticateHtmlTemplate;
	//private Properties _oErrorProperties;
	//private int _iAllowedRetries;
	//private Object _oAuthSPConfig;
	//private String _sConfigID;
	
	/**
	 * Initializes the Radius AuthSP. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The Radius AuthSP uses the following components from the A-Select AuthSP Server:
	 * <ul>
	 * <li>Retrieving the Crypto Engine from the servlet context.</li>
	 * <li>Reading the friendly_name and working_dir from the servlet Context.</li>
	 * <li>Loading the radius AuthSP Configuration from the AuthSP Server Config.</li>
	 * <li>Loading the authenticate.html and error.html Template files.</li>
	 * </ul>
	 * 
	 * @param servletConfig
	 *            the servlet config
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	public void init(ServletConfig servletConfig)
	throws ServletException
	{
		String sMethod = "init";

		try {
			super.init(servletConfig, true, Errors.ERROR_RADIUS_INTERNAL_ERROR);

			StringBuffer sbInfo = new StringBuffer("Starting: ").append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			// Load HTML templates
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "error.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "authenticate.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'authenticate.html' template.");

			// Get allowed retries
			_iAllowedRetries = Utils.getSimpleIntParam(_configManager, _systemLogger, _oAuthSpConfig, "allowed_retries", true);

			sbInfo = new StringBuffer("Successfully started ").append(VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", eAS);
			throw new ServletException("Could not initialize.", eAS);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize due to internal error", e);
			throw new ServletException("Could not initialize due to internal error.", e);
		}
	}

	/**
	 * Entrypoint for handling the A-Select Radius AuthSP protocol requests from the A-Select Server. <br>
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
	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ServletException, java.io.IOException
	{
		String sMethod = "doGet";
		PrintWriter pwOut = null;
		String sQueryString = "";
		String sLanguage = null;

		_systemLogger.log(Level.INFO, MODULE, sMethod, "servletRequest=" + servletRequest);
		try {
			sQueryString = servletRequest.getQueryString();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "query=" + sQueryString);
			HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, false);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htServiceRequest=" + htServiceRequest);

			sLanguage = (String) htServiceRequest.get("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;
			String sCountry = (String) htServiceRequest.get("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;

			servletResponse.setContentType("text/html; charset=utf-8");
			setDisableCachingHttpHeaders(servletRequest, servletResponse);
			pwOut = servletResponse.getWriter();

			String sMyUrl = servletRequest.getRequestURL().toString();
			htServiceRequest.put("my_url", sMyUrl);

			String sRid = (String) htServiceRequest.get("rid");
			String sAsUrl = (String) htServiceRequest.get("as_url");
			String sUid = (String) htServiceRequest.get("uid");
			String sAsId = (String) htServiceRequest.get("a-select-server");
			String sSignature = (String) htServiceRequest.get("signature");

			_systemLogger.log(Level.INFO, MODULE, sMethod, "uid=" + sUid);
			if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sAsId == null) || (sSignature == null)) {
				throw new ASelectException(Errors.ERROR_RADIUS_INVALID_REQUEST);
			}
			
			sAsUrl = URLDecoder.decode(sAsUrl, "UTF-8");
			sUid = URLDecoder.decode(sUid, "UTF-8");
			sSignature = URLDecoder.decode(sSignature, "UTF-8");

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

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Check signature:" + sbSignature);
			if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
				StringBuffer sbWarning = new StringBuffer("Invalid signature from A-Select Server '");
				sbWarning.append(sAsId);
				sbWarning.append("' for user: ");
				sbWarning.append(sUid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());

				throw new ASelectException(Errors.ERROR_RADIUS_INVALID_REQUEST);
			}

			if (RADIUSProtocolHandlerFactory.getContext(_oAuthSpConfig, sUid, _systemLogger) == null) {
				throw new ASelectException(Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER);
			}

			htServiceRequest.put("as_url", sAsUrl);
			htServiceRequest.put("uid", sUid);
			htServiceRequest.put("signature", sSignature);
			htServiceRequest.put("retry_counter", "1");
			if (sCountry != null)
				htServiceRequest.put("country", sCountry);
			if (sLanguage != null)
				htServiceRequest.put("language", sLanguage);

			showAuthenticateForm(pwOut, ""/*no error*/, htServiceRequest);
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
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER, sLanguage);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
		}
	}

	/**
	 * Private entry point of the Radius AuthSP. <br>
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
	protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ServletException, java.io.IOException
	{
		String sMethod = "doPost";
		PrintWriter pwOut = null;

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "servletRequest=" + servletRequest);
		String sLanguage = servletRequest.getParameter("language");  // optional language code
		if (sLanguage == null || sLanguage.trim().length() < 1)
			sLanguage = null;
		String sCountry = servletRequest.getParameter("country");  // optional country code
		if (sCountry == null || sCountry.trim().length() < 1)
			sCountry = null;
		
		try {
			pwOut = servletResponse.getWriter();
			servletResponse.setContentType("text/html; charset=utf-8");
			setDisableCachingHttpHeaders(servletRequest, servletResponse);

			String sMyUrl = servletRequest.getRequestURL().toString();
			String sRid = servletRequest.getParameter("rid");
			String sAsUrl = servletRequest.getParameter("as_url");
			String sUid = servletRequest.getParameter("uid");
			String sAsId = servletRequest.getParameter("a-select-server");
			String sPassword = servletRequest.getParameter("password");
			String sSignature = servletRequest.getParameter("signature");
			String sRetryCounter = servletRequest.getParameter("retry_counter");

			if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sPassword == null) || (sSignature == null)
					|| (sAsId == null)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid request received: one or more mandatory parameters missing.");
				throw new ASelectException(Errors.ERROR_RADIUS_INVALID_REQUEST);
			}
			
			sPassword = sPassword.trim();
			if (sPassword.length() < 1) {
				HashMap htServiceRequest = new HashMap();
				htServiceRequest.put("my_url", sMyUrl);
				htServiceRequest.put("rid", sRid);
				htServiceRequest.put("a-select-server", sAsId);
				htServiceRequest.put("as_url", sAsUrl);
				htServiceRequest.put("uid", sUid);
				htServiceRequest.put("signature", sSignature);
				htServiceRequest.put("retry_counter", sRetryCounter);
				if (sCountry != null)
					htServiceRequest.put("country", sCountry);
				if (sLanguage != null)
					htServiceRequest.put("language", sLanguage);

				showAuthenticateForm(pwOut, ""/*no error*/, htServiceRequest);
				return;
			}

			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sAsUrl);
			sbSignature.append(sUid);
			sbSignature.append(sAsId);
			if (sCountry != null)
				sbSignature.append(sCountry);
			if (sLanguage != null)
				sbSignature.append(sLanguage);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Check signature:" + sbSignature);
			if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
				StringBuffer sbWarning = new StringBuffer("Invalid signature from A-Select Server '");
				sbWarning.append(sAsId);
				sbWarning.append("' for user: ");
				sbWarning.append(sUid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
				throw new ASelectException(Errors.ERROR_RADIUS_INVALID_REQUEST);
			}

			int iRetriesDone = -1;
			try {
				iRetriesDone = Integer.parseInt(sRetryCounter);
			}
			catch (NumberFormatException e) // error parsing retry_counter
			{
				StringBuffer sbWarning = new StringBuffer("Invalid retry counter parameter in request '");
				sbWarning.append(sRetryCounter);
				sbWarning.append("' for user: ");
				sbWarning.append(sUid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString(), e);
				throw new ASelectException(Errors.ERROR_RADIUS_INVALID_REQUEST, e);
			}

			IRADIUSProtocolHandler protocolHandler = RADIUSProtocolHandlerFactory.
							instantiateProtocolHandler(_oAuthSpConfig, sUid, _systemLogger);
			if (protocolHandler == null) {
				throw new ASelectException(Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER);
			}
			String sResultCode = protocolHandler.authenticate(sPassword);
			if (sResultCode.equals(Errors.ERROR_RADIUS_ACCESS_DENIED)) {

				if (iRetriesDone < _iAllowedRetries) {
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

					showAuthenticateForm(pwOut, Errors.ERROR_RADIUS_ACCESS_DENIED, htServiceRequest);
					return;
				}
			}

			if (sResultCode.equals(Errors.ERROR_RADIUS_SUCCESS)) {
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "granted"
				});
			}
			else {
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "denied", sResultCode
				});
			}

			handleResult(servletRequest, servletResponse, pwOut, sResultCode, sLanguage);
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
		catch (Exception e) // internal error
		{
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER, sLanguage);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
		}
	}

	/**
	 * Determines whether or not the Radius AuthSP is restartable. <br>
	 * <br>
	 * 
	 * @return true, if checks if is restartable servlet
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	protected boolean isRestartableServlet()
	{
		// RM_19_01
		return false;
	}

	/**
	 * Outputs the HTML Authentication Form to the Client. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Fills the HTML Authentication Form Template with the correct values and outputs it to the Client. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param pwOutput
	 *            Output Writer
	 * @param sError
	 *            Ocurred Error Code
	 * @param sErrorMessage
	 *            Occured Error Message
	 * @param htServiceRequest
	 *            Incoming servlet request
	 * @throws ASelectException 
	 */
	private void showAuthenticateForm(PrintWriter pwOutput, String sError, HashMap htServiceRequest)
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

		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[rid]", sRid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[as_url]", sAsUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[uid]", sUid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[radius_server]", sMyUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[a-select-server]", sAsId);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[signature]", sSignature);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error]", sError);  // obsoleted 20100817
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_code]", sError);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_message]", sErrorMessage);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[language]", sLanguage);
		sAuthenticateForm = Utils.replaceConditional(sAuthenticateForm, "[if_error,", ",", "]", sErrorMessage != null && !sErrorMessage.equals(""), _systemLogger);
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

		pwOutput.println(sAuthenticateForm);
	}

	/**
	 * Sends the authentication result to the A-Select PKI AuthSP protocol handler by redirecting the user using HTTP
	 * GET. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            Incoming request
	 * @param servletResponse
	 *            Outgoing response
	 * @param pwOut
	 *            The output that is used, when error handling is local.
	 * @param sResultCode
	 *            The Result Code
	 * @throws IOException
	 *             If no output could be send to the client.
	 */
	private void handleResult(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut, String sResultCode, String sLanguage)
	throws IOException
	{
		String sMethod = "handleResult";

		StringBuffer sbTemp;
		try {
			if (_sFailureHandling.equalsIgnoreCase(DEFAULT_FAILUREHANDLING) || sResultCode.equals(Errors.ERROR_RADIUS_SUCCESS)) {
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
					sbTemp.append("&signature=").append(sSignature);
					sbTemp.append("&a-select-server=").append(sAsId);
					servletResponse.sendRedirect(sbTemp.toString());
				}
			}
			else {
				getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
			}
		}
		catch (ASelectException eAS) // could not generate signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate Radius AuthSP signature", eAS);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (UnsupportedEncodingException eUE) // could not encode signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode Radius AuthSP signature", eUE);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
	}
}