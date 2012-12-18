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
 * $Id: IPAuthSP.java,v 1.18 2006/05/03 10:06:47 tom Exp $ 
 *
 * Changelog:
 * $Log: IPAuthSP.java,v $
 * Revision 1.18  2006/05/03 10:06:47  tom
 * Removed Javadoc version
 *
 * Revision 1.17  2006/04/12 13:29:35  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.16.2.1  2006/03/22 09:18:53  martijn
 * changed version to 1.5
 *
 * Revision 1.16  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.15  2005/04/29 12:08:55  martijn
 * fixed bug in failure_handling logging
 *
 * Revision 1.14  2005/04/28 14:55:16  martijn
 * better logging if invalif failure handling type is configured
 *
 * Revision 1.13  2005/04/28 14:39:06  martijn
 * fixed bugs: invalid logging fixed / added more and better logging if configured ip addresses are incorrect
 *
 * Revision 1.12  2005/04/28 09:53:20  martijn
 * fixed bug in checkIP() wrong ip compare
 *
 * Revision 1.11  2005/04/28 09:37:24  martijn
 * changed logging
 *
 * Revision 1.10  2005/04/01 14:19:08  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.9  2005/03/30 09:59:22  erwin
 * Removed redundant code; now extends ASelectHttpServlet and uses AuthSP configmanager functionality.
 *
 * Revision 1.8  2005/03/29 13:02:32  martijn
 * added a default for the failure_handling config option if not configured
 *
 * Revision 1.7  2005/03/24 15:05:53  martijn
 * now showing error page when no parameter is supplied in the query string
 *
 * Revision 1.6  2005/03/24 14:54:27  martijn
 * fixed bug: unlimited while loop when retrieving ipranges from config
 *
 * Revision 1.5  2005/03/24 14:43:15  martijn
 * code restyle, javadoc and error handling
 *
 * Revision 1.4  2005/01/31 14:21:34  leon
 * License toevoegen
 *
 */
package org.aselect.authspserver.authsp.ip;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
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
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.servlet.ASelectHttpServlet;
import org.aselect.system.utils.Utils;


/**
 * A-Select IP AuthSP <br>
 * <br>
 * <b>Description:</b><br>
 * This Authentication Service Provider (AuthSP) handles authentication requests based on valid IP Ranges <br>
 * 
 * @author Alfa & Ariss
 */
public class IPAuthSP extends ASelectHttpServlet
{
	private final static String MODULE = "IPAuthSP";
	private final static String VERSION = "A-Select IP AuthSP " + "1.9";
	private final static String DEFAULT_FAILUREHANDLING = "aselect";

	private CryptoEngine _oCryptoEngine;
	private AuthSPAuthenticationLogger _oAuthSPAuthenticationLogger;
	private AuthSPSystemLogger _oAuthSPSystemLogger;
	private AuthSPConfigManager _oAuthSPConfigManager;

	private Properties _propErrorMessages;
	private HashMap _htIPRanges;

	private String _sWorkingDir;
	private String _sErrorHTMLTemplate;
	private String _sFailureHandling;
	private String _sFriendlyName;

	/**
	 * Initialization of the IP AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Performs the following steps to initialise the <code>IPAuthSP</code>:
	 * <ul>
	 * <li>Retrieve handles to managers and loggers</li>
	 * <li>Retrieve crypto engine from servlet context</li>
	 * <li>Retrieve friendly name from servlet context</li>
	 * <li>Retrieve working_dir from servlet context</li>
	 * <li>Retrieve config_id from web.xml</li>
	 * <li>Get all ip ranges from configuration</li>
	 * <li>Load error properties</li>
	 * <li>Load HTML templates</li>
	 * <li>Get failure handling from configuration</li>
	 * </ul>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The AuthSPServer must be succesfully started</li>
	 * <li>An error config file must exist</li>
	 * <li>An error template file must exist</li>
	 * <li>An IP 'authsp' config section must be available in the configuration of the AuthSP Server. The id of this
	 * section must be available as 'config_id' servlet init paramater.</li>
	 * </ul>
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
		String sMethod = "init()";
		Object oAuthSPConfig = null;
		try {
			super.init(oServletConfig);

			_oAuthSPSystemLogger = AuthSPSystemLogger.getHandle();
			_oAuthSPAuthenticationLogger = AuthSPAuthenticationLogger.getHandle();
			_oAuthSPConfigManager = AuthSPConfigManager.getHandle();

			// log start
			StringBuffer sbInfo = new StringBuffer("Starting : ");
			sbInfo.append(MODULE);
			_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			// Retrieve crypto engine from servlet context.
			ServletContext oContext = oServletConfig.getServletContext();
			_oCryptoEngine = (CryptoEngine) oContext.getAttribute("CryptoEngine");
			if (_oCryptoEngine == null) {
				_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, "No CryptoEngine found in servlet context.");
				throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR);
			}
			_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded CryptoEngine.");

			// Retrieve friendly name
			_sFriendlyName = (String) oContext.getAttribute("friendly_name");
			if (_sFriendlyName == null) {
				_oAuthSPSystemLogger
						.log(Level.WARNING, MODULE, sMethod, "No 'friendly_name' found in servlet context.");
				throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR);
			}
			_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'friendly_name'.");

			// Retrieve working directory
			_sWorkingDir = (String) oContext.getAttribute("working_dir");
			if (_sWorkingDir == null) {
				_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, "No working_dir found in servlet context.");
				throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR);
			}
			_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded working_dir");

			// Retrieve configuration
			String sConfigID = oServletConfig.getInitParameter("config_id");
			if (sConfigID == null) {
				_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'config_id' found as init-parameter in web.xml.");
				throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR);
			}

			try {
				oAuthSPConfig = _oAuthSPConfigManager.getSection(null, "authsp", "id=" + sConfigID);
			}
			catch (ASelectConfigException e) {
				StringBuffer sbError = new StringBuffer("No valid 'authsp' config section found with id='");
				sbError.append(sConfigID);
				_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
				throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR, e);
			}

			_htIPRanges = new HashMap();
			Object oIPRanges = null;
			try {
				oIPRanges = _oAuthSPConfigManager.getSection(oAuthSPConfig, "ipranges");
			}
			catch (ASelectConfigException e) {
				_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'ipranges' config section found", e);
				throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR, e);
			}

			Object oIPRange = null;
			try {
				oIPRange = _oAuthSPConfigManager.getSection(oIPRanges, "iprange");
			}
			catch (ASelectConfigException e) {
				_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"Not even one valid 'iprange' config item found", e);
				throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR, e);
			}

			while (oIPRange != null) {
				String sID = null;
				try {
					sID = _oAuthSPConfigManager.getParam(oIPRange, "id");
				}
				catch (ASelectConfigException e) {
					_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'id' config item found", e);
					throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR, e);
				}

				String sBegin = null;
				try {
					sBegin = _oAuthSPConfigManager.getParam(oIPRange, "begin");
				}
				catch (ASelectConfigException e) {
					_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'begin' config item found", e);
					throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR, e);
				}

				String sEnd = null;
				try {
					sEnd = _oAuthSPConfigManager.getParam(oIPRange, "end");
				}
				catch (ASelectConfigException e) {
					_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'end' config item found", e);
					throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR, e);
				}

				_htIPRanges.put(sID + ".begin", sBegin.trim());
				_htIPRanges.put(sID + ".end", sEnd.trim());

				oIPRange = _oAuthSPConfigManager.getNextSection(oIPRange);
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
				_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString());
				throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR);
			}
			_propErrorMessages = new Properties();
			_propErrorMessages.load(new FileInputStream(sbErrorsConfig.toString()));
			sbInfo = new StringBuffer("Successfully loaded ");
			sbInfo.append(_propErrorMessages.size());
			sbInfo.append(" error messages from: \"");
			sbInfo.append(sbErrorsConfig.toString()).append("\".");
			_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			// Load HTML template
			_sErrorHTMLTemplate = _oAuthSPConfigManager.loadHTMLTemplate(_sWorkingDir, "error.html", sConfigID,
					_sFriendlyName, VERSION);
			_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");

			// get failure handling
			try {
				_sFailureHandling = _oAuthSPConfigManager.getParam(oAuthSPConfig, "failure_handling");
			}
			catch (ASelectConfigException e) {
				_sFailureHandling = DEFAULT_FAILUREHANDLING;
				_oAuthSPSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No 'failure_handling' parameter found in configuration, using default: aselect");
			}

			if (!_sFailureHandling.equalsIgnoreCase("aselect") && !_sFailureHandling.equalsIgnoreCase("local")) {
				StringBuffer sbWarning = new StringBuffer(
						"Invalid 'failure_handling' parameter found in configuration: '");
				sbWarning.append(_sFailureHandling);
				sbWarning.append("', using default: aselect");

				_sFailureHandling = DEFAULT_FAILUREHANDLING;

				_oAuthSPSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbWarning.toString());
			}

			sbInfo = new StringBuffer("Successfully started ");
			sbInfo.append(VERSION).append(".");
			_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		catch (Exception e) {
			_oAuthSPSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			throw new ServletException("Initializing failed");
		}
	}

	/**
	 * Process requests for the HTTP <code>GET</code> method. <br>
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
		String sMethod = "doGet()";
		PrintWriter pwOut = null;
		String sQueryString = "";
		String sLanguage = null;

		try {
			HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, false);
			sLanguage = (String) htServiceRequest.get("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;
			String sCountry = (String) htServiceRequest.get("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;
			
			servletResponse.setContentType("text/html");
			setDisableCachingHttpHeaders(servletRequest, servletResponse);
			pwOut = servletResponse.getWriter();
			sQueryString = servletRequest.getQueryString();

			String sMyUrl = servletRequest.getRequestURL().toString();
			htServiceRequest.put("my_url", sMyUrl);

			String sRid = (String) htServiceRequest.get("rid");
			String sUid = (String) htServiceRequest.get("uid");
			String sAsUrl = (String) htServiceRequest.get("as_url");
			String sIpRange = (String) htServiceRequest.get("ip_range1");
			String sAsId = (String) htServiceRequest.get("a-select-server");
			String sSignature = (String) htServiceRequest.get("signature");

			if ((sRid == null) || (sUid == null) || (sIpRange == null) || (sAsUrl == null) || (sAsId == null)
					|| (sSignature == null)) {
				_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid request received: one or more mandatory parameters missing.");
				throw new ASelectException(Errors.ERROR_IP_INVALID_REQUEST);
			}

			_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, "IP GET {" + servletRequest + ", sQueryString="
					+ sQueryString);

			StringBuffer sbIpRangesData = new StringBuffer();
			int i = 1;
			while (sIpRange != null) {
				sbIpRangesData.append(sIpRange);

				// get next ip range
				i++;
				sIpRange = (String) htServiceRequest.get("ip_range" + i);
			}

			sAsUrl = URLDecoder.decode(sAsUrl, "UTF-8");
			sUid = URLDecoder.decode(sUid, "UTF-8");
			sSignature = URLDecoder.decode(sSignature, "UTF-8");

			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sUid);
			sbSignature.append(sAsUrl);
			sbSignature.append(sbIpRangesData.toString());
			sbSignature.append(sAsId);

			// optional country code
			if (sCountry != null)
				sbSignature.append(sCountry);

			// optional language code
			if (sLanguage != null)
				sbSignature.append(sLanguage);

			if (!_oCryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
				throw new ASelectException(Errors.ERROR_IP_INVALID_REQUEST);
			}

			String sResultCode = checkIP(htServiceRequest, servletRequest.getRemoteAddr());
			if (!sResultCode.equals(Errors.ERROR_IP_SUCCESS)) {
				// authenticate failed
				_oAuthSPAuthenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "denied", sResultCode
				});
			}
			else {
				// Authentication successful
				_oAuthSPAuthenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "granted"
				});
			}

			handleResult(servletRequest, servletResponse, pwOut, sResultCode, sLanguage);
		}
		catch (ASelectException e) {
			_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", e);

			handleResult(servletRequest, servletResponse, pwOut, e.getMessage(), sLanguage);
		}
		catch (Exception e) {
			_oAuthSPSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error",
					e);

			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_IP_COULD_NOT_AUTHENTICATE_USER, sLanguage);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
		}
		_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, "} IP GET");
	}

	/**
	 * Determines whether or not the IP AuthsP is restartable. <br>
	 * <br>
	 * 
	 * @return true, if checks if is restartable servlet
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	@Override
	protected boolean isRestartableServlet()
	{
		// RM_16_01
		return false;
	}

	/**
	 * Method to check if the user's IP address falls in the ranges specified by the A-Select Server. <br>
	 * <br>
	 * 
	 * @param htIpRanges
	 *            the ht ip ranges
	 * @param sIpClient
	 *            the s ip client
	 * @return an error code or ERROR_IP_SUCCESS
	 */
	private String checkIP(HashMap htIpRanges, String sIpClient)
	{
		String sMethod = "checkIP()";

		String sBeginIpRange;
		String sEndIpRange;
		InetAddress oIpRangeBegin;
		InetAddress oIpRangeEnd;
		InetAddress oIpClient;
		byte[] bIpRangeBegin;
		byte[] bIpRangeEnd;
		byte[] bIpClient;
		BigInteger biIpRangeBegin;
		BigInteger biIpRangeEnd;
		BigInteger biIpClient;

		try {
			int i = 1;
			while (true) {
				String sIpRange = (String) htIpRanges.get("ip_range" + i++);
				if (sIpRange == null)
					return Errors.ERROR_IP_ACCESS_DENIED;

				sBeginIpRange = (String) _htIPRanges.get(sIpRange + ".begin");
				sEndIpRange = (String) _htIPRanges.get(sIpRange + ".end");
				if ((sBeginIpRange == null) || (sEndIpRange == null)) {
					StringBuffer sbError = new StringBuffer("ip range not configured: ");
					sbError.append(sIpRange);
					_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
					return Errors.ERROR_IP_COULD_NOT_AUTHENTICATE_USER;
				}

				try {
					oIpRangeBegin = InetAddress.getByName(sBeginIpRange);
				}
				catch (Exception e) {
					StringBuffer sbWarning = new StringBuffer("Configured 'begin' address isn't a valid ip address: ");
					sbWarning.append(sBeginIpRange);
					_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString(), e);

					throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR, e);
				}

				try {
					oIpRangeEnd = InetAddress.getByName(sEndIpRange);
				}
				catch (Exception e) {
					StringBuffer sbWarning = new StringBuffer("Configured 'end' address isn't a valid ip address: ");
					sbWarning.append(sEndIpRange);
					_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString(), e);

					throw new ASelectException(Errors.ERROR_IP_INTERNAL_ERROR, e);
				}

				oIpClient = InetAddress.getByName(sIpClient);

				bIpRangeBegin = oIpRangeBegin.getAddress();
				bIpRangeEnd = oIpRangeEnd.getAddress();
				bIpClient = oIpClient.getAddress();

				biIpRangeBegin = new BigInteger(1, bIpRangeBegin);
				biIpRangeEnd = new BigInteger(1, bIpRangeEnd);
				biIpClient = new BigInteger(1, bIpClient);

				// check if client ip is smaller than begin ip of allowed range
				if (biIpClient.compareTo(biIpRangeBegin) < 0) {
					continue;
				}

				// check if client ip is greater than end ip op allowed range
				if (biIpClient.compareTo(biIpRangeEnd) > 0) {
					continue;
				}
				// client ip is in registered ip range!
				return Errors.ERROR_IP_SUCCESS;
			}
		}
		catch (ASelectException e) {
			_oAuthSPSystemLogger.log(Level.SEVERE, MODULE, sMethod, "could not perform ip check", e);
		}
		catch (Exception e) {
			_oAuthSPSystemLogger.log(Level.SEVERE, MODULE, sMethod, "internal error during ip check", e);
		}
		return Errors.ERROR_IP_ACCESS_DENIED;
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
	 * @throws IOException
	 *             If no output could be send to the client.
	 */
	private void handleResult(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut, String sResultCode, String sLanguage)
	throws IOException
	{
		String sMethod = "handleResult()";

		try {
			if (_sFailureHandling.equalsIgnoreCase("aselect") || sResultCode.equals(Errors.ERROR_IP_SUCCESS)) {
				String sRid = servletRequest.getParameter("rid");
				String sAsUrl = servletRequest.getParameter("as_url");
				if (sRid == null || sAsUrl == null) {
					// RH, 20100621, Remove cyclic dependency system<->server
					showErrorPage(pwOut, _sErrorHTMLTemplate, sResultCode, _oAuthSPConfigManager.getErrorMessage(
//							sResultCode, _propErrorMessages), sLanguage);
							sResultCode, _propErrorMessages), sLanguage, _oAuthSPSystemLogger);
					
				}
				else {
					StringBuffer sbSignature = new StringBuffer(sRid);
					sbSignature.append(sAsUrl);
					sbSignature.append(sResultCode);
					String sSignature = _oCryptoEngine.generateSignature(sbSignature.toString());
					if (sSignature != null) {
						sSignature = URLEncoder.encode(sSignature, "UTF-8");

						StringBuffer sbRedirect = new StringBuffer(sAsUrl);
						sbRedirect.append("&rid=").append(sRid);
						sbRedirect.append("&result_code=").append(sResultCode);
						sbRedirect.append("&signature=").append(sSignature);

						_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, "REDIR " + sbRedirect);

						servletResponse.sendRedirect(sbRedirect.toString());
					}
				}
			}
			else // Local error handling
			{
				// RH, 20100621, Remove cyclic dependency system<->server
				showErrorPage(pwOut, _sErrorHTMLTemplate, sResultCode, _oAuthSPConfigManager.getErrorMessage(
//						sResultCode, _propErrorMessages), sLanguage);
						sResultCode, _propErrorMessages), sLanguage, _oAuthSPSystemLogger);
			}
		}
		catch (ASelectException e) // could not generate signature
		{
			_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate IP AuthSP signature", e);
			String sErrorMessage = _oAuthSPConfigManager.getErrorMessage(Errors.ERROR_IP_COULD_NOT_AUTHENTICATE_USER,
					_propErrorMessages);
			// RH, 20100621, Remove cyclic dependency system<->server
//			showErrorPage(pwOut, _sErrorHTMLTemplate, Errors.ERROR_IP_COULD_NOT_AUTHENTICATE_USER, sErrorMessage, sLanguage);
			showErrorPage(pwOut, _sErrorHTMLTemplate, Errors.ERROR_IP_COULD_NOT_AUTHENTICATE_USER, sErrorMessage, sLanguage, _oAuthSPSystemLogger);
		}
		catch (UnsupportedEncodingException e) // could not encode signature
		{
			_oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode IP AuthSP signature", e);
			String sErrorMessage = _oAuthSPConfigManager.getErrorMessage(Errors.ERROR_IP_COULD_NOT_AUTHENTICATE_USER,
					_propErrorMessages);
			// RH, 20100621, Remove cyclic dependency system<->server
//			showErrorPage(pwOut, _sErrorHTMLTemplate, Errors.ERROR_IP_COULD_NOT_AUTHENTICATE_USER, sErrorMessage, sLanguage);
			showErrorPage(pwOut, _sErrorHTMLTemplate, Errors.ERROR_IP_COULD_NOT_AUTHENTICATE_USER, sErrorMessage, sLanguage, _oAuthSPSystemLogger);
		}
	}
}