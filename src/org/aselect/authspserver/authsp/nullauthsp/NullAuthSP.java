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
 * $Id: NullAuthSP.java,v 1.24 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $Log: NullAuthSP.java,v $
 * Revision 1.24  2006/05/03 10:07:31  tom
 * Removed Javadoc version
 *
 * Revision 1.23  2006/04/12 13:29:35  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.22.2.1  2006/03/22 09:18:53  martijn
 * changed version to 1.5
 *
 * Revision 1.22  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.21  2005/04/01 14:18:40  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.20  2005/03/29 10:59:19  erwin
 * Removed redundant code; now extends ASelectHttpServlet and uses AuthSP configmanager functionality.
 *
 * Revision 1.19  2005/03/23 11:34:35  erwin
 * Fixed problem with nullpointer if errors are handled by A-Select.
 *
 * Revision 1.18  2005/03/23 09:51:10  erwin
 * Fixed problem with error handling missing config_id
 *
 * Revision 1.17  2005/03/18 15:31:07  martijn
 * logs if invalid request was sent
 *
 * Revision 1.16  2005/03/18 15:22:18  martijn
 * if invalid request, then show error page
 *
 * Revision 1.15  2005/03/16 11:18:05  martijn
 * removed version todo, version is set to default
 *
 * Revision 1.14  2005/03/14 09:58:02  martijn
 * config section renamed, new config used an init-param from web.xml to retrieve the config section
 *
 * Revision 1.13  2005/03/14 07:22:03  tom
 * Minor code style changes
 *
 * Revision 1.12  2005/03/11 15:28:18  erwin
 * Renamed loggers.
 *
 * Revision 1.11  2005/03/11 13:48:33  erwin
 * Improved error handling.
 *
 * Revision 1.10  2005/03/11 07:46:31  martijn
 * If succesfully loaded a Level.WARNING was logged. Now a Level.INFO will be logged.
 *
 * Revision 1.9  2005/03/10 16:17:10  tom
 * Added new Authentication Logger
 *
 * Revision 1.8  2005/03/10 08:16:02  tom
 * Added new Logger functionality
 *
 * Revision 1.7  2005/03/09 14:05:53  erwin
 * INFO -> SEVERE
 *
 * Revision 1.6  2005/03/09 14:02:14  tom
 * Added new logging and error handling
 *
 * Revision 1.5  2005/03/03 12:50:09  martijn
 * added javadoc / made compatible with A-Select 1.4.1
 *
 * Revision 1.4  2005/03/03 08:37:23  leon
 * exception x renamed to exception e
 *
 * Revision 1.3  2005/02/09 09:17:44  leon
 * added License
 * code restyle
 *
 */

package org.aselect.authspserver.authsp.nullauthsp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
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
import org.aselect.system.exception.ASelectException;
import org.aselect.system.servlet.ASelectHttpServlet;
import org.aselect.system.utils.Utils;

// TODO: Auto-generated Javadoc
/**
 * . <br>
 * Null AuthSP is an AuthSP used for testing <br>
 * <b>Description: </b> <br>
 * The Null AuthSP is a test AuthSP that uses his configuration tosend an access denied or access granted. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class NullAuthSP extends ASelectHttpServlet
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static String MODULE = "NullAuthSP";
	/**
	 * The Null AuthSP version string
	 */
	private static String VERSION = "A-Select Null AuthSP " + "1.9";

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

	/**
	 * Initialization of the Null AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The Null AuthSP uses the following components from the A-Select AuthSP Server<br>
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
	 * <i>workingdir/conf/nullauthsp/errors/errors.conf</i><br>
	 * - an error template file must exist:<br>
	 * <i>workingdir/conf/nullauthsp/html/error.html</i><br>
	 * - needs an 'authsp' config section with name='nullauthsp' in the configuration of the AuthSP Server <br>
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
		String sMethod = "init()";

		Object oAuthSPConfig = null;

		try {
			super.init(oServletConfig);

			_authenticationLogger = AuthSPAuthenticationLogger.getHandle();
			_systemLogger = AuthSPSystemLogger.getHandle();
			_configManager = AuthSPConfigManager.getHandle();

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
				oAuthSPConfig = _configManager.getSection(null, "authsp", "id=" + sConfigID);
			}
			catch (Exception e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No valid 'authsp' config section found with id='"
						+ sConfigID + "', using default setting: authenitcation mode = granted.");
			}

			String sAuthMode = null;
			try {
				sAuthMode = _configManager.getParam(oAuthSPConfig, "authentication_mode");
			}
			catch (Exception e) {
				sAuthMode = null;

				_systemLogger
						.log(Level.INFO, MODULE, sMethod,
								"No valid 'authentication_mode' config item found, using default: authenitcation mode = granted.");
			}
			if (sAuthMode == null)
				sAuthMode = "";

			if (sAuthMode.equalsIgnoreCase("denied"))
				_sAuthMode = Errors.ERROR_NULL_ACCESS_DENIED;
			else
				_sAuthMode = Errors.ERROR_NULL_SUCCESS;

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
		String sMethod = "doGet()";
		String sQueryString = "";
		String sLanguage = null;
		
		servletResponse.setContentType("text/html");
		setDisableCachingHttpHeaders(servletRequest, servletResponse);

		try {
			sQueryString = servletRequest.getQueryString();
			HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString);

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
			String sUid = (String) htServiceRequest.get("uid");
			String sAsId = (String) htServiceRequest.get("a-select-server");
			String sSignature = (String) htServiceRequest.get("signature");

			if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sAsId == null) || (sSignature == null)) {
				_systemLogger.log(Level.FINE, MODULE, sMethod,
						"Invalid request, at least one mandatory parameter is missing.");
				throw new ASelectException(Errors.ERROR_NULL_INVALID_REQUEST);
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "NULL GET {" + servletRequest + " --> " + sMethod + ": "
					+ sQueryString);


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

			if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
				throw new ASelectException(Errors.ERROR_NULL_INVALID_REQUEST);
			}

			if (_sAuthMode.equals(Errors.ERROR_NULL_SUCCESS)) {
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "granted"
				});
			}
			else {
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "denied"
				});
			}

			handleResult(servletRequest, servletResponse, _sAuthMode, sLanguage);
		}
		catch (ASelectException e) {
			handleResult(servletRequest, servletResponse, e.getMessage(), sLanguage);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);

			handleResult(servletRequest, servletResponse, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, sLanguage);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "} NULL GET");
	}

	/**
	 * Private entry point of the Null AuthSP. This will not be used, so always an error page will be shown. <br>
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

		_systemLogger.log(Level.INFO, MODULE, sMethod, "NULL POST {" + servletRequest + ", qry="
				+ servletRequest.getQueryString());
		String sLanguage = servletRequest.getParameter("language");
		if (sLanguage == null || sLanguage.trim().length() < 1) {
			sLanguage = null;
		}

		try {
			handleResult(servletRequest, servletResponse, Errors.ERROR_NULL_INVALID_REQUEST, sLanguage);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);

			throw new ServletException(Errors.ERROR_NULL_INTERNAL);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "} NULL POST");
	}

	/**
	 * Determines whether or not the NULL AuthSP is restartable. <br>
	 * <br>
	 * 
	 * @return true, if checks if is restartable servlet
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	@Override
	protected boolean isRestartableServlet()
	{
		// TODO Restart functionality has to be added (Erwin)
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
	private void handleResult(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
								String sResultCode, String sLanguage)
	throws IOException
	{
		String sMethod = "handleResult()";

		PrintWriter pwOut = null;
		try {
			pwOut = servletResponse.getWriter();
			if (sResultCode.equals(Errors.ERROR_NULL_SUCCESS)) {
				String sRid = servletRequest.getParameter("rid");
				String sAsUrl = servletRequest.getParameter("as_url");
				String sAsId = servletRequest.getParameter("a-select-server");
				if (sRid == null || sAsUrl == null || sAsId == null) {
					showErrorPage(pwOut, _sErrorHtmlTemplate, sResultCode, _configManager.getErrorMessage(sResultCode,
							_propErrorMessages), sLanguage);
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
				showErrorPage(pwOut, _sErrorHtmlTemplate, sResultCode, _configManager.getErrorMessage(sResultCode,
						_propErrorMessages), sLanguage);
			}
		}
		catch (ASelectException eAS) // could not generate signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate NULL AuthSP signature", eAS);
			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _configManager
					.getErrorMessage(Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _propErrorMessages), sLanguage);

		}
		catch (UnsupportedEncodingException eUE) // could not encode signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode NULL AuthSP signature", eUE);
			showErrorPage(pwOut, _sErrorHtmlTemplate, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _configManager
					.getErrorMessage(Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, _propErrorMessages), sLanguage);
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