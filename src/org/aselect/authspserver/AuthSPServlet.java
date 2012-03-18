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
 * $Id: AuthSPServlet.java,v 1.28 2006/05/03 10:08:49 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthSPServlet.java,v $
 * Revision 1.28  2006/05/03 10:08:49  tom
 * Removed Javadoc version
 *
 * Revision 1.27  2006/04/03 13:11:53  erwin
 * - Fixed error handling during initialization.
 *
 * Revision 1.26  2006/03/20 14:18:47  leon
 * SessionManager Added
 *
 * Revision 1.25  2006/02/28 08:21:17  leon
 * Fixed bug #127 closeHandlers in init.
 *
 * Revision 1.24  2005/09/08 12:47:54  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.23  2005/09/07 12:29:23  erwin
 * Implemented save restart functionality for the AuthSP Server (bug #89)
 *
 * Revision 1.22  2005/09/07 10:04:27  erwin
 * - Changed Dutch error message to English equivalent
 * - pwOut is now closed
 *
 * Revision 1.21  2005/09/07 09:39:45  erwin
 * Fixed problem with error handling working_dir (bug #83)
 *
 * Revision 1.20  2005/04/08 12:42:20  martijn
 * fixed todo's
 *
 * Revision 1.19  2005/03/29 10:36:48  erwin
 * Added implementation of abstract method isRestartableServlet().
 *
 * Revision 1.18  2005/03/16 12:56:42  martijn
 * changed todo
 *
 * Revision 1.17  2005/03/16 11:41:37  tom
 * Fixed Javadoc comment
 *
 * Revision 1.16  2005/03/11 13:27:07  erwin
 * Improved error handling.
 *
 * Revision 1.15  2005/03/10 17:18:10  martijn
 * moved reading of the system logger configuration to the right classes, so changed init() methods
 *
 * Revision 1.14  2005/03/10 12:44:13  martijn
 * moved the config retrieving from the ASelect component to the AuthenticationLogger: resulted in a new init() method in the AuthSPAuthenticationLogger class
 *
 * Revision 1.13  2005/03/09 09:23:54  erwin
 * Renamed and moved errors.
 *
 * Revision 1.12  2005/03/07 14:32:55  martijn
 * fixed typo in logging
 *
 * Revision 1.11  2005/03/04 16:28:41  martijn
 * ASelectAuthenticationLogger init call has been changed
 *
 * Revision 1.10  2005/03/01 14:54:03  martijn
 * fixed typo in javadoc
 *
 * Revision 1.9  2005/03/01 13:12:07  martijn
 * added directory config for initialization of system logger and authentication logger
 *
 * Revision 1.8  2005/02/24 15:17:20  martijn
 * added startup message
 *
 * Revision 1.7  2005/02/24 14:56:07  martijn
 * vars renamed to code convention
 *
 * Revision 1.6  2005/02/24 13:48:10  martijn
 * fixed minor logging faults
 *
 * Revision 1.5  2005/02/24 12:16:11  martijn
 * added java documentation and changed variable names
 *
 */

package org.aselect.authspserver;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.config.Version;
import org.aselect.authspserver.crypto.CryptoEngine;
import org.aselect.authspserver.log.AuthSPAuthenticationLogger;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.authspserver.sam.AuthSPSAMAgent;
import org.aselect.authspserver.session.AuthSPSessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.servlet.ASelectHttpServlet;

/**
 * The A-Select AuthSP Server. <br>
 * <br>
 * <b>Description: </b> <br>
 * Its function is to load shared A-Select AuthSP components in the servlet context. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public class AuthSPServlet extends ASelectHttpServlet
{
	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "AuthSPServlet";

	/**
	 * id for configuration located in a database table
	 */
	private final static String CONFIG_ID = "authspserver";

	/**
	 * If set to FALSE, this servlet isn't restartable.
	 */
	private boolean _bRestartable = false;

	/**
	 * The shared secret that is used to authorize the restart request
	 */
	private String _sMySharedSecret = null;

	/**
	 * Logger that is used for system logging
	 */
	private AuthSPSystemLogger _systemLogger = null;

	/**
	 * Logger that is used for authentication logging
	 */
	private AuthSPAuthenticationLogger _authenticationLogger = null;

	private AuthSPSessionManager _oAuthSPSessionManager = null;

	/**
	 * Initializes the A-Select AuthSP Server.
	 * <ul>
	 * <li>Loads config from database or file</li>
	 * <li>Creates a system logger</li>
	 * <li>Checks if their is enough config to make the servlet restartable.</li>
	 * <li>Puts CryptoEngine, friendly_name and working_dir into the servletcontext.</li>
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

		Object oAuthSPServerConfig = null;
		String sWorkingDir = null;

		try {
			super.init(oServletConfig);
			if (_systemLogger != null) // reinit
				_systemLogger.closeHandlers();
			else
				_systemLogger = AuthSPSystemLogger.getHandle();

			if (_authenticationLogger != null) // reinit
				_authenticationLogger.closeHandlers();
			else
				_authenticationLogger = AuthSPAuthenticationLogger.getHandle();

			// reading all parameters from the servlet context
			ServletContext oServletContext = oServletConfig.getServletContext();
			sWorkingDir = oServletConfig.getInitParameter("working_dir");
			if (sWorkingDir == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'working_dir' parameter from deployment descriptor.");
				throw new ASelectConfigException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			String sSqlDriver = oServletConfig.getInitParameter("sql_driver");
			String sSqlURL = oServletConfig.getInitParameter("sql_url");
			String sSqlUser = oServletConfig.getInitParameter("sql_user");
			String sSqlPassword = oServletConfig.getInitParameter("sql_password");
			String sSqlTable = oServletConfig.getInitParameter("sql_table");

			// prepare the working dir variable
			if (!sWorkingDir.endsWith(File.separator))
				sWorkingDir += File.separator;
			sWorkingDir += "authspserver";

			File fWorkingDir = new File(sWorkingDir);
			if (!fWorkingDir.exists()) {
				StringBuffer sbFailed = new StringBuffer("Could not access the working_dir as configured in web.xml: ");
				sbFailed.append(sWorkingDir);
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbFailed.toString());

				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			// initialize configmanager
			AuthSPConfigManager oAuthSPConfigManager = AuthSPConfigManager.getHandle();

			if (sSqlDriver != null || sSqlPassword != null || sSqlURL != null || sSqlTable != null) {
				StringBuffer sbInfo = new StringBuffer("Reading config from database: ");
				sbInfo.append(sSqlURL);
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString());

				oAuthSPConfigManager.init(sSqlDriver, sSqlUser, sSqlPassword, sSqlURL, sSqlTable, CONFIG_ID,
						_systemLogger);
			}
			else {
				StringBuffer sbConfigFile = new StringBuffer(sWorkingDir);
				sbConfigFile.append(File.separator);
				sbConfigFile.append("conf");
				sbConfigFile.append(File.separator);
				sbConfigFile.append("authsp.xml");

				File fConfigFile = new File(sbConfigFile.toString());
				if (!fConfigFile.exists()) {
					StringBuffer sbFailed = new StringBuffer("Could not access the config file: ");
					sbFailed.append(sbConfigFile);
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbFailed.toString());

					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}

				StringBuffer sbInfo = new StringBuffer("Reading config from file: ");
				sbInfo.append(sbConfigFile);
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString());

				oAuthSPConfigManager.init(sbConfigFile.toString(), _systemLogger);
			}

			try {
				oAuthSPServerConfig = oAuthSPConfigManager.getSection(null, "authspserver");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'authspserver' found", eAC);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}

			// initialize system logger
			Object oSysLogging = null;
			try {
				oSysLogging = oAuthSPConfigManager.getSection(oAuthSPServerConfig, "logging", "id=system");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'logging' config section with id='system' found", eAC);

				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
			_systemLogger.init(oSysLogging, sWorkingDir);

			StringBuffer sbInfo = new StringBuffer("Starting A-Select AuthSP Server ");
			sbInfo.append(Version.getVersion());
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			// initialize authentication logger
			Object oAuthLogging = null;
			try {
				oAuthLogging = oAuthSPConfigManager.getSection(oAuthSPServerConfig, "logging", "id=authentication");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'logging' config section with id='authentication' found", eAC);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
			_authenticationLogger.init(oAuthLogging, sWorkingDir);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully initialized AuthSPAuthenticationLogger.");

			try {
				_sMySharedSecret = oAuthSPConfigManager.getParam(oAuthSPServerConfig, "shared_secret");
				_bRestartable = (_sMySharedSecret != null);

				if (!_bRestartable) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Config item 'shared_secret' is empty");
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}
			}
			catch (Exception e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'shared_secret' configured, disabling servlet restart.");
				_bRestartable = false;
			}

			// Remove the instances, if their already is one.
			// For restarting purposes.
			if (oServletContext.getAttribute("CryptoEngine") != null) {
				oServletContext.removeAttribute("CryptoEngine");
			}

			if (oServletContext.getAttribute("friendly_name") != null) {
				oServletContext.removeAttribute("friendly_name");
			}

			if (oServletContext.getAttribute("SessionManager") != null) {
				oServletContext.removeAttribute("SessionManager");
			}

			String sFriendlyName = null;
			try {
				sFriendlyName = oAuthSPConfigManager.getParam(oAuthSPServerConfig, "organization_friendly_name");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, 
						"Could not retrieve 'organization_friendly_name' config parameter in authspserver config section", eAC);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}

			sFriendlyName = sFriendlyName.trim();

			CryptoEngine oCryptoEngine = new CryptoEngine(sWorkingDir, _systemLogger);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "CryptoEngine successfully initialized.");

			oServletContext.setAttribute("CryptoEngine", oCryptoEngine);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "The CryptoEngine is set to the servlet context.");

			oServletContext.setAttribute("working_dir", sWorkingDir);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "The working_dir is set to the servlet context.");

			oServletContext.setAttribute("friendly_name", sFriendlyName);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "The friendly_name is set to the servlet context.");

			// initializes the SAM Agent needed by the session manager configuration
			AuthSPSAMAgent.getHandle().init();

			_oAuthSPSessionManager = AuthSPSessionManager.getHandle();
			_oAuthSPSessionManager.init();
			oServletContext.setAttribute("SessionManager", _oAuthSPSessionManager);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "The SessionManager is set to the servlet context.");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "A-Select AuthSP Server is successfully initialized");
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", eAS);
			closeResources();
			closeLoggers();
			throw new ServletException("Initializing failed");
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			closeResources();
			closeLoggers();
			throw new ServletException("Initializing failed");
		}
	}

	/**
	 * Returns a short description of the servlet. <br>
	 * <br>
	 * 
	 * @return the servlet info
	 * @see javax.servlet.Servlet#getServletInfo()
	 */
	@Override
	public String getServletInfo()
	{
		return MODULE + " - loads AuthSP engine";
	}

	/**
	 * If the servlet is restartable, the request=restart is supported in the querystring. <br>
	 * <br>
	 * 
	 * @param oHttpServletRequest
	 *            the o http servlet request
	 * @param oHttpServletResponse
	 *            the o http servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public void doGet(HttpServletRequest oHttpServletRequest, HttpServletResponse oHttpServletResponse)
		throws ServletException
	{
		_systemLogger.log(Level.INFO, MODULE, "AUTHSP GET {", "" + _bRestartable);

		if (_bRestartable) {
			// turn off caching
			setDisableCachingHttpHeaders(oHttpServletRequest, oHttpServletResponse);

			// handle request=restart
			String sRequest = oHttpServletRequest.getParameter("request");
			if (sRequest != null) {
				_systemLogger.log(Level.INFO, MODULE, "GET ", "" + sRequest);

				PrintWriter pwOut = null;
				try {
					pwOut = oHttpServletResponse.getWriter();
					if (sRequest.equals("restart"))
						handleRestartRequest(oHttpServletRequest, _sMySharedSecret, pwOut, _systemLogger);
				}
				catch (IOException e) {
					throw new ServletException("Error sending response: " + e.getMessage());
				}
				finally {
					if (pwOut == null)
						pwOut.close();
				}
			}
		}
		_systemLogger.log(Level.INFO, MODULE, "} AUTHSP GET", "");
	}

	/**
	 * Destroys the servlet and closes the <code>SystemLogger</code> handlers. <br>
	 * <br>
	 * 
	 * @see javax.servlet.Servlet#destroy()
	 */
	@Override
	public void destroy()
	{
		closeResources();
		_systemLogger.log(Level.INFO, MODULE, "destroy()", "A-Select AuthSP Server stopped.");
		closeLoggers();
		System.out.println("AuthSPServlet Loggers closed");
		super.destroy();
		System.out.println("AuthSPServlet Super destroyed");
	}

	/**
	 * Closes the AuthSP Server resources. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Closes the SAM agent and session manager if they aren't closed already. <br>
	 * <br>
	 */
	private void closeResources()
	{
		AuthSPSAMAgent.getHandle().destroy();
		if (_oAuthSPSessionManager != null) {
			_oAuthSPSessionManager.destroy();
			_oAuthSPSessionManager = null;
		}
	}

	/**
	 * Closes the Logging Handlers. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Closes the System and Authentication Loggers if they aren't already. <br>
	 * <br>
	 */
	private void closeLoggers()
	{
		if (_authenticationLogger != null) {
			_authenticationLogger.closeHandlers();
			_authenticationLogger = null;
		}
		if (_systemLogger != null) {
			_systemLogger.closeHandlers();
			_systemLogger = null;
		}
	}

	/**
	 * The AuthSP server is not restartable by default. <br>
	 * <br>
	 * the AuthSP server will process the "request=restart" and will restart itself. After that the other restartable
	 * servlets in the context are restarted. <br>
	 * <br>
	 * This ensures that the AuthSP server is restarted before the AuthSP's.
	 * 
	 * @return true, if checks if is restartable servlet
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	@Override
	protected boolean isRestartableServlet()
	{
		return false;
	}

	/**
	 * First restarts this AuthSP Server and then the restartable servlets in the context.
	 * 
	 * @param logger
	 *            the logger
	 * @return true, if restart servlets
	 * @see org.aselect.system.servlet.ASelectHttpServlet#restartServlets(org.aselect.system.logging.SystemLogger)
	 */
	@Override
	protected synchronized boolean restartServlets(SystemLogger logger)
	{
		String sMethod = "restartServlets()";
		boolean bEndResult = true;

		try {
			StringBuffer sbResult = new StringBuffer("Restart: ");
			ServletConfig oConfig = getServletConfig();

			// Set restart attribute
			oConfig.getServletContext().setAttribute("restarting_servlets", "true");
			// Get other restartable Servlets
			HashMap htRestartServlets = (HashMap) oConfig.getServletContext().getAttribute("restartable_servlets");

			// restart the AuthSP Server itself
			try {
				this.init(oConfig);
			}
			catch (Exception eX) {
				bEndResult = false;
			}
			sbResult.append(MODULE).append(" (");
			sbResult.append(bEndResult ? "OK" : "Failed");
			sbResult.append(")");

			// restart the other restartable servlets.
			if (bEndResult && htRestartServlets != null) {
				boolean bResult = true;
				Set keys = htRestartServlets.keySet();
				for (Object s : keys) {
					String sKey = (String) s;
					// for (Enumeration e = htRestartServlets.keys(); e.hasMoreElements();)
					// {
					// String sKey = (String)e.nextElement();
					sbResult.append(", ");
					ASelectHttpServlet servlet = (ASelectHttpServlet) htRestartServlets.get(sKey);
					try {
						servlet.init(servlet.getServletConfig());
					}
					catch (Exception eX) {
						bResult = false;
					}
					bEndResult &= bResult;
					sbResult.append(sKey).append(" (");
					sbResult.append(bResult ? "OK" : "Failed");
					sbResult.append(")");
					// if (e.hasMoreElements())
					// sbResult.append(", ");
				}
			}
			logger.log(Level.INFO, MODULE, sMethod, sbResult.toString());
		}
		catch (Exception e) {
			if (logger != null)
				logger.log(Level.SEVERE, getModuleName(), sMethod, "Restarting servlets failed", e);
			else
				System.err.println(getModuleName() + " " + sMethod + e.getMessage());

			bEndResult = false;
		}
		this.getServletConfig().getServletContext().removeAttribute("restarting_servlets");
		return bEndResult;
	}

}