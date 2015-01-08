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
 * $Id: ASelectServer.java,v 1.52 2006/04/26 12:14:05 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectServer.java,v $
 * Revision 1.52  2006/04/26 12:14:05  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.51  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.50.4.8  2006/04/03 12:57:45  erwin
 * - Fixed error handling during initialization.
 * - Removed some warnings
 *
 * Revision 1.50.4.7  2006/03/16 10:31:35  leon
 * added authspHandlerManager init
 *
 * Revision 1.50.4.6  2006/02/28 08:26:44  jeroen
 * Bugfix for 126:
 * Created closeLoggers method where the handlers of the authenticationLogger and the systemLogger are closed. Method called in the catch of the init and used in the destroy method.
 *
 * Revision 1.50.4.5  2006/02/02 14:49:37  martijn
 * added javadoc
 *
 * Revision 1.50.4.4  2006/01/25 15:35:19  martijn
 * TGTManager rewritten
 *
 * Revision 1.50.4.3  2006/01/13 08:36:49  martijn
 * requesthandlers seperated from core
 *
 * Revision 1.50.4.2  2006/01/04 11:41:33  martijn
 * temporary commit
 *
 * Revision 1.50.4.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.50  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.49  2005/09/07 13:30:24  erwin
 * - Improved cleanup of the attribute gatherer (bug #93)
 * - Removed unnesserary HashMap in attribute gatherer (bug #94)
 *
 * Revision 1.48  2005/09/07 10:03:01  erwin
 * pwOut for the restart request is now closed.
 *
 * Revision 1.47  2005/09/07 09:38:09  erwin
 * Fixed problem with error handling working_dir (bug #82)
 *
 * Revision 1.46  2005/05/10 08:30:01  martijn
 * restart functionality has been made optional
 *
 * Revision 1.45  2005/04/15 11:51:23  tom
 * Removed old logging statements
 *
 * Revision 1.44  2005/04/08 12:41:12  martijn
 *
 * Revision 1.43  2005/04/01 14:27:15  peter
 * cross aselect redesign
 *
 * Revision 1.42  2005/03/30 12:54:58  erwin
 * Fixed problem with restarting Admin Monitor.
 *
 * Revision 1.41  2005/03/29 10:35:12  erwin
 * Added implementation of abstract method isRestartableServlet().
 *
 * Revision 1.40  2005/03/22 15:00:09  peter
 * added initialization of CrossASelectManager
 *
 * Revision 1.39  2005/03/21 07:50:31  tom
 * Fixed error handling
 *
 * Revision 1.38  2005/03/17 13:30:56  tom
 * Fixed Javadoc comment
 *
 * Revision 1.37  2005/03/16 13:00:14  martijn
 *
 * Revision 1.36  2005/03/16 11:15:50  erwin
 * Fixed configurable truststore:
 * There will not be a configuration item, because this is a
 * VM wide option and is otherwise set for all web contexts/applications.
 *
 * Revision 1.35  2005/03/16 08:21:19  tom
 * Moved RequestHandlerFactory to init()
 *
 * Revision 1.34  2005/03/15 09:23:53  erwin
 * Improved error handling with new handlers and fixed comment.
 *
 * Revision 1.33  2005/03/15 08:29:13  tom
 * - Redesign of request handling
 * - All handle and process function can now be found in requesthandler package
 *
 * Revision 1.32  2005/03/14 13:03:05  erwin
 * Fixed problems with Admin monitor.
 *
 * Revision 1.31  2005/03/11 15:05:00  erwin
 * Fixed bug with closing sam agent.
 *
 * Revision 1.30  2005/03/11 10:30:54  erwin
 * Improved error handling.
 *
 * Revision 1.29  2005/03/11 09:49:50  remco
 * ApplicationRequestHandler and ApplicationAPIRequestHandler are now merged
 *
 * Revision 1.28  2005/03/11 08:21:51  tom
 * Fixed javadoc typo
 * Added new Authentication Logger functionality
 * Changed error to result_code in issueErrorTGT
 *
 * Revision 1.27  2005/03/11 07:12:15  remco
 * "cancel" request -> "error" request
 *
 * Revision 1.26  2005/03/11 07:11:01  remco
 * "cancel" request -> "error" request
 *
 * Revision 1.25  2005/03/10 17:41:03  erwin
 * Improved error handling for init and process methods.
 *
 * Revision 1.24  2005/03/10 16:18:48  tom
 * Added new Authentication Logger
 *
 * Revision 1.23  2005/03/10 14:17:45  erwin
 * Improved Javadoc.
 *
 * Revision 1.22  2005/03/09 19:49:53  martijn
 * Bug fixed in ASelectServer.handleAuthSPResponse() : If the authsp response contains an error code, the session will now be killed.
 *
 * Revision 1.21  2005/03/09 17:33:34  remco
 * "cancel" request -> "error" request (with mandatory parameter "result_code")
 *
 * Revision 1.20  2005/03/09 17:08:54  remco
 * Fixed whole bunch of warnings
 *
 * Revision 1.19  2005/03/09 16:47:51  martijn
 * fixed bug: when user has pressed the logout button and lets his ticket expire: two errorpages were shown. A double check in handleLogoutRequest() is removed.
 *
 * Revision 1.18  2005/03/09 15:16:23  remco
 * there was some unfinished code in processAuthSPRequest() causing a double error message to be displayed
 *
 * Revision 1.17  2005/03/09 14:29:36  remco
 * removed invocation of deprecated method
 *
 * Revision 1.16  2005/03/09 09:24:50  erwin
 * Renamed and moved errors.
 *
 * Revision 1.15  2005/03/08 14:00:34  remco
 * javadoc added
 *
 * Revision 1.14  2005/03/08 12:58:18  remco
 * javadoc added
 *
 * Revision 1.3  2005/03/08 09:51:42  remco
 * added javadoc
 *
 * Revision 1.2  2005/03/07 08:19:26  remco
 * resolved bug
 *
 * Revision 1.1  2005/03/04 14:59:43  remco
 * Initial version
 *
 */

package org.aselect.server;

import java.io.File;
import java.io.IOException;
import java.util.Timer;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.admin.AdminMonitor;
import org.aselect.server.application.ApplicationManager;
import org.aselect.server.attributes.AttributeGatherer;
import org.aselect.server.authspprotocol.handler.AuthSPHandlerManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.RequestHandlerFactory;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.servlet.ASelectHttpServlet;

/**
 * This is the A-Select Server main class. It is responsible for <code>init()</code>ializing and <code>destroy()</code>
 * ing all A-Select Server components, and it serves as the entry point for incoming requests (via the
 * <code>service()</code> method). <br>
 * Requests are processed as follows:
 * <ul>
 * <li>If the server is currently restarting, a HTTP SERVICE UNAVAILABLE error is sent back to the client and no further
 * processing is performed.
 * <li>If a <code>request=restart</code> is present, it is handled and further processing is halted.
 * <li>Otherwise, the A-Select Server uses a {@link RequestHandlerFactory} to determine the type and origin
 * (application, authsp, remote a-select server, or the user) of the request and delegates further processing to the
 * appropriate IAuthnRequestHandler implementation.
 * </ul>
 * <br>
 * <br>
 * <b>Concurrency issues:</b> All methods invoked from the <code>service()</code> methods must be thread-safe. Most
 * request handling methods instantiate a new request-handling object per incoming request to avoid concurrency issues. <br>
 * <br>
 * 
 * @author Alfa & Ariss
 */
public class ASelectServer extends ASelectHttpServlet
{
	private static final long serialVersionUID = -2390043713278597255L;
	public final static String MODULE = "ASelectServer";
	private ASelectConfigManager _configManager;
	private SessionManager _sessionManager;
	private ApplicationManager _applicationManager;
	private AuthSPHandlerManager _authspHandlerManager;
	private CrossASelectManager _crossASelectManager;
	private ASelectAuthenticationLogger _authenticationLogger;
	private ASelectSystemLogger _systemLogger;
	private AttributeGatherer _oAttributeGatherer;
	private TGTManager _tgtManager;
	private CryptoEngine _cryptoEngine;
	private AdminMonitor _adminMonitor = null;
	private RequestHandlerFactory _oRequestHandlerFactory;
	private Timer _timerSensorThread = null;
	private String _sWorkingDir = null;
	private int _numRequests = 0;
	
	/**
	 * Initialize the A-Select Server. This method is invoked:
	 * <ul>
	 * <li>by Tomcat when the servlet is instantiated, or
	 * <li>by the A-Select Server itself when it restarts in response to a <code>request=restart</code>.
	 * </ul>
	 * The second case is actually a <b>re-</b>initialization, i.e. the servlet is no longer in its initial state and
	 * care must be taken not to allocate resources twice.
	 * 
	 * @param oServletConfig
	 *            the o servlet config
	 * @throws ServletException
	 *             the servlet exception
	 */
	@Override
	public void init(ServletConfig oServletConfig)
	throws ServletException
	{
		String sMethod = "init";
		// Initialize Configuration
		try {
			super.init(oServletConfig);

			// Create loggers
			if (_systemLogger != null) // restart
			{
				// close de filehandlers
				_systemLogger.closeHandlers();
			}
			else {
				// Create a System logger which logs to System.err
				// after initializing the configmanager, the systemlogger is
				// initialized and will log to the logfile
				_systemLogger = ASelectSystemLogger.getHandle();
			}

			if (_authenticationLogger != null) // reinit
				_authenticationLogger.closeHandlers();
			else
				_authenticationLogger = ASelectAuthenticationLogger.getHandle();

			String strWorkingDir = oServletConfig.getInitParameter("working_dir");
			if (strWorkingDir == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'working_dir' parameter from deployment descriptor.");
				throw new ASelectConfigException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
			if (!strWorkingDir.endsWith(File.separator)) {
				strWorkingDir += File.separator;
			}
			strWorkingDir += "aselectserver";
			_sWorkingDir = strWorkingDir;

			String sqlDriver = oServletConfig.getInitParameter("sql_driver");
			String sqlURL = oServletConfig.getInitParameter("sql_url");
			String sqlUser = oServletConfig.getInitParameter("sql_user");
			String sqlPassword = oServletConfig.getInitParameter("sql_password");
			String sqlTable = oServletConfig.getInitParameter("sql_table");

			_configManager = ASelectConfigManager.getHandle();
			_configManager.init(strWorkingDir, sqlDriver, sqlUser, sqlPassword, sqlURL, sqlTable, MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "INIT " + " T=" + System.currentTimeMillis() +
					", t="+Thread.currentThread().getId());
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", eAS);
			closeLoggers();
			throw new ServletException("Initializing failed");
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			closeLoggers();
			throw new ServletException("Initializing failed");
		}

		// Get default configuration sections
		Object _oASelectConfig = null;
		try {
			try {
				_oASelectConfig = _configManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not find aselect config section in config file", eAC);
				throw eAC;
			}

			Object oRequests = null;
			try {
				oRequests = _configManager.getSection(null, "requests");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'requests' found", e);
			}

			try {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "RequestHandlers...");
				_oRequestHandlerFactory = RequestHandlerFactory.getHandle();
				_oRequestHandlerFactory.init(oServletConfig, oRequests);
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Can't initialize RequestHandlerFactory", e);
				throw e;
			}

			// Initialize other components
			try {
				// Create and initialize our attribute gatherer object
				_systemLogger.log(Level.INFO, MODULE, sMethod, "AttributeGatherer...");
				_oAttributeGatherer = AttributeGatherer.getHandle();
				_oAttributeGatherer.init();
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Can't initialize AttributeGatherer", e);
				throw e;
			}

			try {
				_sessionManager = SessionManager.getHandle();
				_sessionManager.init();
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Can't initialize SessionManager", eAC);
				throw eAC;
			}

			try {
				_tgtManager = TGTManager.getHandle();
				_tgtManager.init();
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Can't initialize TicketManager", eAC);
				throw eAC;
			}

			try {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "ApplicationManager...");
				_applicationManager = ApplicationManager.getHandle();
				_applicationManager.init();
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Can't initialize ApplicationManager", eAC);
				throw eAC;
			}

			try {
				_crossASelectManager = CrossASelectManager.getHandle();
				_crossASelectManager.init();
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Can't initialize CrossASelectManager", eAC);
				throw eAC;
			}

			try {
				_authspHandlerManager = AuthSPHandlerManager.getHandle();
				_authspHandlerManager.init();
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Can't initialize AuthSPHandlerManager", eAC);
				throw eAC;
			}

			try {
				_cryptoEngine = CryptoEngine.getHandle();
				_cryptoEngine.init();
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Can't initialize CryptoEngine", eAC);
				throw eAC;
			}
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Start TimerSensor?");
			_timerSensorThread = ConfigManager.timerSensorStartThread(_configManager, _systemLogger, "aselect");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "TimerSensor thread="+_timerSensorThread);
			// Allow the ConfigManager to supply this Object to interested parties (i.e. AselectRestartRequestHandler
			_configManager.setMainServlet(this);
			
			try {
				String sTemp = _configManager.getParam(_oASelectConfig, "admin_gui");
				if (sTemp.equalsIgnoreCase("true")) {
					if (_adminMonitor == null) {
						_adminMonitor = new AdminMonitor();
						_adminMonitor.start(5);
					}
					else {
						_adminMonitor.stop();
						_adminMonitor.start(5);
					}
				}
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "admin_gui option not found in config file", eAC);
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Can't start AdminMonitor", e);
				throw e;
			}
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Successfully started A-Select server.");
		}
		catch (ASelectException eAS) {
			String sErrorMessage = _configManager.getErrorMessage(MODULE, eAS.getMessage(), ""/*language*/, "");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sErrorMessage, eAS);

			closeResources();
			closeLoggers();
			throw new ServletException(sErrorMessage);
		}
		catch (Exception e) {
			String sErrorMessage = _configManager.getErrorMessage(MODULE, Errors.ERROR_ASELECT_INTERNAL_ERROR, ""/*language*/, "");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sErrorMessage, e);

			closeResources();
			closeLoggers();
			throw new ServletException(sErrorMessage);
		}
	}

	/**
	 * Free resources, stop worker threads, and generally shutdown the A-Select Server. This method is invoked by Tomcat
	 * when the servlet is removed or Tomcat itself shuts down.
	 * 
	 * @see javax.servlet.Servlet#destroy()
	 */
	@Override
	public void destroy()
	{
		_systemLogger.log(Level.INFO, MODULE, "destroy", "DESTROY" + " T=" + System.currentTimeMillis() +
				", t="+Thread.currentThread().getId());
		_systemLogger.log(Level.INFO, MODULE, "destroy", "Stop server");
		closeResources();
		_systemLogger.log(Level.INFO, MODULE, "destroy", "A-Select server stopped.");
		closeLoggers();  // no more logging
		System.out.println("AselectServer Loggers closed");
		super.destroy();
		System.out.println("AselectServer Super destroyed");
	}

	/**
	 * Entry point for all incoming requests (GET and POST). <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method is responsible for the initial processing of all incoming requests. In most cases the
	 * <code>RequestHandlerFactory</code> is called to create the appropriate requesthandler. (see the
	 * <code>requesthandler</code> package for more information). <br>
	 * <br>
	 * 
	 * @param request
	 *            The <code>HttpServletRequest</code> object
	 * @param response
	 *            The <code>HttpServletResponse</code> object
	 * @throws ServletException
	 *             if processing went wrong
	 * @throws IOException
	 *             if no error could be sent to the HttpServletResponse
	 */
	@Override
	protected void service(HttpServletRequest request, HttpServletResponse response)
	throws ServletException, IOException
	{
		String sMethod = "service";
		try {
			// Prevent caching
			setDisableCachingHttpHeaders(request, response);

			// If we're currently restarting, then halt all processing
			if (isRestartInProgress()) {
				response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
				return;
			}
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "TimerSensor thread="+_timerSensorThread+" this="+this);

			_numRequests++;
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Entering SERVICE {" + " currentTimeMillis T="+System.currentTimeMillis()+", currentThreadId t="+Thread.currentThread().getId()+
					" nReq="+_numRequests+" "+request.getMethod() + " Query: "+request.getQueryString());
			//HandlerTools.logCookies(request, _systemLogger);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, request.getRemoteHost() + " / " + request.getRequestURL()
					+ " / " + request.getRemoteAddr());
			_oRequestHandlerFactory.process(request, response);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "} Exiting SERVICE" + " currentTimeMillis T=" + System.currentTimeMillis()+", currentThreadId t="+Thread.currentThread().getId()+ "\n====");
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "} Exiting SERVICE" + "  currentTimeMillis T=" + System.currentTimeMillis()
					+", currentThreadId t="+Thread.currentThread().getId()+" ASelectException while processing request: " + e + " commit="+response.isCommitted()+"\n====");
			if (!response.isCommitted()) {
				// send response if no headers have been written
				if (e.getMessage().equals(Errors.ERROR_ASELECT_INTERNAL_ERROR))
					response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);  // 500
				else
					response.sendError(HttpServletResponse.SC_BAD_REQUEST);  // 400
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "} Exiting SERVICE" + " currentTimeMillis T=" + System.currentTimeMillis()
					+", currentThreadId t="+Thread.currentThread().getId()+" Exception occurred: " + e +  " commit="+response.isCommitted()+"\n====");
			if (!response.isCommitted()) {
				// send response if no headers have been written
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}
		}
	}

	/**
	 * The A-Select server is restartable. <br>
	 * <br>
	 * 
	 * @return true, if checks if is restartable servlet
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	@Override
	protected boolean isRestartableServlet()
	{
		return true;
	}

	/**
	 * Close the admin monitor and other components .
	 */
	private void closeResources()
	{
		String sMethod = "closeResources";
		
		// stop the Gui if applicable
		if (_adminMonitor != null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Stop GUI"); 
			_adminMonitor.stop();
			try {
				_adminMonitor.dispose();
			}
			catch (Exception e) {
				// ignore interrupted errors while disposing
			}
		}
		// Stop attribute gatherer
		if (_oAttributeGatherer != null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Stop Gatherer"); 
			_oAttributeGatherer.destroy();
		}
		// Stop request handler factory
		if (_oRequestHandlerFactory != null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Stop Handlers"); 
			_oRequestHandlerFactory.destroy();
		}
		// Stop & destroy components that perform cleanup
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Stop SAM"); 
		ASelectSAMAgent.getHandle().destroy();
		if (_tgtManager != null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Stop TGT Manager"); 
			_tgtManager.destroy();
		}
		
		try { java.lang.Thread.sleep(1000);	} catch (InterruptedException e) {}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Stop Session Manager"); 
		_sessionManager.destroy();
		try { java.lang.Thread.sleep(1000);	} catch (InterruptedException e) {}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Stop Crypto"); 
		_cryptoEngine.stop();
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "TimerSensor thread="+_timerSensorThread+" nReq="+_numRequests);
		if (_timerSensorThread != null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Stop TimerSensor");
			ConfigManager.timerSensorStopThread(_timerSensorThread);
		}
		try { java.lang.Thread.sleep(1000);	} catch (InterruptedException e) {}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Resources closed");
	}

	/**
	 * Close the system logger and the authentication logger.
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
	
	/* (non-Javadoc)
	 * @see org.aselect.system.servlet.ASelectHttpServlet#mainServletFunction(java.lang.String)
	 */
	public int mainServletFunction(String sRequest)
	{	
		String sMethod = "mainServletFunction";
		if (!"reload_config".equals(sRequest))
			return -1;
		
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "TimerSensor thread="+_timerSensorThread);
			if (_timerSensorThread != null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Stop TimerSensor");
				ConfigManager.timerSensorStopThread(_timerSensorThread);
			}
			
			// Reload the configuration
			_configManager.loadConfiguration(_sWorkingDir, null, null, null, null, null, MODULE);
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Start TimerSensor?");
			_timerSensorThread = ConfigManager.timerSensorStartThread(_configManager, _systemLogger, "aselect");
		}
		catch (ASelectException e) {
			String sErrorMessage = _configManager.getErrorMessage(MODULE, e.getMessage(), ""/*language*/, "");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sErrorMessage, e);
		}
		return 0;
	}
}
