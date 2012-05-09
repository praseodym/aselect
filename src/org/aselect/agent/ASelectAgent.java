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
 * $Id: ASelectAgent.java,v 1.31 2006/05/04 10:04:53 martijn Exp $ 
 * 
 * Changelog:
 * $Log: ASelectAgent.java,v $
 * Revision 1.31  2006/05/04 10:04:53  martijn
 * invalid truststore config item logging changed
 *
 * Revision 1.30  2006/05/04 09:51:14  martijn
 * invalid truststore config item logging changed
 *
 * Revision 1.29  2006/05/03 09:27:29  martijn
 * increased version to 1.5
 *
 * Revision 1.28  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.27  2006/04/03 11:34:45  erwin
 * Added destroy logging
 *
 * Revision 1.26  2006/03/22 09:05:03  martijn
 * changed version to 1.5 RC2
 *
 * Revision 1.25  2006/03/14 15:10:53  martijn
 * changed release to 1.5 RC1a
 *
 * Revision 1.24  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.23  2005/09/07 10:09:04  erwin
 * Changed admin port logging. (bug #86)
 *
 * Revision 1.22  2005/08/30 08:14:40  erwin
 * Added Authorization functionality to the Agent
 *
 * Revision 1.21  2005/05/04 09:08:53  peter
 * trustStore system property was set too late
 *
 * Revision 1.20  2005/04/27 13:47:58  martijn
 * fixed bugs: correct error handling when serviceport or adminport is wrongly configured; correct logging if default communicator will be used
 *
 * Revision 1.19  2005/04/14 16:22:01  tom
 * Removed old logging statements
 *
 * Revision 1.18  2005/04/08 12:40:34  martijn
 * fixed todo's
 *
 * Revision 1.17  2005/04/04 12:27:01  erwin
 * Added todo for AdminServiceHandler response.
 *
 * Revision 1.16  2005/03/30 08:39:02  erwin
 * Improved Javdoc.
 *
 * Revision 1.15  2005/03/16 11:10:35  erwin
 * Fixed problem with agent destroy in NT service mode.
 *
 * Revision 1.14  2005/03/10 17:02:43  martijn
 * moved reading of the system logger configuration to the right classes, so changed init() methods
 *
 * Revision 1.13  2005/03/09 17:10:22  remco
 * fixed compiler warnings
 *
 * Revision 1.12  2005/03/09 12:09:59  remco
 * added preliminary signing
 *
 * Revision 1.11  2005/03/09 09:20:38  erwin
 * Renamed errors.
 *
 * Revision 1.10  2005/03/08 14:33:38  erwin
 * keystore -> truststore
 *
 * Revision 1.9  2005/03/08 13:41:05  erwin
 * Added truststore parameter in configuration/init.
 *
 * Revision 1.8  2005/03/07 14:43:24  erwin
 * asp -> authsp in requests and admin monitor.
 *
 * Revision 1.7  2005/03/03 17:24:19  erwin
 * Applied code style, added javadoc comment.
 *
 * Revision 1.6  2005/03/02 15:15:07  martijn
 * added directory config for initialization of system logger
 *
 * Revision 1.5  2005/03/01 12:58:27  erwin
 * Improved closing of ServerSocket.
 *
 * Revision 1.4  2005/03/01 08:34:50  erwin
 * Removed args[] in constructor.
 *
 * Revision 1.3  2005/02/25 15:51:33  erwin
 * Improved logging.
 *
 * Revision 1.2  2005/02/24 15:09:09  ali
 * Added IAgentEventListener class and updates internal Javadoc.
 * 
 */

package org.aselect.agent;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Timer;
import java.util.logging.Level;

import org.aselect.agent.admin.AdminMonitor;
import org.aselect.agent.authorization.AuthorizationEngine;
import org.aselect.agent.config.ASelectAgentConfigManager;
import org.aselect.agent.handler.RequestHandler;
import org.aselect.agent.handler.TraceRequestHandler;
import org.aselect.agent.log.ASelectAgentSystemLogger;
import org.aselect.agent.sam.ASelectAgentSAMAgent;
import org.aselect.agent.session.SessionManager;
import org.aselect.agent.ticket.TicketManager;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.communication.client.soap11.SOAP11Communicator;
import org.aselect.system.communication.client.soap12.SOAP12Communicator;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.storagemanager.SendQueue;
import org.aselect.system.storagemanager.SendQueueSender;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;

/**
 * A-Select Agent Main Class. <br>
 * <br>
 * <b>Description: </b> <br>
 * The A-Select Agent is a lightweight server that offers a convenient API for applications to make use of the services
 * of multiple A-Select Servers. <br>
 * <br>
 * The A-Select Agent also offers advanced session management that applications may use. The A-Select Agent only accepts
 * connections from applications that run on the same host. <br>
 * <br>
 * Currently, the A-Select Agent supports the following API requests:
 * <ul>
 * <li><code>authenticate</code></li>
 * <li><code>cross_authenticate</code></li>
 * <li><code>verify_credentials</code></li>
 * <li><code>verify_ticket</code></li>
 * <li><code>kill_ticket</code></li>
 * </ul>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * None.<br>
 * 
 * @author Alfa & Ariss
 */
public class ASelectAgent
{
	/**
	 * Module string.
	 */
	public final static String MODULE = "ASelectAgent";
	/**
	 * Version string.
	 */
	public final static String VERSION = "1.9";

	/**
	 * Port number of A-Select Agent for receiving API requests.
	 */
	private int _servicePort;

	/**
	 * Port number of A-Select Agent for receiving admin requests.
	 */
	private int _adminPort;

	/**
	 * Boolean whether A-Select Agent is active.
	 */
	private boolean _bActive;
	/**
	 * Boolean whether to use the GUI A-Select monitor.
	 */
	private boolean _bGui;

	/**
	 * Handle to GUI A-Select monitor.
	 */
	private AdminMonitor _adminMonitor;
	/**
	 * Handle to system logger.
	 */
	private ASelectAgentSystemLogger _oASelectAgentSystemLogger;
	private ASelectAgentConfigManager _oASelectAgentConfigManager;

	// TimerSensor dispatch
	private int _iBatchPeriod = -1;
	Timer _timerSensorThread = null;	
	
	/**
	 * The agent configuration section.
	 */
	private Object _oAgentSection;

	/**
	 * The working directory.
	 */
	private String _sWorkingDir = null;

	/**
	 * Socket that A-Select Agent listens on for admin requests.
	 */
	private ServerSocket _oAdminSocket;

	/**
	 * Socket that A-Select Agent listens on for API requests.
	 */
	private ServerSocket _oServiceSocket;

	/**
	 * The communicator for server requests.
	 */
	private IClientCommunicator _oCommunicator;

	/**
	 * The service handler thread.
	 */
	private Thread _tServiceHandler;

	/**
	 * <code>true</code> if Authorization is enabled.
	 */
	private boolean _bAuthorization = false;

	/**
	 * Main entry point for starting the Agent in console mode. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The main function instantiates an A-Select Agent and lets it start. It does this by calling the
	 * <code>init()</code> method and then the <code>startServices()</code> method. <br>
	 * <br>
	 * If the A-Select Agent cannot start, a <code>System.exit(1)</code> is returned. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param saArgs
	 *            Command line parameters; currently not used.
	 */
	public static void main(String[] saArgs)
	{
		String sMethod = "main()";
		ASelectAgentSystemLogger oASelectAgentSystemLogger = ASelectAgentSystemLogger.getHandle();
		ASelectAgent oASelectAgent = null;
       
		StringBuffer sbInfo = new StringBuffer(MODULE);
		sbInfo.append(" ").append(VERSION);
		try {
			oASelectAgent = new ASelectAgent();
			oASelectAgent.init();
			oASelectAgent.startServices();

			sbInfo.append(" succesfully started.");
			//for (int i=0; i<10; i++) {
			//	oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod,
			//			"nano="+Long.toString(System.nanoTime())+" usi="+Tools.generateUniqueSensorId());
			//}
			
			System.out.println(sbInfo.toString());
			oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		catch (Exception e) {
			sbInfo.append(" failed to start.");
			System.out.println(sbInfo.toString());

			oASelectAgentSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to start ASelectAgent", e);

			if (oASelectAgent != null)
				oASelectAgent.destroy();

			System.exit(1);
		}
	}

	/**
	 * Constructor for the A-Select Agent class.
	 */
	public ASelectAgent() {
	}

	/**
	 * Initializes the A-Select Agent. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The A-Select Agent initializes itself by reading its configuration, getting the handles to essential objects and
	 * initializing the logging system. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @throws ASelectException
	 *             if initialization was unsuccessful.
	 */
	public void init()
		throws ASelectException
	{
		String sMethod = "init()";
		try {
			// create logger
			_oASelectAgentSystemLogger = ASelectAgentSystemLogger.getHandle();

			// get handle to the ASelectAgentConfigManager and initialize it
			_oASelectAgentConfigManager = ASelectAgentConfigManager.getHandle();

			_sWorkingDir = System.getProperty("user.dir");
			_oASelectAgentConfigManager.init(_sWorkingDir);
			_oAgentSection = _oASelectAgentConfigManager.getSection(null, "agent");

			// System properties must be set first!
			// retrieve truststore configuration
			try {
				String sKeystoreFile = _oASelectAgentConfigManager.getParam(_oAgentSection, "truststore");
				System.setProperty("javax.net.ssl.trustStore", sKeystoreFile);
			}
			catch (ASelectConfigException eAC) {
				_oASelectAgentSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Missing or invalid optional config item 'truststore', using default keystore", eAC);
			}

			// initialize system logger
			Object oSysLogging = null;
			try {
				oSysLogging = _oASelectAgentConfigManager.getSection(_oAgentSection, "logging", "id=system");
			}
			catch (Exception e) {
				_oASelectAgentSystemLogger.log(Level.SEVERE, MODULE, sMethod,
						"No valid 'logging' config section with id='system' found.", e);

				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			_oASelectAgentSystemLogger.init(oSysLogging, _sWorkingDir);
			_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, "Starting A-Select Agent");

			// initialize SAMAgent
			ASelectAgentSAMAgent _samAgent = ASelectAgentSAMAgent.getHandle();
			_samAgent.init();

			// initialize the ticket and session managers
			if (!TicketManager.getHandle().init())
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);

			if (!SessionManager.getHandle().init())
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);

			// initialize the Authorization engine
			Object oAuthorizationSection = null;
			try {
				oAuthorizationSection = _oASelectAgentConfigManager.getSection(_oAgentSection, "authorization");
				_bAuthorization = true;
			}
			catch (Exception e) {
				_oASelectAgentSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid 'authorization' config section found, authorization is disabled.");
				_bAuthorization = false;
			}

			if (_bAuthorization) {
				AuthorizationEngine oAuthorizationEngine = AuthorizationEngine.getHandle();
				if (!oAuthorizationEngine.init(oAuthorizationSection, _oASelectAgentConfigManager,
						_oASelectAgentSystemLogger))
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			// read the service portnumbers from the configuration
			String sPort = null;
			try {
				sPort = _oASelectAgentConfigManager.getParam(_oAgentSection, "serviceport");
				_servicePort = Integer.parseInt(sPort);
			}
			catch (ASelectConfigException e) {
				_oASelectAgentSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"missing serviceport directive in configuration", e);
				throw e;
			}
			catch (NumberFormatException e) {
				_oASelectAgentSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"invalid serviceport directive in configuration: " + sPort, e);

				throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
			}

			try {
				sPort = _oASelectAgentConfigManager.getParam(_oAgentSection, "adminport");
				_adminPort = Integer.parseInt(sPort);
			}
			catch (ASelectConfigException e) {
				_oASelectAgentSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"missing 'adminport' directive in configuration", e);
				throw e;
			}
			catch (NumberFormatException e) {
				_oASelectAgentSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"invalid 'adminport' directive in configuration: " + sPort, e);
				throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
			}
		
			// 20111116, Bauke: added
			_iBatchPeriod = ConfigManager.timerSensorConfig(_oASelectAgentConfigManager, _oASelectAgentSystemLogger, _oAgentSection, "agent");

			// get a handle to the communicator
			_oCommunicator = getCommunicator();
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_oASelectAgentSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Error during initialisation", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Clean up Agent. <br>
	 * <br>
	 * <b>Description: </b>
	 * <ul>
	 * <li>Stops the service handler.</li>
	 * <li>Closes all managers and handlers.</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * Should be called once. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All resources are cleared.
	 */
	public void destroy()
	{
		String sMethod = "destroy";

		// All threads must be stopped, otherwise the process keeps running
		_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, "Stopping all components.");
		try {
			_bActive = false;
			// if thread waits ->interrupt and close socket
			try {
				if (_tServiceHandler != null) {
					_tServiceHandler.interrupt();
					if (!_oServiceSocket.isClosed())
						_oServiceSocket.close();
				}
			}
			catch (Exception e) {
				_oASelectAgentSystemLogger.log(Level.WARNING, MODULE, sMethod, "Error stopping service handler", e);
			}

			if (_bGui) {
				_adminMonitor.stop();
			}

			ASelectAgentSAMAgent.getHandle().destroy();
			TicketManager.getHandle().stop();
			SessionManager.getHandle().stop();
			_timerSensorThread.cancel();
			
			_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, "A-Select Agent stopped.");
			_oASelectAgentSystemLogger.closeHandlers();
		}
		catch (Exception e) {
			// Error closing, no logging
		}
	}

	/**
	 * Clean up Agent GUI recourses if applicable. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if GUI mode is enabled. Calls the {@link java.awt.Window#dispose()} method which disposes the Agent GUI. <br>
	 * <br>
	 * <i> <b>Warning:</b> Should be called as the last method in the destroying process because after calling
	 * <code>dispose()</code> the Java virtual machine (VM) may terminate. </i> <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The GUI is disposed, the virtual machine may terminate.
	 */
	public void destroyGui()
	{
		// clean GUI recourses
		if (_bGui)
			_adminMonitor.dispose();
	}

	/**
	 * Starts the services of the A-Select Agent. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method initializes the services and tries to allocate the listening sockets for the A-Select Agent's
	 * services. This method also starts the GUI A-Select Monitor if it was specified in the configuration options. <br>
	 * <br>
	 * After allocating the services the request handler threads are started. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None.<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @throws Exception
	 *             if the services could not be started.
	 */
	public void startServices()
		throws Exception
	{
		String sMethod = "startServices()";
		// try to allocate the listening ports on localhost.
		_oServiceSocket = new ServerSocket(this._servicePort, 50, InetAddress.getByName("localhost"));
		_oAdminSocket = new ServerSocket(this._adminPort, 50, InetAddress.getByName("localhost"));

		// set default values
		_bGui = false;

		try {
			String sTemp = ASelectAgentConfigManager.getHandle().getParam(_oAgentSection, "admin_gui");
			if (sTemp.equalsIgnoreCase("true")) {
				_bGui = true;
				_adminMonitor = new AdminMonitor();
				_adminMonitor.start(5);
			}
		}
		catch (ASelectConfigException e1) {
			// admin.gui parameter not found in config file
			_oASelectAgentSystemLogger.log(Level.CONFIG, MODULE, sMethod,
					"No admin.gui parameter found in configuration (default is off).");
		}

		// set the active flag
		_bActive = true;

		// start the handler threads
		if (_oASelectAgentSystemLogger.isDebug())
			_tServiceHandler = new Thread(new VerboseServiceHandler());
		else
			_tServiceHandler = new Thread(new APIServiceHandler());

		_tServiceHandler.start();
		
		_timerSensorThread = ConfigManager.timerSensorStartThread(_oASelectAgentConfigManager, _oASelectAgentSystemLogger, "agent", _iBatchPeriod);

		new Thread(new AdminServiceHandler()).start();  // accepts "stop"
	}

	/**
	 * Returns the TCP/IP portnumber of the A-Select Agent's Admin interface.
	 * 
	 * @return the portnumber of the Admin interface.
	 */
	public int getAdminPort()
	{
		return _adminPort;
	}

	/**
	 * Returns whether A-Select Agent is active.
	 * 
	 * @return true if A-Select Agent is active, otherwise false.
	 */
	public boolean isActive()
	{
		return _bActive;
	}

	/**
	 * Returns The A-Select Agent GUI mode.
	 * 
	 * @return true if the A-Select Agent GUI is active, otherwise false.
	 */
	public boolean isInGuiMode()
	{
		return _bGui;
	}

	/**
	 * Retrieve the <code>ClientCommunicator</code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method determines according to the configuration of the A-Select Agent which <code>ClientCommunicator</code>
	 * should be used. The <code>ClientCommunicator</code> implements the communication protocol that the A-Select Agent
	 * uses with the A-Select Server. <br>
	 * <br>
	 * Currently, the following protocols are supported:
	 * <ul>
	 * <li>A-Select raw</li>
	 * <li>Soap 1.1</li>
	 * <li>Soap 1.2</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @return the ClientCommunicator object to use.
	 */
	private IClientCommunicator getCommunicator()
	{
		String sMethod = "getCommunicator()";
		IClientCommunicator oCommunicator = null;

		ASelectAgentConfigManager oASelectAgentConfigManager = ASelectAgentConfigManager.getHandle();

		String sComm = null;
		try {
			Object oServerComm = oASelectAgentConfigManager.getSection(_oAgentSection, "server_communication");

			sComm = oASelectAgentConfigManager.getParam(oServerComm, "transferprotocol");
		}
		catch (ASelectConfigException e) {
			_oASelectAgentSystemLogger.log(Level.CONFIG, MODULE, sMethod,
					"Could not find transferprotocol class in config file, using Raw communication.", e);
			sComm = "raw";
		}

		_oASelectAgentSystemLogger.log(Level.FINE, MODULE, sMethod, "communicator="+sComm);
		if (sComm.equalsIgnoreCase("soap11")) {
			oCommunicator = new SOAP11Communicator("ASelect", ASelectAgentSystemLogger.getHandle());
		}
		else if (sComm.equalsIgnoreCase("soap12")) {
			oCommunicator = new SOAP12Communicator("ASelect", ASelectAgentSystemLogger.getHandle());
		}
		else if (sComm.equalsIgnoreCase("raw")) {
			oCommunicator = new RawCommunicator(ASelectAgentSystemLogger.getHandle());
		}
		else {
			StringBuffer sbError = new StringBuffer("Invalid transferprotocol configured: ");
			sbError.append(sComm);
			sbError.append(" , using Raw communication");
			_oASelectAgentSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbError.toString());

			// raw communication is specified or something unreadable
			oCommunicator = new RawCommunicator(ASelectAgentSystemLogger.getHandle());
		}
		return oCommunicator;
	}

	/**
	 * Inner class that accepts API service requests. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The APIServiceHandler class is the heart of the A-Select Agent accepting service requests from applications. <br>
	 * <br>
	 * The APIServiceHandler keeps looping in its <code>run()</code> method until the A-Select Agent shuts down (
	 * <code>_active == false</code>). <br>
	 * <br>
	 * Upon each connection a <code>RequestHandler</code> is started which does the actual handling of the API request. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * 
	 * @author Alfa & Ariss
	 */
	private class APIServiceHandler implements Runnable
	{		
		/**
		 * Loop for accepting API requests and instantiating RequestHandler objects.
		 * 
		 * @see java.lang.Runnable#run()
		 */
		public void run()
		{
			Socket oSocket = null;
			RequestHandler oHandler;
			String sMethod = "APIServiceHandler.run()";

			StringBuffer sbInfo = new StringBuffer("APIServiceHandler started on port: ");
			sbInfo.append(_servicePort);
			_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
			while (_bActive) {
				try {
					long now = System.currentTimeMillis();
					long stamp = now % 1000000;
					_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, "Accept T=" + now + " " + stamp);
					oSocket = _oServiceSocket.accept();
					int port = oSocket.getPort();
					_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, "Create T="
							+ System.currentTimeMillis() + " " + stamp + " port=" + port);
					oHandler = new RequestHandler(oSocket, _oCommunicator, _bAuthorization);
					_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, "Start  T="
							+ System.currentTimeMillis() + " " + stamp + " port=" + port);
					oHandler.start();
					_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, "StartD T="
							+ System.currentTimeMillis() + " " + stamp + " port=" + port);
				}
				catch (Exception e) {
					if (_bActive) { // only log if active
						_oASelectAgentSystemLogger.log(Level.WARNING, MODULE, sMethod, "Exception occurred", e);
					}
				}
			}
			// stopped
			_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, "APIServiceHandler stopped.");
		}

	}

	/**
	 * Inner class that accepts API service requests and logs verbosely. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * See <code>APIServiceHandler</code> for more descriptive information. <br>
	 * <br>
	 * Upon each connection a TraceRequestHandler thread is started which does the actual handling of the API request. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * 
	 * @author Alfa & Ariss
	 */
	private class VerboseServiceHandler extends APIServiceHandler implements Runnable
	{
		
		/**
		 * Loop for accepting API requests and instantiating TraceRequestHandler objects.
		 * 
		 * @see java.lang.Runnable#run()
		 */
		@Override
		public void run()
		{
			Socket oSocket = null;
			RequestHandler oHandler;
			String sMethod = "VerboseServiceHandler.run()";

			StringBuffer sbInfo = new StringBuffer("VerboseServiceHandler started on port: ");
			sbInfo.append(_servicePort);
			_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
			while (_bActive) {
				try {
					oSocket = _oServiceSocket.accept();
					oHandler = new TraceRequestHandler(oSocket, _oCommunicator, _bAuthorization);
					oHandler.start();
				}
				catch (Exception e) {
					if (_bActive) // only log if active
					{
						StringBuffer sbError = new StringBuffer("Exception occurred: \"");
						sbError.append(e.getMessage());
						sbError.append("\"");
						_oASelectAgentSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
					}
				}
			}
			// stopped
			sbInfo = new StringBuffer("VerboseServiceHandler stopped.");
			_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
	}

	/**
	 * Inner class that accepts Admin service requests. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The AdminServiceHandler supports the following API requests: <br>
	 * <code>request=stop</code> to stop the A-Select Agent. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * 
	 * @author Alfa & Ariss
	 */
	private class AdminServiceHandler implements Runnable
	{
		/**
		 * Loop for accepting AdminAPI requests.
		 * 
		 * @see java.lang.Runnable#run()
		 */
		public void run()
		{
			Socket oSocket;
			String sMethod = "AdminServiceHandler.run()";

			StringBuffer sbInfo = new StringBuffer("AdminServiceHandler started on port: ");
			sbInfo.append(_adminPort);
			_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			while (_bActive) {
				try {
					oSocket = _oAdminSocket.accept();
					BufferedReader isInput = new BufferedReader(new InputStreamReader(oSocket.getInputStream()));
					PrintStream osOutput = new PrintStream(oSocket.getOutputStream());

					String sRequestString = isInput.readLine();
					_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, sRequestString);
					HashMap htParameters = Utils.convertCGIMessage(sRequestString, false);
					String sRequest = (String) htParameters.get("request");
					if (sRequest.equalsIgnoreCase("stop")) {
						destroy();
					}
					osOutput.println("result=" + Errors.ERROR_ASELECT_SUCCESS);
					oSocket.close();

				}
				catch (Exception e) {
					_oASelectAgentSystemLogger.log(Level.WARNING, MODULE, sMethod, "Exception occurred", e);
				}
			}
			// clean GUI recourses
			destroyGui();

			// stopped
			_oASelectAgentSystemLogger.log(Level.INFO, MODULE, sMethod, "AdminServiceHandler stopped.");
		}
	}
}