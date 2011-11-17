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
 * $Id: RequestHandler.java,v 1.55 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: RequestHandler.java,v $
 * Revision 1.55  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.54  2006/03/10 15:18:35  martijn
 * added support for multivalue attributes
 *
 * Revision 1.53  2006/03/09 12:45:04  jeroen
 * adaptation for multi-valued attributes feature
 *
 * Revision 1.52  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.51  2005/09/07 08:41:19  erwin
 * Changed error codes in verify ticket request (bug #78)
 *
 * Revision 1.50  2005/09/05 09:28:04  erwin
 * Fixed problem with ";", changed the set authorization rules method.
 *
 * Revision 1.49  2005/09/02 14:44:29  erwin
 * - Added Authorization Rule ID
 * - Added ip parameter in request=verify_ticket
 *
 * Revision 1.48  2005/08/30 08:14:40  erwin
 * Added Authorization functionality to the Agent
 *
 * Revision 1.47  2005/05/20 13:02:47  erwin
 * Fixed some minor bugs in Javadoc
 *
 * Revision 1.46  2005/05/11 15:13:29  peter
 * Compatibility with A-Select Server version 1.3
 *
 * Revision 1.45  2005/04/27 13:49:01  martijn
 * fixed bug: if attribute cookie is changed, the processVerifyTicketRequest() will now log a WARNING message instead of an INFO message
 *
 * Revision 1.44  2005/04/22 14:18:51  tom
 * Improved error handling in signRequest
 *
 * Revision 1.43  2005/04/15 12:12:28  tom
 * Removed old logging statements
 *
 * Revision 1.42  2005/04/14 16:22:01  tom
 * Removed old logging statements
 *
 * Revision 1.41  2005/04/11 09:06:04  remco
 * - removed request=forced_authenticate
 * - added parameter forced_logon to request=authenticate
 *
 * Revision 1.40  2005/04/07 13:09:55  tom
 * Fixed Killticket javadoc and return parameters
 *
 * Revision 1.39  2005/04/07 13:07:46  tom
 * Updated javadoc
 *
 * Revision 1.38  2005/04/07 13:03:27  tom
 * Fixed javadoc
 *
 * Revision 1.37  2005/04/07 12:05:56  remco
 * - using SHA1 instead of MD5 for attributes_hash (in verify_ticket)
 * - attributes_hash must be omitted if there are no attributes
 *
 * Revision 1.36  2005/04/07 07:50:37  remco
 * processVerifyTicketRequest() tried to set result_code twice on corrupt attributes error
 *
 * Revision 1.35  2005/04/05 07:50:11  martijn
 * added forced_authenticate
 *
 * Revision 1.34  2005/04/01 14:52:19  martijn
 * added better verification of country and language code
 *
 * Revision 1.33  2005/04/01 14:17:17  martijn
 * added support for the optional attributes country and language in the authenticate api calls
 *
 * Revision 1.32  2005/04/01 13:46:51  peter
 * Removed cross request.
 * authenticate request now has an optional remote organization parameter
 *
 * Revision 1.31  2005/04/01 07:58:31  martijn
 * added new api call: request=attributes
 *
 * Revision 1.30  2005/03/31 12:58:41  martijn
 * attributes are now being forwarded to the filter as retrieved from the A-Select Server
 *
 * Revision 1.29  2005/03/30 08:39:02  erwin
 * Improved Javdoc.
 *
 * Revision 1.28  2005/03/24 13:22:34  erwin
 * Removed URL encoding/decoding
 * (this is handled in communication package)
 *
 * Revision 1.27  2005/03/21 10:14:03  martijn
 * updated imports
 *
 * Revision 1.26  2005/03/18 16:06:11  tom
 * Fixed problem with attribute handling, wrong delimiter used
 *
 * Revision 1.25  2005/03/18 15:28:02  peter
 * Fixed cross-authenticate bugs.
 * organization parameter is now optional in request=cross_authenticate, A-Select Server will retrieve the organization id.
 *
 * Revision 1.24  2005/03/18 14:50:55  erwin
 * Removed processCreateTGT()
 *
 * Revision 1.23  2005/03/18 13:43:59  remco
 * added untested create_tgt
 *
 * Revision 1.22  2005/03/17 14:07:51  remco
 * Attributes functionality
 *
 * Revision 1.21  2005/03/17 08:26:01  erwin
 * Removed fixmes
 *
 * Revision 1.20  2005/03/16 11:29:46  martijn
 * renamed todo's
 *
 * Revision 1.19  2005/03/16 11:22:16  martijn
 * todo's converted to fixme's
 *
 * Revision 1.18  2005/03/15 16:22:46  peter
 * createSession bug solved in processCrossAuthenticateRequest()
 *
 * Revision 1.17  2005/03/15 10:52:17  martijn
 * The crypto configuration is changed, providers are now also configurable. The 'do_signing' config parameter is changed to 'sign_requests'
 *
 * Revision 1.16  2005/03/14 10:09:07  erwin
 * The ticket and session expiration and start
 * time are now read from the ticket and session
 * manager.
 *
 * Revision 1.15  2005/03/09 17:10:22  remco
 * fixed compiler warnings
 *
 * Revision 1.14  2005/03/09 16:23:34  remco
 * agent always signed requests, even when this option was turned off
 *
 * Revision 1.13  2005/03/09 14:28:47  remco
 * proper signing
 *
 * Revision 1.12  2005/03/09 12:09:59  remco
 * added preliminary signing
 *
 * Revision 1.11  2005/03/09 09:20:38  erwin
 * Renamed errors.
 *
 * Revision 1.10  2005/03/08 08:44:41  erwin
 * Improved Ticket managent
 *
 * Revision 1.9  2005/03/07 15:58:44  erwin
 * improved sendRequestToASelectServer() and local variable names
 *
 * Revision 1.8  2005/03/07 14:43:24  erwin
 * asp -> authsp in requests and admin monitor.
 *
 * Revision 1.7  2005/03/03 17:24:19  erwin
 * Applied code style, added javadoc comment.
 *
 * Revision 1.6  2005/03/01 16:30:17  erwin
 * Fixed fixme's.
 *
 * Revision 1.5  2005/02/28 14:03:06  erwin
 * Fixed logging messages and levels.
 *
 * Revision 1.4  2005/02/25 15:51:33  erwin
 * Improved logging.
 *
 * Revision 1.3  2005/02/24 15:09:09  ali
 * Added IAgentEventListener class and updates internal Javadoc.
 *
 */

package org.aselect.agent.handler;

import java.io.IOException;
import java.net.Socket;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Signature;
import java.text.DateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeSet;
import java.util.Vector;
import java.util.logging.Level;
import org.aselect.agent.authorization.AuthorizationEngine;
import org.aselect.agent.config.ASelectAgentConfigManager;
import org.aselect.agent.log.ASelectAgentSystemLogger;
import org.aselect.agent.sam.ASelectAgentSAMAgent;
import org.aselect.agent.session.SessionManager;
import org.aselect.agent.ticket.TicketManager;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.server.Communicator;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.communication.server.IMessageCreatorInterface;
import org.aselect.system.communication.server.IOutputMessage;
import org.aselect.system.communication.server.TCPProtocolRequest;
import org.aselect.system.communication.server.TCPProtocolResponse;
import org.aselect.system.communication.server.raw.RawMessageCreator;
import org.aselect.system.communication.server.soap11.SOAP11MessageCreator;
import org.aselect.system.communication.server.soap12.SOAP12MessageCreator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthorizationException;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.storagemanager.SendQueue;
import org.aselect.system.utils.*;

/**
 * Main A-Select Agent API Request handler. <br>
 * <br>
 * <b>Description: </b> <br>
 * This class implements the A-Select Agent API for applications. <br>
 * The A-Select Agent main accept loop spawns an instance of this class for each incoming API request. <br>
 * This class implements all the communication with the configured A-Select Servers and uses the Session and Ticket
 * managers to perform ticket en session management. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * None. <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - Added htmlEncode to prevent cross-site scripting - Send upgrade_tgt
 *         request to the server every the application makes contact This way, single sign-on also works longer than a
 *         few minutes (as long as the user keeps working)
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl)
 */
public class RequestHandler extends Thread
{
	public String MODULE;

	/**
	 * The attribute that contains the current date time.
	 */
	private final String CURRENT_TIME_ATTRIBUTE = "current_time";

	/**
	 * The attribute that contains the local IP address of the user.
	 */
	private final String IP_ATTRIBUTE = "ip";

	/**
	 * Handle to SystemLogger.
	 */
	protected SystemLogger _systemLogger;
	/**
	 * A-Select error state identifier.
	 */
	protected String _sErrorCode;
	/**
	 * Handle to TicketManager.
	 */
	private TicketManager _ticketManager;
	/**
	 * Handle to ASelectAgentConfigManager.
	 */
	private ASelectAgentConfigManager _configManager;

	/**
	 * The socket bound to the calling application.
	 */
	private Socket _socket;

	/**
	 * Handle to SessionManager.
	 */
	private SessionManager _sessionManager;

	/**
	 * Handle to ClientCommunicator.
	 */
	private IClientCommunicator _clientCommunicator;

	/**
	 * <code>true</code> if Authorization is enabled.
	 */
	private boolean _bAuthorization = false;

	// Store timing data
	TimeSensor timeSensor;

	/**
	 * Initializes instance variables. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Constructs this object, sets fields and initializes managers. <br>
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
	 * @param oSocket
	 *            socket to read and write to.
	 * @param oCommunicator
	 *            <code>ClientCommunicator</code> to use for communicating with the A-Select Server.
	 * @param bAuthorization
	 *            <code>true</code> if authorization is enabled, otherwise <code>false</code>.
	 */
	public RequestHandler(Socket oSocket, IClientCommunicator oCommunicator, boolean bAuthorization)
	{
		MODULE = "RequestHandler";

		_socket = oSocket;
		_ticketManager = TicketManager.getHandle();
		_configManager = ASelectAgentConfigManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_systemLogger = ASelectAgentSystemLogger.getHandle();
		_clientCommunicator = oCommunicator;
		_bAuthorization = bAuthorization;
		timeSensor = new TimeSensor(_systemLogger, "agt_all");
	}

	/**
	 * Returns the ClientCommunicator.
	 * 
	 * @return A handle to the ClientCommunicator object.
	 */
	public IClientCommunicator getClientCommunicator()
	{
		return _clientCommunicator;
	}

	/**
	 * Main method for reading the request and processing it. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method reads the request from the socket with the caller. The request may be one of the supported
	 * communication protocols. Once the corresponding protocol is recognized, the API request is deduced and dispatched
	 * to <code>processRequest</code> for processing. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None.
	 */
	public void run()
	{
		String sMethod = "run()";
		int port = _socket.getPort();

		try {
			// create protocol requests
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN stt T=" + System.currentTimeMillis() + " socket="
					+ _socket + " port=" + port);
			TCPProtocolRequest oTCPProtocolRequest = new TCPProtocolRequest(_socket, _systemLogger);
			TCPProtocolResponse oTCPProtocolResponse = new TCPProtocolResponse(_socket, oTCPProtocolRequest
					.getProtocolName());

			IMessageCreatorInterface oMessageCreator = null;

			// Determine what type of protocol request the caller is using.
			String sContentType = oTCPProtocolRequest.getProperty("Content-Type");
			if (sContentType == null)
				sContentType = "";

			_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN ctt T=" + System.currentTimeMillis() + " ContentType="
					+ sContentType + " port=" + port);
			// Check if it is a SOAP 1.1 request
			if (sContentType.indexOf("text/xml") > -1) {
				// Instantiate a SOAP11MessageCreator object
				oMessageCreator = new SOAP11MessageCreator(oTCPProtocolRequest.getTarget(), "ASelect",
						ASelectAgentSystemLogger.getHandle());
			}
			// Check if it is a SOAP 1.2 request
			else if (sContentType.indexOf("application/soap+xml") > -1) {
				// Instantiate a SOAP12MessageCreator object
				oMessageCreator = new SOAP12MessageCreator(oTCPProtocolRequest.getTarget(), "ASelect",
						ASelectAgentSystemLogger.getHandle());
			}
			else { // Instantiate a RawMessageCreator object
				oMessageCreator = new RawMessageCreator(ASelectAgentSystemLogger.getHandle());
			}

			// Create Communicator object with the specified messagecreator
			Communicator xCommunicator = new Communicator(oMessageCreator);

			// Initialize the communicator
			if (xCommunicator.init(oTCPProtocolRequest, oTCPProtocolResponse)) {
				// Call processRequest for procesing
				_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN prc T=" + System.currentTimeMillis()+" port="+port);
				processRequest(xCommunicator, port);

				// Send our response
				if (!xCommunicator.send()) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not send response to caller.");
				}
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize request.");
			}
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize request.", eAC);
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Exception: \"");
			sbError.append(e);
			sbError.append("\"");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
		}
		finally { // Close socket
			if (_socket != null) {
				try {
					_socket.close();
					_socket = null;
				}
				catch (IOException eIO) { // closing failed
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error closing socket.", eIO);
				}
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN end T=" + System.currentTimeMillis() + " port=" + port);
		}
	}

	/**
	 * Main API request dispatch method. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method dispatches the API request to the approperiate methods. <br>
	 * Currently, the following API requests are supported:
	 * <ul>
	 * <li><code>authenticate</code></li>
	 * <li><code>cross_authenticate</code></li>
	 * <li><code>verify_credentials</code></li>
	 * <li><code>verify_ticket</code></li>
	 * <li><code>kill_ticket</code></li>
	 * <li><code>set_authorization_rules</code></li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None.
	 * 
	 * @param oCommunicator
	 *            handle to <code>Communicator</code> object for the request.
	 * @param port
	 *            the port
	 */
	protected void processRequest(Communicator oCommunicator, int port)
	{
		String sMethod = "processRequest";
		String sRequest = null;
		String sUsi = null;
		long lMyThread = Thread.currentThread().getId();

		try {
			// create the input and output message
			IInputMessage oInputMessage = oCommunicator.getInputMessage();
			IOutputMessage oOutputMessage = oCommunicator.getOutputMessage();

			try {
				sRequest = oInputMessage.getParam("request");
			}
			catch (Exception eX) { // sRequest is already null
			}
			if (sRequest == null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Request is missing");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
				return;
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "REQ { T=" + System.currentTimeMillis() + " port="
					+ port + ", t="+lMyThread + ": " + sRequest+", oInput=" + oInputMessage);
			
			timeSensor.timeSensorStart(1/*level*/, 2/*agent*/, lMyThread);  // default is success
			try {
				sUsi = oInputMessage.getParam("usi");  // unique sensor id
			}
			catch (Exception e) {  // should generate our own usi here
				// using System.nanoTime();
			}
			if (Utils.hasValue(sUsi))
				timeSensor.setTimeSensorId(sUsi);

			// check which API request was sent and let it be processed
			_sErrorCode = Errors.ERROR_ASELECT_SUCCESS;  // optimistic default
			if (sRequest.equals("authenticate")) {
				timeSensor.setTimeSender("agt_aut");
				processAuthenticateRequest(oInputMessage, oOutputMessage);
			}
			else if (sRequest.equals("verify_credentials")) {
				timeSensor.setTimeSender("agt_vcr");
				processVerifyCredentialsRequest(oInputMessage, oOutputMessage);
			}
			else if (sRequest.equals("verify_ticket")) {
				timeSensor.setTimeSender("agt_vtk");
				processVerifyTicketRequest(oInputMessage, oOutputMessage);
			}
			else if (sRequest.equals("kill_ticket")) {
				timeSensor.setTimeSender("agt_ktk");
				processKillTicketRequest(oInputMessage, oOutputMessage);
			}
			else if (sRequest.equals("kill_tgt")) {
				timeSensor.setTimeSender("agt_ktg");
				processKillTgtRequest(oInputMessage, oOutputMessage);
			}
			else if (sRequest.equals("attributes")) {
				timeSensor.setTimeSender("agt_atr");
				processAttributesRequest(oInputMessage, oOutputMessage);
			}
			else if (sRequest.equals("set_authorization_rules")) {
				timeSensor.setTimeSender("agt_rul");
				processSetAuthorizationRulesRequest(oInputMessage, oOutputMessage);
			}
			else { // Unknown or unsupported request
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unknown or unsupported request received.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
			}
			oOutputMessage.setParam("result_code", _sErrorCode);
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Communication with A-Select Server failed.", eAC);
		}
		
		timeSensor.timeSensorFinish(_sErrorCode.equals(Errors.ERROR_ASELECT_SUCCESS));
		
		//StringBuffer sb = new StringBuffer("DATA=");
		//sb.append(timeSensor.timeSensorPack()).append("\n");
		//Tools.reportTimerSensorData(_configManager, "agent"/*xml*/, "timer_sensor", _systemLogger, sb.toString());
		SendQueue.getHandle().addEntry(timeSensor.timeSensorPack());
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "} REQ T="+System.currentTimeMillis() + " port="+port + ": "+sRequest);
	}

	/**
	 * Performs initiation of (forced) authentication with the A-Select Server. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method performs the A-Select Server's (forced) authenticate request and parses the response from the
	 * A-Select Server. This method contacts any available A-Select Server through the SAM Agent. <br>
	 * <br>
	 * The API request should contain the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>request</code></td>
	 * <td>Should contain <code>authenticate</code> </code>.</td>
	 * </tr>
	 * <tr>
	 * <td><code>app_url</code></td>
	 * <td>Should contain the full URL to the caller. This parameter should be a <code>http</code> or <code>https</code>
	 * URL.</td>
	 * </tr>
	 * <tr>
	 * <td><code>app_id</code></td>
	 * <td>The ID of the application (i.e., the caller of this API request).</td>
	 * </tr>
	 * <tr>
	 * <td><code>remote_organization</code></td>
	 * <td>Optional paramater: the organization where the user originates from.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * The API response contains the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>as_url</code></td>
	 * <td>The A-Select server URL for redirecting</td>
	 * </tr>
	 * <tr>
	 * <td><code>a-select-server</code></td>
	 * <td>The ID of the A-Select Server that handled the request.</td>
	 * </tr>
	 * <tr>
	 * <td><code>result_code</code></td>
	 * <td>The A-Select response code:
	 * <ul>
	 * <li>{@link Errors#ERROR_ASELECT_SUCCESS} (OK)</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INVALID_REQUEST}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INTERNAL_ERROR}</li>
	 * </ul>
	 * </td>
	 * </tr>
	 * <tr>
	 * <td><code>rid</code></td>
	 * <td>The A-Select server request ID</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oInputMessage != null</code></li>
	 * <li><code>oOutputMessage != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * Upon a succesfull response from the A-Select Server, a session context with key <code>rid</code> is created with
	 * the following parameters:
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>rid</code></td>
	 * <td>The rid was received from the A-Select Server.</td>
	 * </tr>
	 * <tr>
	 * <td><code>a-select-server</code></td>
	 * <td>The ID of the A-Select Server that handled the request.</td>
	 * </tr>
	 * <tr>
	 * <td><code>user_type</code></td>
	 * <td>Set to <code>local</code> to denote a local authentication.</td>
	 * </tr>
	 * <tr>
	 * <td><code>app_id</code></td>
	 * <td>The ID of the application (i.e., the caller of this API request).</td>
	 * </tr>
	 * <tr>
	 * <td><code>as_url</code></td>
	 * <td>The A-Select server URL.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * 
	 * @param oInputMessage
	 *            The API request message.
	 * @param oOutputMessage
	 *            The API response message.
	 * @throws ASelectCommunicationException
	 *             If sending response fails.
	 */
	private void processAuthenticateRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
	throws ASelectCommunicationException
	{
		String sMethod = "processAuthenticateRequest()";
		StringBuffer sbBuffer = new StringBuffer();
		try {
			String sAppUrl = null;
			String sAppId = null;
			String sUid = null;
			String sAuthsp = null;
			String sRemoteOrg = null;

			try {
				sAppUrl = oInputMessage.getParam("app_url");
				if (!sAppUrl.startsWith("http")) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "invalid 'app_url'");
					_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
					return;
				}
				sAppId = oInputMessage.getParam("app_id");
				if (sAppId.length() == 0) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "invalid 'app_id'");
					_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
					return;
				}
				timeSensor.setTimeSensorAppId(sAppId);
			}
			catch (ASelectCommunicationException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received.", eAC);
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
				return;
			}
			try {
				sUid = oInputMessage.getParam("uid");
				if (sUid.length() == 0) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Ignoring empty 'uid'.");
					sUid = null;
				}
			}
			catch (ASelectCommunicationException eAC) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No optional parameter 'uid' found.");
				sUid = null;
			}
			// Bauke: added to choose the AuthSP in advance
			try {
				sAuthsp = oInputMessage.getParam("authsp");
				if (sAuthsp.length() == 0) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Ignoring empty 'authsp'.");
					sAuthsp = null;
				}
			}
			catch (ASelectCommunicationException eAC) {
				sAuthsp = null;
			}

			String sForcedLogon = null;
			try {
				// API accepts the 'forced_logon' String parameter to the 'authenticate' request.
				// Internally a Boolean object 'forced_authenticate' is used to represent the same thing
				sForcedLogon = oInputMessage.getParam("forced_logon");
			}
			catch (ASelectCommunicationException eAC) {
			}

			// 20090613, Bauke: accept forced_authenticate as well
			if (sForcedLogon == null) {
				try {
					sForcedLogon = oInputMessage.getParam("forced_authenticate");
				}
				catch (ASelectCommunicationException eAC) {
				}
			}

			try {
				sRemoteOrg = oInputMessage.getParam("remote_organization");
				if (sRemoteOrg.length() == 0) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Ignoring empty 'remote_organization'.");
					sRemoteOrg = null;
				}
			}
			catch (ASelectCommunicationException eAC) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No optional parameter 'remote_organization' found.");
				sRemoteOrg = null;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "AuthREQ sAppUrl=" + sAppUrl + ", sAppId=" + sAppId
					+ ", sUid=" + sUid + ", sAuthsp=" + sAuthsp + ", sForcedLogon=" + sForcedLogon + ", sRemoteOrg="
					+ sRemoteOrg);

			// send an authenticate request to the A-Select Server
			HashMap htRequest = new HashMap();
			htRequest.put("request", "authenticate");
			// Bauke: added htmlEncode to prevent cross-site scripting
			htRequest.put("app_url", Tools.htmlEncode(sAppUrl));
			htRequest.put("app_id", sAppId);
			if (sUid != null)
				htRequest.put("uid", sUid);
			if (sAuthsp != null)
				htRequest.put("authsp", sAuthsp);
			if (sRemoteOrg != null)
				htRequest.put("remote_organization", sRemoteOrg);
			if (sForcedLogon != null)
				htRequest.put("forced_logon", sForcedLogon); // To Server API, change to forced_authenticate later!!

			String sCountry = null;
			try {
				sCountry = oInputMessage.getParam("country");
				if (sCountry.trim().length() > 0)
					htRequest.put("country", sCountry);
			}
			catch (ASelectCommunicationException e) {
				sCountry = null;
			}

			String sLanguage = null;
			try {
				sLanguage = oInputMessage.getParam("language");
				if (sLanguage.trim().length() > 0)
					htRequest.put("language", sLanguage);
			}
			catch (ASelectCommunicationException e) {
				sLanguage = null;
			}

			// 20111108, Bauke: Send unique session id too
			htRequest.put("usi", timeSensor.getTimeSensorId());
			HashMap htResponseParameters = sendToASelectServer(htRequest);
			if (htResponseParameters.isEmpty()) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not reach A-Select Server.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}

			String sResultCode = (String) htResponseParameters.get("result_code");
			if (sResultCode == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid response from A-Select Server.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}
			if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
				sbBuffer = new StringBuffer("A-Select Server returned error: '");
				sbBuffer.append(sResultCode).append("'.");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());

				_sErrorCode = sResultCode;
				return;
			}

			// check the response of the A-Select Server
			String sRid = (String) htResponseParameters.get("rid");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "A-Select Server did not return 'rid'.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}
			String sAsUrl = (String) htResponseParameters.get("as_url");
			if (sAsUrl == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "A-Select Server did not return 'as_url'.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}
			String sAsId = (String) htResponseParameters.get("a-select-server");
			if (sAsId == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "A-Select Server did not return 'a-select-server'.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}

			// create a session
			HashMap htSessionContext = new HashMap();
			htSessionContext.put("rid", sRid);
			htSessionContext.put("a-select-server", sAsId);
			htSessionContext.put("user_type", "Local");
			htSessionContext.put("app_id", sAppId);
			htSessionContext.put("as_url", sAsUrl);
			
			timeSensor.setTimeSensorRid(sRid);  // Rid received from Server

			if (!_sessionManager.createSession(sRid, htSessionContext)) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "could not create session.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
				return;
			}

			// session created, set output parameters for caller
			oOutputMessage.setParam("as_url", sAsUrl);
			oOutputMessage.setParam("a-select-server", sAsId);
			oOutputMessage.setParam("rid", sRid);
			_sErrorCode = Errors.ERROR_ASELECT_SUCCESS;
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create response message.", eAC);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
		catch (Exception e) {

			sbBuffer = new StringBuffer("Exception while processing request: \"");
			sbBuffer.append(e.getMessage());
			sbBuffer.append("\"");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), e);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
	}

	/**
	 * Performs verification of A-Select credentials with the A-Select Server. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method performs the verification of authentication of a user when a user is redirected back to the calling
	 * application having A-Select credentials. <br>
	 * <br>
	 * This API request should contain the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>request</code></td>
	 * <td>Should contain <code>verify_credentials</code>.</td>
	 * </tr>
	 * <tr>
	 * <td><code>rid</code></td>
	 * <td>Must contain the request identifier as received by the A-Select Server.</td>
	 * </tr>
	 * <tr>
	 * <td><code>aselect_credentials</code></td>
	 * <td>The credentials as received from the A-Select server.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * The API response contains the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>ticket</code></td>
	 * <td>The A-Select application ticket.</td>
	 * </tr>
	 * <tr>
	 * <td><code>ticket_start_time</code></td>
	 * <td>The start time of the application ticket.</td>
	 * </tr>
	 * <tr>
	 * <td><code>ticket_exp_time</code></td>
	 * <td>The expiration time of the application ticket.</td>
	 * </tr>
	 * <tr>
	 * <td><code>uid</code></td>
	 * <td>The user ID.</td>
	 * </tr>
	 * <tr>
	 * <td><code>organization</code></td>
	 * <td>The users' organisation.</td>
	 * </tr>
	 * <tr>
	 * <td><code>authsp_level</code></td>
	 * <td>The authentication level of the AuthSP that authenticated the user.</td>
	 * </tr>
	 * <tr>
	 * <td><code>authsp</code></td>
	 * <td>The AuthSP that authenticated the user.</td>
	 * </tr>
	 * <tr>
	 * <td><code>attributes</code></td>
	 * <td>The complete set of attributes.<br>
	 * <br>
	 * The attributes are encoded using a combination of base64 and url encoding.To retrieve the attributes an
	 * application must first decode the attributes using base64, the result is an attributes string containing a
	 * concatenation of the attributes (key=value) using &amp as the delimiter. The attributes key and value are url
	 * encoded.<br>
	 * <br>
	 * <b>NOTE: If no attributes are available the attributes parameter is omitted.</b> <br>
	 * <br>
	 * </td>
	 * </tr>
	 * <tr>
	 * <td><code>result_code</code></td>
	 * <td>The A-Select response code:
	 * <ul>
	 * <li>{@link Errors#ERROR_ASELECT_SUCCESS} (OK)</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INVALID_REQUEST}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INTERNAL_ERROR}</li>
	 * </ul>
	 * </td>
	 * </tr>
	 * <tr>
	 * <td><code>asp_level</code></td>
	 * <td>The authentication level of the AuthSP that authenticated the user. (added for backwards compatibility with
	 * A-Select 1.4)</td>
	 * </tr>
	 * <tr>
	 * <td><code>asp</code></td>
	 * <td>The AuthSP that authenticated the user. (added for backwards compatibility with A-Select 1.4)</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oInputMessage != null</code></li>
	 * <li><code>oOutputMessage != null</code></li>
	 * <li>The caller must have initiated authentication (local or remote) and thus a session context must be present
	 * identified by the given <code>rid</code>.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * Upon a succesfull response from the A-Select Server, a ticket context with key <code>ticket</code> is created
	 * with the following parameters:
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>uid</code></td>
	 * <td>The user ID.</td>
	 * </tr>
	 * <tr>
	 * <td><code>organization</code></td>
	 * <td>The user its organisation.</td>
	 * </tr>
	 * <tr>
	 * <td><code>authsp_level</code></td>
	 * <td>The authentication level of the AuthSP that authenticated the user.</td>
	 * </tr>
	 * <tr>
	 * <td><code>authsp</code></td>
	 * <td>The AuthSP that authenticated the user.</td>
	 * </tr>
	 * <tr>
	 * <td><code>app_id</code></td>
	 * <td>The ID of the application (i.e., the caller of this API request).</td>
	 * </tr>
	 * <tr>
	 * <td><code>app_level</code></td>
	 * <td>The required level of the application.</td>
	 * </tr>
	 * <tr>
	 * <td><code>a-select-server</code></td>
	 * <td>The ID of the A-Select Server that handled the request.</td>
	 * </tr>
	 * <tr>
	 * <td><code>tgt_exp_time</code></td>
	 * <td>The ticket expiration time of the TGT</td>
	 * </tr>
	 * <tr>
	 * <td><code>attributes</code></td>
	 * <td>The base64 encoded attributes string received from the A-Select Server</td>
	 * </tr>
	 * <tr>
	 * <td><code>attributes_hash</code></td>
	 * <td>The SHA1 hash computed over the attributes string after being base64 decoded.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * In addition the user its session is deleted after successful processing the request. <br>
	 * 
	 * @param oInputMessage
	 *            The API request message.
	 * @param oOutputMessage
	 *            The API response message.
	 * @throws ASelectCommunicationException
	 *             If setting response parameters fails.
	 */
	//
	// Bauke 20081201: added parameter: saml_attributes=<attr1>,<attr2>,...
	// Will request the server to send a Saml token containing the requested attributes
	//
	private void processVerifyCredentialsRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
	throws ASelectCommunicationException
	{
		String sMethod = "processVerifyCredentialsRequest";
		StringBuffer sbBuffer = new StringBuffer();

		try {
			String sRid = null;
			String sCredentials = null;
			String sAsId = null;
			String sSamlAttributes = null;
			String sAppArgs = null;

			try { // check parameters
				sRid = oInputMessage.getParam("rid");
				sCredentials = oInputMessage.getParam("aselect_credentials");

				HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
				if (htSessionContext == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid session");
					_sErrorCode = Errors.ERROR_ASELECT_AGENT_SESSION_EXPIRED;
					return;
				}

				sAsId = (String) htSessionContext.get("a-select-server");
				if (sAsId == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing 'a-select-server' in session.");
					_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
					return;
				}
			}
			catch (ASelectCommunicationException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received.", eAC);
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
				return;
			}
			try {
				sSamlAttributes = oInputMessage.getParam("saml_attributes");
			}
			catch (ASelectCommunicationException e) { // ignore absence
			}
			try {
				sAppArgs = oInputMessage.getParam("aselect_app_args");
			}
			catch (ASelectCommunicationException e) { // ignore absence
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "VerCRED rid=" + sRid + " server=" + sAsId +
					" samlAttr="+sSamlAttributes+" appArgs="+sAppArgs);

			// send the verify_credentials request to the A-Select Server
			HashMap htRequest = new HashMap();
			htRequest.put("request", "verify_credentials");
			htRequest.put("rid", sRid);
			htRequest.put("aselect_credentials", sCredentials);
			if (sSamlAttributes != null)
				htRequest.put("saml_attributes", sSamlAttributes);

			// To the SERVER
			htRequest.put("usi", timeSensor.getTimeSensorId());
			HashMap htResponseParameters = sendToASelectServer(htRequest);

			if (htResponseParameters.isEmpty()) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not reach A-Select Server.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}

			String sResultCode = (String) htResponseParameters.get("result_code");
			if (sResultCode == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid response from A-Select Server.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}
			if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
				sbBuffer = new StringBuffer("A-Select Server returned error: '");
				sbBuffer.append(sResultCode);
				sbBuffer.append("'.");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				_sErrorCode = sResultCode;
				return;
			}

			// check response parameters
			String sUID = (String) htResponseParameters.get("uid");
			if (sUID == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "A-Select Server did not return 'uid'");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}
			sUID = URLDecoder.decode(sUID, "UTF-8");

			String sOrg = (String) htResponseParameters.get("organization");
			if (sOrg == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "A-Select Server did not return 'organization'");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}
			String sAL = (String) htResponseParameters.get("authsp_level");
			if (sAL == null) {
				// Compatibility with A-Select Server version 1.3
				sAL = (String) htResponseParameters.get("asp_level");
			}
			if (sAL == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "A-Select Server did not return 'authsp_level'");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}
			String sASP = (String) htResponseParameters.get("authsp");
			if (sASP == null) {
				// Compatibility with A-Select Server version 1.3
				sASP = (String) htResponseParameters.get("asp");
			}
			if (sASP == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "A-Select Server did not return 'authsp'");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}
			String sAPP = (String) htResponseParameters.get("app_id");
			if (sAPP == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "A-Select Server did not return 'app_id'");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}
			timeSensor.setTimeSensorAppId(sAPP);
			
			String sAppLevel = (String) htResponseParameters.get("app_level");
			if (sAppLevel == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "A-Select Server did not return 'app_level'");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}
			String sTgtExp = (String) htResponseParameters.get("tgt_exp_time");
			if (sTgtExp == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "A-Select Server did not return 'tgt_exp_time'");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
				return;
			}

			// all parameters are there; create a ticket for this user and
			// store it in a ticket context
			HashMap htTicketContext = new HashMap();
			htTicketContext.put("uid", sUID);
			htTicketContext.put("organization", sOrg);
			htTicketContext.put("authsp_level", sAL);
			htTicketContext.put("authsp", sASP);
			htTicketContext.put("app_id", sAPP);
			htTicketContext.put("app_level", sAppLevel);
			htTicketContext.put("a-select-server", sAsId);
			htTicketContext.put("tgt_exp_time", new Long(sTgtExp));
			// Bauke: added to allow upgrading the server's TGT
			htTicketContext.put("crypted_credentials", sCredentials);
			// 20100521, Bauke: added to save original application arguments
			if (sAppArgs != null)
				htTicketContext.put("aselect_app_args", sAppArgs);
			
			// The attributes parameter is optional.
			String sAttributes = (String) htResponseParameters.get("attributes");
			if (sAttributes != null) {
				htTicketContext.put("attributes", sAttributes);
				// Store hash of attributes (we use this in verify_ticket)
				BASE64Decoder b64d = new BASE64Decoder();
				MessageDigest md = MessageDigest.getInstance("SHA1");
				md.update(b64d.decodeBuffer(sAttributes));
				htTicketContext.put("attributes_hash", org.aselect.system.utils.Utils.byteArrayToHexString(md.digest()));
			}
			else
				htTicketContext.put("attributes_hash", new String(""));

			// Create ticket
			String sTicket = _ticketManager.createTicket(htTicketContext);
			if (sTicket == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "TicketManager could not create ticket");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_TOO_MUCH_USERS;
				return;
			}

			// NO, this is the agent ticket
			// timeSensor.setTimeSensorTgt(sTicket);  // TgT still valid according to the SERVER

			// prepare the response parameters for the calling application
			oOutputMessage.setParam("ticket", sTicket);
			oOutputMessage.setParam("ticket_start_time", new Long(_ticketManager.getTicketStartTime(sTicket))
					.toString());
			oOutputMessage.setParam("ticket_exp_time", new Long(_ticketManager.getTicketTimeout(sTicket)).toString());
			oOutputMessage.setParam("uid", sUID);
			oOutputMessage.setParam("organization", sOrg);
			oOutputMessage.setParam("authsp_level", sAL);
			oOutputMessage.setParam("authsp", sASP);
			// 1.4 backwards compatibility
			oOutputMessage.setParam("asp_level", sAL);
			oOutputMessage.setParam("asp", sASP);

			if (sAttributes != null)
				oOutputMessage.setParam("attributes", sAttributes);

			_sErrorCode = Errors.ERROR_ASELECT_SUCCESS;

			// delete the session context as we dont need it anymore
			_sessionManager.killSession(sRid);
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create response message.", eAC);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
		catch (Exception e) {
			sbBuffer = new StringBuffer("Exception while processing request: \"");
			sbBuffer.append(e.getMessage());
			sbBuffer.append("\"");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), e);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
	}

	/**
	 * Performs verification of A-Select application ticket. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method performs the verification of the user ticket when a user is accessing the calling application having
	 * a application ticket.<br>
	 * <br>
	 * NOTE: The optional parameter <code>attributes_hash</code> can be used to verify the received attributes. If the
	 * hash is incorrect the response will contain the error code
	 * <code>{@link Errors#ERROR_ASELECT_AGENT_CORRUPT_ATTRIBUTES}</code> and a new complete set of attributes belonging
	 * to the ticket. <br>
	 * <br>
	 * This method will make an authorization decision based on the authorization rules available for the application
	 * and the attributes stored in the user's session. <br>
	 * <br>
	 * This method processes the <code>verify_ticket</code> request. <br>
	 * <br>
	 * This API request should contain the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>request</code></td>
	 * <td>Should contain <code>verify_ticket</code>.</td>
	 * </tr>
	 * <tr>
	 * <td><code>ticket</code></td>
	 * <td>The A-Select application ticket that was issued to the user.</td>
	 * </tr>
	 * <tr>
	 * <td><code>uid</code></td>
	 * <td>The user ID.</td>
	 * </tr>
	 * <tr>
	 * <td><code>organization</code></td>
	 * <td>The organization that the user belongs to.</td>
	 * </tr>
	 * <tr>
	 * <td><code>attributes_hash</code></td>
	 * <td><b>OPTIONAL</b>. A SHA1 hash over the previously received attributes. If this parameter is present, the hash
	 * is compared to a SHA1 hash of the attributes stored in the Agent.<br>
	 * The SHA1 hash is computed by hashing the complete attributes value received in the previous call to
	 * {@link RequestHandler#processVerifyCredentialsRequest}</td>
	 * </tr>
	 * <tr>
	 * <td><code>request_uri</code></td>
	 * <td><b>OPTIONAL</b>. The URI that is used for authorizing a user. Only authorization rules that are conforming
	 * this URI are evaluated.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * The API response contains the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>attributes</code></td>
	 * <td><b>OPTIONAL</b>. If attribute(hash) verification failed, this parameter contains the complete set of
	 * attributes. <br>
	 * <br>
	 * See {@link RequestHandler#processVerifyCredentialsRequest} for detailed information.</td>
	 * </tr>
	 * <tr>
	 * <td><code>result_code</code></td>
	 * <td>The A-Select response code:
	 * <ul>
	 * <li>{@link Errors#ERROR_ASELECT_SUCCESS} (OK)</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INVALID_REQUEST}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_UNKNOWN_TICKET}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INTERNAL_ERROR}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_CORRUPT_ATTRIBUTES}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_AUTHORIZATION_FAILED}</li>
	 * </ul>
	 * </td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oInputMessage != null</code></li>
	 * <li><code>oOutputMessage != null</code></li>
	 * <li>The caller must have validated A-Select credentials with the A-Select Server (
	 * {@link #processVerifyCredentialsRequest(IInputMessage, IOutputMessage)}) and thus a ticket context must be
	 * present identified by the given <code>ticket</code>.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * On successful processing the given uid and organisation are checked upon and are therefore valid. <br>
	 * 
	 * @param oInputMessage
	 *            The API request message.
	 * @param oOutputMessage
	 *            The API response message.
	 * @throws ASelectCommunicationException
	 *             If setting response parameters fails.
	 */
	private void processVerifyTicketRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
		throws ASelectCommunicationException
	{
		String sMethod = "processVerifyTicketRequest()";
		StringBuffer sbBuffer = new StringBuffer();
		String sTicket = null;
		String sUid = null;
		String sOrg = null;
		String sAttributesHash = null;
		String sRequestURI = null;
		String sIP = null;
		String sLanguage = null;

		try {
			try {
				// get required API parameters
				sTicket = oInputMessage.getParam("ticket");
				sUid = oInputMessage.getParam("uid");
				sOrg = oInputMessage.getParam("organization");
			}
			catch (ASelectCommunicationException eAC) {
				// missing required API parameters
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received.", eAC);
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
				return;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "VerTICKET uid="+sUid + ", org="+sOrg + ", ticket="+sTicket);

			// Get optional parameters
			// Parameter "attributes_hash" and 'request_uri' are not required
			// Bauke: modified, if "attributes_hash" was not present, the other parameters would not be read.
			try {
				sAttributesHash = oInputMessage.getParam("attributes_hash");
			}
			catch (ASelectCommunicationException e) {
			}
			try {
				sRequestURI = oInputMessage.getParam("request_uri");
			}
			catch (ASelectCommunicationException e) {
			}
			try {
				sIP = oInputMessage.getParam("ip");
			}
			catch (ASelectCommunicationException e) {
			}
			try {
				sLanguage = oInputMessage.getParam("language");
			}
			catch (ASelectCommunicationException e) {
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "VerTICKET attributes_hash=" + sAttributesHash
					+ ", request_uri=" + sRequestURI + ", ip=" + sIP);

			// get the ticket context
			HashMap htTicketContext = _ticketManager.getTicketContext(sTicket);
			if (htTicketContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request: unknown ticket.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_UNKNOWN_TICKET;
				return;
			}

			String sStoredUid = (String) htTicketContext.get("uid");
			String sStoredOrg = (String) htTicketContext.get("organization");
			String sStoredAttributes = (String) htTicketContext.get("attributes_hash");

			// check uid match
			if (!sStoredUid.equals(sUid)) {
				sbBuffer = new StringBuffer("Invalid request: uid mismatch: expected ");
				sbBuffer.append(sStoredUid).append(" but got ").append(sUid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_TICKET_NOT_VALID;
				return;
			}
			// check organization match
			if (!sStoredOrg.equals(sOrg)) {
				sbBuffer = new StringBuffer("Invalid request: organization mismatch: ");
				sbBuffer.append("expected ").append(sStoredOrg);
				sbBuffer.append(" but got ").append(sOrg);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_TICKET_NOT_VALID;
				return;
			}
			// match attributes
			if (sAttributesHash != null) {
				if (!sStoredAttributes.equalsIgnoreCase(sAttributesHash)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Received attributes do not match stored attributes.");
					sStoredAttributes = (String) htTicketContext.get("attributes");
					if (sStoredAttributes == null)
						sStoredAttributes = "";
					oOutputMessage.setParam("attributes", sStoredAttributes);
					_sErrorCode = Errors.ERROR_ASELECT_AGENT_CORRUPT_ATTRIBUTES;
					return;
				}
			}
			
			// Authorize if applicable
			if (_bAuthorization) {
				// get app_id
				String sAppId = (String) htTicketContext.get("app_id");
				if (Utils.hasValue(sAppId))
					timeSensor.setTimeSensorAppId(sAppId);

				// Get user attributes
				HashMap htUserAttributes = deserializeAttributes((String) htTicketContext.get("attributes"));

				_systemLogger.log(Level.INFO, MODULE, sMethod, "VerTICKET attr=" + htUserAttributes);

				// Add ip if applicable
				if (sIP != null)
					htUserAttributes.put(IP_ATTRIBUTE, sIP);
				// Add current date
				DateFormat df = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT); // current time
				htUserAttributes.put(CURRENT_TIME_ATTRIBUTE, df.format(new Date(System.currentTimeMillis())));
				// Add all Ticket attributes
				htUserAttributes.putAll(htTicketContext);
				// Remove encoded attributes
				htUserAttributes.remove("attributes");
				if (!AuthorizationEngine.getHandle().isUserAuthorized(sAppId, sRequestURI, htUserAttributes)) {
					// not authorized
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "User not authorized to access application "+sAppId);
					_sErrorCode = Errors.ERROR_ASELECT_AGENT_AUTHORIZATION_FAILED;
					return;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "VerTICKET OK");
			}

			// Bauke: added, upgrade ticket so it will live longer and prosper some more
			// must also be send to the server, to keep the user's session alive accross different applications
			// START NEW CODE
			boolean _bSendUpgrade_tgt = true;
			if (_bSendUpgrade_tgt) {
				String sCryptedCredentials = (String) htTicketContext.get("crypted_credentials");
				String sAselectServer = (String) htTicketContext.get("a-select-server");
				HashMap htRequest = new HashMap();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "VerTICKET upgrade_tgt");
				htRequest.put("request", "upgrade_tgt");
				htRequest.put("a-select-server", sAselectServer);
				// htRequest.put("rid",sRid);
				htRequest.put("crypted_credentials", sCryptedCredentials);

				// 20091113, Bauke: added, to let the filter report the user's language to the A-Select server
				if (sLanguage != null)
					htRequest.put("language", sLanguage);

				// Send to SERVER
				htRequest.put("usi", timeSensor.getTimeSensorId());
				HashMap htResponseParameters = sendToASelectServer(htRequest);
				if (htResponseParameters.isEmpty()) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not reach A-Select Server.");
					_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
					return;
				}
				String sResultCode = (String) htResponseParameters.get("result_code");
				if (sResultCode == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid response from A-Select Server.");
					_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
					return;
				}
				sLanguage = (String) htResponseParameters.get("language");
				if (sLanguage != null) {
					oOutputMessage.setParam("language", sLanguage);
				}
				if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
					sbBuffer = new StringBuffer("A-Select Server returned error: '");
					sbBuffer.append(sResultCode);
					sbBuffer.append("'.");
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
					_sErrorCode = sResultCode;
					return;
				}
			}
			// END NEW CODE

			String sAppArgs = (String)htTicketContext.get("aselect_app_args");
			_ticketManager.updateTicketContext(sTicket, htTicketContext);
			
			// NO, this is the agent ticket
			// timeSensor.setTimeSensorTgt(sTicket);  // TgT still valid according to local checks (and upgrade_ticket)
			
			// Ticket OK, create response message
			_sErrorCode = Errors.ERROR_ASELECT_SUCCESS;
			if (sAppArgs != null)
				oOutputMessage.setParam("aselect_app_args", sAppArgs);
		}
		catch (NumberFormatException eNF) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create response message.", eNF);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
		catch (ASelectCommunicationException eAC) {
			sbBuffer = new StringBuffer("Could not create response message.");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), eAC);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error while processing request", eAS);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error while processing request", e);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
	}

	/**
	 * Supplies all attributes. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method performs the retrieval of all known attributes after the verification of the user ticket when a user
	 * is accessing the calling application having a application ticket. This method processes the
	 * <code>attributes</code> request. <br>
	 * <br>
	 * This API request should contain the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>request</code></td>
	 * <td>Should contain <code>attributes</code>.</td>
	 * </tr>
	 * <tr>
	 * <td><code>ticket</code></td>
	 * <td>The A-Select application ticket that was issued to the user.</td>
	 * </tr>
	 * <tr>
	 * <td><code>uid</code></td>
	 * <td>The user ID.</td>
	 * </tr>
	 * <tr>
	 * <td><code>organization</code></td>
	 * <td>The organization that the user belongs to.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * The API response contains the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>ticket_start_time</code></td>
	 * <td>The start time of the application ticket.</td>
	 * </tr>
	 * <tr>
	 * <td><code>ticket_exp_time</code></td>
	 * <td>The expiration time of the application ticket.</td>
	 * </tr>
	 * <tr>
	 * <td><code>uid</code></td>
	 * <td>The user ID.</td>
	 * </tr>
	 * <tr>
	 * <td><code>organization</code></td>
	 * <td>The users' organisation.</td>
	 * </tr>
	 * <tr>
	 * <td><code>authsp_level</code></td>
	 * <td>The authentication level of the AuthSP that authenticated the user.</td>
	 * </tr>
	 * <tr>
	 * <td><code>authsp</code></td>
	 * <td>The AuthSP that authenticated the user.</td>
	 * </tr>
	 * <tr>
	 * <td><code>asp_level</code></td>
	 * <td>The authentication level of the AuthSP that authenticated the user. (added for backwards compatibility with
	 * A-Select 1.4)</td>
	 * </tr>
	 * <tr>
	 * <td><code>asp</code></td>
	 * <td>The AuthSP that authenticated the user. (added for backwards compatibility with A-Select 1.4)</td>
	 * </tr>
	 * <tr>
	 * <td><code>attributes</code></td>
	 * <td>The attributes.</td>
	 * </tr>
	 * <tr>
	 * <td><code>attributes</code></td>
	 * <td>The complete set of attributes. <br>
	 * <br>
	 * See {@link RequestHandler#processVerifyCredentialsRequest} for detailed information. <br>
	 * <br>
	 * <b>NOTE: If no attributes are available the attributes parameter is still sent but will contain an empty string
	 * <code>""</code></b></td>
	 * </tr>
	 * <tr>
	 * <td><code>result_code</code></td>
	 * <td>The A-Select response code:
	 * <ul>
	 * <li>{@link Errors#ERROR_ASELECT_SUCCESS} (OK)</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INVALID_REQUEST}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_UNKNOWN_TICKET}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INTERNAL_ERROR}</li>
	 * </ul>
	 * </td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oInputMessage != null</code></li>
	 * <li><code>oOutputMessage != null</code></li>
	 * <li>The caller must have validated A-Select credentials with the A-Select Server (
	 * {@link #processVerifyCredentialsRequest(IInputMessage, IOutputMessage)}) and thus a ticket context must be
	 * present identified by the given <code>ticket</code>.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * On successful processing the given uid and organisation are checked upon and are therefore valid. <br>
	 * 
	 * @param oInputMessage
	 *            The API request message.
	 * @param oOutputMessage
	 *            The API response message.
	 * @throws ASelectCommunicationException
	 *             If setting response parameters fails.
	 */
	private void processAttributesRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
	throws ASelectCommunicationException
	{
		String sMethod = "processAttributesRequest()";
		StringBuffer sbBuffer = new StringBuffer();

		try {
			String sTicket = null;
			String sUid = null;
			String sOrg = null;
			
			try {  // get required API parameters
				sTicket = oInputMessage.getParam("ticket");
				sUid = oInputMessage.getParam("uid");
				sOrg = oInputMessage.getParam("organization");
			}
			catch (ASelectCommunicationException eAC) {  // missing required API parameters
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received.", eAC);
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
				return;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "AttrReq uid="+sUid + ", org="+sOrg + ", ticket="+sTicket);

			// get the ticket context
			HashMap htTicketContext = _ticketManager.getTicketContext(sTicket);
			if (htTicketContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request: unknown ticket.");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_UNKNOWN_TICKET;
				return;
			}

			String sAuthSP = (String) htTicketContext.get("authsp");
			String sAppLevel = (String) htTicketContext.get("app_level");
			String sAppId = (String) htTicketContext.get("app_id");
			if (Utils.hasValue(sAppId))
				timeSensor.setTimeSensorAppId(sAppId);

			oOutputMessage.setParam("ticket_start_time", new Long(_ticketManager.getTicketStartTime(sTicket))
					.toString());
			oOutputMessage.setParam("ticket_exp_time", new Long(_ticketManager.getTicketTimeout(sTicket)).toString());
			oOutputMessage.setParam("uid", sUid);
			oOutputMessage.setParam("organization", sOrg);
			oOutputMessage.setParam("authsp_level", sAppLevel);
			oOutputMessage.setParam("authsp", sAuthSP);
			// 1.4 backwards compatibility
			oOutputMessage.setParam("asp_level", sAppLevel);
			oOutputMessage.setParam("asp", sAuthSP);

			// Append attributes to the result
			String sAttributes = (String) htTicketContext.get("attributes");
			if (sAttributes != null)
				oOutputMessage.setParam("attributes", sAttributes);
			else
				oOutputMessage.setParam("attributes", "");

			_sErrorCode = Errors.ERROR_ASELECT_SUCCESS;
		}
		catch (NumberFormatException eNF) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create response message.", eNF);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create response message.", eAC);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
		catch (Exception e) {

			sbBuffer = new StringBuffer("Exception while processing request: \"");
			sbBuffer.append(e.getMessage());
			sbBuffer.append("\"");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), e);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
	}

	/**
	 * Performs the deletion of an A-Select application ticket. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Processes a kill_ticket request. That is, the caller has specified <code>request=kill_ticket</code>. <br>
	 * <br>
	 * This API request should contain the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>request</code></td>
	 * <td>Should contain <code>kill_ticket</code>.</td>
	 * </tr>
	 * <tr>
	 * <td><code>ticket</code></td>
	 * <td>The A-Select application ticket that was issued to the user.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * The API response contains the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>result_code</code></td>
	 * <td>The A-Select response code:
	 * <ul>
	 * <li>{@link Errors#ERROR_ASELECT_SUCCESS} (OK)</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INVALID_REQUEST}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_UNKNOWN_TICKET}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INTERNAL_ERROR}</li>
	 * </ul>
	 * </td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oInputMessage != null</code></li>
	 * <li><code>oOutputMessage != null</code></li>
	 * <li>The caller must have a valid A-Select application <code>ticket</code>.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The ticket context is deleted and the application ticket is no longer valid. The user can still have a valid TGT
	 * at the A-Select server. <br>
	 * 
	 * @param oInputMessage
	 *            The API request message.
	 * @param oOutputMessage
	 *            The API response message.
	 * @throws ASelectCommunicationException
	 *             If setting response parameters fails.
	 */
	private void processKillTicketRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
		throws ASelectCommunicationException
	{
		String sMethod = "processKillTicketRequest()";
		StringBuffer sbBuffer = new StringBuffer();
		String sTicket = null;
		try {
			// Get parameters
			sTicket = oInputMessage.getParam("ticket"); // mandatory
			_systemLogger.log(Level.INFO, MODULE, sMethod, "VerCRED sTicket=" + sTicket);

			if (!_ticketManager.killTicket(sTicket)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not kill ticket");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_UNKNOWN_TICKET;
				return;
			}

			// set response parameters
			_sErrorCode = Errors.ERROR_ASELECT_SUCCESS;
		}
		catch (ASelectCommunicationException eAC) {
			// mandatory parameter missing
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received.", eAC);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
			return;
		}
		catch (Exception e) {
			sbBuffer = new StringBuffer("Exception while processing request: \"");
			sbBuffer.append(e.getMessage());
			sbBuffer.append("\"");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), e);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
	}

	// "tgt_blob" "a-select-server" "signature"
	// Optional: "logout_return_url"
	/**
	 * Process kill tgt request.
	 * 
	 * @param oInputMessage
	 *            the o input message
	 * @param oOutputMessage
	 *            the o output message
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 */
	private void processKillTgtRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
		throws ASelectCommunicationException
	{
		String sMethod = "processKillTgtRequest()";
		StringBuffer sbBuffer = new StringBuffer();
		String sTicket = null;
		try {
			// Get parameters
			sTicket = oInputMessage.getParam("ticket"); // mandatory
			_systemLogger.log(Level.INFO, MODULE, sMethod, "VerCRED sTicket=" + sTicket);

			if (!_ticketManager.killTicket(sTicket)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not kill ticket");
				_sErrorCode = Errors.ERROR_ASELECT_AGENT_UNKNOWN_TICKET;
				return;
			}

			// set response parameters
			_sErrorCode = Errors.ERROR_ASELECT_SUCCESS;
		}
		catch (ASelectCommunicationException eAC) {
			// mandatory parameter missing
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received.", eAC);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
			return;
		}
		catch (Exception e) {
			sbBuffer = new StringBuffer("Exception while processing request: \"");
			sbBuffer.append(e.getMessage());
			sbBuffer.append("\"");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), e);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR;
		}
	}

	/**
	 * Add authorization rules to the A-Select Agent Authorization Engine. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method processes the <code>request=set_authorization_rules</code> API call. The
	 * <code>set_authorization_rules</code> request can be used by applications and A-Select Filters to add
	 * authorization rules to the A-Select Agent Authorisation engine. These rules are then used for authorizing users
	 * during the runtime of the A-Select Agent. <br>
	 * <br>
	 * If authorization rules exist for the application that is issuing the request, for example configured in the Agent
	 * configuration, they are removed before adding the new authorization rules. <br>
	 * <br>
	 * This API request should contain the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>request</code></td>
	 * <td>Should contain <code>set_authorization_rules</code>.</td>
	 * </tr>
	 * <tr>
	 * <td><code>app_id</code></td>
	 * <td>The id of the application that has been registered with the A-Select Server.</td>
	 * </tr>
	 * <tr>
	 * <td><code>rules</code></td>
	 * <td>The authorization rules that have to be added to the application. These rules should be placed in a array
	 * parameter conform the following syntax: <code>
	 * rules[]=[Rule-1];[URI-1]&rules[]=[Rule-2];[URI-2]rules[]=[Rule-n];[URI-n]
	 * </code> <br>
	 * <br>
	 * The URI may be omitted.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * The API response contains the following parameters: <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">Parameter</td>
	 * <td bgcolor="#EEEEFF">Value</td>
	 * </tr>
	 * <tr>
	 * <td><code>result_code</code></td>
	 * <td>The A-Select response code:
	 * <ul>
	 * <li>{@link Errors#ERROR_ASELECT_SUCCESS} (OK)</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_INVALID_REQUEST}</li>
	 * <li>{@link Errors#ERROR_ASELECT_AGENT_AUTHORIZATION_NOT_ENABLED}</li>
	 * </ul>
	 * </td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oInputMessage != null</code></li>
	 * <li><code>oOutputMessage != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The possible existing rules for this application are removed. The new authorization rules are set. <br>
	 * 
	 * @param oInputMessage
	 *            The API request message.
	 * @param oOutputMessage
	 *            The API response message.
	 * @throws ASelectCommunicationException
	 *             If setting response parameters fails.
	 */
	private void processSetAuthorizationRulesRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
		throws ASelectCommunicationException
	{
		final String sMethod = "processSetAuthorizationRulesRequest()";
		if (!_bAuthorization) { // Authorization not enabled
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received: authorization is not enabled.");
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_AUTHORIZATION_NOT_ENABLED;
			return;
		}

		try { // get required API parameters
			String sAppId = oInputMessage.getParam("app_id");
			String[] saReceivedRules = oInputMessage.getArray("rules");
			if (Utils.hasValue(sAppId))
				timeSensor.setTimeSensorAppId(sAppId);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RULES sAppId=" + sAppId + ", saReceivedRules="
					+ saReceivedRules);

			// Split id, rules and URI's
			String[] saRuleIDs = new String[saReceivedRules.length];
			String[] saURIs = new String[saReceivedRules.length];
			String[] saRules = new String[saReceivedRules.length];
			for (int i = 0; i < saReceivedRules.length; i++) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "RULES Rule=" + sAppId + ", saReceivedRules="
						+ saReceivedRules[i]);
				String[] saSplit = saReceivedRules[i].split(";", 3);
				if (saSplit.length == 3) {
					saRuleIDs[i] = saSplit[0];
					if (!saSplit[1].equals(""))
						saURIs[i] = saSplit[1];
					else
						saURIs[i] = null;
					saRules[i] = saSplit[2];

				}
				else if (saSplit.length == 2) {
					saRuleIDs[i] = saSplit[0];
					saRules[i] = saSplit[1];
					saURIs[i] = null;
				}
				else { // Invalid rules
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received: invalid rules[].");
					_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
					return;
				}
			}
			// add rules for this application
			AuthorizationEngine.getHandle().setAuthorizationRules(sAppId, saRuleIDs, saRules, saURIs);

			// set result code OK
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Authorization rules set for application " + sAppId);
			_sErrorCode = Errors.ERROR_ASELECT_SUCCESS;
		}
		catch (ASelectCommunicationException eAC) {
			// missing required API parameters
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received.", eAC);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
		}
		catch (ASelectAuthorizationException e) {
			// Invalid rule parameter
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Invalid request received: one or more rules are invalid", e);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST;
			return;
		}
	}

	/**
	 * Send a request to the A-Select Server. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method sends a request to the A-Select Server by using a configured {@link IClientCommunicator}
	 * implementation.
	 * 
	 * @param htParams
	 *            the request parameters.
	 * @return The response parameters.
	 */
	private HashMap sendToASelectServer(HashMap htParams)
	{
		String sMethod = "sendToASelectServer";
		HashMap htResponse = new HashMap();

		ASelectAgentSAMAgent oSAMAgent = ASelectAgentSAMAgent.getHandle();
		try {
			SAMResource oResource = oSAMAgent.getActiveResource("aselectserver");
			Object oConfigSection = oResource.getAttributes();

			String sAS = _configManager.getParam(oConfigSection, "aselect-server-id");
			htParams.put("a-select-server", sAS);
			signRequest(htParams);

			String sAsUrl = _configManager.getParam(oConfigSection, "url");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "ToSERVER, url=" + sAsUrl + ", params=" + htParams);
			htResponse = sendRequestToASelectServer(sAsUrl, htParams);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "FromSERVER, htResponse=" + htResponse);
		}
		catch (ASelectSAMException eSAM) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error retrieving A-Select Server resource.", eSAM);
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Mandatory A-Select Server configuration parameter not found", eAC);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unknown error reading A-Select server configuration.", e);
		}
		return htResponse;
	}

	/**
	 * Uses a <code>IClientCommunicator</code> to send a API call to the A-Select server.
	 * 
	 * @param sUrl
	 *            The A-Select Server URL.
	 * @param htParamsTable
	 *            The parameters to send to A-Select.
	 * @return The return parameters in a <code>HashMap</code>.
	 */
	protected HashMap sendRequestToASelectServer(String sUrl, HashMap htParamsTable)
	{
		String sMethod = "sendRequestToASelectServer";

		// send message
		HashMap htReturnTable = new HashMap();
		timeSensor.timeSensorPause();
		try {
			htReturnTable = _clientCommunicator.sendMessage(htParamsTable, sUrl);
		}
		catch (ASelectCommunicationException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "The A-Select server could not be reached.", e);
			_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
		}
		timeSensor.timeSensorResume();

		// return reponse
		return htReturnTable;
	}

	/**
	 * Sign a request if necessary.
	 * 
	 * @param htRequest
	 *            The request parameters.
	 * @throws Exception
	 *             If signing fails.
	 */
	private void signRequest(HashMap htRequest)
		throws Exception
	{
		if (!_configManager.isSigningEnabled())
			return;
		try {
			String sSignatureAlgorithm = _configManager.getSignatureAlgorithm();
			Provider oSignatureProvider = _configManager.getSignatureProvider();
			Signature oSignature = null;
			if (oSignatureProvider != null)
				oSignature = Signature.getInstance(sSignatureAlgorithm, oSignatureProvider);
			else
				oSignature = Signature.getInstance(sSignatureAlgorithm);

			StringBuffer sbCreateFrom = new StringBuffer();
			TreeSet sortedSet = new TreeSet(htRequest.keySet());
			for (Iterator i = sortedSet.iterator(); i.hasNext();) {
				String sKey = (String) i.next();
				if (!sKey.equals("request"))
					sbCreateFrom.append(htRequest.get(sKey));
			}

			_systemLogger.log(Level.INFO, MODULE, "signRequest()", "Sign:" + sbCreateFrom);
			oSignature.initSign(_configManager.getSigningKey());
			oSignature.update(sbCreateFrom.toString().getBytes());
			byte[] baRawSignature = oSignature.sign();
			BASE64Encoder oBase64Enc = new BASE64Encoder();
			String sRawSignature = oBase64Enc.encode(baRawSignature);
			htRequest.put("signature", sRawSignature);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, "signRequest()", "Could not sign request:", e);
			throw new Exception("Unable to sign request.");
		}
	}
	
	// RH, 20100622, sn 
	// RH, Avoid cyclic dependency system<->server and dependency agent->server
	/**
	 * Deserialize attributes and convertion to a <code>HashMap</code>. <br/>
	 * Conatins support for multivalue attributes, with name of type <code>
	 * String</code> and value of type <code>Vector</code>.
	 * 
	 * @param sSerializedAttributes
	 *            the serialized attributes.
	 * @return The deserialized attributes (key,value in <code>HashMap</code>)
	 * @throws ASelectException
	 *             If URLDecode fails
	 */
	private HashMap deserializeAttributes(String sSerializedAttributes)
		throws ASelectException
	{
		String sMethod = "deSerializeAttributes";
		HashMap htAttributes = new HashMap();
		if (sSerializedAttributes != null) {  // Attributes available
			try {  // base64 decode
				BASE64Decoder base64Decoder = new BASE64Decoder();
				String sDecodedUserAttrs = new String(base64Decoder.decodeBuffer(sSerializedAttributes));
	
				// decode & and = chars
				String[] saAttrs = sDecodedUserAttrs.split("&");
				for (int i = 0; i < saAttrs.length; i++) {
					int iEqualChar = saAttrs[i].indexOf("=");
					String sKey = "";
					String sValue = "";
					Vector vVector = null;
	
					if (iEqualChar > 0) {
						sKey = URLDecoder.decode(saAttrs[i].substring(0, iEqualChar), "UTF-8");
						sValue = URLDecoder.decode(saAttrs[i].substring(iEqualChar + 1), "UTF-8");
	
						if (sKey.endsWith("[]")) { // it's a multi-valued attribute
							// Strip [] from sKey
							sKey = sKey.substring(0, sKey.length() - 2);
							if ((vVector = (Vector) htAttributes.get(sKey)) == null)
								vVector = new Vector();
							vVector.add(sValue);
						}
					}
					else
						sKey = URLDecoder.decode(saAttrs[i], "UTF-8");
	
					if (vVector != null)  // store multivalue attribute
						htAttributes.put(sKey, vVector);
					else  // store singlevalue attribute
						htAttributes.put(sKey, sValue);
				}
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error during deserialization of attributes", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
		}
		return htAttributes;
	}
	// RH, 20100622, en 

}
