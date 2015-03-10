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
 * $Id: AbstractAPIRequestHandler.java,v 1.4 2006/05/03 10:10:18 tom Exp $ 
 * 
 * Changelog:
 * $Log: AbstractAPIRequestHandler.java,v $
 * Revision 1.4  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.2  2006/03/09 12:32:52  jeroen
 * Adaptation to support multi-valued attributes
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.1  2006/01/13 08:40:00  martijn
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.13  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.12  2005/05/20 13:08:32  erwin
 * Fixed some minor bugs in Javadoc
 *
 * Revision 1.11  2005/05/02 14:14:51  peter
 * Fixed logging and code-style
 *
 * Revision 1.10  2005/04/27 12:58:41  erwin
 * Fixed error codes and logging.
 *
 * Revision 1.9  2005/04/26 15:13:18  erwin
 * IF -> ID in error
 *
 * Revision 1.8  2005/04/15 11:51:23  tom
 * Removed old logging statements
 *
 * Revision 1.6  2005/04/07 09:05:17  remco
 * Attributes (keys and values) are now URL encoded
 *
 * Revision 1.4  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.3  2005/03/16 12:52:10  tom
 * - Fixed javadoc
 *
 * Revision 1.2  2005/03/15 15:18:51  erwin
 * Moved redundant code to seperate methods and AbstractAPIRequestHandler.
 *
 * Revision 1.1  2005/03/15 10:15:29  erwin
 * Moved redundant code to seperate class (AbstractAPIRequestHandler)
 *
 */

package org.aselect.server.request.handler.aselect.authentication;

import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.Application;
import org.aselect.server.application.ApplicationManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.BasicRequestHandler;
import org.aselect.system.communication.server.Communicator;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.communication.server.IMessageCreatorInterface;
import org.aselect.system.communication.server.IOutputMessage;
import org.aselect.system.communication.server.IProtocolRequest;
import org.aselect.system.communication.server.IProtocolResponse;
import org.aselect.system.communication.server.ServletRequestWrapper;
import org.aselect.system.communication.server.ServletResponseWrapper;
import org.aselect.system.communication.server.raw.RawMessageCreator;
import org.aselect.system.communication.server.soap11.SOAP11MessageCreator;
import org.aselect.system.communication.server.soap12.SOAP12MessageCreator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.storagemanager.SendQueue;
import org.aselect.system.utils.TimerSensor;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;

/**
 * Abstract API request handler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class can be used as a base class for request handlers which handle API requests. The
 * <code>AbstractAPIRequestHandler</code> creates an appropriate message creator. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>AbstractAPIRequestHandler</code> implementation for a single request. <br>
 * 
 * @author Alfa & Ariss
 */
public abstract class AbstractAPIRequestHandler extends BasicRequestHandler implements IAuthnRequestHandler
{
	/** The module name. Can be overwritten in sub classes */
	protected String _sModule = "AbstractAPIRequestHandler";

	/** The message creator. */
	private IMessageCreatorInterface _messageCreator = null;

	/** The system logger is in BaseRequestHandler */

	private HttpServletRequest _servletRequest;
	private HttpServletResponse _servletResponse;

	/** The server ID */
	protected String _sMyServerId;

	/** The organisation */
	protected String _sMyOrg;

	// For the needy
	protected TimerSensor _timerSensor;
	
	long _lMyThreadId;

	protected HashMap _htSessionContext;

	/**
	 * Construct a instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Handles are obtained to relevant managers and determines the protocol. <br>
	 * 
	 * @param reqParser
	 *            The request parser to be used.
	 * @param servletRequest
	 *            The request.
	 * @param servletResponse
	 *            The response.
	 * @param sMyServerId
	 *            The A-Select Server ID.
	 * @param sMyOrg
	 *            The A-Select Server organization.
	 * @throws ASelectCommunicationException
	 *             If communication fails.
	 */
	public AbstractAPIRequestHandler(RequestParser reqParser, HttpServletRequest servletRequest,
			HttpServletResponse servletResponse, String sMyServerId, String sMyOrg)
	throws ASelectCommunicationException
	{
		String sMethod = "AbstractAPIRequestHandler";

		_systemLogger = ASelectSystemLogger.getHandle();
		_servletRequest = servletRequest;
		_servletResponse = servletResponse;
		_sMyServerId = sMyServerId;
		_sMyOrg = sMyOrg;
		_lMyThreadId = Thread.currentThread().getId();
		_timerSensor = new TimerSensor(_systemLogger, "srv_aah");

		_systemLogger.log(Level.INFO, _sModule, sMethod, "Protocol=" + reqParser.getRequestProtocol());
		switch (reqParser.getRequestProtocol()) {
		case RequestParser.PROTOCOL_SOAP11:
			_messageCreator = new SOAP11MessageCreator(_servletRequest.getRequestURL().toString(), "ASelect", _systemLogger);
			break;
		case RequestParser.PROTOCOL_SOAP12:
			_messageCreator = new SOAP12MessageCreator(_servletRequest.getRequestURL().toString(), "ASelect", _systemLogger);
			break;
		case RequestParser.PROTOCOL_CGI:
			_messageCreator = new RawMessageCreator(_systemLogger);
			break;
		default:
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request protocol received.");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}

	/**
	 * Main process function. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a <code>Communicator</code> and calls
	 * {@link #processAPIRequest(IProtocolRequest, IInputMessage, IOutputMessage)}
	 * 
	 * @throws ASelectException
	 *             if communication fails and no response is send to the client.
	 */
	public void processRequest()
	throws ASelectException
	{
		String sMethod = "processRequest";
		ApplicationManager _applicationManager = ApplicationManager.getHandle();
		boolean bSuccess = false;
		_systemLogger.log(Level.INFO, _sModule, sMethod, "processRequest");

		// create protocol wrappers
		IProtocolRequest protocolRequest = new ServletRequestWrapper(_servletRequest);
		IProtocolResponse protocolResponse = new ServletResponseWrapper(_servletResponse);

		// create the communicator with the message creator
		Communicator communicator = new Communicator(_messageCreator);
		try {
			if (communicator.comInit(protocolRequest, protocolResponse)) {
				IInputMessage inputMessage = communicator.getInputMessage();
				IOutputMessage outputMessage = communicator.getOutputMessage();
				
				// 20111108, Bauke: For whoever needs it:
				_timerSensor.timerSensorStart(-1/*level unused*/, 3/*type=server*/, _lMyThreadId);  // unused by default
				String sUsi = null;
				try {
					sUsi = inputMessage.getParam("usi");  // unique sensor id
				}
				catch (Exception e) {  // Generate our own usi here
					sUsi = Tools.generateUniqueSensorId();
				}
				if (Utils.hasValue(sUsi))
					_timerSensor.setTimerSensorId(sUsi);
				
				try {
					String sServerId = null;
					String sAppId = null;

					try {
						sServerId = inputMessage.getParam("a-select-server");
					}
					catch (ASelectException ase) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameter \"a-select-server\"");
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					_systemLogger.log(Level.FINER, _sModule, sMethod, "a-select-server=" + sServerId);
					if (!sServerId.equals(_sMyServerId)) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid \"a-select-server\" parameter: "+sServerId);
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_ID_MISMATCH);
					}
					try {
						sAppId = inputMessage.getParam("app_id");
						Application app = _applicationManager.getApplication(sAppId);
						boolean doUrlEncode = app.isDoUrlEncode();
						outputMessage.setDoUrlEncode(doUrlEncode);
					}
					catch (ASelectException e) {
						_systemLogger.log(Level.INFO, _sModule, sMethod, "Parameter \"app_id\" missing / not used");
					}

					_systemLogger.log(Level.FINER, _sModule, sMethod, "AbstApiREQ processAPIRequest");
					processAPIRequest(protocolRequest, inputMessage, outputMessage);
					bSuccess = true;  // no exceptions thrown
				}
				catch (ASelectException ace) {
					_timerSensor.setTimerSensorType(0);
					try {
						outputMessage.setParam("result_code", ace.getMessage());
					}
					catch (ASelectCommunicationException ace2) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Error setting 'result_code' in outputmessage", ace2);
						throw ace2;
					}
				}
				finally {
					try {
						outputMessage.setParam("a-select-server", _sMyServerId);
					}
					catch (ASelectCommunicationException ace2) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod,
								"Error setting 'a-select-server' in outputmessage", ace2);
						throw ace2;
					}
				}

				communicator.comSend();
			}
			else { // could not init, error was sent in communicator.
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Can't initialize Message Creator object: "
						+ _messageCreator.getClass().getName());
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Error while processing API request", eAS);
			throw eAS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Internal error while processing API request", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			try {
				if (_timerSensor.getTimerSensorLevel() >= 1) {  // used
					_timerSensor.timerSensorFinish(bSuccess);
					SendQueue.getHandle().addEntry(_timerSensor.timerSensorPack());
				}
			}
			catch (Exception e) { }
		}
	}

	/**
	 * Processes the API request. <br>
	 * <br>
	 * 
	 * @param oProtocolRequest
	 *            The request protocol properties.
	 * @param oInputMessage
	 *            The input message.
	 * @param oOutputMessage
	 *            The output message.
	 * @throws ASelectException
	 *             If processing fails and no response is send to the client.
	 */
	abstract protected void processAPIRequest(IProtocolRequest oProtocolRequest, IInputMessage oInputMessage,
			IOutputMessage oOutputMessage)
	throws ASelectException;

	/**
	 * Gets the _servlet request.
	 * 
	 * @return the _servlet request
	 */
	public synchronized HttpServletRequest get_servletRequest()
	{
		return _servletRequest;
	}
}
