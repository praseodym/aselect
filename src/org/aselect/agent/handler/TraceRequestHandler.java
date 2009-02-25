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
 * $Id: TraceRequestHandler.java,v 1.13 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: TraceRequestHandler.java,v $
 * Revision 1.13  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.12  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.11  2005/08/30 08:14:40  erwin
 * Added Authorization functionality to the Agent
 *
 * Revision 1.10  2005/04/15 11:51:42  tom
 * Removed old logging statements
 *
 * Revision 1.9  2005/04/14 16:22:01  tom
 * Removed old logging statements
 *
 * Revision 1.8  2005/03/09 09:20:38  erwin
 * Renamed errors.
 *
 * Revision 1.7  2005/03/07 15:58:52  erwin
 * improved sendRequestToASelectServer()
 *
 * Revision 1.6  2005/03/03 17:24:19  erwin
 * Applied code style, added javadoc comment.
 *
 * Revision 1.5  2005/03/01 16:30:17  erwin
 * Fixed fixme's.
 *
 * Revision 1.4  2005/02/28 14:03:06  erwin
 * Fixed logging messages and levels.
 *
 * Revision 1.3  2005/02/25 15:51:33  erwin
 * Improved logging.
 *
 * Revision 1.2  2005/02/24 15:09:09  ali
 * Added IAgentEventListener class and updates internal Javadoc.
 *
 */

package org.aselect.agent.handler;

import java.net.Socket;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;

/**
 * Verbosely traces requests and responses. 
 * <br><br>
 * <b>Description: </b> 
 * <br>
 * This class implements a verbose trace of the requests (and responses) that
 * are handled by the super RequestHandler class that implements the API of the
 * A-Select Agent. 
 * <br><br>
 * <b>Concurrency issues: </b> 
 * <br>
 * None. 
 * <br>
 * 
 * @author Alfa & Ariss
 */
public class TraceRequestHandler extends RequestHandler
{
	/**
	 * Create new instance. 
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>
	 * Creates a new <code>TraceRequestHandler</code>.
	 * <br><br>
	 * <b>Concurrency issues: </b> 
	 * <br>
	 * Every request should have its own <code>TraceRequestHandler</code>.
	 * <br><br>
	 * <b>Preconditions: </b> 
	 * <br>
	 * none. 
	 * <br><br>
	 * <b>Postconditions: </b> 
	 * <br>
	 * The module name is set. 
	 * <br>
	 * 
	 * @param oSocket
	 *            The communication socket (incoming).
	 * @param oCommunicator
	 *            The communicator (outgoing).
	 * @param bAuthorization <code>true</code> if authorization is enabled, 
	 * 	otherwise <code>false</code>.
	 * @see RequestHandler#RequestHandler(Socket, IClientCommunicator, boolean)
	 */
	public TraceRequestHandler(Socket oSocket, IClientCommunicator oCommunicator, boolean bAuthorization) {
		super(oSocket, oCommunicator, bAuthorization);
		MODULE = "TraceRequestHandler";
	}

	/**
	 * Send a request to the A-Select Server.
	 * @see org.aselect.agent.handler.RequestHandler#sendRequestToASelectServer(java.lang.String, java.util.HashMap)
	 */
	protected HashMap sendRequestToASelectServer(String sUrl, HashMap htParamsTable)
	{
		String sMethod = "sendRequestToASelectServer()";

		_systemLogger.log(Level.FINE, MODULE, sMethod, "Sending API request");
		_systemLogger.log(Level.FINE, MODULE, sMethod, "Destination : " + sUrl);

		_systemLogger.log(Level.FINE, MODULE, sMethod, "Parameters and values:\n" + dumpHashtable(htParamsTable));

		HashMap htReturnTable = new HashMap();
		try {
			htReturnTable = super.getClientCommunicator().sendMessage(htParamsTable, sUrl);
		}
		catch (ASelectCommunicationException e) {
			StringBuffer sbError = new StringBuffer("error while sending request to A-Select Server at \"");
			sbError.append(sUrl);
			sbError.append("\"");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);

			_sErrorCode = Errors.ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER;
			return htReturnTable;
		}
		if (!htReturnTable.isEmpty()) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Response parameters and values: "
					+ dumpHashtable(htReturnTable));
		}
		return htReturnTable;
	}

	/**
	 * Create a String representation of the table.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Creates a <code>String</code> containg all keys and values 
	 * from the <code>HashMap</code>.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * none.
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * <code>htTable != null</code>
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * none.
	 * 
	 * @param htTable The table to be dumped.
	 * @return The formatted table as <code>String</code>.
	 */
	private String dumpHashtable(HashMap htTable)
	{
		String sDump = new String();

		Set keys = htTable.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
			//Enumeration eKeys = htTable.keys();
			//String sKey;
			//while (eKeys.hasMoreElements())
			//{
			//sKey = (String)eKeys.nextElement();
			sDump += ("\t" + sKey + "=" + (String) htTable.get(sKey) + "\n");
		}
		return sDump;
	}
}