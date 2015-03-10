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
 * $Id: AgentNTService.java,v 1.11 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: AgentNTService.java,v $
 * Revision 1.11  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.10  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.9  2005/04/27 13:50:00  martijn
 * fixed bug: now using correct error handling in init() method
 *
 * Revision 1.8  2005/04/15 11:51:42  tom
 * Removed old logging statements
 *
 * Revision 1.7  2005/03/16 11:10:35  erwin
 * Fixed problem with agent destroy in NT service mode.
 *
 * Revision 1.6  2005/03/03 17:24:19  erwin
 * Applied code style, added javadoc comment.
 *
 * Revision 1.5  2005/03/01 08:34:50  erwin
 * Removed args[] in constructor.
 *
 * Revision 1.4  2005/02/28 14:09:26  erwin
 * Fixed logging for stopAgent()
 *
 * Revision 1.3  2005/02/25 15:51:33  erwin
 * Improved logging.
 *
 * Revision 1.2  2005/02/24 15:09:09  ali
 * Added IAgentEventListener class and updates internal Javadoc.
 *
 */

package org.aselect.agent.ntservice;

import java.util.logging.Level;

import org.aselect.agent.ASelectAgent;
import org.aselect.agent.log.ASelectAgentSystemLogger;
import org.aselect.system.logging.SystemLogger;


/**
 * A-Select agent service wrapper. <br>
 * <br>
 * <b>Description:</b><br>
 * This class can be used to use the start the A-Select Agent as a Windows service. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * none. <br>
 * 
 * @author Alfa & Ariss
 */
public class AgentNTService implements IAgentEventListener
{
	/** The MODULE name. */
	public static final String MODULE = "AgentNTService";

	/** The logger for system log entries. */
	private SystemLogger _systemLogger;

	/** The instance. */
	private ASelectAgent _oASelectAgent = null;

	/**
	 * main[] entry point for starting the Agent in service mode. <br>
	 * <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Instantiates an <code>AgentNTService</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * none. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * none. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * none. <br>
	 * 
	 * @param saArgs
	 *            the commandline parameters.
	 */
	public static void main(String[] saArgs)
	{
		new AgentNTService();
	}

	/**
	 * Create a new intance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Instantiates an A-Select Agent and lets it start by calling the <code>init()</code> method and then the
	 * <code>startServices()</code> method. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * none. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The A-Select agent is started and the listeners and handling threads are started.
	 */
	public AgentNTService() {
		String sMethod = "AgentNTService";
		try {
			_systemLogger = ASelectAgentSystemLogger.getHandle();

			_oASelectAgent = new ASelectAgent();
			_oASelectAgent.init();
			_oASelectAgent.startServices();

			AgentEventManager.getInstance().addAgentEventListener(this);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to start the AgentNTService", e);

			if (_oASelectAgent != null)
				_oASelectAgent.destroy();

			System.exit(1);
		}
	}

	/**
	 * Handles Agent events.
	 * 
	 * @param oAgentEvent
	 *            the o agent event
	 * @see org.aselect.agent.ntservice.IAgentEventListener#handleAgentEvent(org.aselect.agent.ntservice.AgentEvent)
	 */
	public void handleAgentEvent(AgentEvent oAgentEvent)
	{
		String sMethod = "handleAgentEvent";
		if (oAgentEvent.getId() == AgentEvent.STOP) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "received STOP event; stopping");
			if (_oASelectAgent != null)
				stopAgent();
		}
		else if (oAgentEvent.getId() == AgentEvent.SHUTDOWN) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "received SHUTDOWN event; stopping");
			if (_oASelectAgent != null)
				stopAgent();
		}
	}

	/**
	 * Stops the A-Select Agent. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method calls the destroy method of the <code>ASelectAgent</code> and is usually called when receiving a
	 * "STOP" or "SHUTDOWN" event. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * none. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The A-Select agent has stopped.
	 * 
	 * @see ASelectAgent#destroy()
	 */
	private void stopAgent()
	{
		String sMethod = "stopAgent";
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Stopping Agent...");
			// stop agent
			_oASelectAgent.destroy();
			// clean GUI recourses
			_oASelectAgent.destroyGui();
			_oASelectAgent = null;
		}
		catch (Exception e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not stop Agent", e);
			System.exit(1);
		}
	}

}
