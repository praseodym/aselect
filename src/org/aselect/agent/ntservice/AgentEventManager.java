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
 * $Id: AgentEventManager.java,v 1.5 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: AgentEventManager.java,v $
 * Revision 1.5  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.4  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/03/03 17:24:19  erwin
 * Applied code style, added javadoc comment.
 *
 * Revision 1.2  2005/02/24 15:09:09  ali
 * Added IAgentEventListener class and updates internal Javadoc.
 *
 */

package org.aselect.agent.ntservice;

import java.util.Vector;

// TODO: Auto-generated Javadoc
/**
 * The agent event manager. <br>
 * <br>
 * <b>Description: </b> <br>
 * This manager manages events of type <code>AgentEvent</code>. <br>
 * <br>
 * <i>Note: this manager is implemented as a Singleton.</i> <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * none. <br>
 * 
 * @author Alfa & Ariss
 * @see AgentEvent
 */
public class AgentEventManager extends Vector
{
	/** The static handle to the actual <code>AgentEventManager</code>. */
	private static AgentEventManager _oHandle = null;

	/**
	 * private constructor.
	 */
	private AgentEventManager() {
		super();
	}

	/**
	 * Get a static handle to the <code>AgentEventManager</code> instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if a static instance exists, otherwise it is created. This instance is returned. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * A static instance of the <code>AgentEventManager</code> exists. <br>
	 * 
	 * @return A static handle to the <code>AgentEventManager</code>
	 */
	public static AgentEventManager getInstance()
	{
		if (_oHandle == null) {
			_oHandle = new AgentEventManager();
		}
		return _oHandle;
	}

	/**
	 * Dispatch an Agent event. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Dispatches a Agent event to all listeners. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param iEventID
	 *            The ID of the event.
	 */
	public void dispatchAgentEvent(int iEventID)
	{
		AgentEvent xEvent = new AgentEvent(iEventID);

		for (int i = 0; i < size(); i++) {
			Object o = get(i);

			if (o == null)
				continue;

			((IAgentEventListener) o).handleAgentEvent(xEvent);
		}
	}

	/**
	 * Add a new listener for Agent events. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Adds the given <code>IAgentEventListener</code> to the listeners. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>oListener != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The listeners contains the given listener. <br>
	 * 
	 * @param oListener
	 *            The <code>IAgentEventListener</code> to add.
	 */
	public void addAgentEventListener(IAgentEventListener oListener)
	{
		if (!contains(oListener))
			add(oListener);
	}

	/**
	 * Removes a listener for Agent events. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Removes the given <code>IAgentEventListener</code> from the listeners. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>oListener != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The listeners does not contain the given listener. <br>
	 * 
	 * @param oListener
	 *            The <code>IAgentEventListener</code> to remove.
	 */
	public void removeAgentEventListener(IAgentEventListener oListener)
	{
		remove(oListener);
	}
}