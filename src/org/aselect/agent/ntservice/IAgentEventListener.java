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
 * $Id: IAgentEventListener.java,v 1.4 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: IAgentEventListener.java,v $
 * Revision 1.4  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.3  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/03/03 17:24:19  erwin
 * Applied code style, added javadoc comment.
 *
 * Revision 1.1  2005/02/24 15:09:09  ali
 * Added IAgentEventListener class and updates internal Javadoc.
 *
 */

package org.aselect.agent.ntservice;

/**
 * Interface for handling events in Windows Services. <br>
 * <br>
 * <b>Description:</b><br>
 * Specifies the interface to handle A-Select Agent events. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public interface IAgentEventListener
{
	
	/**
	 * Processes a <code>AgentEvent</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method should be called if a Windows service event is received. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * none. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>oEvent != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oEvent
	 *            The event that should be processed.
	 */
	public void handleAgentEvent(AgentEvent oEvent);
}
