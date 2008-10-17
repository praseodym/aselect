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
 * $Id: AgentEvent.java,v 1.5 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: AgentEvent.java,v $
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

/**
 * Implements the class with event codes for use with the ASelect Agent Service
 * for use in Windows environments. 
 * <br><br>
 * <b>Concurrency issues: </b> 
 * <br>
 * None. 
 * 
 * @author Alfa & Ariss
 */
public class AgentEvent
{
    /** Stop event ID. */
    public static final int STOP = 1;
    
    /** Shutdown event ID. */
    public static final int SHUTDOWN = 2;
    
    /** Close event ID */
    public static final int CLOSE = 3;
    
    /** Logoff event ID. */
    public static final int LOGOFF = 4;

    /**
     * The Event ID
     */
    private int _iID;

    /**
     * Create a new instance.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Creates a new <code>AgentEvent</code> with the given ID.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param iID The event ID.
     */
    public AgentEvent (int iID)
    {
        _iID = iID;
    }

    /**
     * get the event ID.
     * @return The event ID.
     */
    public int getId()
    {
        return _iID;
    }
}