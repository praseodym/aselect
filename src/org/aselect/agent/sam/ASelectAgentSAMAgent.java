/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license. See the included
 * LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE please contact SURFnet bv.
 * (http://www.surfnet.nl)
 */

/*
 * $Id: ASelectAgentSAMAgent.java,v 1.5 2006/04/14 13:42:48 tom Exp $
 * 
 * Changelog: $Log: ASelectAgentSAMAgent.java,v $
 * Changelog: Revision 1.5  2006/04/14 13:42:48  tom
 * Changelog: QA: removed javadoc version tag, minor javadoc fixes
 * Changelog:
 * Changelog: Revision 1.4  2005/09/08 12:46:02  erwin
 * Changelog: Changed version number to 1.4.2
 * Changelog:
 * Changelog: Revision 1.3  2005/03/03 17:24:20  erwin
 * Changelog: Applied code style, added javadoc comment.
 * Changelog: Revision 1.2 2005/02/24
 * 15:09:09 ali Added IAgentEventListener class and updates internal Javadoc.
 *  
 */

package org.aselect.agent.sam;

import org.aselect.agent.config.ASelectAgentConfigManager;
import org.aselect.agent.log.ASelectAgentSystemLogger;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;

/**
 * The SAM agent for the A-Select Agent.
 * <br><br>
 * <b>Description:</b><br>
 * The <code>ASelectAgentSAMAgent</code> is a {@link SAMAgent} 
 * for the A-Select Agent.
 * <br><br>
 * <i>Note: this agent is implemented as a Singleton.</i>
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 */
public class ASelectAgentSAMAgent extends SAMAgent
{

    /** The static instance */
    private static ASelectAgentSAMAgent _oASelectAgentSAMAgent;

    /**
     * Get a static handle to the <code>ASelectAgentSAMAgent</code> instance.
     * <br><br>
     * <b>Description:</b>
     * <br>
     *  Checks if a static instance exists, otherwise it is created. This 
     * instance is returned.
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
     * A static instance of the <code>ASelectAgentSAMAgent</code> exists.
     * 
     * @return A static handle to the <code>ASelectAgentSAMAgent</code>
     */
    public static ASelectAgentSAMAgent getHandle()
    {
        if (_oASelectAgentSAMAgent == null)
            _oASelectAgentSAMAgent = new ASelectAgentSAMAgent();

        return _oASelectAgentSAMAgent;
    }

    /**
     * Initializes the <code>ASelectAgentSAMAgent</code>.
     * 
     * @throws ASelectSAMException
     * @see SAMAgent#init(ConfigManager, SystemLogger)
     */
    public void init() throws ASelectSAMException
    {
        super.init(ASelectAgentConfigManager.getHandle(),
            ASelectAgentSystemLogger.getHandle());
    }

    /** Private constructor. */
    private ASelectAgentSAMAgent (){}

}