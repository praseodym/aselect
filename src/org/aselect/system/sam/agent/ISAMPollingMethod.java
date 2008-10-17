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
 * $Id: ISAMPollingMethod.java,v 1.4 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: ISAMPollingMethod.java,v $
 * Revision 1.4  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.1  2005/02/23 14:15:31  martijn
 * added java documentation and changed variable names
 *
 */

package org.aselect.system.sam.agent;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.logging.SystemLogger;

/**
 * The interface for polling methods. 
 * <br>
 * <br>
 * <b>Description: </b> <br>
 * The interface for polling methods that can be used by the <code>SAMAgent
 * </code>.
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -
 * <br>
 * 
 * @author Alfa & Ariss
 * 
 */
public interface ISAMPollingMethod
{
    /**
     * Initialization method for the SAM polling methods.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Reads the configuration used by the polling method.
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
     * @param oResourceConfigSection the config section of the resource which 
     * has to be polled
     * @param oPollingMethodConfigSection The config section of the polling 
     * method config section
     * @param oConfigManager The config manager used to resolve the configuration
     * @param oSystemLogger the logger used for system logging
     * @throws ASelectSAMException if the poller could not be initialized
     */
    public void init(Object oResourceConfigSection, Object oPollingMethodConfigSection,
            ConfigManager oConfigManager, SystemLogger oSystemLogger)
            throws ASelectSAMException;

    /**
     * Will poll a resource.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Checks the availability of the resource by the configured interval.
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
     * @return TRUE if the resource is available, FALSE if the resource is 
     * unavailable.
     */
    public boolean poll();

}