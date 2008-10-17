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
 * $Id: UDBConnectorFactory.java,v 1.9 2006/04/26 12:18:59 tom Exp $ 
 * 
 * Changelog:
 * $Log: UDBConnectorFactory.java,v $
 * Revision 1.9  2006/04/26 12:18:59  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.8  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/03/14 14:23:56  martijn
 * The UDBConnector init method expects the connector config section instead of a resource config section
 *
 * Revision 1.6  2005/03/11 13:52:37  martijn
 * moved config item resourcegroup from udb config section to connector config section
 *
 * Revision 1.5  2005/03/10 16:43:44  erwin
 * Improved error handling.
 *
 * Revision 1.4  2005/02/28 09:26:07  martijn
 * changed all variable names to naming convention and added java documentation
 *
 */

package org.aselect.server.udb;

import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectUDBException;


/**
 * User database connector factory.
 * <br><br>
 * <b>Description:</b><br>
 * Resolves, creates and initializes the UDB connector class as an <code>
 * IUDBConnector</code> object.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class UDBConnectorFactory
{
    /**
     * The name of the class, used for logging.
     */
    private final static String MODULE = "UDBConnectorFactory";
    
    /**
     * Method to resolve a valid UDB Connector object. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * Returns a <code>IUDBConnector</code> that can be used to connect to the 
     * A-Select User Database as configured in the A-Select Server configuration.
     * <br>
     * <b>Concurrency issues: </b> <br>
     * -
     * <br>
     * <br>
     * <b>Preconditions: </b> <br>
     * - 
     * <br>
     * <br>
     * <b>Postconditions: </b> <br>
     * - 
     * <br>
     * 
     * @return <code>null</code> if no valid <code>IUDBConnector</code> 
     * can be created.
     * @throws ASelectException If retrieving fails.
     * 
     */
    public static IUDBConnector getUDBConnector() throws ASelectException 
    {
       String sMethod = "getUDBConnector()";

        ASelectConfigManager oASelectConfigManager = null; 
        ASelectSystemLogger systemLogger = null; 
        IUDBConnector oIUDBConnector = null;
        String sConnectorType = null;
        Object oUDBConfigSection = null;
        String sConnectorID = null;
        Object oConnectorSection = null;
        
        try
        {
            oASelectConfigManager = ASelectConfigManager.getHandle();
            systemLogger = ASelectSystemLogger.getHandle();
        
            //get udb connector id from udb config section
            try
            {
                oUDBConfigSection = oASelectConfigManager.getSection(
                    null, "udb");
            }
            catch (ASelectConfigException eAC)
            {
                systemLogger.log(Level.SEVERE, MODULE, sMethod,
                    "No 'udb' config section found in configuration", eAC);
                throw eAC;
            }

            try
            {
                sConnectorID = oASelectConfigManager.getParam(
                    oUDBConfigSection, "connector");
            }
            catch (ASelectConfigException eAC)
            {
                systemLogger.log(Level.SEVERE, MODULE, sMethod,
                    "No 'connector' config item found in 'udb' config section.", eAC);
                throw eAC;
            }
            
            try
            {
                //get udb connector handler from connector section
                oConnectorSection = oASelectConfigManager.getSection(
                    oUDBConfigSection, "connector", "id=" + sConnectorID);
            }
            catch (ASelectConfigException eAC)
            {
                StringBuffer sbFailed = new StringBuffer(
                    "No 'connector' config section found with id='");
                sbFailed.append(sConnectorID);
                sbFailed.append("'");
                systemLogger.log(Level.SEVERE, MODULE, sMethod,
                    sbFailed.toString(), eAC);
                throw eAC;
            }

            try
            {
                sConnectorType = oASelectConfigManager.getParam(oConnectorSection,
                "class");
            }
            catch (ASelectConfigException eAC)
            {
                StringBuffer sbFailed = new StringBuffer(
                    "No 'class' config item found in 'connector' config section with id='");
                sbFailed.append(sConnectorID);
                sbFailed.append("'.");
                systemLogger.log(Level.SEVERE, MODULE, sMethod,
                    sbFailed.toString(), eAC);
                throw eAC;
            }
            
            try
            {
                Class oClass = Class.forName(sConnectorType);
                oIUDBConnector = (IUDBConnector)oClass.newInstance();
            }
            catch (Exception e)
            {
                StringBuffer sbFailed = new StringBuffer(
                	"Config item 'class' in 'connector' config section with id='");
                sbFailed.append(sConnectorID);
                sbFailed.append("' doesn't contain a valid IUDBConnector class");
                systemLogger.log(Level.SEVERE, MODULE, sMethod,
                    sbFailed.toString(), e);
                throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_INTERNAL,e);
            }
            
            oIUDBConnector.init(oConnectorSection);
        }
        catch (ASelectException e)
        {
           throw e;
        }
        catch (Exception e)
        {
            systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize UDB connector", e);
            throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_INTERNAL,e);
        }
        
        return oIUDBConnector;
    }
}

