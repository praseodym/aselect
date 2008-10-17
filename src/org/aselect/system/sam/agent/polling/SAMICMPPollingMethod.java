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
 * $Id: SAMICMPPollingMethod.java,v 1.8 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: SAMICMPPollingMethod.java,v $
 * Revision 1.8  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.7  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.6  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.5  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.4  2005/02/28 15:30:49  erwin
 * Improved logging and error handling
 *
 * Revision 1.3  2005/02/23 14:15:31  martijn
 * added java documentation and changed variable names
 *
 */

package org.aselect.system.sam.agent.polling;

import java.net.URI;
import java.util.StringTokenizer;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.ISAMPollingMethod;

/**
 * Polls a resource by using ICMP PING commands. <br>
 * <br>
 * <b>Description: </b> <br>
 * Will check the availability of a resource by sending a ping (ICMP echo
 * request). <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class SAMICMPPollingMethod implements ISAMPollingMethod
{
    /**
     * The name of the class, used for logging.
     */
    private final static String MODULE = "SAMICMPPollingMethod";
    
    /**
     * The ICMP ping command that wll be used for polling
     */
    private StringBuffer _sbPingCommand;
    
    /**
     * The logger that will be used for system logging
     */
    private SystemLogger _oSystemLogger;

    /**
     * Reads the config parameters 'url' and 'pingcommand' from the supplied 
     * polling method config and sets the given system logger as logger for this 
     * class. 
     * <br>
     * <br>
     * 
     * @see org.aselect.system.sam.agent.ISAMPollingMethod#init(java.lang.Object,
     *      java.lang.Object, org.aselect.system.configmanager.ConfigManager,
     *      org.aselect.system.logging.SystemLogger)
     */
    public void init(Object oResourceConfigSection,
        Object oPollingMethodConfigSection, ConfigManager oConfigManager,
        SystemLogger oSystemLogger) throws ASelectSAMException
    {
        StringBuffer sbError = new StringBuffer();
        String sMethod = "init()";
        
        String sUrl = null;
        String sPingCommand = null;
        URI oUri = null;
        
        _oSystemLogger = oSystemLogger;

        try
        {
	        try
	        {
	            sUrl = oConfigManager.getParam(oResourceConfigSection, "url");
	        }
	        catch (Exception e)
	        {
	            sbError.append("Error retrieving config item 'url' from the resource section.");
	            _oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
	
	            throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
	        }
	
	        try
	        {
	            sPingCommand = oConfigManager.getParam(oPollingMethodConfigSection,
	                "pingcommand");
	        }
	        catch (Exception e)
	        {
	            sbError.append("Error retrieving config item 'pingcommand' from the resource section.");
	            _oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
	
	            throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
	        }
	
	        oUri = new URI(sUrl);

            if (oUri.getScheme().equalsIgnoreCase("jdbc"))
            {
                oUri = parseJDBCString(sUrl);
            }

            if (oUri.getHost() == null)
            {
                sbError.append("The configured url doesn't contain a host.");
	            _oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
	
	            throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR);
            }
            
            _sbPingCommand = new StringBuffer(sPingCommand);
            _sbPingCommand.append(" ");
            _sbPingCommand.append(oUri.getHost());
	     
        }
        catch (ASelectSAMException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            sbError.append("An error occured during the initialization of the SAM ICMP Poller: ");
            sbError.append(e.getMessage());
            _oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);

            throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
        }
    }

    /**
     * Polls the resource by executing the ping command located in <i>
     * _sbPingCommand</i>.
     * <br><br>
     * @see org.aselect.system.sam.agent.ISAMPollingMethod#poll()
     */
    public boolean poll()
    {
        StringBuffer sbError = new StringBuffer(MODULE);
        String sMethod = "poll()";
        
        boolean bPing = false;

        try
        {
            Runtime oRuntime = Runtime.getRuntime();
            Process oPingProcess = oRuntime.exec(_sbPingCommand.toString());
            bPing =  (oPingProcess.waitFor() == 0);
        }
        catch (Exception e)
        {
            sbError.append(
                "An error occured during the polling of the resource with command '");
            sbError.append(_sbPingCommand);
            sbError.append("'");
            _oSystemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString(), e);
        }

        return bPing;
    }

    /**
     * Will parse the JDBC URI to an <code>URI</code> Object.
     * 
     * @param sUri The JDBC URI to parse.
     * 
     * @return the parsed URI object
     * @throws ASelectSAMException if the uri couldn't be parsed or the result 
     * is empty.
     */
    private URI parseJDBCString(String sUri) throws ASelectSAMException
    {
        StringBuffer sbError = new StringBuffer();
        String sMethod = "parseJDBCString()";
        URI uriResponse = null;

        try
        {
            StringTokenizer stUri = new StringTokenizer(sUri, ":");
            while (stUri.hasMoreElements())
            {
                String sToken = (String)stUri.nextElement();

                if (sToken.startsWith("//"))
                {
                    uriResponse = new URI("jdbc", sToken.substring(2), null,
                        null);
                }
            }
        }
        catch (Exception e)
        {
            sbError.append("Could not parse the JDBC URI '");
            sbError.append(sUri);
            sbError.append("'");
            _oSystemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString(), e);

            throw new ASelectSAMException(Errors.ERROR_ASELECT_PARSE_ERROR);
        }

        if (uriResponse == null)
        {
            sbError.append("Invalid JDBC URI '");
            sbError.append(sUri);
            sbError.append("'. Empty result after creating the URI object.");
            _oSystemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
            
            throw new ASelectSAMException(Errors.ERROR_ASELECT_PARSE_ERROR);
        }

        return uriResponse;
    }
}