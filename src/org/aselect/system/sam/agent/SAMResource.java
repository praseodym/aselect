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
 * $Id: SAMResource.java,v 1.10 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: SAMResource.java,v $
 * Revision 1.10  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.9  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.8  2005/04/27 09:50:36  martijn
 * logging in init() method fixed
 *
 * Revision 1.7  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.6  2005/03/11 10:54:44  martijn
 * added more logging when config item id is missing in resource section
 *
 * Revision 1.5  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.4  2005/02/28 15:30:49  erwin
 * Improved logging and error handling
 *
 * Revision 1.3  2005/02/24 15:29:21  martijn
 * changed some Level.INFO to Level.CONFIG
 *
 * Revision 1.2  2005/02/23 14:15:31  martijn
 * added java documentation and changed variable names
 *
 */

package org.aselect.system.sam.agent;

import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.logging.SystemLogger;

/**
 * A shield surrounding a configured resource in a resourcegroup. 
 * <br>
 * <br>
 * <b>Description: </b> <br>
 * SAM stands for Simple A-Select Management. SAM is designed to enable A-Select
 * to work in a redundant envirnoment. A SAMResource resembles a server,
 * connection or entry point for a specific resource (e.g. an A-Select Server or
 * a database). At a given interval the SAMResource will check whether or not
 * it's resource is still available. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -
 * <br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class SAMResource
{
    /**
     * The name of the class, used for logging.
     */
    private final static String MODULE = "SAMResource";
    
    /**
     * The logger used for system logging
     */
    private SystemLogger _oSystemLogger;
    
    /**
     * The id of the resource
     */
    private String _sId;

    /**
     * The resource config section
     */
    private Object _oConfiguredAttributesSection;

    /**
     * A <code>boolean</code> that keeps track iof the resource availability
     */
    private boolean _bLive;

    /**
     * The thread that polls every interval
     */
    private PollingThread _oPollingThread;

    /**
     * The polling interval
     */
    private long _lInterval;

    /**
     * Used for stopping the <code>Thread</code>.
     */
    private boolean _bRunThread;

    /**
     * The polling method used for polling this resource
     */
    private ISAMPollingMethod _oSAMPollingMethod;
    
    /**
     * Default constructor.
     */
    public SAMResource()
    {
    }
    
    /**
     * Initializes the configured resource.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Checks if their is a polling methodconfigured for the resource and starts 
     * polling. If no polling method is found, no thread is started.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * - <i>oConfigSection</i> may not be <code>null</code><br>
     * - <i>oConfigManager</i> may not be <code>null</code><br>
     * - <i>oSystemLogger</i> may not be <code>null</code><br>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param oConfigSection - The section within the configuration file in 
     * which the parameters for the SAMAgent can be found.
     * @param oConfigManager the config manager object that is used to retrieve 
     * the configuration
     * @param oSystemLogger the logger used for system logging
     * @throws ASelectSAMException if the resource could not initialize
     */
    public void init(Object oConfigSection, ConfigManager oConfigManager,
            SystemLogger oSystemLogger) throws ASelectSAMException
    {
        String sMethod = "init()";
        
        //must always be set, even if no polling method is configured
        _oConfiguredAttributesSection = oConfigSection;
        _oSystemLogger = oSystemLogger;
                
        String sConfiguredPollingMethod = null;
        Object oPollingMethodSection = null;
        Class cPollingClass = null;
        String sConfiguredInterval = null;
        _bLive = true;

        try
        {
	        try
	        {
	            _sId = oConfigManager.getParam(oConfigSection, "id");
	        } 
	        catch (Exception e)
	        {
	            _oSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Error resolving config item 'id' in 'resource' section.", e);
	
	            throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
	        }
	
	        try
	        {
	            sConfiguredPollingMethod = oConfigManager.getParam(oConfigSection,
	            	"polling");
	        } 
	        catch (Exception e)
	        {
	            _oSystemLogger.log(Level.CONFIG, MODULE, sMethod, "No config item 'polling' is found, disabling polling.", e);
	        }
	
	        if (sConfiguredPollingMethod != null)
	        {
	            try
	            {
	                oPollingMethodSection = oConfigManager.getSection(
	                        oConfigSection, "pollingmethod", "id="
	                                + sConfiguredPollingMethod);
	            } 
	            catch (Exception e)
	            {
	                StringBuffer sbError = new StringBuffer(
	                    "No config item 'pollingmethod' is found, disabling polling for resource: ");
	                sbError.append(_sId);
	                
	                _oSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbError.toString(), e);
	            }
	        
		        if (oPollingMethodSection != null)
		        {
		            try
		            {
		                cPollingClass = Class.forName(oConfigManager.getParam(
		                        oPollingMethodSection, "class"));
		            } 
		            catch (Exception e)
		            {
		                StringBuffer sbError = new StringBuffer(
		                    "No config item 'class' is found or isn't a correct polling class.");
		                sbError.append(_sId);
		                _oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
		                
		                throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		            } 
		            
		            try
		            {
		                sConfiguredInterval = oConfigManager.getParam(oConfigSection,
		                        "interval");
		            } 
		            catch (Exception e)
		            {
		                StringBuffer sbError = new StringBuffer(
		                    "No config item 'interval' is found for resource with id: '");
		                sbError.append(_sId);
		                sbError.append("'");		                
		                _oSystemLogger.log(Level.INFO, MODULE, sMethod, sbError.toString(), e);
		                
		                throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		            }
		            
		            _oSAMPollingMethod = (ISAMPollingMethod) cPollingClass.newInstance();
		            _oSAMPollingMethod.init(oConfigSection, oPollingMethodSection,
	                        oConfigManager, _oSystemLogger);
	
	                _lInterval = (Long.parseLong(sConfiguredInterval) * 1000);
	
	                _bRunThread = true;
	                
	                //start polling
	                _oPollingThread = new PollingThread();
	                _oPollingThread.start();
		        }
	        }
        }
    	catch (ASelectSAMException e)
        {
            throw e;
        } 
    	catch (Exception e)
        {
    	    StringBuffer sbError = new StringBuffer("Could not initialize the resource with id: '");
            sbError.append(_sId);
            sbError.append("'.");
            _oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
            
            throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
        }
    }

    /**
     * Check if the resource is still available.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns the <i>_bLive</i> variable that is set when the resource is 
     * alive.
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
    public boolean live()
    {
        return _bLive;
    }

    /**
     * Returns the configuration attributes of this resource as an <code>Object
     * </code>.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Along with the configuration of the SAMResource, additional parameters
     * can be defined. These parameters can hold information about the resource.
     * For example, a username and password. This functions returns these
     * parameters to the application.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * The init() method must be called before using this method.
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @return A Object pointing to the section with the attributes within the 
     * configuration file.
     */
    public Object getAttributes()
    {
        return _oConfiguredAttributesSection;
    }

    /**
     * Class destroyer.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Destroy this class properly and stopped the polling thread.
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
     * The polling thread is stopped. 
     * <br>
     * 
     */
    public void destroy()
    {
        _bRunThread = false;
        _bLive = false;
        
        try
        {
            _oPollingThread.interrupt();
        } 
        catch (Exception e) {}  
    }

    /**
     * To keep track of whether or not this resource is still available, this
     * thread poll the resource periodically.
     */
    private class PollingThread extends Thread
    {
        /**
         * Start polling every configured interval
         * <br><br>
         * @see java.lang.Runnable#run()
         */
        public void run()
        {
            String sMethod = "run()";
            
            while (_bRunThread)
            {
                try
                {
                    _bLive = _oSAMPollingMethod.poll();

                    if (!_bLive)
                    {
                        StringBuffer sbError = new StringBuffer(MODULE);
                        sbError.append(":PollingThread.run() -> ");
                        sbError.append("Resource '");
                        sbError.append(_sId);
                        sbError.append("' is currently unavailable.");
                        _oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
                    }

                    sleep(_lInterval);
                } 
                catch (Exception e) {}
            }
        }
    }
}