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
 * $Id: SAMResourceGroup.java,v 1.4 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: SAMResourceGroup.java,v $
 * Revision 1.4  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.1  2005/03/11 13:32:14  martijn
 * Renamed SAMLocator to SAMResourceGroup
 *
 * Revision 1.9  2005/03/11 10:51:44  martijn
 * fixed bug in logging: missing interval config item was logged in stead of missing section config item
 *
 * Revision 1.8  2005/03/09 20:27:29  martijn
 * fixed bug: if no interval was set in resourcegroup configuration, no default updatestatus polling interval time was set. Now the default polling time of 50ms is set.
 *
 * Revision 1.7  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.6  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.5  2005/03/01 14:14:03  martijn
 * fixed typo in logging
 *
 * Revision 1.4  2005/02/28 15:30:49  erwin
 * Improved logging and error handling
 *
 * Revision 1.3  2005/02/25 11:59:17  erwin
 * Removed super.destoy()
 *
 * Revision 1.2  2005/02/23 14:15:31  martijn
 * added java documentation and changed variable names
 *
 */

package org.aselect.system.sam.agent;

import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.logging.SystemLogger;

/**
 * The SAM Resource Group is a Thread that represents a resource that will be checked every interval time. <br>
 * <br>
 * <b>Description: </b> <br>
 * SAM stands for Simple A-Select Management. SAM is designed to enable A-Select to work in a redundant environment. A
 * SAMResourceGroup resembles a group of entry points (SAMResources) to a particular resource (for example a database).
 * The SAMResourceGroup will query the SAMResources periodically and keeps a list of active resources. When queried by
 * an A-Select component, through the SAMAgent, the SAMResourceGroup will present the A-Select component an active
 * SAMResource. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class SAMResourceGroup extends Thread
{
	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "SAMResourceGroup";

	/**
	 * Used for stopping the <code>Thread</code>.
	 */
	private boolean _bRunThread;

	/**
	 * All resources that are configured inside a resourcegroup
	 */
	private HashMap _htResources;

	/**
	 * List of resources from a resourcegroup that are active
	 */
	private Vector _vActive;

	/**
	 * The logger that logs system errors
	 */
	private SystemLogger _oSystemLogger;

	/**
	 * Default status update check time, used as interval for checking resources in a resourcegroup.
	 */
	private final long DEFAULT_UPDATE_INTERVAL = 50;

	/**
	 * The interval which is used to check all resources within a resourcegroup
	 */
	private long _lInterval;

	/**
	 * Identifier for this resourcegroup.
	 */
	private String sResourceGroupID = null;
	
	/**
	 * Logging level when resourcegroup has critical number of resources ( e.g. non at all )
	 * Defaults to WARNING for backward compatbility
	 */
	private static final Level  DEFAULT_NOTICE_LEVEL = Level.WARNING;
	private Level _criticalResourceGroupNoticeLevel = DEFAULT_NOTICE_LEVEL;

	/**
	 * This function is to initialize the SAMAgent. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Reads all resources configured inside a resourcegroup from the configuration and initializes them. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - oConfigSection != null<br>
	 * - oConfigManager != null<br>
	 * - oSystemLogger != null<br>
	 * <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oConfigSection
	 *            The section within the configuration file in which the parameters for this SAMResourceGroup can be
	 *            found.
	 * @param oConfigManager
	 *            The ConfigManager used to retrieve the config from.
	 * @param oSystemLogger
	 *            The logger used for system logging
	 * @throws ASelectSAMException
	 *             if initialization fails.
	 */
	public void init(Object oConfigSection, ConfigManager oConfigManager, SystemLogger oSystemLogger)
	throws ASelectSAMException
	{
		StringBuffer sbError = new StringBuffer(MODULE + " ");
		String sMethod = "init()";

		_htResources = new HashMap();
		_vActive = new Vector();
		_oSystemLogger = oSystemLogger;

		Object oResourceSection = null;
		try {

			try {
				sResourceGroupID = oConfigManager.getParam(oConfigSection, "id");
			}
			catch (Exception e) {
				sbError.append("Could not find config item 'id' in config section 'resourcegroup'.");
				_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
				throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_lInterval = new Long(oConfigManager.getParam(oConfigSection, "interval")).longValue() * 1000;
			}
			catch (Exception e) {

				// the interval is not configured, using the default interval time
				_lInterval = DEFAULT_UPDATE_INTERVAL * 1000;

				StringBuffer sbWarning = new StringBuffer(sbError.toString());
				sbWarning.append("Could not find config item 'interval' in config section 'resourcegroup' with id=");
				sbWarning.append(sResourceGroupID);
				sbWarning.append(". Setting interval to default value: '");
				sbWarning.append(DEFAULT_UPDATE_INTERVAL);
				sbWarning.append("'");
				_oSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbWarning.toString());
			}

			try {
				oResourceSection = oConfigManager.getSection(oConfigSection, "resource");
			}
			catch (Exception e) {
				sbError.append("Could not find config section 'resource' in config section 'resourcegroup' with id=");
				sbError.append(sResourceGroupID);
				_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
				throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			SAMResource oSAMResource = new SAMResource();
			oSAMResource.init(oResourceSection, oConfigManager, oSystemLogger);

			String sResourceId = null;

			try {
				sResourceId = oConfigManager.getParam(oResourceSection, "id");
			}
			catch (Exception e) {
				sbError.append("Could not find config item 'id' in section 'resource'.");
				_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
				throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			_htResources.put(sResourceId, oSAMResource);

			while ((oResourceSection = oConfigManager.getNextSection(oResourceSection)) != null) {
				oSAMResource = new SAMResource();
				oSAMResource.init(oResourceSection, oConfigManager, _oSystemLogger);

				try {
					sResourceId = oConfigManager.getParam(oResourceSection, "id");
				}
				catch (Exception e) {
					sbError.append("Could not find config item 'id' in section 'resource'.");
					_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
					throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				_htResources.put(sResourceId, oSAMResource);
			}
			try {
			String sCriticalResourceNoticeLevel = oConfigManager.getParam(oConfigSection, "criticalresourcegroupnoticelevel");
				try {
					_criticalResourceGroupNoticeLevel = Level.parse(sCriticalResourceNoticeLevel);
					} catch (IllegalArgumentException ie) {
						_oSystemLogger.log(Level.CONFIG, MODULE, sMethod, "Invalid argument for 'criticalresourcegroupnoticelevel', defaults:" + DEFAULT_NOTICE_LEVEL.getName() +  ". Valid argumants are [ SEVERE | WARNING | ..... | ALL ]");
						_criticalResourceGroupNoticeLevel = DEFAULT_NOTICE_LEVEL;
					}
			} catch ( ASelectConfigException e ) {
				_oSystemLogger.log(Level.CONFIG, MODULE, sMethod, "No argument for 'criticalresourcegroupnoticelevel', defaults to:" + DEFAULT_NOTICE_LEVEL.getName());
				_criticalResourceGroupNoticeLevel = DEFAULT_NOTICE_LEVEL;
			}
			
			
			updateStatus();
			_bRunThread = true;
		}
		catch (ASelectSAMException e) {
			throw e;
		}
		catch (Exception e) {
			sbError.append("Could not initialize: ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Gets a active resource from this group. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the first active resource (the active resource with the highest priority) <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - The class variable <i>_vActive</i> may not be <code>null</code><br>
	 * - All objects inside the class variable <i>_vActive</i> must be <code>
	 * SAMResource</code> objects. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return The SAMResource object of an active resource.
	 * @throws ASelectSAMException
	 *             If no active resource was found.
	 */
	public SAMResource getActiveResource()
	throws ASelectSAMException
	{
		StringBuffer sbError = new StringBuffer(MODULE);
		String sMethod = "getActiveResource()";

		if (_vActive.isEmpty()) {
			sbError.append("There were no resources found to be active for resourcegroup id:" + getsResourceGroupID());
//			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());	// RH, 20120628, o
			_oSystemLogger.log(getCriticalResourceGroupNoticeLevel(), MODULE, sMethod, sbError.toString());	// RH, 20120628, n
			throw new ASelectSAMException(Errors.ERROR_ASELECT_SAM_NO_RESOURCE_ACTIVE);
		}

		return (SAMResource) _vActive.firstElement();
	}

	/**
	 * Returns a <code>SAMResource</code> specified by it's id. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns a <code>SAMResource</code> specified by it's key as it contains in the class variable
	 * <i>_htResources</i>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - sKey may not be <code>null</code><br>
	 * <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sKey
	 *            The id of the resource that will be returned
	 * @return The <code>SAMResource</code> object that is specified by <i>sKey</i>
	 * @throws ASelectSAMException
	 *             if no resource is found
	 * @deprecated Use getActiveResource instead
	 */
	@Deprecated
	public SAMResource getResource(String sKey)
	throws ASelectSAMException
	{
		StringBuffer sbError = new StringBuffer(MODULE);
		String sMethod = "getResource()";

		SAMResource oSAMResource = null;

		try {
			oSAMResource = (SAMResource) _htResources.get(sKey);
		}
		catch (Exception e) {
			sbError.append("There is no resource associated with the supplied key: '");
			sbError.append(sKey);
			sbError.append("'.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);

			throw new ASelectSAMException(Errors.ERROR_ASELECT_SAM_UNAVALABLE, e);

		}

		if (oSAMResource == null) {
			sbError.append("There is no resource associated with the supplied key: '");
			sbError.append(sKey);
			sbError.append("'");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());

			throw new ASelectSAMException(Errors.ERROR_ASELECT_SAM_UNAVALABLE);
		}

		return oSAMResource;
	}

	/**
	 * Default methode to start the update status <code>Thread</code> <br>
	 * <br>
	 * .
	 * 
	 * @see java.lang.Thread#run()
	 */
	@Override
	public void run()
	{
		while (_bRunThread) {
			try {
				updateStatus();
				sleep(_lInterval);
			}
			catch (Exception e) {
			}
		}
	}

	/**
	 * Destroys this resourcegroup (SAMResourceGroup) and all resources (SAMResource) within this group. <br>
	 * <br>
	 * 
	 * @see java.lang.Thread#destroy()
	 */
	@Override
	public void destroy()
	{
		Set keys = _htResources.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
			// Enumeration enumKeys = _htResources.keys();
			// while (enumKeys.hasMoreElements())
			// {
			// String sKey = (String) enumKeys.nextElement();
			SAMResource oSAMResource = (SAMResource) _htResources.get(sKey);
			oSAMResource.destroy();
		}
		_bRunThread = false;
	}

	/**
	 * Makes a pass along all SAMResources within this group and updates the Vector of active SAMResources. Every status
	 * update verifies the status of the resources in the configurated order. The first configured resource has the
	 * highest priority.
	 */
	private void updateStatus()
	{
		Vector vLive = new Vector();

		Set keys = _htResources.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
			// Enumeration enumKeys = _htResources.keys();
			// while (enumKeys.hasMoreElements()) {
			// String sKey = (String) enumKeys.nextElement();
			SAMResource oSAMResource = (SAMResource) _htResources.get(sKey);
			
			if (oSAMResource.live()) {
				// RH, 20110202, sn
				// Make a priority list based on cost
				int index = 0;
				for (Object r : vLive ) {
					if ( oSAMResource.getiCost() >  ((SAMResource)r).getiCost() ) {
						index++;
					} else break;
				}
				vLive.add(index, oSAMResource);
				// RH, 20110202, en
//				vLive.add(oSAMResource);			// RH, 20110202, o
			}
		}
		// RH, 20120628, sn
		if ( vLive.size() == 0 ) {
			String sMethod = "updateStatus()";
			StringBuffer sbError = new StringBuffer("No active resources for resourcegroup:" + getsResourceGroupID() );
			_oSystemLogger.log(getCriticalResourceGroupNoticeLevel(), MODULE, sMethod, sbError.toString());
		}
		// RH, 20120628, en
		_vActive = vLive;

	}

	public String getsResourceGroupID()
	{
		return sResourceGroupID;
	}

	public void setsResourceGroupID(String sResourceGroupID)
	{
		this.sResourceGroupID = sResourceGroupID;
	}

	public Level getCriticalResourceGroupNoticeLevel()
	{
		return _criticalResourceGroupNoticeLevel;
	}

	public void setCriticalResourceGroupNoticeLevel(Level criticalResourceGroupNoticeLevel)
	{
		_criticalResourceGroupNoticeLevel = criticalResourceGroupNoticeLevel;
	}
}
