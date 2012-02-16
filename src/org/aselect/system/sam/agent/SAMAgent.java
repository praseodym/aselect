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
 * $Id: SAMAgent.java,v 1.12 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: SAMAgent.java,v $
 * Revision 1.12  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.11  2006/04/12 13:20:41  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.10.4.1  2006/03/22 08:53:27  martijn
 * fixed logging messages
 *
 * Revision 1.10  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.9  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.8  2005/03/14 08:58:28  martijn
 * renamed config section samagent to section sam with subsection agent
 *
 * Revision 1.7  2005/03/11 13:32:14  martijn
 * Renamed SAMLocator to SAMResourceGroup
 *
 * Revision 1.6  2005/03/09 14:13:31  martijn
 * fixed bug in getActiveResource(): nullpointer occurred when no resourcegroup with the supplied group name was found
 *
 * Revision 1.5  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.4  2005/02/28 15:30:49  erwin
 * Improved logging and error handling
 *
 * Revision 1.3  2005/02/25 11:58:47  erwin
 * Fixed destroy
 *
 * Revision 1.2  2005/02/23 14:15:31  martijn
 * added java documentation and changed variable names
 *
 */

package org.aselect.system.sam.agent;

import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.logging.SystemLogger;

/**
 * The SAM Agent is used as a central location to retrieve an active resource. <br>
 * <br>
 * <b>Description: </b> <br>
 * SAM stands for Simple A-Select Management. SAM is designed to enable A-Select to work in a redundant envirnoment. The
 * SAMAgent is the central component, for all other A-Select components, to obtain an active SAMResource. A SAMResource
 * resembles, for example, an A-Select Server or a database. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class SAMAgent
{

	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "SAMAgent";

	/**
	 * Contains the SAM ResourceGroups
	 */
	private HashMap _htResourceGroups = null;

	private SystemLogger _oSystemLogger;
	

	/**
	 * Default constructor.
	 */
	public SAMAgent() {
	}

	/**
	 * This function is to initialize the SAMAgent. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Loads all configured resources within the 'samagent' config section in the <code>HashMap</code>
	 * <i>_htResourceGroups</i>. <br>
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
	 * @param oConfigManager
	 *            The section within the configuration file in which the parameters for the SAMAgent can be found.
	 * @param oSystemLogger
	 *            the <code>SystemLogger</code> object that is the logging target
	 * @throws ASelectSAMException
	 *             if no correct configuration was found
	 */
	public void init(ConfigManager oConfigManager, SystemLogger oSystemLogger)
		throws ASelectSAMException
	{
		String sMethod = "init()";

		Object oSAMSection = null;
		Object oAgentSection = null;
		Object oResourceGroupSection = null;
		try {
			_oSystemLogger = oSystemLogger;

			try {
				oSAMSection = oConfigManager.getSection(null, "sam");
			}
			catch (Exception e) {
				_oSystemLogger.log(Level.WARNING, MODULE, sMethod, "Could not find the 'sam' config section", e);
				throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				oAgentSection = oConfigManager.getSection(oSAMSection, "agent");
			}
			catch (Exception e) {
				_oSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not find the 'agent' config section inside the 'sam' section", e);
				throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				oResourceGroupSection = oConfigManager.getSection(oAgentSection, "resourcegroup");
			}
			catch (Exception e) {
				_oSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not find the 'resourcegroup' config section with the 'agent' section", e);
				throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			// Remove old resource groups
			destroy();

			_htResourceGroups = new HashMap();
			
			SAMResourceGroup oSAMResourceGroup = new SAMResourceGroup();
			oSAMResourceGroup.init(oResourceGroupSection, oConfigManager, _oSystemLogger);
			oSAMResourceGroup.start();
			_htResourceGroups.put(oConfigManager.getParam(oResourceGroupSection, "id"), oSAMResourceGroup);

			while ((oResourceGroupSection = oConfigManager.getNextSection(oResourceGroupSection)) != null) {
				oSAMResourceGroup = new SAMResourceGroup();
				oSAMResourceGroup.init(oResourceGroupSection, oConfigManager, _oSystemLogger);
				oSAMResourceGroup.start();
				_htResourceGroups.put(oConfigManager.getParam(oResourceGroupSection, "id"), oSAMResourceGroup);
			}
		}
		catch (ASelectSAMException e) {
			throw e;
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize SAMLAgent", e);
			throw new ASelectSAMException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);

		}
	}

	/**
	 * Gets an active resource from a paricular group. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Returns the active resource from the resource group with the supplied id. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <i>sID </i>!= null <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param sID
	 *            The identifier for a particular group of resources.
	 * @return The SAMResource object of an active resource.
	 * @throws ASelectSAMException
	 *             if no active resource can be found
	 */
	public SAMResource getActiveResource(String sID)
	throws ASelectSAMException
	{
		String sMethod = "getActiveResource()";
		SAMResource oSAMResource = null;
		
		_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Getting active resource for: " + sID);		// RH, 20110202, n
		SAMResourceGroup oSAMResourceGroup = (SAMResourceGroup) _htResourceGroups.get(sID);

		if (oSAMResourceGroup != null) {
			oSAMResource = oSAMResourceGroup.getActiveResource();
		}
		else {
			StringBuffer sbError = new StringBuffer("Resourcegroup with name '");
			sbError.append(sID).append("' does not exist");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectSAMException(Errors.ERROR_ASELECT_SAM_UNAVALABLE);
		}
		return oSAMResource;
	}

	/**
	 * Destroys all resourcegroups (SAMResourceGroups). <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Destroys all SAMResourceGroups in the <i>_htResourceGroups</i> and removes them. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 */
	public void destroy()
	{
		if (_htResourceGroups != null) {
			try {
				Set keys = _htResourceGroups.keySet();
				for (Object s : keys) {
					String sKey = (String) s;
					SAMResourceGroup oSAMResourceGroup = (SAMResourceGroup) _htResourceGroups.get(sKey);
					oSAMResourceGroup.destroy();
					oSAMResourceGroup.interrupt();
				}
			}
			catch (Exception e) {
				// SAMLOcator allready disposed
			}
		}
	}
}