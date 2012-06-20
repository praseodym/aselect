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
 * $Id: SAMAPIPollingMethod.java,v 1.10 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: SAMAPIPollingMethod.java,v $
 * Revision 1.10  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.9  2005/09/08 13:14:45  erwin
 * Fixed problem with IOD_ALL, retrieving all oid's
 *
 * Revision 1.8  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.6  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.5  2005/02/28 15:30:49  erwin
 * Improved logging and error handling
 *
 * Revision 1.4  2005/02/23 14:15:31  martijn
 * added java documentation and changed variable names
 *
 */

package org.aselect.system.sam.agent.polling;

import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.communication.client.soap11.SOAP11Communicator;
import org.aselect.system.communication.client.soap12.SOAP12Communicator;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.ISAMPollingMethod;

/**
 * The interface for polling methods. <br>
 * <br>
 * <b>Description: </b> <br>
 * Will check the availability of a resource by making an API call by using the SAM protocol. <br>
 * <b>Concurrency issues: </b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class SAMAPIPollingMethod implements ISAMPollingMethod
{
	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "SAMAPIPollingMethod";

	/**
	 * The OID that is used to check if the A-Select component is operational
	 */
	private final static String OID_OPERATIONAL = "1.3.6.1.4.1.15396.10.10.2.1.3";

	/**
	 * A SAM wildcard OID that will return all information available
	 */
	private final static String OID_ALL = "1.3.6.1.4.1.15396.10.10.2.";

	/**
	 * The target url that will be polled
	 */
	private String _sUrl;

	/**
	 * The logger used for system logging
	 */
	private SystemLogger _oSystemLogger;

	/**
	 * The client that is used for communicating with the <code>SAMService
	 * </code> servlet
	 */
	private IClientCommunicator _oClientCommunicator;

	/**
	 * The configuration manager that is used for resolving config
	 */
	private ConfigManager _oConfigManager;

	/**
	 * Will read the url from the SAMService servlet that must be polled and sets the given <code>ConfigManager</code>
	 * and <code>SystemLogger</code> as class variables. <br>
	 * <br>
	 * 
	 * @param oResourceConfigSection
	 *            the o resource config section
	 * @param oPollingMethodConfigSection
	 *            the o polling method config section
	 * @param oConfigManager
	 *            the o config manager
	 * @param oSystemLogger
	 *            the o system logger
	 * @throws ASelectSAMException
	 *             the a select sam exception
	 * @see org.aselect.system.sam.agent.ISAMPollingMethod#init(java.lang.Object, java.lang.Object,
	 *      org.aselect.system.configmanager.ConfigManager, org.aselect.system.logging.SystemLogger)
	 */
	public void init(Object oResourceConfigSection, Object oPollingMethodConfigSection, ConfigManager oConfigManager,
			SystemLogger oSystemLogger)
	throws ASelectSAMException
	{
		StringBuffer sbError = new StringBuffer(MODULE);
		String sMethod = "init()";

		_oSystemLogger = oSystemLogger;
		_oConfigManager = oConfigManager;

		try {
			_sUrl = _oConfigManager.getParam(oPollingMethodConfigSection, "url");
		}
		catch (ASelectConfigException e) {
			sbError.append("Config item 'url' is missing.");
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);

			throw new ASelectSAMException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		_oClientCommunicator = getCommunicator(oPollingMethodConfigSection);
	}

	/**
	 * The method that used to poll the SAMService. It checks only if the OID: 1.3.6.1.4.1.15396.10.10.2.1.3 is 1 (only
	 * the operational check) <br>
	 * <br>
	 * 
	 * @return true, if poll
	 * @see org.aselect.system.sam.agent.ISAMPollingMethod#poll()
	 */
	public boolean poll()
	{
		StringBuffer sbError = new StringBuffer(MODULE);
		String sMethod = "poll()";
		boolean bLive = false;

		try {
			HashMap htResponse = communicate();

			String sOperational = (String) htResponse.get(OID_OPERATIONAL);
			if (sOperational != null && sOperational.equals("1")) {
				bLive = true;
			}
		}
		catch (Exception e) {
			sbError.append("Could not poll the resource");
			_oSystemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString(), e);
		}

		return bLive;
	}

	/**
	 * Communicates with the <code>SAMService</code> by using the SAM protocol. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Communicates by using a <code>ClientCommunicator</code> object with the <code>SAMService</code>. It send a
	 * message containing a wildcard OID to retrieve all available information from that SAMService. <br>
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
	 * @return a <code>HashMap</code> containing all requested SAM OID's with it's values.
	 * @throws ASelectSAMException
	 *             if no response can be retrieved
	 */
	private HashMap communicate()
	throws ASelectSAMException
	{
		String sMethod = "communicate()";
		StringBuffer sbError = new StringBuffer();

		HashMap htRequest = new HashMap();
		HashMap htResponse = new HashMap();
		String[] saArray = new String[1];
		String sStatusKeyValue = null;
		String sStatusKey = null;
		String sStatusValue = null;
		int iEqualsPos = -1;

		saArray[0] = OID_ALL;
		htRequest.put("samversion", "1.0");
		htRequest.put("get", saArray);

		try {
			HashMap htCCResponse = _oClientCommunicator.sendMessage(htRequest, _sUrl);
			String saStatus[] = (String[]) htCCResponse.get("get");

			for (int i = 0; i < saStatus.length; i++) {
				sStatusKeyValue = saStatus[i];

				iEqualsPos = sStatusKeyValue.indexOf("=");
				sStatusKey = sStatusKeyValue.substring(0, iEqualsPos);
				sStatusValue = sStatusKeyValue.substring(iEqualsPos + 1);
				htResponse.put(sStatusKey, sStatusValue);
			}

			if (htResponse.isEmpty()) {
				sbError.append("No response from SAM Service: \"");
				sbError.append(_sUrl);
				sbError.append("\"");

				_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectSAMException(Errors.ERROR_ASELECT_SAM_UNAVALABLE);
			}
		}
		catch (ASelectSAMException e) {
			throw e;
		}
		catch (Exception e) {
			sbError.append("Error in communicating with: \"");
			sbError.append(_sUrl);
			sbError.append("\"");

			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectSAMException(Errors.ERROR_ASELECT_SAM_UNAVALABLE);
		}
		return htResponse;
	}

	/**
	 * Resolves the <code>ClientCommunicator</code> object. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Resolves the <code>ClientCommunicator</code> object that must be used for polling. It can be configured or is
	 * default 'raw'. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <i>oConfigSection</i> may not be <code>null</code>. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oConfigSection
	 *            the config section object that contains the polling method configuration
	 * @return the client communicator that is configured, or the default
	 */
	private IClientCommunicator getCommunicator(Object oConfigSection)
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "getCommunicator()";

		IClientCommunicator oClientCommunicator = null;
		String sProtocol = null;
		try {
			sProtocol = _oConfigManager.getParam(oConfigSection, "transferprotocol");
		}
		catch (Exception e) {
			sbError.append("Could not find config item 'transferprotocol', using Raw communication.");
			_oSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbError.toString());
			sProtocol = "raw";
		}

		if (sProtocol == null)
			sProtocol = "";

		_oSystemLogger.log(Level.FINE, MODULE, sMethod, "communicator="+sProtocol);
		if (sProtocol.equalsIgnoreCase("soap11")) {
			oClientCommunicator = new SOAP11Communicator("Status", _oSystemLogger);
		}
		else if (sProtocol.equalsIgnoreCase("soap12")) {
			oClientCommunicator = new SOAP12Communicator("Status", _oSystemLogger);
		}
		else {
			// raw communication is specified or something unreadable
			oClientCommunicator = new RawCommunicator(_oSystemLogger);
		}
		return oClientCommunicator;
	}
}