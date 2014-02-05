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
 * $Id: APIAttributeRequestor.java,v 1.10 2006/05/03 09:32:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: APIAttributeRequestor.java,v $
 * Revision 1.10  2006/05/03 09:32:06  tom
 * Removed Javadoc version
 *
 * Revision 1.9  2006/03/09 13:06:13  jeroen
 * Bugfix for 141 AttributeMapping not optional in (JNDI)AttributeGatherer also applicable to the APIAttributeRequestor
 *
 * Also extracted the parameter "id" from the <attribute_mapping> configuration within the APIRequestor and created a own tag <attribute_parameter_name> which also is added to the aselect.xml.sample
 *
 */
package org.aselect.server.attributes.requestors.api;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.attributes.requestors.GenericAttributeRequestor;
import org.aselect.server.attributes.requestors.IAttributeRequestor;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.communication.client.soap11.SOAP11Communicator;
import org.aselect.system.communication.client.soap12.SOAP12Communicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.sam.agent.SAMResource;

/**
 * API call Attribute requestor. <br>
 * <br>
 * <b>Description:</b><br>
 * Attribute requestor wich uses SOAP1.1, SOAP1.2, or RAW API calls to sends an API attributes retrieval call to a
 * server. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * The <code>APIAttributeRequestor</code> should be initialized once. <br>
 * 
 * @author Alfa & Ariss
 */
public class APIAttributeRequestor extends GenericAttributeRequestor implements IAttributeRequestor
{
	/** The module name. */
	private final String MODULE = "APIAttributeRequestor";

	/** The method name for SOAP communication */
	private String _sSOAPMethod;

	/** The name of the attributes array */
	protected String _sAttributesName;

	/** The communicator */
	protected IClientCommunicator _communicator;

	/** All parameters that should be send */
	protected Vector _vTGTParameters;
	protected HashMap _htConfigParameters;

	/** All attributes that can be retrieved */
	protected Vector _vAllAttributes;
	protected Vector _vAllAttributesMappings;

	/** The recourcegroup */
	private String _sAPIResourceGroup;

	/**
	 * Create a new <code>APIAttributeRequestor</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * calls <code>super()</code>. <br>
	 * <br>
	 * 
	 * @see GenericAttributeRequestor#GenericAttributeRequestor()
	 */
	public APIAttributeRequestor()
	{
		super();
	}

	/**
	 * Initializes the <code>APIAttributeRequestor</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Performs the following steps:
	 * <ul>
	 * <li>Create an appropiate communicator</li>
	 * <li>get target URL using SAM</li>
	 * <li>Get configured parameters</li>
	 * <li>Get attributes array name</li>
	 * <li>Get attributes mapping</li>
	 * </ul>
	 * 
	 * @param oConfig
	 *            the o config
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#init(java.lang.Object)
	 */
	public void init(Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";
		
		super.init(oConfig);
		try {
			// Get main configuration
			Object oMainConfiguration = null;
			try {
				oMainConfiguration = _configManager.getSection(oConfig, "main");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve 'main' configuration section",
						eAC);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}

			// Get communicator
			String sProtocol = null;
			try {
				sProtocol = _configManager.getParam(oMainConfiguration, "transferprotocol");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Could not find config item 'transferprotocol', using Raw communication", eAC);
				sProtocol = "raw";
			}
			if (sProtocol == null)
				sProtocol = "";

			_systemLogger.log(Level.FINE, MODULE, sMethod, "communicator="+sProtocol);
			if (sProtocol.equalsIgnoreCase("soap11")) {
				retrieveSOAPMethodFromConfig(oMainConfiguration);
				_communicator = new SOAP11Communicator(_sSOAPMethod, _systemLogger);
			}
			else if (sProtocol.equalsIgnoreCase("soap12")) {
				retrieveSOAPMethodFromConfig(oMainConfiguration);
				_communicator = new SOAP12Communicator(_sSOAPMethod, _systemLogger);
			}
			else {
				// raw communication is specified or something unreadable
				_communicator = new RawCommunicator(_systemLogger);
			}

			// get target from SAM
			try {
				_sAPIResourceGroup = _configManager.getParam(oConfig, "resourcegroup");
				getConnection();
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'resourcegroup' parameter in 'main' configuration section", eAC);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
			catch (ASelectSAMException eSAM) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve SAM resource group with name:"
						+ _sAPIResourceGroup, eSAM);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, eSAM);
			}

			// Get configured parameters
			_vTGTParameters = new Vector();
			_htConfigParameters = new HashMap();
			Object oParameterConfiguration = null;
			try {
				oParameterConfiguration = _configManager.getSection(oConfig, "parameters");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Could not retrieve 'parameters' configuration section; no parameters will be send", eAC);
			}
			if (oParameterConfiguration != null) {
				Object oParameter = null;
				try {
					oParameter = _configManager.getSection(oParameterConfiguration, "parameter");
				}
				catch (ASelectConfigException eAC) {
					_systemLogger.log(Level.CONFIG, MODULE, sMethod,
							"Could not retrieve one 'parameter' in 'parameters' configuration section", eAC);
				}
				while (oParameter != null) {  // for all parameters
					try {
						String sParameterName = _configManager.getParam(oParameter, "id");
						// check if the parameter is a session parameter
						boolean bSession = false;
						try {
							String sAttributeMapping = _configManager.getParam(oParameter, "session");
							if (sAttributeMapping.equals("true"))
								bSession = true;
						}
						catch (ASelectConfigException eAC) {  // bSession allready false
						}

						if (bSession)
							_vTGTParameters.add(sParameterName);
						else {
							// retrieve value
							String sParameterValue = _configManager.getParam(oParameter, "value");
							_htConfigParameters.put(sParameterName, sParameterValue);
						}
					}
					catch (ASelectConfigException eAC) {
						_systemLogger.log(Level.CONFIG, MODULE, sMethod,
								"Could not retrieve mandatory parameter in attribute", eAC);
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
					}
					oParameter = _configManager.getNextSection(oParameter);
				}
			}

			try {
				_sAttributesName = _configManager.getParam(oConfig, "attribute_parameter_name");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'attribute_parameter_name' parameter in configuration section", eAC);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}

			// Get configured attributes from configuration
			_vAllAttributes = new Vector();
			_vAllAttributesMappings = new Vector();
			Object oAttributesConfiguration = null;
			try {
				oAttributesConfiguration = _configManager.getSection(oConfig, "attribute_mapping");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Could not retrieve 'attribute_mapping' configuration section, no mapping used", eAC);
			}

			if (oAttributesConfiguration != null) {
				Object oAttribute = null;
				// get all attribute mappings
				try {
					oAttribute = _configManager.getSection(oAttributesConfiguration, "attribute");
				}
				catch (ASelectConfigException eAC) {
					_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Could not retrieve one 'attribute' in 'attribute_mapping' configuration section, no mapping used",	eAC);
				}
				while (oAttribute != null) {  // for all attributes
					try {
						String sAttributeName = _configManager.getParam(oAttribute, "id");
						_vAllAttributes.add(sAttributeName);
					}
					catch (ASelectConfigException eAC) {
						_systemLogger.log(Level.CONFIG, MODULE, sMethod,
								"Could not retrieve 'id' parameter in attribute", eAC);
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
					}
					try {
						String sAttributeMapping = _configManager.getParam(oAttribute, "map");
						_vAllAttributesMappings.add(sAttributeMapping);

					}
					catch (ASelectConfigException eAC) {
						_systemLogger.log(Level.CONFIG, MODULE, sMethod,
								"Could not retrieve 'map' parameter in attribute", eAC);
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
					}
					oAttribute = _configManager.getNextSection(oAttribute);
				}
			}
		}
		catch (ASelectException eAS) {
			throw eAS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error initializing due to internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Retrieve all, or the specified attributes. <br>
	 * <br>
	 * 
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param vAttributes
	 *            the v attributes
	 * @return the attributes
	 * @throws ASelectAttributesException
	 *             the a select attributes exception
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#getAttributes(HashMap, Vector)
	 */
	public HashMap getAttributes(HashMap htTGTContext, Vector vAttributes, HashMap hmAttributes)
	throws ASelectAttributesException
	{
		final String sMethod = "getAttributes";
		String sStatusKeyValue = null;
		String sStatusKey = null;
		String sStatusValue = null;
		int iEqualsPos = -1;
		String sURL = null;
		String[] oaAttributes;

		HashMap htAttributes = new HashMap();
		try {
			if (!vAttributes.isEmpty()) {  // Attributes should be gathered.
				// get connection
				try {
					sURL = getConnection();
				}
				catch (ASelectSAMException eSAM) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve connection from sam", eSAM);
					throw new ASelectAttributesException(eSAM.getMessage());
				}
				// create request/response
				HashMap htRequest = new HashMap();
				HashMap htResponse = new HashMap();
				// set TGT parameters
				Enumeration e = _vTGTParameters.elements();
				while (e.hasMoreElements()) {
					String sName = (String) e.nextElement();
					String sValue = (String) htTGTContext.get(sName);
					if (sValue == null) {
						StringBuffer sbError = new StringBuffer("Error retrieving '");
						sbError.append(sName);
						sbError.append("' parameter from session context.");
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_CONFIG_ERROR);
					}
					htRequest.put(sName, sValue);
				}

				// set Configuration parameters
				htRequest.putAll(_htConfigParameters);

				// add attribute names to request if applicable
				if (!vAttributes.firstElement().equals("*")) {  // Not a Wildcard
					// Map requested attributes
					Vector vRequestAttributes = new Vector();
					Object[] oa = vAttributes.toArray();
					for (int i = 0; i < oa.length; i++) {  // for all requested attributes
						// get mapping
						int iIndex = _vAllAttributes.indexOf(oa[i]);
						if (iIndex < 0) { // no mapping available
							vRequestAttributes.add(oa[i]);
						}
						else { // map name
							vRequestAttributes.add(_vAllAttributesMappings.get(iIndex));
						}
					}
					oaAttributes = (String[]) vRequestAttributes.toArray(new String[0]);
					// Add attributes
					htRequest.put(_sAttributesName, oaAttributes);
				}

				// send message
				htResponse = _communicator.sendMessage(htRequest, sURL);
				// retrieve response
				String saValues[] = (String[]) htResponse.get(_sAttributesName);
				if (saValues == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No attributes in response from: " + sURL);
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Response: " + htResponse);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
				}

				for (int i = 0; i < saValues.length; i++)
				// for all response attributes
				{
					Vector vVector = null;
					// Spit value: key=value
					sStatusKeyValue = saValues[i];
					iEqualsPos = sStatusKeyValue.indexOf("=");
					sStatusKey = sStatusKeyValue.substring(0, iEqualsPos);
					sStatusValue = sStatusKeyValue.substring(iEqualsPos + 1);
					// convert to mapping
					int iIndex = _vAllAttributesMappings.indexOf(sStatusKey);
					if (iIndex >= 0) { // mapping available
						sStatusKey = (String) _vAllAttributes.get(iIndex);
					}
					// <1.5.4 htAttributes.put(sStatusKey, sStatusValue);

					// 1.5.4 added
					if (htAttributes.containsKey(sStatusKey)) {
						Object oTemp = htAttributes.get(sStatusKey);
						if (oTemp instanceof Vector) {
							vVector = (Vector) oTemp;
						}
						else {
							vVector = new Vector();
							vVector.add(oTemp.toString());
						}
						vVector.add(sStatusValue);
						htAttributes.put(sStatusKey, vVector);
					}
					else {
						htAttributes.put(sStatusKey, sStatusValue);
					}
				}
			}
		}
		catch (ASelectCommunicationException eAC) {
			StringBuffer sbError = new StringBuffer("Error communicating with host: ");
			sbError.append(sURL);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), eAC);
			throw new ASelectAttributesException(eAC.getMessage());
		}
		catch (ASelectAttributesException eAA) {
			// allready logged
			throw eAA;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error retrieving attributes due to internal error", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return htAttributes;
	}

	/**
	 * Destroy the <code>APIAttributeRequestor</code>. <br>
	 * <br>
	 * 
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#destroy()
	 */
	public void destroy()
	{
		// Do nothing for now
	}

	/**
	 * Retrieving a URL from a resource that is available.
	 * 
	 * @return URL as <code>String</code>.
	 * @throws ASelectSAMException
	 *             If retrieving fails.
	 */
	protected String getConnection()
	throws ASelectSAMException
	{
		String sMethod = "getConnection";
		SAMResource oSAMResource = null;
		String sUrl = null;
		try {
			oSAMResource = _samAgent.getActiveResource(_sAPIResourceGroup);
		}
		catch (ASelectSAMException e) {
			StringBuffer sbFailed = new StringBuffer("No active resource found in udb resourcegroup: ");
			sbFailed.append(_sAPIResourceGroup);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
			throw e;
		}

		Object oResourceConfig = oSAMResource.getAttributes();
		try {
			sUrl = _configManager.getParam(oResourceConfig, "url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'url' found in connector resource configuration", e);
			throw new ASelectSAMException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}
		return sUrl;
	}

	/**
	 * retrieve SOAPMethod from configuration.
	 * 
	 * @param oMainConfiguration
	 *            The main configuration exception.
	 * @throws ASelectAttributesException
	 *             if retrieving fails.
	 */
	private void retrieveSOAPMethodFromConfig(Object oMainConfiguration)
	throws ASelectAttributesException
	{
		String sMethod = "retrieveSOAPMethodFromConfig";
		try {
			_sSOAPMethod = _configManager.getParam(oMainConfiguration, "method");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not retrieve 'SOAPMethod' parameter in 'main' configuration section", eAC);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}
	}
}
