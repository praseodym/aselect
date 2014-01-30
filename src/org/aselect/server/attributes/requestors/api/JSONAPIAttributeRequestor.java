package org.aselect.server.attributes.requestors.api;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.system.communication.client.json.JSONCommunicator;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.communication.client.soap11.SOAP11Communicator;
import org.aselect.system.communication.client.soap12.SOAP12Communicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;

public class JSONAPIAttributeRequestor extends APIAttributeRequestor {

	/** The module name. */
	private final String MODULE = "JSONAPIAttributeRequestor";
	private String jsonkey = null;

	
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

			_systemLogger.log(Level.FINEST, MODULE, sMethod, "communicator="+sProtocol);
			if (sProtocol.equalsIgnoreCase("json")) {
//				retrieveSOAPMethodFromConfig(oMainConfiguration);	// Maybe provide for POST here
				_communicator = new JSONCommunicator(_systemLogger);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "communicator= 'json' loaded");
			} else {
				// raw communication is specified or something unreadable
				_communicator = new RawCommunicator(_systemLogger);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "communicator= 'raw' loaded");
			}

			try {
				jsonkey = ASelectConfigManager.getParamFromSection(oConfig, "attribute_mapping", "id", true);
			}			
			catch (ASelectConfigException eAC) {	// maybe provide some default here
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not retrieve 'id' in attribute_mapping section",
						eAC);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
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
		String sURL = null;

		HashMap htAttributes = new HashMap();
		try {
			if (!vAttributes.isEmpty()) {  // Attributes should be gathered.
				// get connection
				try {
					sURL = getConnection();
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "retrieved url from resources:" + sURL);
				}
				catch (ASelectSAMException eSAM) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve connection from sam", eSAM);
					throw new ASelectAttributesException(eSAM.getMessage());
				}
				// create request/response
				HashMap htRequest = new HashMap();
				HashMap htRequestpairs = new HashMap();
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
					int iIndex = _vAllAttributes.indexOf(sName);
					if (iIndex >= 0 && iIndex <_vAllAttributesMappings.size()) { // mapping available
						sName = (String) _vAllAttributesMappings.get(iIndex);
						htRequestpairs.put(sName, sValue);
					}
				}
				Iterator itr = _htConfigParameters.keySet().iterator();
				while (itr.hasNext()) {
					String sName = (String)itr.next();
					int iIndex = _vAllAttributes.indexOf(sName);
					if (iIndex >= 0 && iIndex <_vAllAttributesMappings.size()) { // mapping available
						sName = (String) _vAllAttributesMappings.get(iIndex);
						htRequestpairs.put(sName, _htConfigParameters.get(sName));
					}
					
				}
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "json requestpairs:" + htRequestpairs);

				HashMap jsonrequest = new HashMap();
				jsonrequest.put(jsonkey, htRequestpairs);
//				// set Configuration parameters
				htRequest.putAll(_htConfigParameters);
				htRequest.put(_sAttributesName, jsonrequest);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "request:" + htRequest);
				

				// send message
				htResponse = _communicator.sendMessage(htRequest, sURL);
				
				htAttributes = htResponse;
				// retrieve response and forward 1-on-1
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "retrieved attributes:" + htAttributes);
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
	
}
