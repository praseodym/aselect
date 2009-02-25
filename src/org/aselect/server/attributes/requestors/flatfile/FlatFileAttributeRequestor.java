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
 * $Id: FlatFileAttributeRequestor.java,v 1.3 2006/05/03 09:32:06 tom Exp $ 
 */
package org.aselect.server.attributes.requestors.flatfile;

import java.io.File;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.attributes.requestors.GenericAttributeRequestor;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.sam.agent.SAMResource;

/**
 * -
 * <br><br>
 * <b>Description:</b><br>
 * -
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * None.
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class FlatFileAttributeRequestor extends GenericAttributeRequestor
{
	private final static String MODULE = "FlatFileAttributeRequestor";
	private ConfigManager _oFlatFileManager;
	private HashMap _htGlobalAttributes;

	/**
	 * Initialize the <code>OpaqueAttributeRequestor</code>.
	 * 
	 * The user id is case sensitive
	 * <br><br>
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#init(java.lang.Object)
	 */
	public void init(Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";
		SAMResource oSAMResource = null;
		Object oResourceConfig = null;

		try {
			String sResourceGroup = null;
			try {
				sResourceGroup = _configManager.getParam(oConfig, "resourcegroup");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'resourcegroup' config item found", e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				oSAMResource = _samAgent.getActiveResource(sResourceGroup);
			}
			catch (ASelectSAMException e) {
				StringBuffer sbFailed = new StringBuffer("No active resource found in attributes resourcegroup: ");
				sbFailed.append(sResourceGroup);

				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);

				throw e;
			}

			oResourceConfig = oSAMResource.getAttributes();

			String sFileName = null;
			try {
				sFileName = _configManager.getParam(oResourceConfig, "file");
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'file' found", e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			File fFlatFile = new File(sFileName);
			if (!fFlatFile.exists()) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Configured 'file' item doesn't exist: " + sFileName);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			_oFlatFileManager = new ConfigManager();
			_oFlatFileManager.init(sFileName, _systemLogger);

			Object oGlobal = null;
			try {
				oGlobal = _oFlatFileManager.getSection(null, "global");
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'global' found", e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			Object oAttribute = null;
			try {
				oAttribute = _oFlatFileManager.getSection(oGlobal, "attribute");
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No global attributes configured, not using global attributes", e);
			}

			_htGlobalAttributes = readAttributes(oAttribute);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Attrs=" + _htGlobalAttributes);

		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to generate flatfile handle", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Retrieve attributes from flatfilehandler.
	 * <br><br>
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#getAttributes(java.util.HashMap, java.util.Vector)
	 */
	public HashMap getAttributes(HashMap htTGTContext, Vector vAttributes)
		throws ASelectAttributesException
	{
		HashMap htReturn = new HashMap();
		String sMethod = "getAttributes()";

		try {
			htReturn.putAll(_htGlobalAttributes);

			String sUserId = (String) htTGTContext.get("uid");
			if (sUserId == null) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No user in attribute flatfile with id: " + sUserId);
				return htReturn;
			}
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Get uid=" + sUserId);

			Object oUser = null;
			try {
				oUser = _oFlatFileManager.getSection(null, "user", "id=" + sUserId);
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No config section 'user' found", e);
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No attributes found for user with id: " + sUserId);
				return htReturn;
			}

			Object oAttribute = null;
			try {
				oAttribute = _oFlatFileManager.getSection(oUser, "attribute");
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Not one config section 'attribute' found", e);
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No attributes found for user with id: " + sUserId);
				return htReturn;
			}
			htReturn.putAll(readAttributes(oAttribute));
		}
		catch (ASelectAttributesException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to resolve attributes", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return htReturn;
	}

	/**
	 * Destroys the <code>FlatfileAttributeRequestor</code>.
	 * <br><br>
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#destroy()
	 */
	public void destroy()
	{
		//Does nothing
	}

	private HashMap readAttributes(Object oAttribute)
		throws ASelectException
	{
		String sMethod = "readAttributes()";
		HashMap htReturn = new HashMap();
		_systemLogger.log(Level.WARNING, MODULE, sMethod, "Read");
		try {
			while (oAttribute != null) {
				String sID = null;
				try {
					sID = _oFlatFileManager.getParam(oAttribute, "id");
				}
				catch (ASelectException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No config item 'id' in 'attribute' section found", e);
					throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
				}

				Object oValue = null;
				try {
					oValue = _oFlatFileManager.getSection(oAttribute, "value");
				}
				catch (ASelectException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Not one config section 'value' in 'attribute' section found", e);
					throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
				}

				Vector vValues = new Vector();
				while (oValue != null) {
					String sValue = null;
					try {
						sValue = _oFlatFileManager.getParam(oValue, "id");
					}
					catch (ASelectException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"No config item 'value' in section 'attribute' found", e);
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					vValues.add(sValue);

					oValue = _oFlatFileManager.getNextSection(oValue);
				}

				if (htReturn.containsKey(sID)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Attribute isn't unique: " + sID);
					throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR);
				}

				if (vValues.size() > 1) {
					//multivalue attribute
					htReturn.put(sID, vValues);
				}
				else {
					//singlevalue attribute
					htReturn.put(sID, vValues.firstElement());
				}

				oAttribute = _oFlatFileManager.getNextSection(oAttribute);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to resolve attributes", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return htReturn;
	}

}
