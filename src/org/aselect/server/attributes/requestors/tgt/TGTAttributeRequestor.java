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
 * $Id: TGTAttributeRequestor.java,v 1.4 2006/05/03 09:32:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: TGTAttributeRequestor.java,v $
 * Revision 1.4  2006/05/03 09:32:06  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2006/03/14 15:11:20  martijn
 * added support for multivalue attributes
 *
 * Revision 1.2  2005/09/07 14:54:07  erwin
 * Improved deserialization (bug #105)
 *
 * Revision 1.1  2005/04/07 13:09:08  erwin
 * Initial version.
 *
 */

package org.aselect.server.attributes.requestors.tgt;

import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.attributes.requestors.GenericAttributeRequestor;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

/**
 * Retrieves 'attributes' from TGT context. <br>
 * <br>
 * <b>Description:</b><br>
 * An Attribute requestor which retrieves the 'attributes' parameter from a TGT context. The value of this
 * parameter is decoded and converted to a <code>HashMap</code>. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class TGTAttributeRequestor extends GenericAttributeRequestor
{
	/** The module name. */
	private final String MODULE = "TGTAttributeRequestor";
	protected HashMap _htReMapAttributes;
	protected HashMap _htDuplicate;

	/**
	 * Initialize the <code>TGTAttributeRequestor</code> <br>
	 * <br>
	 * .
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

		_htReMapAttributes = new HashMap();
		_htDuplicate = new HashMap();

		super.init(oConfig);
		Object oAttributes = null;
		try {
			oAttributes = _configManager.getSection(oConfig, "attribute_mapping");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "No valid 'attribute_mapping' config section found, no mapping used, cause="+e);
		}

		if (oAttributes != null) {
			Object oAttribute = null;
			try {
				oAttribute = _configManager.getSection(oAttributes, "attribute");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Not one valid 'attribute' config section in 'attributes' section found, no mapping used, cause="+e);
			}

			while (oAttribute != null) {
				String sAttributeID = null;
				String sAttributeMap = null;
				try {
					sAttributeID = _configManager.getParam(oAttribute, "id");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No valid 'id' config item in 'attribute' section found", e);
					throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					sAttributeMap = _configManager.getParam(oAttribute, "map");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No valid 'map' config item in 'attribute' section found", e);
					throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				String sDuplicate;
				boolean bDuplicate;
				try {
					sDuplicate = _configManager.getParam(oAttribute, "duplicate");
					bDuplicate = new Boolean(sDuplicate).booleanValue();
				}
				catch (ASelectConfigException e) {
					bDuplicate = false;
					_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'duplicate' config item found for attribute '"
							+ sAttributeID + "', using default value 'false'");
				}
				_htReMapAttributes.put(sAttributeMap, sAttributeID);
				if (bDuplicate) {
					_htDuplicate.put(sAttributeMap, sAttributeID);
				}
				oAttribute = _configManager.getNextSection(oAttribute);
			}
		}
	}

	/**
	 * Retrieves all remote attributes that are currently in the TGT context. <br>
	 * <br>
	 * 
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param vAttributes
	 *            the v attributes
	 * @return the attributes
	 * @throws ASelectAttributesException
	 *             the a select attributes exception
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#getAttributes(java.util.HashMap,
	 *      java.util.Vector)
	 */
	public HashMap getAttributes(HashMap htTGTContext, Vector vAttributes, HashMap hmAttributes)
	throws ASelectAttributesException
	{
		String sMethod = "getAttributes";
		HashMap htAttributes = new HashMap();

		try {
			// 20100228, Bauke: changed from "remote_attributes" to "attributes"
			String sSerializedRemoteAttributes = (String) htTGTContext.get("attributes");
			if (sSerializedRemoteAttributes != null) { // remote attributes available
				htAttributes = org.aselect.server.utils.Utils.deserializeAttributes(sSerializedRemoteAttributes);
			}
			else {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No attribute called 'attributes' found in TGT.");
			}
			HashMap htMapped = new HashMap();
			Set keys = htAttributes.keySet();
			for (Object s : keys) {
				String oldName = (String) s;
				String newName = oldName;
				Object value = htAttributes.get(oldName);
				if (_htReMapAttributes.containsKey(oldName)) {
					newName = (String) _htReMapAttributes.get(oldName);
				}
				htMapped.put(newName, value);
				if (_htDuplicate.containsKey(oldName)) {
					htMapped.put(oldName, value);
				}
			}
			htAttributes = htMapped;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error retrieving attributes due to internal error", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return htAttributes;
	}

	/**
	 * Clean-up the <code>TGTAttributeRequestor</code>. <br>
	 * <br>
	 * 
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#destroy()
	 */
	public void destroy()
	{
		// No destroy functionality
	}
}
