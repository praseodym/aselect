/*
 * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 *
 * PKI Attribute Requestor 
 */
package org.aselect.server.attributes.requestors.copy;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.attributes.requestors.GenericAttributeRequestor;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 */
public class CopyAttributeRequestor extends GenericAttributeRequestor
{
	final private String MODULE = "CopyAttributeRequestor";

	LinkedList<AttributeSetter> attributeSetters = new LinkedList<AttributeSetter>();
	
	private class AttributeSetter
	{
		String sDest = null;
		String sSrc = null;
		String sSep = null;
		String sName = null;
		int iIndex = -1;
		boolean bDestTgt = false;
		boolean bSrcTgt = false;
		
		public String getDest() { return sDest; }
		public String getSrc() { return sSrc; }
		public String getSep() { return sSep; }
		public String getName() { return sName; }
		public int getIndex() { return iIndex; }
		public boolean isDestTgt() { return bDestTgt; }
		public boolean isSrcTgt() { return bSrcTgt; }

		protected AttributeSetter(String sDest, String sSrc, String sSep, String sName, int iIndex, boolean bDestTgt, boolean bSrcTgt)
		{
			this.sDest = sDest;
			this.sSrc = sSrc;
			this.sSep = sSep;
			this.sName = sName;
			this.iIndex = iIndex;
			this.bDestTgt = bDestTgt;
			this.bSrcTgt = bSrcTgt;
		}
	}
	/**
	 * Initialize the <code>OpaqueAttributeRequestor</code>. <br>
	 * <br>
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
		Object oAttributes, oSetAttr;
		
		super.init(oConfig);
		
		oAttributes = ASelectConfigManager.getSimpleSection(oConfig, "attributes", true);
		if (oAttributes == null)
			return;
		
		oSetAttr = ASelectConfigManager.getSimpleSection(oAttributes, "set_attr", false);
		if (oSetAttr == null)
			return;

		//_sRemoteLast = ASelectConfigManager.getSimpleParam(oRequestorsSection, "remote", false);
		//_systemLogger.log(Level.INFO, MODULE, sMethod, "sRemoteLast="+_sRemoteLast);
		
		while (oSetAttr != null) {
			boolean bDestTgt = false, bSrcTgt = false;
       		String sDest = ASelectConfigManager.getSimpleParam(oSetAttr, "dest", false);
       		if (!Utils.hasValue(sDest)) {
       			sDest = ASelectConfigManager.getSimpleParam(oSetAttr, "tgt_dest", true);
       			bDestTgt = true;
       		}
			String sSrc = ASelectConfigManager.getSimpleParam(oSetAttr, "src", false);
       		if (!Utils.hasValue(sSrc)) {
       			sSrc = ASelectConfigManager.getSimpleParam(oSetAttr, "tgt_src", true);
       			bSrcTgt = true;
       		}
			String sSep = ASelectConfigManager.getSimpleParam(oSetAttr, "sep", false);
			String sName = ASelectConfigManager.getSimpleParam(oSetAttr, "name", false);
			String sIndex = ASelectConfigManager.getSimpleParam(oSetAttr, "index", false);
			int iIndex = -1;
			try {
				iIndex = Integer.valueOf(sIndex);
			} catch (Exception e) { }
			_systemLogger.log(Level.INFO, MODULE, sMethod, (bDestTgt?"tgt_":"")+"dest="+sDest+" "+(bSrcTgt?"tgt_":"")+"src="+sSrc+" name="+sName+" sep="+sSep+" index="+sIndex);
			attributeSetters.add(new AttributeSetter(sDest, sSrc, sSep, sName, iIndex, bDestTgt, bSrcTgt));
			
			// Obtain handle to the next requestor
			try {
				oSetAttr = _configManager.getNextSection(oSetAttr);
			}
			catch (ASelectConfigException e) {
				oSetAttr = null;
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "size="+attributeSetters.size());
	}

	/**
	 * Retrieve the requested attributes. <br>
	 * <br>
	 * 
	 * @param htTGTContext
	 *            the TGT context
	 * @param vAttributes
	 *            the attributes to be released (can be *)
	 * @param hmAttributes
	 *            the attributes collected by the previous gatherers
	 * @return the gathered attributes
	 */
	public HashMap getAttributes(HashMap htTGTContext, Vector vAttributes, HashMap hmAttributes)
	throws ASelectAttributesException
	{
		final String sMethod = "getAttributes";
		String sUid = (String)(_bFromTgt? htTGTContext: hmAttributes).get(_sUseKey);  // serves as an example
		_systemLogger.log(Level.INFO, MODULE, sMethod, "release="+vAttributes+" all so far="+hmAttributes+" "+_sUseKey+"="+sUid+" fromTgt="+_bFromTgt);

		HashMap htNewAttrs = new HashMap();
		try {
			String sValue = null;
			
			for (int idx = 0; idx < attributeSetters.size(); idx++) {
				AttributeSetter setter = attributeSetters.get(idx);
				String sDest = setter.getDest();
				if (!Utils.hasValue(sDest))
					continue;
				
				String sSrc = setter.getSrc();
				if (!Utils.hasValue(sSrc))
					continue;
				_systemLogger.log(Level.FINER, MODULE, sMethod, "sSrc="+sSrc+",isTgt="+setter.isSrcTgt()+" sDest="+sDest+",isTgt="+setter.isDestTgt());
				
				// Take from source
				if (setter.isSrcTgt())
					sValue = (String)htTGTContext.get(sSrc);
				else
					sValue = (String)hmAttributes.get(sSrc);
				_systemLogger.log(Level.FINER, MODULE, sMethod, "sValue="+sValue);
				if (!Utils.hasValue(sValue))
					continue;
				
				// Split the value using sSep
				String sSep = setter.getSep();
				if (Utils.hasValue(sSep)) {
					String sNewValue = null;
					String[] fields = sValue.split(sSep+" *");  // eat white space too
					
					// Get field i or get a named field
					int iIndex = setter.getIndex();
					String sName = setter.getName();
					if (iIndex != -1) {
						if (iIndex >= 1 && iIndex <= fields.length)
							sNewValue = fields[iIndex-1];
						// index and name combined?
						if (Utils.hasValue(sName) && Utils.hasValue(sNewValue)) {
							if (sNewValue.startsWith(sName+"="))
								sNewValue = sNewValue.substring(sName.length()+1);
						}
					}
					else {
						if (Utils.hasValue(sName)) {
							for (int i=0; i<fields.length; i++) {
								if (fields[i].startsWith(sName+"="))
									sNewValue = fields[i].substring(sName.length()+1);
							}
							// Last value found wins!
						}
					}
					if (Utils.hasValue(sNewValue))
						sValue = sNewValue;
				}
				if (setter.isDestTgt())
					htTGTContext.put(sDest, sValue);
				else
					htNewAttrs.put(sDest, sValue);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Attribute collection failed", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return htNewAttrs;
	}

	/**
	 * Destroys the <code>OpaqueAttributeRequestor</code>. <br>
	 * <br>
	 * 
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#destroy()
	 */
	public void destroy()
	{
		// Does nothing
	}
}
