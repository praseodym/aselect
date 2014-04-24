package org.aselect.server.utils;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/*
 * @author Bauke Hiemstra
 * 
 * Save Attribute setter data from configuration files
 */
public class AttributeSetter
{
	private static final String MODULE = "AttributeSetter";

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

	// Creator
	public AttributeSetter(String sDest, String sSrc, String sSep, String sName, int iIndex, boolean bDestTgt, boolean bSrcTgt)
	{
		this.sDest = sDest;
		this.sSrc = sSrc;
		this.sSep = sSep;
		this.sName = sName;
		this.iIndex = iIndex;
		this.bDestTgt = bDestTgt;
		this.bSrcTgt = bSrcTgt;
	}

	/**
	 * Read attributes config.
	 * 
	 * @param oConfigManager
	 *            the config manager
	 * @param oConfig
	 *            the config
	 * @param attributeSetters
	 *            the attribute setter rules
	 * @param sysLogger
	 *            the system logger
	 * @throws ASelectException
	 */
	public static void initAttributesConfig(ASelectConfigManager oConfigManager, Object oConfig,
					LinkedList<AttributeSetter> attributeSetters, ASelectSystemLogger sysLogger)
	throws ASelectException
	{
		String sMethod = "initAttributesConfig";
		
		Object oAttributes = ASelectConfigManager.getSimpleSection(oConfig, "attributes", false);
		if (oAttributes == null)
			return;
		Object oSetAttr = ASelectConfigManager.getSimpleSection(oAttributes, "set_attr", false);
		if (oSetAttr == null)
			return;

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
			sysLogger.log(Level.INFO, MODULE, sMethod, (bDestTgt?"tgt_":"")+"dest="+sDest+" "+(bSrcTgt?"tgt_":"")+"src="+sSrc+" name="+sName+" sep="+sSep+" index="+sIndex);
			attributeSetters.add(new AttributeSetter(sDest, sSrc, sSep, sName, iIndex, bDestTgt, bSrcTgt));
			
			// Obtain handle to the next requestor
			try {
				oSetAttr = oConfigManager.getNextSection(oSetAttr);
			}
			catch (ASelectConfigException e) {
				oSetAttr = null;
			}
		}
	}

	/**
	 * Attribute processing.
	 * 
	 * @param htTGTContext
	 *            the tgt context
	 * @param hmAttributes
	 *            the collected attributes so far
	 * @param attributeSetters
	 *            the attribute setter specifications
	 * @return the resulting hash map
	 * @throws ASelectAttributesException
	 */
	public static HashMap attributeProcessing(HashMap htTGTContext, HashMap hmAttributes, LinkedList<AttributeSetter> attributeSetters,
			ASelectSystemLogger sysLog)
	throws ASelectAttributesException
	{
		final String sMethod = "attributeProcessing";
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
				sysLog.log(Level.FINER, MODULE, sMethod, (setter.isSrcTgt()?"tgt_":"")+"src="+sSrc+(setter.isDestTgt()?" tgt_":" ")+"dest="+sDest+
						" sep="+setter.getSep()+" index="+setter.getIndex()+" name="+setter.getName());
				
				// Take from source, multi valued (Vector) attributes will be converted to a string
				Object oValue = (setter.isSrcTgt())? htTGTContext.get(sSrc): hmAttributes.get(sSrc);
				sysLog.log(Level.FINEST, MODULE, sMethod, "oValue="+oValue);
				if (oValue == null)
					continue;
				sValue = oValue.toString();
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
				if (setter.isDestTgt()) {
					sysLog.log(Level.FINEST, MODULE, sMethod, "Tgt: "+sDest+"="+sValue);
					htTGTContext.put(sDest, sValue);
				}
				else {
					sysLog.log(Level.FINEST, MODULE, sMethod, "New: "+sDest+"="+sValue);
					htNewAttrs.put(sDest, sValue);
				}
			}
		}
		catch (Exception e) {
			sysLog.log(Level.WARNING, MODULE, sMethod, "Attribute collection failed", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return htNewAttrs;
	}
}
