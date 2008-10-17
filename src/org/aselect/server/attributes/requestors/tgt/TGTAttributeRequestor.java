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

import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.attributes.requestors.GenericAttributeRequestor;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Base64;

/**
 * Retrieves 'remote_attributes' from TGT context.
 * <br><br>
 * <b>Description:</b><br>
 * An Attribute requestor which retrieves the remote_attributes parameter 
 * from a TGT context. The value of this parameter is decoded and converted 
 * to a <code>Hashtable</code>.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class TGTAttributeRequestor extends GenericAttributeRequestor
{
    /** The module name. */
    private final String MODULE = "TGTAttributeRequestor";
    protected Hashtable _htReMapAttributes;
    protected Hashtable _htDuplicate;
   
    /**
     * Initialize the <code>TGTAttributeRequestor</code>
     * <br><br>
     * @see org.aselect.server.attributes.requestors.IAttributeRequestor#init(java.lang.Object)
     */
    public void init(Object oConfig)
    throws ASelectException
    {
		String sMethod = "init()";

		_htReMapAttributes = new Hashtable();
		_htDuplicate = new Hashtable();

		Object oAttributes = null;
		try {
			oAttributes = _configManager.getSection(oConfig, "attribute_mapping");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
					"No valid 'attribute_mapping' config section found, no mapping used", e);
		}

		if (oAttributes != null) {
			Object oAttribute = null;
			try {
				oAttribute = _configManager.getSection(oAttributes, "attribute");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Not one valid 'attribute' config section in 'attributes' section found,no mapping used", e);
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
							+ sAttributeID + "', using default value 'false'", e);
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
	 * Retrieves all remote attributes that are currently in the TGT context.
	 * <br>
	 * <br>
	 * 
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#getAttributes(java.util.Hashtable,
	 *      java.util.Vector)
	 */
    public Hashtable getAttributes(Hashtable htTGTContext, Vector vAttributes) 
    throws ASelectAttributesException
    {
        String sMethod = "getAttributes()";
        Hashtable htAttributes = new Hashtable();       
        
        try {
			String sSerializedRemoteAttributes = (String) htTGTContext.get("remote_attributes");
			if (sSerializedRemoteAttributes != null) // remote attributes available
			{
				htAttributes = deserializeAttributes(sSerializedRemoteAttributes);
			}
			else {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No 'remote_attributes' found in TGT.");
			}
			Hashtable htMapped = new Hashtable();
			for (Enumeration e = htAttributes.keys(); e.hasMoreElements();) {
				String oldName = (String) e.nextElement();
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
    
    /**
	 * Deserialize attributes and convertion to a <code>Hashtable</code>.
	 * 
	 * @param sSerializedAttributes
	 *            the serialized attributes.
	 * @return The deserialized attributes (key,value in <code>Hashtable</code>)
	 * @throws ASelectException
	 *             If URLDecode fails
	 */
    private Hashtable deserializeAttributes(String sSerializedAttributes) 
        throws ASelectException
    {
        String sMethod = "deSerializeAttributes()";
        Hashtable htAttributes = new Hashtable();
        if(sSerializedAttributes != null) //Attributes available
        {
            try
            {
                //base64 decode
                String sDecodedUserAttrs = new String(Base64.decode(sSerializedAttributes));
                
                //decode & and = chars
                String[] saAttrs = sDecodedUserAttrs.split("&");
                for (int i = 0; i < saAttrs.length; i++)
                {
                    int iEqualChar = saAttrs[i].indexOf("=");
                    String sKey = "";
                    String sValue = "";
                    Vector vVector = null;
                    
                    if (iEqualChar > 0)
                    {
                        sKey = URLDecoder.decode(
                            saAttrs[i].substring(0 , iEqualChar), "UTF-8");
                        
                        sValue= URLDecoder.decode(
                            saAttrs[i].substring(iEqualChar + 1), "UTF-8");
                        
                        if (sKey.endsWith("[]"))
                        { //it's a multi-valued attribute
                            // Strip [] from sKey
                            sKey = sKey.substring(0,sKey.length() - 2);
                            
                            if ((vVector = (Vector)htAttributes.get(sKey)) == null)
                                vVector = new Vector();                                
                            
                            vVector.add(sValue);
                        }                        
                    }
                    else
                        sKey = URLDecoder.decode(saAttrs[i], "UTF-8");
                    
                    
                    if (vVector != null)
                        //store multivalue attribute
                        htAttributes.put(sKey, vVector);
                    else
                        //store singlevalue attribute
                        htAttributes.put(sKey, sValue);
                }
            }
            catch (Exception e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, 
                    "Error during deserialization of attributes", e);
                throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
            }
        }
        return htAttributes;
    }
}
