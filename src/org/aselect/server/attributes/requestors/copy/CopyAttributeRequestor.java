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
import org.aselect.server.utils.AttributeSetter;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 */
public class CopyAttributeRequestor extends GenericAttributeRequestor
{
	final private String MODULE = "CopyAttributeRequestor";

	private LinkedList<AttributeSetter> attributeSetters = new LinkedList<AttributeSetter>();
	
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

		// 20140417, Bauke: User id manipulation
		AttributeSetter.initAttributesConfig(_configManager, oConfig, attributeSetters, _systemLogger);
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

		return AttributeSetter.attributeProcessing(htTGTContext, hmAttributes, attributeSetters, _systemLogger);
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
