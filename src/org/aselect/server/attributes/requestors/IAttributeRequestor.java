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
 * $Id: IAttributeRequestor.java,v 1.7 2006/04/26 12:15:59 tom Exp $ 
 * 
 * Changelog:
 * $Log: IAttributeRequestor.java,v $
 * Revision 1.7  2006/04/26 12:15:59  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.6  2005/03/30 14:25:58  martijn
 * the getAttributes() method needs an TGT context instead of the A-Select user id
 *
 * Revision 1.5  2005/03/30 14:00:29  erwin
 * Fixed comment to be compliant with new gathering process
 *
 * Revision 1.4  2005/03/24 14:36:58  erwin
 * Improved Javadoc.
 *
 * Revision 1.3  2005/03/17 10:10:35  martijn
 * getAttributes will now throw an ASelectAttributesException instead of an ASelectException
 *
 * Revision 1.2  2005/03/17 10:07:22  erwin
 * Changed interface.
 *
 * Revision 1.1  2005/03/16 13:12:11  remco
 * added attributes (initial version)
 *
 */
package org.aselect.server.attributes.requestors;

import java.util.HashMap;
import java.util.Vector;

import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectException;

// TODO: Auto-generated Javadoc
/**
 * The interface for Attribute Requestors. <br>
 * <br>
 * <b>Description:</b><br>
 * An Attribute Requestor's job is to obtain attributes associated with a certain user id (UID). <br>
 * <br>
 * They are used as follows: <br>
 * The <code>AttributeGatherer</code> instantiates each configured Attribute Requestor, invokes its <code>
 * getAttributes()</code>
 * method, and processes the result. Therefore, an Attribute Requestor object does not have to be reusable. They are
 * destroyed once they have done their job. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public interface IAttributeRequestor
{
	
	/**
	 * Initialize the <code>IAttributeRequestor</code> implementation.
	 * 
	 * @param oConfig
	 *            The configuration section to use.
	 * @throws ASelectException
	 *             If configuration fails.
	 */
	public void init(Object oConfig)
		throws ASelectException;

	/**
	 * Retrieve the specified attributes. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Retrieve all known attributes or attributes that are specified in <code>vAttributes</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * Must be a threadsafe implementation. <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>htTGTContext != null</code></li>
	 * <li><code>vAttributes != null</code></li>
	 * <li>The attribute requestor must be able to map all attributes in <code>vAttributes</code>.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htTGTContext
	 *            the TGT context.
	 * @param vAttributes
	 *            The attributes to gather.
	 * @return The retrieved attributes.
	 * @throws ASelectAttributesException
	 *             If gathering fails.
	 */
	public HashMap getAttributes(HashMap htTGTContext, Vector vAttributes)
		throws ASelectAttributesException;

	/**
	 * Clean up used resources. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Close all resources and stop running threads if applicable. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The <code>IAttributeRequestor</code> implementation is stopped. <br>
	 */
	public void destroy();
}
