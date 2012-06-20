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
 * $Id: ISelectorHandler.java,v 1.3 2006/04/26 12:17:17 tom Exp $ 
 * 
 * Changelog:
 * $Log: ISelectorHandler.java,v $
 * Revision 1.3  2006/04/26 12:17:17  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.2  2005/09/08 12:46:34  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.1  2005/04/01 14:22:57  peter
 * cross aselect redesign
 *
 * Revision 1.1  2005/03/22 15:12:58  peter
 * Initial version
 *
 */

package org.aselect.server.cross;

import java.io.PrintWriter;
import java.util.HashMap;

import javax.servlet.http.HttpServletResponse;

import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;


/**
 * Handler to determine the remote A-Select Server. <br>
 * <br>
 * <b>Description:</b><br>
 * Selector handler will 'tell' A-Select which remote A-Select Server should be used to set up a 'cross-authenticate'
 * request.<br>
 * Handlers may use HTML forms to gather user information.<br>
 * If applicable, the handler can also pass a user-id to A-Select.<br>
 * <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - Only one instance of a Handler is created within A-Select that will be active till A-Select stops/restarts. <br>
 * 
 * @author Alfa & Ariss
 */
public interface ISelectorHandler
{
	
	/**
	 * Handler specific initialization. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * Called at startup of A-Select. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oHandlerConfig
	 *            the o handler config
	 * @throws ASelectConfigException
	 *             * @throws ASelectException the a select exception
	 */
	public void init(Object oHandlerConfig)
	throws ASelectException;

	/**
	 * Entry point of the handler during cross-authentication. Handler may present the user with a HTML page here to
	 * gather more information. If done so, the function <b>must</b> return <b>null</b>. <br>
	 * The HTML page should contain a form with <code>request=cross_login</code>. <br>
	 * If enough information is gathered, the function should return a HashMap as described below.<br>
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @return HashMap containing
	 *         <ul>
	 *         <li>'organization_id'
	 *         <li>'user_id' (optional)
	 *         </ul>
	 *         or <b>NULL</b>
	 * @throws ASelectException
	 *             the a select exception
	 */
	public HashMap getRemoteServerId(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException;

}
