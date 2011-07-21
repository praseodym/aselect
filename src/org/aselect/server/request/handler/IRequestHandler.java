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
 * $Id: IAuthnRequestHandler.java,v 1.3 2006/04/26 12:18:32 tom Exp $ 
 */

package org.aselect.server.request.handler;

import java.util.regex.Pattern;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.system.exception.ASelectException;

/**
 * Interface for request handlers. <br>
 * <br>
 * <b>Description:</b><br>
 * Interface that describes the methods that a RequestHandler object must implement <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public interface IRequestHandler
{
	
	/**
	 * Initializes the Request Handler. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Reads the Request Handler configuration <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>oServletConfig != null</li> <li>oConfig != null</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oServletConfig
	 *            Servlet Config of the Parent servlet
	 * @param oConfig
	 *            Object containing the RequestHandler configuration
	 * @throws ASelectException
	 *             if initalization fails
	 */
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException;

	/**
	 * Processes the request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Processes the request from the <code>HttpServletRequest</code> and sends the response to the
	 * <code>HttpServletResponse</code> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>request != null</li> <li>response != null</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param request
	 *            HttpServletRequest containing the request
	 * @param response
	 *            HttpServletResponse containing the response
	 * @return RequestState containing the request handling state
	 * @throws ASelectException
	 *             if the request couldn't be processed
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException;

	/**
	 * Returns the RequestHandler unique ID. <br>
	 * <br>
	 * 
	 * @return String continaing the requesthandler
	 */
	public String getID();

	/**
	 * Returns the regular expression configured for this ReuqestHandler. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The regular expression <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return Pattern that contains the regular expression that will handle the request
	 */
	public Pattern getPattern();

	/**
	 * Removes the class objects from memory. <br>
	 * <br>
	 */
	public void destroy();
}
