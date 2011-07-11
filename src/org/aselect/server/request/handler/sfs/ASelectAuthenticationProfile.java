/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.server.request.handler.sfs;

import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.sfs.authentication.IRequestHandler;
import org.aselect.server.request.handler.sfs.authentication.RequestHandlerFactory;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

/**
 * The A-Select Authentication Profile. <br>
 * <br>
 * <b>Description:</b><br>
 * The A-Select Server Authentication Profile for legacy A-Select request handlers (> A-Select 1.4).<br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class ASelectAuthenticationProfile extends AbstractRequestHandler
{
	private final static String MODULE = "ASelectAuthenticationProfile";

	private RequestHandlerFactory _oRequestHandlerFactory;
	private String _sMyServerID;
	private String _sMyOrg;
	
	/**
	 * Init function. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Initializes the request handler by reading the following configuration: <br/>
	 * <br/>
	 * &lt;aselect&gt;<br/>
	 * &nbsp;&lt;server_id&gt;[server_id]&lt;/server_id&gt;<br/>
	 * &nbsp;&lt;organization&gt;[organization]&lt;/organization&gt;<br/>
	 * &nbsp;&nbsp;...<br/>
	 * &lt;/aselect&gt;<br/>
	 * <ul>
	 * <li><b>server_id</b> - The A-Select Server ID</li>
	 * <li><b>organization</b> - The A-Select Server organization ID</li>
	 * </ul>
	 * <br/>
	 * Initializes the A-Select Legacy Request Handler factory <br>
	 * <br>
	 * 
	 * @param oServletConfig
	 *            the o servlet config
	 * @param oConfig
	 *            the o config
	 * @throws ASelectException
	 *             If initialization fails.
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";
		try {
			super.init(oServletConfig, oConfig);

			Object oASelect = null;
			try {
				oASelect = _configManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not find 'aselect' config section in config file", e);
				throw e;
			}

			try {
				_sMyServerID = _configManager.getParam(oASelect, "server_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'server_id' config parameter in 'aselect' config section", e);
				throw e;
			}

			try {
				_sMyOrg = _configManager.getParam(oASelect, "organization");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'organization' config parameter in 'aselect' config section", e);
				throw e;
			}

			_oRequestHandlerFactory = RequestHandlerFactory.getHandle();
			_oRequestHandlerFactory.init(_sMyServerID, _sMyOrg);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Main process function. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Processes all A-Select Server requests by creating a specific request handler for the supplied request. <br>
	 * <br>
	 * <i>Note: The restart request should be handled by one <code>Servlet</code> in the context. </i> <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * RequestHandlerFactory != null <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * - <br>
	 * <br>
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @return the request state
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#process(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";

		_systemLogger.log(Level.FINER, MODULE, "ASelectAuthenticationProfile.process()",
				"SFS Authentication Profile request: " + request.getRequestURI().toString() + "?"
						+ request.getQueryString());

		try {
			// create the appropriate handler
			IRequestHandler iHandler = _oRequestHandlerFactory.createRequestHandler(request, response);
			iHandler.processRequest();
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return new RequestState(null);
	}

	/**
	 * Removes the class variables from memory. <br>
	 * <br>
	 * 
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#destroy()
	 */
	public void destroy()
	{
		// do nothing
	}
}
