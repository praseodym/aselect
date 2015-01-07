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
 * $Id: RequestHandlerFactory.java,v 1.2 2006/05/03 10:10:18 tom Exp $ 
 * 
 * Changelog:
 * $Log: RequestHandlerFactory.java,v $
 * Revision 1.2  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.1  2006/01/13 08:40:26  martijn
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.8  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/03/15 16:09:30  tom
 * Fixed small code style error
 *
 * Revision 1.6  2005/03/15 16:06:01  erwin
 * Moved redundant code to seperate methods and AbstractAPIRequestHandler.
 *
 * Revision 1.5  2005/03/15 15:15:38  erwin
 * Added additional Javadoc.
 *
 * Revision 1.4  2005/03/15 11:14:38  peter
 * ASelectSystemLogger.getHandle() added in init()
 *
 * Revision 1.3  2005/03/15 10:15:29  erwin
 * Moved redundant code to seperate class (AbstractAPIRequestHandler)
 *
 * Revision 1.2  2005/03/15 09:23:27  erwin
 * Made Singleton.
 *
 * Revision 1.1  2005/03/15 08:22:24  tom
 * - Redesign of request handling
 * - Initial RequestHandlerFactory
 *
 */

package org.aselect.server.request.handler.aselect.authentication;

import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;

/**
 * The request handler factory for the A-Select Server. <br>
 * <br>
 * <b>Description:</b><br>
 * A singleton factory, which can be used to create <code>IAuthnRequestHandler</code> implementations. The factory uses
 * a {@link RequestParser} to determine the type of request handler and constructs this type of handler. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * The class is a singleton, so the same class is used in all the classes of the A-Select Server. <br>
 * 
 * @author Alfa & Ariss
 */
public class ASelectRequestHandlerFactory
{
	/** The module name */
	private final String MODULE = "ASelectRequestHandlerFactory";

	/** The system logger */
	private ASelectSystemLogger _systemLogger;

	/** configuration: server ID */
	private String _sMyServerId = null;

	/** configuration: organisation */
	private String _sMyOrg = null;

	/** The static instance. */
	private static ASelectRequestHandlerFactory _instance;

	/**
	 * Get a static handle to the <code>RequestHandlerFactory</code> instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if a static instance exists, otherwise it is created. This instance is returned. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * One instance of the <code>RequestHandlerFactory</code> exists.
	 * 
	 * @return A static handle to the <code>RequestHandlerFactory</code>
	 */
	public static ASelectRequestHandlerFactory getHandle()
	{
		if (_instance == null)
			_instance = new ASelectRequestHandlerFactory();
		return _instance;
	}

	/**
	 * Initializes the <code>ASelectRequestHandlerFactory</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Initializes the components. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The instance variables and components are initialized. <br>
	 * 
	 * @param sServerId
	 *            The A-Select Server ID.
	 * @param sOrg
	 *            The A-Select server organization.
	 */
	public void init(String sServerId, String sOrg)
	{
		_sMyServerId = sServerId;
		_sMyOrg = sOrg;
		_systemLogger = ASelectSystemLogger.getHandle();
	}

	/**
	 * Factory method for creating a request handler. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Uses a {@link RequestParser} to determine the type of request handler and constructs this type of handler. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The <code>RequestHandlerFactory</code> is initialised.</li>
	 * <li><code>servletRequest != null</code></li>
	 * <li><code>servletResponse != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param servletRequest
	 *            The request that was issued to the server.
	 * @param servletResponse
	 *            The response to the client.
	 * @return A request handler which can be used to process the request.
	 * @throws ASelectCommunicationException
	 *             If communication failed and no response was sent to the client yet.
	 */
	public IAuthnRequestHandler createRequestHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectCommunicationException
	{
		String sMethod = "createRequestHandler";
		IAuthnRequestHandler oRequestHandler = null;

		// Process all other requests
		RequestParser reqParser = new RequestParser(servletRequest);
		int orig = reqParser.getRequestOrigin();
		_systemLogger.log(Level.FINER, MODULE, sMethod, "HANDLER Orig="
				+ ((orig == RequestParser.ORIGIN_APPLICATION) ? "APPL"
					: (orig == RequestParser.ORIGIN_ASELECTSERVER) ? "ASELECT"
					: (orig == RequestParser.ORIGIN_AUTHSP) ? "AUTHSP"
					: (orig == RequestParser.ORIGIN_USER) ? "USER" : "INVALID") + ", type="
				+ ((reqParser.getRequestType() == RequestParser.REQTYPE_API_CALL) ? "API" : "BROWSER") + ", method="
				+ servletRequest.getMethod() + ", req=" + servletRequest.getParameter("request"));
		/*
		 * if (servletRequest.getMethod().equals("POST")) { Enumeration hdrNames = servletRequest.getHeaderNames();
		 * while (hdrNames.hasMoreElements()) { String hdrName = (String)hdrNames.nextElement();
		 * _systemLogger.log(Level.INFO, MODULE, sMethod, hdrName+": "+servletRequest.getHeader(hdrName)); } }
		 */

		switch (reqParser.getRequestOrigin()) {
		case RequestParser.ORIGIN_APPLICATION:
			if (reqParser.getRequestType() == RequestParser.REQTYPE_API_CALL)
				oRequestHandler = new ApplicationAPIHandler(reqParser, servletRequest, servletResponse, _sMyServerId, _sMyOrg);
			else
				oRequestHandler = new ApplicationBrowserHandler(servletRequest, servletResponse, _sMyServerId, _sMyOrg);
			break;

		case RequestParser.ORIGIN_ASELECTSERVER:
			if (reqParser.getRequestType() == RequestParser.REQTYPE_API_CALL)
				oRequestHandler = new ASelectAPIHandler(reqParser, servletRequest, servletResponse, _sMyServerId, _sMyOrg);
			else
				oRequestHandler = new ASelectBrowserHandler(servletRequest, servletResponse, _sMyServerId, _sMyOrg);
			break;

		case RequestParser.ORIGIN_AUTHSP:
			if (reqParser.getRequestType() == RequestParser.REQTYPE_API_CALL)
				oRequestHandler = new AuthSPAPIHandler(reqParser, servletRequest, servletResponse, _sMyServerId, _sMyOrg);
			else
				oRequestHandler = new AuthSPBrowserHandler(servletRequest, servletResponse, _sMyServerId, _sMyOrg);
			break;

		case RequestParser.ORIGIN_USER:
			if (reqParser.getRequestType() == RequestParser.REQTYPE_API_CALL)
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			oRequestHandler = new ApplicationBrowserHandler(servletRequest, servletResponse, _sMyServerId, _sMyOrg);
			break;

		default:
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received.");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		return oRequestHandler;
	}

	/**
	 * private constructor.
	 */
	private ASelectRequestHandlerFactory() {
	}
}
