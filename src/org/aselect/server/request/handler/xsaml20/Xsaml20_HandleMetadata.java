/*
 * Copyright (c) ICTU. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 *
 * @author Bauke Hiemstra - www.anoigo.nl
 * 
 * Version 1.0 - 16-1-2008
 */
package org.aselect.server.request.handler.xsaml20;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.xsaml20.idp.MetaDataManagerIdp;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;

/*
 * Calling example:
 * 	/aselectserver/server/handle_metadata?url=https://my.sp.nl/aselectserver/server/metadata.xml
 */
public class Xsaml20_HandleMetadata extends AbstractRequestHandler
{
	private final static String MODULE = "Xsaml20_HandleMetadata";

	/**
	 * Init method
	 * <br>
	 * @param servletConfig ServletConfig.
	 * @param config Object.
	 * @throws ASelectException If initialization fails.
	 */
	@Override
	public void init(ServletConfig servletConfig, Object config)
	throws ASelectException
	{
		String sMethod = "init()";
		super.init(servletConfig, config);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "init");
	}

	/**
	 * Process incoming request
	 * <br>
	 * @param request HttpServletRequest.
	 * @param response HttpServletResponse.
	 * @throws ASelectException If processing of meta data request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process";
		String urlSite = "//localhost";
		PrintWriter out;

		StringBuffer path = request.getRequestURL();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "path="+path);
		try {
			out = response.getWriter();
			response.setContentType("text/xml");
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not handle the request", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		// We only accept this request from localhost
		// http://localhost:8080/...
		int idx = path.indexOf(urlSite);
		char nextChar = '\0';
		if (idx >= 0) {
			nextChar = path.charAt(idx+urlSite.length());
		}
		if (idx < 0 || (nextChar != ':' && nextChar != '/')) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Not called from '//localhost'");
			out.println("This request must be called from '//localhost'!");
		}
		else {
			String sList = request.getParameter("list");
			String entityId = request.getParameter("metadata");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId="+entityId);
			
			if (sList == null && entityId == null) {
				out.println("Parameter 'metadata' is missing!");
			}
			else {
				MetaDataManagerIdp metadataMgr = MetaDataManagerIdp.getHandle();
				metadataMgr.handleMetadataProvider(out, entityId, sList != null);
			}
		}
		out.flush();
		out.close();
		return null;
	}

	public void destroy()
	{
	}
}
