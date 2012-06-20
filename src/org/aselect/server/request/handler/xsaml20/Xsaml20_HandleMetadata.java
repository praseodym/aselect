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
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;

/*
 * Calling example:
 * 	/aselectserver/server/handle_metadata?url=https://my.sp.nl/aselectserver/server/metadata.xml
 */
public class Xsaml20_HandleMetadata extends AbstractRequestHandler
{
	private final static String MODULE = "Xsaml20_HandleMetadata";
	private String _sMySharedSecret = null;
	
	/**
	 * Init method <br>
	 * .
	 * 
	 * @param servletConfig
	 *            ServletConfig.
	 * @param config
	 *            Object.
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig servletConfig, Object config)
	throws ASelectException
	{
		String sMethod = "init()";
		super.init(servletConfig, config);
		_sMySharedSecret = _configManager.getSharedSecret();
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "init");
		if (!Utils.hasValue(_sMySharedSecret)) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Could not retrieve 'shared_secret' from aselect config section");
			throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR);
		}

	}

	/**
	 * Process incoming request.
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If processing of meta data request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process";
		PrintWriter out;

		try {
			out = response.getWriter();
			response.setContentType("text/xml");
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not handle the request", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		String sSharedSecret = request.getParameter("shared_secret");
		if (!Utils.hasValue(sSharedSecret)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Parameter 'shared_secret' not found in request");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		if (!sSharedSecret.equals(_sMySharedSecret)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid 'shared_secret' received");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		// We only accept this request from localhost
		String sServerIp = Tools.getServerIpAddress(_systemLogger);
		String sClientIp = request.getRemoteAddr();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "ServerIp="+sServerIp+" ClientIp="+sClientIp);
		if (!sServerIp.equals(sClientIp)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Not called from the local server"+" client_ip="+sClientIp);
			out.println("This request must be called from the local server");
		}
		else {
			String sList = request.getParameter("list");
			String entityId = request.getParameter("metadata");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "list="+sList+" entityId=" + entityId);

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

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.IRequestHandler#destroy()
	 */
	public void destroy()
	{
	}
}
