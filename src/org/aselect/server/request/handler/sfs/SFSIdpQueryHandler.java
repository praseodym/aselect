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

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;


/**
 * The A-Select SFS Idp Query Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * The A-Select Server IdP Query request handler (> A-Select 1.4).<br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class SFSIdpQueryHandler extends AbstractRequestHandler
{
	private final static String MODULE = "SFSIdpQueryHandler";
	private CrossASelectManager _crossASelectManager;
	private String _sMySharedSecret = null;
	private HashMap _htSFSOrganizations = null;
	private String _sOrganizationId = null;

	/**
	 * Init function. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * <br>
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

		_htSFSOrganizations = new HashMap();
		super.init(oServletConfig, oConfig);
		try {
			try {
				_sMySharedSecret = _configManager.getParam(oConfig, "shared_secret");

			}
			catch (ASelectConfigException e) {
				_sMySharedSecret = null;
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'shared_secret' configured");
			}
			try {
				Object oASelectConfig = _configManager.getSection(null, "aselect");
				_sOrganizationId = _configManager.getParam(oASelectConfig, "organization");
				String sOrganizationFriendlyName = _configManager
						.getParam(oASelectConfig, "organization_friendly_name");
				_htSFSOrganizations.put(sOrganizationFriendlyName, _sOrganizationId);

			}
			catch (ASelectConfigException e) {
				_sMySharedSecret = null;
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No extra sfs configuration found, skipping.");
				throw e;
			}

			Object oSfsConfig = null;
			try {
				oSfsConfig = _configManager.getSection(null, "sfs");

			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No extra sfs configuration found, skipping.");
			}

			if (oSfsConfig != null) {
				try {
					Object oIdpCfg = null;

					try {
						oIdpCfg = _configManager.getSection(oSfsConfig, "idp");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.INFO, MODULE, sMethod,
								"No \"idp\" entries configured in \"sfs\" section.");
						oIdpCfg = null;
					}

					while (oIdpCfg != null) {
						String sFriendlyName = _configManager.getParam(oIdpCfg, "friendly_name");
						String sOrganization = _configManager.getParam(oIdpCfg, "organization");
						_htSFSOrganizations.put(sFriendlyName, sOrganization);
						oIdpCfg = _configManager.getNextSection(oIdpCfg);

					}
				}
				catch (ASelectConfigException e) {
					throw e;
				}
			}

		}
		catch (ASelectException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "initialization failed", e);
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unexpected runtime error occured: ", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		_crossASelectManager = CrossASelectManager.getHandle();

	}

	/**
	 * Main process function.
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
		boolean bContinue = true;
		String sMethod = "process()";
		HashMap htResult = new HashMap();
		try {
			StringBuffer sbResult = null;
			if (!_crossASelectManager.isCrossSelectorEnabled() || !_crossASelectManager.remoteServersEnabled()) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"cross is disabled or there are no remote servers configured.");
				sbResult = new StringBuffer("result_code=").append(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			else {
				if (_sMySharedSecret != null) {
					String sSharedSecret = request.getParameter("shared_secret");
					if (sSharedSecret == null || !sSharedSecret.equals(_sMySharedSecret)) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid 'shared_secret' provided.");
						sbResult = new StringBuffer("result_code=").append(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
						bContinue = false;
					}
				}
				if (bContinue) {
					HashMap htRemoteServers = _crossASelectManager.getRemoteServers();
					Set keys = htRemoteServers.keySet();
					for (Object s : keys) {
						String sOldKey = (String) s;
						// Enumeration e = htRemoteServers.keys();
						// while (e.hasMoreElements())
						// {
						// String sOldKey = (String)e.nextElement();
						String sOldValue = (String) htRemoteServers.get(sOldKey);

						if (!htResult.containsValue(sOldValue)) {
							String sDisplay = _crossASelectManager.getRemoteParam(sOldKey, "display");
							if ((sDisplay == null) || (sDisplay.equalsIgnoreCase("true"))) {
								htResult.put(sOldValue, sOldKey);
							}
						}
						else
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to add '" + sOldValue
									+ "', value already exists.");
					}

					keys = _htSFSOrganizations.keySet();
					for (Object s : keys) {
						String sFriendlyName = (String) s;
						// e = _htSFSOrganizations.keys();
						// while (e.hasMoreElements())
						// {
						// String sFriendlyName = (String)e.nextElement();
						String sOrganizationId = (String) _htSFSOrganizations.get(sFriendlyName);
						htResult.put(sFriendlyName, sOrganizationId);
					}

					String sCgiString = Utils.hashtable2CGIMessage(htResult);

					String sEncodedCgiString = URLEncoder.encode(sCgiString, "UTF-8");
					sbResult = new StringBuffer("result_code=").append(Errors.ERROR_ASELECT_SUCCESS).append("&result=")
							.append(sEncodedCgiString);
				}
			}
			PrintWriter pwOut = response.getWriter();
			pwOut.print(sbResult.toString());
			if (pwOut != null)
				pwOut.close();
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request", e);
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
