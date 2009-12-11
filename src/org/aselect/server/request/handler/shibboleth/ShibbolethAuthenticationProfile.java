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
 * $Id: ShibbolethAuthenticationProfile.java,v 1.8 2006/05/03 10:11:08 tom Exp $ 
 */

package org.aselect.server.request.handler.shibboleth;

import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.communication.client.soap11.SOAP11Communicator;
import org.aselect.system.communication.client.soap12.SOAP12Communicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

// TODO: Auto-generated Javadoc
/**
 * Shibboleth interface for A-Select. <br>
 * <br>
 * <b>Description:</b><br>
 * The Shibboleth interface for the A-Select Server.<br/>
 * HTTP GET containg the following items in the querystring<br/>
 * <ul>
 * <li><b>target</b> - The location of the resource that the user wants to access</li>
 * <li><b>shire</b> - the Service Provider location wereto the response must be sent</li>
 * <li><b>providerId</b> - The ID of the application that is secured</li>
 * <li><b>time</b> (optional) - The client system time in seconds</li>
 * </ul>
 * <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class ShibbolethAuthenticationProfile extends AbstractRequestHandler
{
	private final static String MODULE = "ShibbolethAuthenticationProfile";
	private final static String SESSION_ID_PREFIX = "saml11_";

	private IClientCommunicator _oClientCommunicator;
	private HashMap _htApplications;
	private String _sASelectServerID;
	private String _sResponseURI;
	private long _lTimeOffset;

	/**
	 * Initializes the request handler by reading the following configuration: <br/>
	 * <br/>
	 * &lt;handler&gt;<br/>
	 * &nbsp;&lt;clientcommunicator&gt;[clientcommunicator]&lt;/clientcommunicator&gt;<br/>
	 * &nbsp;&lt;response_uri&gt;[response_uri]&lt;/response_uri&gt;<br/>
	 * &nbsp;&lt;time offset='[offset]'/&gt;<br/>
	 * &nbsp;&lt;providers&gt;<br/>
	 * &nbsp;&nbsp;&lt;provider id='[providerId]' app_id='[app_id]'/&gt;<br/>
	 * &nbsp;&nbsp;...<br/>
	 * &nbsp;&lt;/providers&gt;<br/>
	 * &lt;/handler&gt;<br/>
	 * <ul>
	 * <li><b>clientcommunicator</b> - Client communicator used for communicating to the A-Select Server SAML 11
	 * requesthandler (raw/soap11/soap12)</li>
	 * <li><b>response_uri</b> - URI to the SAML 1.1 requesthandler</li>
	 * <li><b>offset</b> - time offset in seconds</li>
	 * <li><b>providerId</b> - The providerId that corresponds to the A-Select application ID</li>
	 * <li><b>app_id</b> - The A-Select Application id that corresponds to the providerId</li>
	 * </ul>
	 * <br>
	 * <br>
	 * 
	 * @param oServletConfig
	 *            the o servlet config
	 * @param oConfig
	 *            the o config
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";
		try {
			super.init(oServletConfig, oConfig);

			String sClientCommunicator = null;
			try {
				sClientCommunicator = _configManager.getParam(oConfig, "clientcommunicator");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'clientcommunicator' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sResponseURI = _configManager.getParam(oConfig, "response_uri");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'response_uri' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			Object oTime = null;
			try {
				oTime = _configManager.getSection(oConfig, "time");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'time' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			String sTimeOffset = null;
			try {
				sTimeOffset = _configManager.getParam(oTime, "offset");
				_lTimeOffset = Long.parseLong(sTimeOffset);
				_lTimeOffset = _lTimeOffset * 1000;
			}
			catch (NumberFormatException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Configured time offset isn't a number: "
						+ sTimeOffset, e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'offset' found in section 'time'", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			if (_lTimeOffset < 1) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Config item 'offset' in 'time' section must be higher than 0 and not: " + sTimeOffset);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			_htApplications = new HashMap();

			Object oProviders = null;
			try {
				oProviders = _configManager.getSection(oConfig, "providers");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'providers' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			Object oProvider = null;
			try {
				oProvider = _configManager.getSection(oProviders, "provider");
			}
			catch (ASelectConfigException e) {
				_systemLogger
						.log(
								Level.CONFIG,
								MODULE,
								sMethod,
								"No config item 'provider' in section 'providers' found, not using any application id to provider id mapping",
								e);
			}

			while (oProvider != null) {
				String sProviderID = null;
				try {
					sProviderID = _configManager.getParam(oProvider, "id");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No config item 'id' found in 'provider' section", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				String sAppID = null;
				try {
					sAppID = _configManager.getParam(oProvider, "app_id");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No config item 'app_id' found in 'provider' section", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				if (_htApplications.containsKey(sProviderID)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Configured provider id isn't unique: "
							+ sProviderID);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}

				_htApplications.put(sProviderID, sAppID);

				oProvider = _configManager.getNextSection(oProvider);
			}

			Object oASelect = null;
			try {
				oASelect = _configManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'aselect' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sASelectServerID = _configManager.getParam(oASelect, "server_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config item 'server_id' found in 'aselect' section", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			if (sClientCommunicator == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'clientcommunicator' found");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			if (sClientCommunicator.equalsIgnoreCase("soap11")) {
				_oClientCommunicator = new SOAP11Communicator("ASelect", _systemLogger);
			}
			else if (sClientCommunicator.equalsIgnoreCase("soap12")) {
				_oClientCommunicator = new SOAP12Communicator("ASelect", _systemLogger);
			}
			else if (sClientCommunicator.equalsIgnoreCase("raw")) {
				_oClientCommunicator = new RawCommunicator(_systemLogger);
			}

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
	 * Processes the following request:<br/>
	 * <code>?providerId=[providerId]&shire=[shire]&target=[target]&time=[time]</code><br/>
	 * The <code>time</code> parameter is optional, if available the request will be checked for expiration. A request
	 * is expired if the sent time has a bigger delay then the configured offset. <br/>
	 * <br/>
	 * During processing, the following steps are runned through:
	 * <ul>
	 * <li>checking validity of the request parameters</li>
	 * <li>maps the providerId to a configured app_id</li>
	 * <li>sends a <code>request=authenticate</code> to the A-Select Server</li>
	 * <li>creates a SAML session</li>
	 * <li>redirects the user to the A-Select Server</li>
	 * </ul>
	 * <br>
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
		HashMap htSession = new HashMap();
		try {
			String sProviderId = request.getParameter("providerId"); // application ID
			if (sProviderId == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing request parameter 'providerId'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			htSession.put("providerId", sProviderId);

			String sShire = request.getParameter("shire"); // response address
			if (sShire == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing request parameter 'shire'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			htSession.put("shire", sShire);

			String sTarget = request.getParameter("target"); // information
			if (sTarget == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing request parameter 'target'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			htSession.put("target", sTarget);

			String sTime = request.getParameter("time"); // current time at the application
			if (sTime == null) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Missing optional request parameter 'time'");
			}
			else {
				long lOffset = 0;
				try {
					long lTime = Long.parseLong(sTime);
					lTime = lTime * 1000;
					lOffset = System.currentTimeMillis() - lTime;
					if (lOffset < 0)
						lOffset = lOffset * -1;
				}
				catch (NumberFormatException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request item 'time' isn't a number: " + sTime);
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST, e);
				}

				if (lOffset > _lTimeOffset) {
					StringBuffer sbError = new StringBuffer();
					sbError.append("Request not accepted; Time offset is '");
					sbError.append(lOffset);
					sbError.append("' , it may be: ");
					sbError.append(_lTimeOffset);
					_systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());

					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}

				htSession.put("time", sTime);
			}

			String sApplicationID = null;
			if ((sApplicationID = (String) _htApplications.get(sProviderId)) == null) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No mapping found for app_id: " + sProviderId);
				sApplicationID = sProviderId;
			}

			htSession.put("app_id", sApplicationID);

			String sRequestURL = request.getRequestURL().toString();
			String sContextPath = request.getContextPath();
			String sServletPath = request.getServletPath();

			int iLocation = sRequestURL.indexOf(sContextPath);
			String sStartURL = sRequestURL.substring(0, iLocation);
			StringBuffer sbUrl = new StringBuffer(sStartURL);
			sbUrl.append(sContextPath);
			sbUrl.append(sServletPath);
			String sASelectURL = sbUrl.toString();

			sbUrl.append(_sResponseURI);

			HashMap htRequest = new HashMap();
			htRequest.put("request", "authenticate");
			htRequest.put("app_id", sApplicationID);
			htRequest.put("app_url", sbUrl.toString());
			htRequest.put("a-select-server", _sASelectServerID);

			// added 1.5.4
			// https://wayf.surfnet.nl/aselectserver/server/shib-idp?target=https%3A%2F%2Fsdauth-cert3.sciencedirect.com&shire=https%3A%2F%2Fsdauth-cert3.sciencedirect.com%2FSHIRE&providerId=https%3A%2F%2Fsdauth.sciencedirect.com%2F
			String pathInfo = request.getPathInfo();
			// TODO: make this configurable or at least matching to handler target...
			if (!pathInfo.endsWith("shib-idp")) {

				String[] split = pathInfo.split("/");
				String sRemoteOrg = split[split.length - 1];
				_systemLogger.log(Level.FINER, MODULE, sMethod, "set remote organization to: " + sRemoteOrg);

				if ((sRemoteOrg != null) && (sRemoteOrg.length() > 0)) {
					htRequest.put("remote_organization", sRemoteOrg);
				}
			}

			if (ApplicationManager.getHandle().isSigningRequired()) {
				CryptoEngine.getHandle().signRequest(htRequest);
			}

			HashMap htResponse = null;

			try {
				htResponse = _oClientCommunicator.sendMessage(htRequest, sASelectURL);
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not send authentication request to: "
						+ sASelectURL);
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}

			String sResultCode = (String) htResponse.get("result_code");
			if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Authentication request was not succesful, server returned 'result_code': " + sResultCode);
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}

			sASelectURL = (String) htResponse.get("as_url");
			String sRid = (String) htResponse.get("rid");
			htSession.put("as_url", sASelectURL);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "htSession client_ip was " + htSession.get("client_ip"));
			htSession.put("client_ip", request.getRemoteAddr());
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htSession client_ip is now " + htSession.get("client_ip"));

			_oSessionManager.writeSession(SESSION_ID_PREFIX + sRid, htSession);

			// redirect with A-Select request=login1
			StringBuffer sbURL = new StringBuffer(sASelectURL);
			sbURL.append("&rid=");
			sbURL.append(sRid);
			sbURL.append("&a-select-server=");
			sbURL.append(_sASelectServerID);
			response.sendRedirect(sbURL.toString());
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return new RequestState(null);
	}

	/**
	 * Removes the class variables from memory <br>
	 * <br>
	 * .
	 * 
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#destroy()
	 */
	public void destroy()
	{
		// does nothing
	}

}
