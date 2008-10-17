package org.aselect.server.request.handler.saml20.sp.authentication;

import java.io.IOException;
import java.util.logging.Level;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml20.common.*;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.server.log.ASelectSystemLogger;

public class SSSpRequestHandler extends AbstractRequestHandler
{
	private final static String MODULE = "SSSpRequestHandler";

	private ASelectSystemLogger _oSystemLogger = _systemLogger;

	private String _sFederationUrl;

	private String _sUpdateInterval;

	private String _sMessageType;

	private long updateInterval;

	private String _sSpUrl;

	/**
	 * Init for SSSpRequestHandler. <br>
	 * 
	 * @param oServletConfig
	 *            The Servlet Config.
	 * @param oHandlerConfig
	 *            The Handler Config.
	 * @throws ASelectException
	 *             If initialisation fails.
	 */
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		super.init(oServletConfig, oHandlerConfig);
		_oSystemLogger = _systemLogger;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		try {
			ConfigManager oConfigManager = ASelectConfigManager.getHandle();
			Object aselectSection = oConfigManager.getSection(null, "aselect");
			_sSpUrl = _configManager.getParam(aselectSection, "redirect_url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_url' found in 'aselect' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		try {
			_sFederationUrl = _configManager.getParam(oHandlerConfig, "federation_url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'federation_url' found in 'handler' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		try {
			_sUpdateInterval = _configManager.getParam(oHandlerConfig, "update_interval");
			updateInterval = Long.parseLong(_sUpdateInterval);
			updateInterval = updateInterval * 1000;
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Update interval on SP = " + updateInterval);
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'updateinterval' found in 'handler' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		try {
			_sMessageType = _configManager.getParam(oHandlerConfig, "message_type");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'message_type' found in 'handler' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	public void destroy()
	{
	}

	/**
	 * Process incoming session synchronization message. <br>
	 * TODO: Signature checking is missing
	 * 
	 * @param request
	 *            The HttpServletRequest.
	 * @param response
	 *            The HttpServletResponse.
	 * @throws ASelectException
	 *             If processing of request fails.synchronizeSession
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String errorCode = Errors.ERROR_ASELECT_SUCCESS;
		String _sMethod = "process";

		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SS SP RequestHandler, SpUrl=" + _sSpUrl +
				" MessageType=" + _sMessageType);

		// get credentials from url
		String sEncryptedTgt = request.getParameter("credentials");

		// Do we need to send an update to the federation?
		if (sEncryptedTgt != null) {
			SessionSyncRequestSender ss_req = new SessionSyncRequestSender(_oSystemLogger, _sSpUrl,
					updateInterval, _sMessageType, _sFederationUrl);
			errorCode = ss_req.synchronizeSession(sEncryptedTgt, true/*coded*/, true/*upgrade*/);
		}
		else {
			errorCode = Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST;
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SP - No credentials available");
		}

		try {
			response.getWriter().write("result_code=" + errorCode);
		}
		catch (IOException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to write response", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return null;
	}

}
