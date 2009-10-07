package org.aselect.server.request.handler.xsaml20.sp;

import java.io.IOException;
import java.security.PublicKey;
import java.util.logging.Level;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.server.log.ASelectSystemLogger;

// public class Xsaml20_SessionSync extends ProtoRequestHandler // RH, 20080603, o
public class Xsaml20_SessionSync extends Saml20_BaseHandler // RH, 20080603, n
{
	private final static String MODULE = "Xsaml20_SessionSync";
	private ASelectSystemLogger _oSystemLogger = _systemLogger;
	private String _sFederationUrl;
	private String _sUpdateInterval;
	private String _sMessageType;
	private long updateInterval;
	private String _sSpUrl;

	/**
	 * Init for Xsaml20_SessionSync. <br>
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

		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SP Session Sync Handler, SpUrl=" + _sSpUrl +
				" MessageType=" + _sMessageType);

		// get credentials from url
		String sEncryptedTgt = request.getParameter("credentials");

		// Do we need to send an update to the federation?
		if (sEncryptedTgt != null) {
//			SessionSyncRequestSender ss_req = new SessionSyncRequestSender(_oSystemLogger, _sSpUrl,
//					updateInterval, _sMessageType, _sFederationUrl);
			_systemLogger.log(Level.INFO, MODULE, _sMethod, "Do session synchronization signature verification=" + is_bVerifySignature());
			PublicKey pkey = null;
			if (is_bVerifySignature()) {
				// check signature of session synchronization here
				// We get the public key from the metadata
				// We use _sFederationUrl as the Issuer to lookup the entityID in the metadata
				// We get the _sFederationUrl from aselect.xml so we consider this safe and authentic
				if (_sFederationUrl == null || "".equals(_sFederationUrl)) {
					_systemLogger.log(Level.SEVERE, MODULE, _sMethod, "For signature verification we need a valid FederationUrl");
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}
				MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
				pkey = metadataManager.getSigningKeyFromMetadata(_sFederationUrl);
				if (pkey == null || "".equals(pkey)) {
					_systemLogger.log(Level.SEVERE, MODULE, _sMethod, "No public valid key in metadata from: " + _sFederationUrl);
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
			}
//			SessionSyncRequestSender ss_req = new SessionSyncRequestSender(_oSystemLogger, _sSpUrl,
//					updateInterval, _sMessageType, _sFederationUrl, pkey);
			SessionSyncRequestSender ss_req = new SessionSyncRequestSender(_oSystemLogger, _sSpUrl,
					updateInterval, _sMessageType, _sFederationUrl, pkey, getMaxNotBefore(), getMaxNotOnOrAfter(), is_bVerifyInterval());
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
