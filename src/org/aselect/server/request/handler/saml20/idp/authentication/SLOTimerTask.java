package org.aselect.server.request.handler.saml20.idp.authentication;

import java.util.List;
import java.util.TimerTask;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.saml20.common.BackChannelLogoutRequestSender;
import org.aselect.server.request.handler.saml20.common.BackChannelLogoutResponseSender;
import org.aselect.server.request.handler.saml20.common.Utils;
import org.aselect.server.request.handler.saml20.idp.metadata.MetaDataManagerIDP;
import org.aselect.system.exception.ASelectException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.SingleLogoutService;

/**
 * This class is a timertask.
 */
public class SLOTimerTask extends TimerTask
{
	private static final String MODULE = "SLOTimerTask";

	private ASelectSystemLogger _systemLogger;

	private String issuer;
	private String user;
	private String requestId;
	private String tgtId;

	/**
	 * @param user
	 * @param requestId
	 *            the id of the original saml request
	 */
	public SLOTimerTask(String user, String requestId, String tgtId, String issuer)
	{
		super();
		String sMethod = "SLOTimerTask";
		this.user = user;
		this.requestId = requestId;
		this.issuer = issuer;
		this.tgtId = tgtId;
		_systemLogger = ASelectSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "user="+user+" requestId="+requestId+" issuer="+issuer);
	}

	@Override
	public void run()
	{
		String sMethod = "run()";

		// Check if there are any involved SPs left for this user
		// if not, we dont have to do anything
		_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN user="+user+" - requestId="+requestId + " - "+tgtId);
		UserSsoSession session = null;
		try {
			SSOSessionManager sessionManager = SSOSessionManager.getHandle();
			if (sessionManager.containsKey(user)) {
				session = sessionManager.getSsoSession(user);
			}
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Can't get session: "+e);
		}
		if (session == null) {
			// if there is no session we cant do anything
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN END - requestId="+requestId+" NO SESSION, no backchannel logout requiered");
			return;
		}
		if (!session.getTgtId().equals(tgtId)) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN END - requestId="+requestId+" NO TGT MATCH, no backchannel logout required");
			return;
		}
		List<ServiceProvider> sps = session.getServiceProviders();
		for (ServiceProvider serviceProvider : sps) {
			try {
				String sp = serviceProvider.getServiceProviderUrl();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Logout to SP="+sp+" requestId="+requestId);
				MetaDataManagerIDP metadataManager = MetaDataManagerIDP.getHandle();
				String url = metadataManager.getLocation(sp, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,
						SAMLConstants.SAML2_SOAP11_BINDING_URI);
				sendBackChannelLogoutRequest(url);
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Send failed (just continue): "+e);
			}
		}

		// now we have to send a logoutResponse to the initiating SP. One
		// of the 'other SPs' did not respond, so the chain is broken. This
		// means there was no logoutresponse send to the initiating SP yet
		// this response must now be backchannel. This is necesary for the sake
		// of completeness. Plus we get to log it

		String initiatingSP = session.getLogoutInitiator();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutResponse to initiating SP="+initiatingSP);
		try {
			if (initiatingSP != null)
				sendBackChannelLogoutResponse(initiatingSP);

			// Throw the session in the trash can, the TGT was already removed
			SSOSessionManager sessionManager = SSOSessionManager.getHandle();
			sessionManager.remove(user);
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Send failed: "+e);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN END - requestId="+requestId);
	}

	private void sendBackChannelLogoutRequest(String serviceProvider)
		throws ASelectException
	{
		String sMethod = "sendBackChannelLogoutRequest";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Logging out '" + serviceProvider + "' via backchannel");
		BackChannelLogoutRequestSender sender = new BackChannelLogoutRequestSender();
		sender.sendLogoutRequest(serviceProvider, issuer, user, "Federation initiated logout");
	}

	private void sendBackChannelLogoutResponse(String serviceProvider)
		throws ASelectException
	{
		String sMethod = "sendBackChannelLogoutResponse";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Logging out initiator '" + serviceProvider + "' via backchannel");
		BackChannelLogoutResponseSender sender = new BackChannelLogoutResponseSender();
		sender.sendLogoutResponse(serviceProvider, issuer, user, StatusCode.SUCCESS_URI, requestId);
	}
}
