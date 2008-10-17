package org.aselect.server.request.handler.xsaml20.idp;

import java.security.PublicKey;
import java.util.Hashtable;
import java.util.List;
import java.util.TimerTask;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.xsaml20.ServiceProvider;
import org.aselect.server.request.handler.xsaml20.idp.MetaDataManagerIdp;
import org.aselect.server.request.handler.xsaml20.SoapLogoutRequestSender;
import org.aselect.server.request.handler.xsaml20.SoapLogoutResponseSender;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
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
	// sso contains the remaining SP's, they were not reached using a redirect logout
	private UserSsoSession sso;
	private String requestId;
	private String tgtId;
	private boolean _bVerifySignature = false; 	// choose default = false


	/**
	 * @param user
	 * @param requestId
	 *            the id of the original saml request
	 */
	public SLOTimerTask(String tgtId, String requestId, UserSsoSession sso, String issuer)
	{
		super();
		String sMethod = "SLOTimerTask";
		this.sso = sso;
		this.requestId = requestId;
		this.issuer = issuer;
		this.tgtId = tgtId;
		_systemLogger = ASelectSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "user="+sso.getUserId()+" requestId="+requestId+" issuer="+issuer);
	}

	@Override
	public void run()
	{
		String sMethod = "run()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN user="+sso.getUserId()+" - requestId="+requestId + " - "+tgtId);

		// Check if there are any involved SPs left for this user
//		try {
		TGTManager tgtManager = TGTManager.getHandle();
		Hashtable tgtContext = tgtManager.getTGT(tgtId);
		if (tgtContext == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN END - requestId="+requestId+" NO TGT, no backchannel logout requiered");
			return;
		}
		// Remove the TGT if it's still there
		try {
			tgtManager.remove(tgtId);
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Removing TGT failed "+tgtId+", continue");
		}
			//SSOSessionManager sessionManager = SSOSessionManager.getHandle();
			//if (sessionManager.containsKey(user)) {
			//	session = sessionManager.getSsoSession(user);
			//}
//		}
//		catch (ASelectException e) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Can't get session: "+e);
//		}
		
		// We have our own version: UserSsoSession sso = (UserSsoSession)tgtContext.get("sso_session");
		
		// Nono use the version from the Tgt, it contains all that's left of the SP's
		if (sso == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN END - requestId="+requestId+" NO SESSION, no backchannel logout requiered");
			return;
		}
//		if (!session.getTgtId().equals(tgtId)) {
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN END - requestId="+requestId+" NO TGT MATCH, no backchannel logout required");
//			return;
//		}
		
		// Send a backchannel logout to all known SP's
		String initiatingSP = sso.getLogoutInitiator();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "initiatingSP="+initiatingSP);
		List<ServiceProvider> sps = sso.getServiceProviders();
		for (ServiceProvider serviceProvider : sps) {
			try {
				String sp = serviceProvider.getServiceProviderUrl();
				if (initiatingSP != null && sp.equals(initiatingSP)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "SKIP "+serviceProvider);
					continue;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Logout to SP="+sp+" requestId="+requestId);
				MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
				String url = metadataManager.getLocation(sp, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,
						SAMLConstants.SAML2_SOAP11_BINDING_URI);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Logging out '" + serviceProvider + "' via backchannel");
				SoapLogoutRequestSender sender = new SoapLogoutRequestSender();
				
				// Unfortunately we have no handle to the aselect configuration
				// so we have no way to know whether we should verify the signature
				// TODO verify the signature if we know that we have to and set_bVerirfySignature accordingly
				PublicKey pkey = null;
				if (is_bVerifySignature()) {
					pkey = metadataManager.getSigningKey(sp);
					if (pkey == null || "".equals(pkey)) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No valid public key in metadata");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
				}
//				sender.sendSoapLogoutRequest(url, issuer, tgtId, "Federation initiated logout");
				sender.sendSoapLogoutRequest(url, issuer, tgtId, "Federation initiated logout", pkey);
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Send failed (but continue): "+e);
			}
		}

		// now we have to send a logoutResponse to the initiating SP. One
		// of the 'other SPs' did not respond, so the chain is broken. This
		// means there was no logoutresponse send to the initiating SP yet
		// this response must now be backchannel. This is necesary for the sake
		// of completeness. Plus we get to log it
		_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutResponse to initiating SP="+initiatingSP);
		try {
			if (initiatingSP != null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Logging out initiator '" + initiatingSP + "' via backchannel");
				SoapLogoutResponseSender sender = new SoapLogoutResponseSender();
				sender.sendSoapLogoutResponse(initiatingSP, issuer, tgtId, StatusCode.SUCCESS_URI, requestId);
			}
			// Throw the session in the trash can, the TGT was already removed
			//SSOSessionManager sessionManager = SSOSessionManager.getHandle();
			//sessionManager.remove(user);
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Send failed: "+e);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN END - requestId="+requestId);
	}

	public synchronized boolean is_bVerifySignature() {
		return _bVerifySignature;
	}

	public synchronized void set_bVerifySignature(boolean verifySignature) {
		_bVerifySignature = verifySignature;
	}
}
