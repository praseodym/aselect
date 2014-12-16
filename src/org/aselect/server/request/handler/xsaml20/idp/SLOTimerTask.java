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
package org.aselect.server.request.handler.xsaml20.idp;

import java.security.PublicKey;
import java.util.HashMap;
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
	private boolean _bVerifySignature = false; // choose default = false

	/**
	 * The Constructor.
	 * 
	 * @param requestId
	 *            the id of the original saml request
	 * @param tgtId
	 *            the tgt id
	 * @param sso
	 *            the sso
	 * @param issuer
	 *            the issuer
	 */
	public SLOTimerTask(String tgtId, String requestId, UserSsoSession sso, String issuer) {
		super();
		String sMethod = "SLOTimerTask";
		this.sso = sso;
		this.requestId = requestId;
		this.issuer = issuer;
		this.tgtId = tgtId;
		_systemLogger = ASelectSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "user=" + sso.getUserId() + " requestId=" + requestId
				+ " issuer=" + issuer);
	}

	/* (non-Javadoc)
	 * @see java.util.TimerTask#run()
	 */
	@Override
	public void run()
	{
		String sMethod = "run";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN user=" + sso.getUserId() + " - requestId=" + requestId
				+ " - " + tgtId + " mySso=" + this.sso);

		// Check if there are any involved SPs left for this user
		TGTManager tgtManager = TGTManager.getHandle();
		HashMap tgtContext = tgtManager.getTGT(tgtId);
		if (tgtContext == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN END - requestId=" + requestId
					+ " NO TGT, no backchannel logout requiered");
			return;
		}
		// Remove the TGT if it's still there
		try {
			tgtManager.remove(tgtId);
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Removing TGT failed " + tgtId + ", continue");
		}
		UserSsoSession tgtSso = (UserSsoSession) tgtContext.get("sso_session");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Soap logout to all, using tgt.SSO=" + tgtSso);

		// We have our own version: UserSsoSession sso = (UserSsoSession)tgtContext.get("sso_session");
		// Nono use the version from the Tgt, it contains all that's left of the SP's
		if (tgtSso == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN END - requestId=" + requestId
					+ " NO SESSION, no backchannel logout requiered");
			return;
		}

		// Send a backchannel logout to all known SP's
		String initiatingSP = tgtSso.getLogoutInitiator();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "initiatingSP=" + initiatingSP);
		List<ServiceProvider> sps = tgtSso.getServiceProviders();
		for (ServiceProvider serviceProvider : sps) {
			try {
				String sp = serviceProvider.getServiceProviderUrl();
				if (initiatingSP != null && sp.equals(initiatingSP)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "SKIP " + serviceProvider);
					continue;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Logout to SP=" + sp + " requestId=" + requestId);
				MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
				String url = metadataManager.getLocation(sp, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,
						SAMLConstants.SAML2_SOAP11_BINDING_URI);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Logging out '" + sp + "' via backchannel");
				SoapLogoutRequestSender sender = new SoapLogoutRequestSender();

				// Unfortunately we have no handle to the aselect configuration
				// so we have no way to know whether we should verify the signature
				// RM_44_01
				PublicKey pkey = null;
				if (is_bVerifySignature()) {
					pkey = metadataManager.getSigningKeyFromMetadata(sp);
					if (pkey == null || "".equals(pkey)) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No valid public key in metadata");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
				}
				sender.sendSoapLogoutRequest(url, issuer, tgtId, "urn:oasis:names:tc:SAML:2.0:logout:admin", pkey); // was:
				// "Federation initiated logout"
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Send failed (but continue): " + e);
			}
		}

		// Now we have to send a logoutResponse to the initiating SP. One
		// of the 'other SPs' did not respond, so the chain is broken. This
		// means there was no logoutresponse sent to the initiating SP yet
		// this response must now be backchannel. This is necesary for the sake
		// of completeness. Plus we get to log it
		_systemLogger.log(Level.INFO, MODULE, sMethod, "FINAL: LogoutResponse to initiating SP=" + initiatingSP);
		try {
			if (initiatingSP != null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Logging out initiator '" + initiatingSP
						+ "' via backchannel");
				SoapLogoutResponseSender sender = new SoapLogoutResponseSender();
				sender.sendSoapLogoutResponse(initiatingSP, issuer, tgtId, StatusCode.SUCCESS_URI, requestId);
			}
			// Throw the session in the trash can, the TGT was already removed
			// SSOSessionManager sessionManager = SSOSessionManager.getHandle();
			// sessionManager.remove(user);
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Send failed: " + e);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "RUN END - requestId=" + requestId);
	}

	/**
	 * Checks if is _b verify signature.
	 * 
	 * @return true, if is _b verify signature
	 */
	public synchronized boolean is_bVerifySignature()
	{
		return _bVerifySignature;
	}

	/**
	 * Sets the _b verify signature.
	 * 
	 * @param verifySignature
	 *            the new _b verify signature
	 */
	public synchronized void set_bVerifySignature(boolean verifySignature)
	{
		_bVerifySignature = verifySignature;
	}
}
