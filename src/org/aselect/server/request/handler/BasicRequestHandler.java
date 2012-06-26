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
package org.aselect.server.request.handler;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.application.Application;
import org.aselect.server.application.ApplicationManager;
import org.aselect.server.authspprotocol.handler.AuthSPHandlerManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.server.udb.UDBConnectorFactory;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectUDBException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;

//
// The mother of all RequestHandlers ...
//
public abstract class BasicRequestHandler
{
	public final static String MODULE = "BasicRequestHandler";

	protected ASelectSystemLogger _systemLogger;
	protected ASelectConfigManager _configManager;

	// This code was stolen from ApplicationAPIHandler.handleAuthenticateRequest()
	// But also slightly different versions were found in ASelectAPIHandler and the 'sfs' handlers
	// Improve: Code should be merged.
	/**
	 * Handle authenticate and create session.
	 * 
	 * @param hmInput
	 *            the hm input
	 * @param sUrlTarget
	 *            the s url target
	 * @return the hash map< string, string>
	 * @throws ASelectException
	 *             on any failure
	 */
	protected HashMap<String, Object> handleAuthenticateAndCreateSession(HashMap<String, String> hmInput, String sUrlTarget)
	throws ASelectException
	{
		String sMethod = "handleAuthenticateAndCreateSession";
		AuthSPHandlerManager _authSPManagerManager = AuthSPHandlerManager.getHandle();
		SessionManager _sessionManager = SessionManager.getHandle();
		ApplicationManager _applicationManager = ApplicationManager.getHandle();

		if (!_applicationManager.hasApplicationsConfigured()) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request since no applications are configured.");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		String sUsi = hmInput.get("usi");
		if (!Utils.hasValue(sUsi))
			sUsi = Tools.generateUniqueSensorId();  // 20120111, Bauke added

		String sAppId = hmInput.get("app_id");
		String sAppUrl = hmInput.get("app_url");
		String sASelectServer = hmInput.get("a-select-server");
		if (sAppId == null || sAppUrl == null || sASelectServer == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing required parameter(s)");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		String sUid = hmInput.get("uid");
		String sAuthsp = hmInput.get("authsp");
		String sRemoteOrg = hmInput.get("remote_organization");
		String sCountry = hmInput.get("country");
		String sLanguage = hmInput.get("language");

		// Accept both 'forced_logon' and 'forced_authenticate' (preferred)
		String sForcedAuthn = hmInput.get("forced_authenticate");  // a String this time
		Boolean boolForcedAuthn = new Boolean(sForcedAuthn);

		String sForcedLogon = hmInput.get("forced_logon");
		if (sForcedLogon != null)
			boolForcedAuthn = new Boolean(sForcedLogon);

		// check if request should be signed
		String sCheckSignature = hmInput.get("check-signature");

		// RH, 20100910, Remove fishing leak and make signature verification configurable per application
//		if (_applicationManager.isSigningRequired() && bCheckSignature) {		// RH, 20100910, o
//		if (_applicationManager.isSigningRequired(sAppId)) {		// RH, 20100910, n
		
		// 20110407, Bauke: use check-signature
		if (_applicationManager.isSigningRequired(sAppId) && "true".equals(sCheckSignature)) {
			String sSignature = hmInput.get("signature");
			if (sSignature == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing required 'signature' parameter");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			// Check signature
			// NOTE: add sbData items sorted!
			StringBuffer sbData = new StringBuffer(sASelectServer);
			sbData.append(sAppId).append(sAppUrl);
			if (sAuthsp != null)
				sbData.append(sAuthsp);
			if (sCountry != null)
				sbData.append(sCountry);
			if (sForcedAuthn != null)
				sbData.append(sForcedAuthn);
			if (sForcedLogon != null)
				sbData.append(sForcedLogon);
			if (sLanguage != null)
				sbData.append(sLanguage);
			if (sRemoteOrg != null)
				sbData.append(sRemoteOrg);
			if (sUid != null)
				sbData.append(sUid);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "sbData=" + sbData);
			verifyApplicationSignature(sSignature, sbData.toString(), sAppId);
		}

		// check if application is registered
		if (!_applicationManager.isApplication(sAppId)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unknown application ID");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
		}
		Integer intAppLevel = _applicationManager.getRequiredLevel(sAppId);
		if (intAppLevel == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No level specified for application with ID: '"+sAppId+"'");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_APP_LEVEL);
		}
		Integer intMaxAppLevel = _applicationManager.getMaxLevel(sAppId);

		// 20090305, Bauke: Accept DigiD protocol
		Application aApp = _applicationManager.getApplication(sAppId);
		String sSharedSecret = aApp.getSharedSecret();
		if (sSharedSecret != null) {
			String sArg = hmInput.get("shared_secret");
			if (sArg == null || !sSharedSecret.equals(sArg)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Shared secret for app '" + sAppId
//						+ "' does not match or is missing: "+ sArg + "!="+ sSharedSecret);
				// we don't want to disclose any secrets in the log
				+ "' does not match or is missing");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}

		// 20090305, Bauke: The <application> itself can also set forced_uid / forced_authsp if so configured
		if (sAuthsp == null) {
			sAuthsp = aApp.getForcedAuthsp();
//			// RH, 20110920, sn,  for sequential authsps introduced new parameter for backward compatibility
//			// sequential authsps not implemented (yet) for "normal" authsp, only for direct_authsp
//			if (sAuthsp == null && aApp.getFirstAuthsp() != null ) {
//				_systemLogger.log(Level.INFO, MODULE, sMethod, "found first_authsp="+aApp.getFirstAuthsp()+" ,setting authsp to:"+aApp.getFirstAuthsp());
//				sAuthsp = aApp.getFirstAuthsp();
//			}			
//			// RH, 20110920, en
		}
		if (sUid == null) {
			sUid = aApp.getForcedUid();
		}
		_systemLogger.log(Level.FINE, MODULE, sMethod, "sAuthsp="+sAuthsp+" sUid="+sUid);
				
		// Create Session
		HashMap htSessionContext = new HashMap();
		htSessionContext.put("usi", sUsi);
		htSessionContext.put("app_id", sAppId);
		htSessionContext.put("app_url", sAppUrl);
		htSessionContext.put("level", intAppLevel); // NOTE: Integer put
		if (intMaxAppLevel != null)
			htSessionContext.put("max_level", intMaxAppLevel);

		String sOrg = ASelectConfigManager.getParamFromSection(null, "aselect", "organization", true);
		htSessionContext.put("organization", sOrg);

		// Organization and uid are stored in the session context with a temporary identifier.
		// This because the values are not validated yet.
		// After validation, these values can be set as 'user_id' and 'remote_organization'.
		//
		// Bauke 20080511: added "forced_authsp" to influence AuthSP choice
		if (sRemoteOrg != null)
			htSessionContext.put("forced_organization", sRemoteOrg);
		if (sUid != null)
			htSessionContext.put("forced_uid", sUid);
		if (sAuthsp != null)
			htSessionContext.put("forced_authsp", sAuthsp);

		// need to check if the request must be handled as a forced authentication
		if (!boolForcedAuthn.booleanValue() && _applicationManager.isForcedAuthenticateEnabled(sAppId)) {
			boolForcedAuthn = new Boolean(true);
		}
		htSessionContext.put("forced_authenticate", boolForcedAuthn); // NOTE: the Boolean object, not a string

		// check single sign-on groups
		if (_configManager.isSingleSignOn()) {
			Vector vSSOGroups = _applicationManager.getSSOGroups(sAppId);
			if (vSSOGroups != null)
				htSessionContext.put("sso_groups", vSSOGroups);
		}

		if (sCountry != null && sCountry.trim().length() > 0)
			htSessionContext.put("country", sCountry);

		// 20091113, Bauke: Also take sAppUrl into consideration
		if (sLanguage != null && sLanguage.trim().length() > 0)
			htSessionContext.put("language", sLanguage.toLowerCase());
		int idx = sAppUrl.indexOf("?");
		if (idx != -1) {
			String sArgs = sAppUrl.substring(idx + 1);
			HashMap<String, String> hmArgs = Utils.convertCGIMessage(sArgs, false);
			sLanguage = hmArgs.get("language");
			if (sLanguage != null) // takes precedence
				htSessionContext.put("language", sLanguage.toLowerCase());
		}
		// *1

		StringBuffer sbAsUrl = new StringBuffer();
		String sAsUrl = _configManager.getRedirectURL();
		if (sAsUrl != null)
			sbAsUrl.append(sAsUrl);
		else if (sUrlTarget != null)
			sbAsUrl.append(sUrlTarget);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "appLevel="+intAppLevel+" maxAppLevel="+intMaxAppLevel);
		Vector vAuthSPs = _authSPManagerManager.getConfiguredAuthSPs(intAppLevel, intMaxAppLevel);
		
		// Authentication OK
		// Single direct_authsp left?
		if (vAuthSPs.size() == 1 && _authSPManagerManager.isDirectAuthSP((String)vAuthSPs.get(0))) {
			// A-Select will show username and password box in one page.
			sbAsUrl.append("?request=direct_login1");
			htSessionContext.put("direct_authsp", vAuthSPs.get(0));
		}
		// RH, 20110920, sn, for sequential authsps introduced new parameter for backward compatibility
		else if (aApp.getFirstAuthsp() != null && _authSPManagerManager.isDirectAuthSP(aApp.getFirstAuthsp() ) ) {
			// If there is a first_authsp there must be a next_authsp defined for this app
			// to ensure no tgt will be set until next_authsp has been handled
			if (_authSPManagerManager.getNextAuthSP(aApp.getFirstAuthsp(), aApp.getId()) != null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found first_authsp="+aApp.getFirstAuthsp()+" , setting direct_authsp to:"+aApp.getFirstAuthsp());
				// A-Select will show username and password box in one page.
				sbAsUrl.append("?request=direct_login1");
				htSessionContext.put("direct_authsp", aApp.getFirstAuthsp());
			}	
			else {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Found first_authsp="+aApp.getFirstAuthsp()+" , but no next_authsp defined for app: "+aApp.getId());
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
		// RH, 20110920, en
		else {  // multiple authsps
			sbAsUrl.append("?request=login1");
		}

		// 20101009, Bauke: createSession was at *1 above, moved here
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Create htSessionContext=" + htSessionContext);
		String sSessionId = _sessionManager.createSession(htSessionContext, true);
		if (sSessionId == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to create session");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Create sbAsUrl=" + sbAsUrl + ", rid=" + sSessionId);

		HashMap<String, Object> hmOutput = new HashMap<String, Object>();
		hmOutput.put("as_url", sbAsUrl.toString());
		hmOutput.put("rid", sSessionId);
		hmOutput.put("result_code", Errors.ERROR_ASELECT_SUCCESS);
		hmOutput.put("session", htSessionContext);
		return hmOutput;
	}

	/**
	 * Verify application signature.
	 * 
	 * @param sSignature
	 *            the signature
	 * @param sData
	 *            the data
	 * @param sAppId
	 *            the app id
	 * @throws ASelectException
	 *             the aselect exception
	 */
	protected void verifyApplicationSignature(String sSignature, String sData, String sAppId)
	throws ASelectException
	{
		String sMethod = "verifyApplicationSignature()";
		ApplicationManager _applicationManager = ApplicationManager.getHandle();
		CryptoEngine _cryptoEngine = CryptoEngine.getHandle();

		PublicKey pk = null;
		try {
			pk = _applicationManager.getSigningKey(sAppId);
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid application ID: \"" + sAppId
					+ "\". Could not find signing key for application.", e);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		if (!_cryptoEngine.verifyApplicationSignature(pk, sData, sSignature)) { // can throw ERROR_ASELECT_INTERNAL_ERROR
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Application:" + sAppId + " Invalid signature:"
					+ sSignature + " Key=" + pk);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}

	/**
	 * Checks if the user is ASelect enabled.
	 * 
	 * @param sUID
	 *            the uid
	 * @throws ASelectException
	 * @throws ASelectUDBException
	 */
	protected boolean isUserAselectEnabled(String sUID)
	throws ASelectException, ASelectUDBException
	{
		String sMethod = "isUserAselectEnabled";
		IUDBConnector oUDBConnector = null;
		
		try {
			oUDBConnector = UDBConnectorFactory.getUDBConnector();
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to connect to the UDB.", e);
			throw e;
		}

		if (!oUDBConnector.isUserEnabled(sUID)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unknown user id or user account is not enabled.");
			return false;
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "User is enabled: "+sUID);
		return true;
	}
}
