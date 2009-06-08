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
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;

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
	// TODO: merge
	protected HashMap<String, String> handleAuthenticateAndCreateSession(HashMap<String,String> hmInput, String sUrlTarget)
	throws ASelectException
	{
		String sMethod = "handleAuthenticateAndCreateSession()";
		AuthSPHandlerManager _authSPManagerManager = AuthSPHandlerManager.getHandle();
		SessionManager _sessionManager = SessionManager.getHandle();
		ApplicationManager _applicationManager = ApplicationManager.getHandle();

		if (!_applicationManager.hasApplicationsConfigured()) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request since no applications are configured.");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

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
		Boolean boolForced = false;
		String sForcedLogon = hmInput.get("forced_logon");
		if (sForcedLogon != null)
			boolForced = new Boolean(sForcedLogon);
		Boolean bCheckSignature = true;
		String sCheckSignature = hmInput.get("check-signature");
		if (sCheckSignature != null)
			bCheckSignature = Boolean.valueOf(sCheckSignature);

		// check if request should be signed
		if (_applicationManager.isSigningRequired() && bCheckSignature) {
			String sSignature = hmInput.get("signature");
			if (sSignature == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing required 'signature' parameter");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			// Check signature
			// NOTE: add sbData items sorted!
			StringBuffer sbData = new StringBuffer(sASelectServer);
			sbData.append(sAppId).append(sAppUrl);
			if (sAuthsp != null) sbData.append(sAuthsp);
			if (sCountry != null) sbData.append(sCountry);
			if (sForcedLogon != null) sbData.append(sForcedLogon);
			if (sLanguage != null) sbData.append(sLanguage);
			if (sRemoteOrg != null) sbData.append(sRemoteOrg);
			if (sUid != null) sbData.append(sUid);
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
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No level specified for application with ID: '" + sAppId + "'");
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
						+ "' does not match or is missing");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}

		// 20090305, Bauke: The <application> itself can also set forced_uid / forced_authsp if so configured
		if (sAuthsp == null) {
			sAuthsp = aApp.getForcedAuthsp();
		}
		if (sUid == null) {
			sUid = aApp.getForcedUid();
		}

		// Create Session
		HashMap htSessionContext = new HashMap();
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
		if (sRemoteOrg != null) htSessionContext.put("forced_organization", sRemoteOrg);
		if (sUid != null) htSessionContext.put("forced_uid", sUid);
		if (sAuthsp != null) htSessionContext.put("forced_authsp", sAuthsp);

		// need to check if the request must be handled as a forced
		// authentication
		if (!boolForced.booleanValue() && _applicationManager.isForcedAuthenticateEnabled(sAppId)) {
			boolForced = new Boolean(true);
		}
		htSessionContext.put("forced_authenticate", boolForced);

		// check single sign-on groups
		if (_configManager.isSingleSignOn()) {
			Vector vSSOGroups = _applicationManager.getSSOGroups(sAppId);
			if (vSSOGroups != null)
				htSessionContext.put("sso_groups", vSSOGroups);
		}

		if (sCountry != null && sCountry.trim().length() > 0)
			htSessionContext.put("country", sCountry);
		if (sLanguage != null && sLanguage.trim().length() > 0)
			htSessionContext.put("language", sLanguage);

		// We only want to set the client_ip on application browserrequests (see ApplicationBrwoserHandler)
		// Bauke 20081217: Therefore the lines below should go!
		//htSessionContext.put("client_ip", get_servletRequest().getRemoteAddr()); // RH, 20080716, n // RH, 20080719, o
		//String sAgent = get_servletRequest().getHeader("User-Agent");
		//if (sAgent != null) htSessionContext.put("user_agent", sAgent);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "CTX htSessionContext=" + htSessionContext);

		String sSessionId = _sessionManager.createSession(htSessionContext);
		if (sSessionId == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to create session");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
		}

		StringBuffer sbAsUrl = new StringBuffer();
		String sAsUrl = _configManager.getRedirectURL();
		if (sAsUrl != null)
			sbAsUrl.append(sAsUrl);
		else if (sUrlTarget != null)
			sbAsUrl.append(sUrlTarget);

		Vector vAuthSPs = _authSPManagerManager.getConfiguredAuthSPs(intAppLevel, intMaxAppLevel);

		// Authentication OK
		if (vAuthSPs.size() == 1 && _authSPManagerManager.isDirectAuthSP((String) vAuthSPs.get(0))) {
			// A-Select will show username and password box in one page.
			sbAsUrl.append("?request=direct_login1");
			htSessionContext.put("direct_authsp", vAuthSPs.get(0));
		}
		else {
			sbAsUrl.append("?request=login1");
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "OUT sbAsUrl=" + sbAsUrl + ", rid=" + sSessionId);

		HashMap<String, String> hmOutput = new HashMap<String, String>(); 
		hmOutput.put("as_url", sbAsUrl.toString());
		hmOutput.put("rid", sSessionId);
		hmOutput.put("result_code", Errors.ERROR_ASELECT_SUCCESS);
		return hmOutput;
	}

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
	
		if (!_cryptoEngine.verifyApplicationSignature(pk, sData, sSignature)) {  // can throw ERROR_ASELECT_INTERNAL_ERROR
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Application:" + sAppId +
					" Invalid signature:" + sSignature + " Key=" + pk);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}
}
