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
 * $Id: ApplicationAPIHandler.java,v 1.10 2006/05/03 10:10:18 tom Exp $ 
 * 
 * Changelog:
 * $Log: ApplicationAPIHandler.java,v $
 * Revision 1.10  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.9  2006/04/06 08:42:47  leon
 * bugfix
 *
 * Revision 1.8  2006/03/22 11:53:32  martijn
 * fixed uid bug in verify credentials if use_opaque_uid is true
 *
 * Revision 1.7  2006/03/16 13:55:56  martijn
 * fixed logging typo
 *
 * Revision 1.6  2006/03/16 12:36:13  martijn
 * added support for returning the uid as opaque uid in verify_credentials request
 *
 * Revision 1.5  2006/03/16 08:13:14  leon
 * small change for direct login
 *
 * Revision 1.4  2006/03/14 11:25:36  martijn
 * removed support for hashed uid in verify_credentials response
 *
 * Revision 1.3  2006/03/13 14:01:39  martijn
 * added optional external_url support
 *
 * Revision 1.2  2006/03/09 12:34:21  jeroen
 * adaptations for the use of OID and redirect URL
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.2  2006/01/25 14:40:05  martijn
 * TGTManager and SessionManager changed
 *
 * Revision 1.1  2006/01/13 08:40:26  martijn
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.36  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.35  2005/05/02 14:15:12  peter
 * code-style
 *
 * Revision 1.34  2005/04/27 13:04:48  erwin
 * AGENT -> SERVER Error codes.
 *
 * Revision 1.33  2005/04/27 12:58:41  erwin
 * Fixed error codes and logging.
 *
 * Revision 1.32  2005/04/22 06:52:18  tom
 * Improved error handling
 *
 * Revision 1.31  2005/04/15 14:04:41  peter
 * javadoc and comment
 *
 * Revision 1.30  2005/04/15 11:51:23  tom
 * Removed old logging statements
 *
 * Revision 1.29  2005/04/11 14:56:31  peter
 * code restyle
 *
 * Revision 1.28  2005/04/11 14:25:22  peter
 * resolved a fix-me
 *
 * Revision 1.27  2005/04/11 14:23:08  peter
 * - function handleGetAppLevel is now deprecated
 * - handleAuthenticateRequest checks if there are configured any applications
 *
 * Revision 1.26  2005/04/11 09:07:12  remco
 * - fixed bug where optional parameters weren't included in signature check, so check always failed when these were present
 * - removed request=forced_authenticate
 * - added forced_logon parameter to request=authenticate
 *
 * Revision 1.25  2005/04/07 13:43:06  tom
 * Check application id  (Required for signed requests)
 *
 * Revision 1.24  2005/04/07 12:25:56  martijn
 * ssogroups can be null after ApplicationManager.getSSOGroups()
 *
 * Revision 1.23  2005/04/07 12:13:51  martijn
 * added single sign-on groups support
 *
 * Revision 1.22  2005/04/07 07:38:09  erwin
 * Moved serializeAttributes() to abstract class
 *
 * Revision 1.21  2005/04/06 11:38:55  peter
 * Added support for optional uid in request authenticate
 *
 * Revision 1.20  2005/04/05 07:50:11  martijn
 * added forced_authenticate
 *
 * Revision 1.19  2005/04/01 15:18:13  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.18  2005/04/01 14:26:35  peter
 * cross aselect redesign
 *
 * Revision 1.17  2005/03/30 13:46:46  martijn
 * now supplying the TGT context to the AttributeGatherer
 *
 * Revision 1.16  2005/03/24 13:23:45  erwin
 * Improved URL encoding/decoding
 * (this is handled in communication package for API calls)
 *
 * Revision 1.15  2005/03/24 09:34:43  erwin
 * URL encoding problem fixed (in communication package)
 *
 * Revision 1.14  2005/03/22 15:19:56  peter
 * handleCrossAuthenticateRequest makes use of the CrossSelectorManager
 *
 * Revision 1.12  2005/03/18 15:47:52  remco
 * Using our base64 encoder instead of Sun's (there's a bug in it)
 *
 * Revision 1.11  2005/03/18 13:43:35  remco
 * made credentials shorter (base64 encoding instead of hex representation)
 *
 * Revision 1.10  2005/03/18 08:11:02  remco
 * made AttributeGatherer singleton
 *
 * Revision 1.9  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.8  2005/03/17 14:08:48  remco
 * changed attribute functionality
 *
 * Revision 1.7  2005/03/16 13:19:14  martijn
 * changed todo to fixme
 *
 * Revision 1.6  2005/03/16 13:12:11  remco
 * added attributes (initial version)
 *
 * Revision 1.5  2005/03/16 08:18:24  erwin
 * Fixed problem with decrypt TGT error handling.
 *
 * Revision 1.4  2005/03/15 15:18:51  erwin
 * Moved redundant code to seperate methods and AbstractAPIRequestHandler.
 *
 * Revision 1.3  2005/03/15 10:15:29  erwin
 * Moved redundant code to seperate class (AbstractAPIRequestHandler)
 *
 * Revision 1.2  2005/03/15 08:44:37  erwin
 * Fixed problem with tgt_exp_time
 *
 * Revision 1.1  2005/03/15 08:21:13  tom
 * - Redesign of request handling
 * - Renamed from ApplicationHandler
 *
 * Revision 1.12  2005/03/14 11:14:41  tom
 * Removed killsession in verifyCredentials
 *
 * Revision 1.11  2005/03/14 10:20:23  tom
 * If TGT contains result_code return RID and result_code
 *
 * Revision 1.10  2005/03/14 10:18:12  tom
 * If the TGT contains a result_code we only return the error, no other information
 *
 * Revision 1.9  2005/03/11 13:28:09  remco
 * - fixed incorrect result_code handling
 * - fixed multiple a-select-server id
 *
 * Revision 1.8  2005/03/11 13:15:13  martijn
 * Renamed single-sign-on config item that now will be read once at startup of the config manager.
 *
 * Revision 1.7  2005/03/11 10:31:34  remco
 * processRequest() created a new instance of itself
 *
 * Revision 1.6  2005/03/11 10:29:40  tom
 * Added new Logger functionality and error handling
 *
 * Revision 1.5  2005/03/11 09:28:29  remco
 * ApplicationRequestHandler and ApplicationAPIRequestHandler are now merged
 *
 */

package org.aselect.server.request.handler.aselect.authentication;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.Application;
import org.aselect.server.application.ApplicationManager;
import org.aselect.server.attributes.AttributeGatherer;
import org.aselect.server.authspprotocol.handler.AuthSPHandlerManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.sp.MetaDataManagerSp;
import org.aselect.server.request.handler.xsaml20.sp.SessionSyncRequestSender;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.communication.server.IOutputMessage;
import org.aselect.system.communication.server.IProtocolRequest;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Utils;

/**
 * Handle API requests from Applications and A-Select Agents.
 * <br><br>
 * <b>Description:</b>
 * <br>
 * This class processes the following incoming application API calls:
 * <ul>
 * 	<li><code>authenticate</code>
 * 	<li><code>cross_authenticate</code>
 * 	<li><code>get_app_level</code>
 * 	<li><code>kill_tgt</code>
 * 	<li><code>verify_credentials</code>
 * </ul>
 * 
 * @author Alfa & Ariss
 * 
 * 
 * 14-11-2007 - Changes:
 * - Added to support TGT refreshing,
 *   Agent will refresh TGT every time the application makes contact
 *
 * 5-3-2009
 * - Added DigiD-ization, the handler will accept the DigiD request protocol
 * 
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright Gemeente Den Haag (http://www.denhaag.nl)
 * 
 */
public class ApplicationAPIHandler extends AbstractAPIRequestHandler
{
	//The managers and engine
	private ASelectConfigManager _configManager;
	private TGTManager _oTGTManager;
	private SessionManager _sessionManager;
	private ApplicationManager _applicationManager;
	private AuthSPHandlerManager _authSPManagerManager;
	private CryptoEngine _cryptoEngine;
	private MetaDataManagerSp _metadataManager;
	protected String _sServerUrl;

	/**
	 * Create a new instance.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Calls {@link AbstractAPIRequestHandler#AbstractAPIRequestHandler(
	 * RequestParser, HttpServletRequest, HttpServletResponse, String, String)}
	 * and handles are obtained to relevant managers.
	 * <br><br>
	 * @param reqParser The request parser to be used.
	 * @param servletRequest The request.
	 * @param servletResponse The response.
	 * @param sMyServerId The A-Select Server ID.
	 * @param sMyOrg The A-Select Server organisation.
	 * @throws ASelectException 
	 */
	public ApplicationAPIHandler(RequestParser reqParser, HttpServletRequest servletRequest,
			HttpServletResponse servletResponse, String sMyServerId, String sMyOrg)
		throws ASelectCommunicationException {
		super(reqParser, servletRequest, servletResponse, sMyServerId, sMyOrg);

		//set variables and get handles
		_sModule = "ApplicationAPIHandler";
		_configManager = ASelectConfigManager.getHandle();
		_oTGTManager = TGTManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_applicationManager = ApplicationManager.getHandle();
		_authSPManagerManager = AuthSPHandlerManager.getHandle();
		_cryptoEngine = CryptoEngine.getHandle();

		try {
			_sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url");
		}
		catch (ASelectConfigException e) {
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			_metadataManager = MetaDataManagerSp.getHandle();
		}
		catch (ASelectException e) {
			// authentication.RequestHandlerFactory wants a ASelectCommunicationException
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_PARSE_ERROR + ":" + e.toString());
		}
	}

	/**
	 * Processes all incoming application API calls.
	 * <br><br>
	 * @see org.aselect.server.request.handler.aselect.authentication.AbstractAPIRequestHandler#processAPIRequest(
	 * org.aselect.system.communication.server.IProtocolRequest, org.aselect.system.communication.server.IInputMessage, 
	 * org.aselect.system.communication.server.IOutputMessage)
	 */
	protected void processAPIRequest(IProtocolRequest oProtocolRequest, IInputMessage oInputMessage,
			IOutputMessage oOutputMessage)
		throws ASelectException
	{
		String sMethod = "processAPIRequest";

		// Get the request parameter
		String sAPIRequest = null;
		try {
			sAPIRequest = oInputMessage.getParam("request");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unsupported API call", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_systemLogger.log(Level.INFO, _sModule, sMethod, "ApplApiREQ " + sAPIRequest);

		if (sAPIRequest.equals("authenticate")) {
			handleAuthenticateRequest(oProtocolRequest, oInputMessage, oOutputMessage);
		}
		else if (sAPIRequest.equals("verify_credentials")) {
			handleVerifyCredentialsRequest(oInputMessage, oOutputMessage);
		}
		else if (sAPIRequest.equals("get_app_level")) {
			handleGetAppLevelRequest(oInputMessage, oOutputMessage);
		}
		else if (sAPIRequest.equals("kill_tgt")) {
			handleKillTGTRequest(oInputMessage, oOutputMessage);
		}
		else if (sAPIRequest.equals("upgrade_tgt")) {
			handleUpgradeTGTRequest(oInputMessage, oOutputMessage);
		}
		else {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unsupported API Call: " + sAPIRequest);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}

	/**
	 * This method handles the <code>request=authenticate</code> request. <br>
	 * 
	 * @param oProtocolRequest
	 *            The request protocol properties.
	 * @param oInputMessage
	 *            The input message.
	 * @param oOutputMessage
	 *            The output message.
	 * @throws ASelectException
	 *             If proccessing fails.
	 */
	private void handleAuthenticateRequest(IProtocolRequest oProtocolRequest, IInputMessage oInputMessage,
			IOutputMessage oOutputMessage)
		throws ASelectException
	{
		String sMethod = "handleAuthenticateRequest()";
		String sSessionId = null;
		Integer intAppLevel = null;
		Integer intMaxAppLevel = null;
		String sAppUrl = null;
		String sAppId = null;
		String sASelectServer = null;
		HashMap htSessionContext = null;
		String sUid = null;
		String sAuthsp = null;
		String sRemoteOrg = null;
		String sForcedLogon = null;
		String sCountry = null;
		String sLanguage = null;

		if (!_applicationManager.hasApplicationsConfigured()) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request since no applications are configured.");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		try {
			sAppId = oInputMessage.getParam("app_id");
			sAppUrl = oInputMessage.getParam("app_url");
			sASelectServer = oInputMessage.getParam("a-select-server");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameters", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		try {
			sUid = oInputMessage.getParam("uid");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'uid' parameter found.", eAC);
		}
		try {
			sAuthsp = oInputMessage.getParam("authsp");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'authsp' parameter found.", eAC);
		}
		try {
			sRemoteOrg = oInputMessage.getParam("remote_organization");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'remote_organization' parameter found.", eAC);
		}
		try {
			sCountry = oInputMessage.getParam("country");
		}
		catch (ASelectCommunicationException e) {
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'country' parameter found.", e);
		}
		try {
			sLanguage = oInputMessage.getParam("language");
		}
		catch (ASelectCommunicationException e) {
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'language' parameter found.", e);
		}
		Boolean boolForced = null;
		try {
			sForcedLogon = oInputMessage.getParam("forced_logon");
			boolForced = new Boolean(sForcedLogon);
		}
		catch (ASelectCommunicationException e) {
			boolForced = new Boolean(false);
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'forced_logon' parameter found.", e);
		}
		Boolean bCheckSignature = true;
		try {
			String sCheckSignature = oInputMessage.getParam("check-signature");
			bCheckSignature = Boolean.valueOf(sCheckSignature);
		}
		catch (ASelectCommunicationException e) {
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'check-signature' parameter found.", e);
		}

		// check if request should be signed
		if (_applicationManager.isSigningRequired() && bCheckSignature) {
			// check signature
			// NOTE: add sbData items sorted!
			StringBuffer sbData = new StringBuffer(sASelectServer);
			sbData.append(sAppId).append(sAppUrl);
			if (sAuthsp != null)
				sbData.append(sAuthsp);
			if (sCountry != null)
				sbData.append(sCountry);
			if (sForcedLogon != null)
				sbData.append(sForcedLogon);
			if (sLanguage != null)
				sbData.append(sLanguage);
			if (sRemoteOrg != null)
				sbData.append(sRemoteOrg);
			if (sUid != null)
				sbData.append(sUid);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "sbData=" + sbData);
			verifyApplicationSignature(oInputMessage, sbData.toString(), sAppId);
		}

		// check if application is registered
		if (!_applicationManager.isApplication(sAppId)) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unknown application ID");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
		}
		intAppLevel = _applicationManager.getRequiredLevel(sAppId);
		if (intAppLevel == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "No level specified for application with ID: '"
					+ sAppId + "'");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_APP_LEVEL);
		}
		intMaxAppLevel = _applicationManager.getMaxLevel(sAppId);

		// 20090305, Bauke: Accept DigiD protocol
		Application aApp = _applicationManager.getApplication(sAppId);
		String sSharedSecret = aApp.getSharedSecret();
		if (sSharedSecret != null) {
			String sArg = oInputMessage.getParam("shared_secret");
			if (sArg == null || !sSharedSecret.equals(sArg)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Shared secret for app '" + sAppId
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
		htSessionContext = new HashMap();
		htSessionContext.put("app_id", sAppId);
		htSessionContext.put("app_url", sAppUrl);
		htSessionContext.put("level", intAppLevel); // NOTE: Integer put
		if (intMaxAppLevel != null)
			htSessionContext.put("max_level", intMaxAppLevel);
		htSessionContext.put("organization", _sMyOrg);

		// organization and uid are stored in the session context with a
		// temporary identifier.
		// This because the values are not validated yet.
		// After validation, these values can be set as
		// 'user_id' and 'remote_organization'.
		//
		// Bauke 20080511: added "forced_authsp" to influence AuthSP choice
		if (sRemoteOrg != null)
			htSessionContext.put("forced_organization", sRemoteOrg);
		if (sUid != null)
			htSessionContext.put("forced_uid", sUid);
		if (sAuthsp != null)
			htSessionContext.put("forced_authsp", sAuthsp);

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
		_systemLogger.log(Level.INFO, _sModule, sMethod, "CTX htSessionContext=" + htSessionContext);

		sSessionId = _sessionManager.createSession(htSessionContext);
		if (sSessionId == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unable to create session");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
		}

		StringBuffer sbAsUrl = new StringBuffer();
		String sAsUrl = _configManager.getRedirectURL();
		if (sAsUrl != null)
			sbAsUrl.append(sAsUrl);
		else
			sbAsUrl.append(oProtocolRequest.getTarget());

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
		_systemLogger.log(Level.INFO, _sModule, sMethod, "OUT sbAsUrl=" + sbAsUrl + ", rid=" + sSessionId);

		try {
			String sAsURL = sbAsUrl.toString();
			oOutputMessage.setParam("rid", sSessionId);
			if (aApp.isDoUrlEncode())
				oOutputMessage.setParam("as_url", sAsURL);
			else
				oOutputMessage.setParam("as_url", sAsURL, false);  // only for DigiD protocol: do not url-encode
			
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not set response parameter", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, eAC);
		}
	}

	/**
	 * This function handles the <code>request=get_app_level</code> request.
	 * <br>
	 * 
	 * @param oInputMessage
	 *            The input message.
	 * @param oOutputMessage
	 *            The output message.
	 * @throws ASelectException
	 *             If proccessing fails.
	 * @deprecated Not used anymore since A-Select 1.4.1
	 */
	private void handleGetAppLevelRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
		throws ASelectException
	{
		String sMethod = "handleGetAppLevelRequest()";
		String sAppId = null;
		String sASelectServer = null;

		try {
			sAppId = oInputMessage.getParam("app_id");
			sASelectServer = oInputMessage.getParam("a-select-server");
		}
		catch (ASelectCommunicationException eAC) {
			// check if application id is given
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameters");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		// check if request should be signed
		if (_applicationManager.isSigningRequired()) {
			// check signature
			StringBuffer sbData = new StringBuffer(sASelectServer).append(sAppId);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "sbData=" + sbData);
			verifyApplicationSignature(oInputMessage, sbData.toString(), sAppId);
		}

		// check if application is registered
		Integer intAppLevel = _applicationManager.getRequiredLevel(sAppId);
		if (intAppLevel == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unknown application ID");

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
		}
		try {
			oOutputMessage.setParam("app_level", intAppLevel.toString());
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not set response parameter", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, eAC);
		}

	}

	/**
	 * This function handles the <code>request=kill_tgt</code> request.
	 * <br>
	 * @param oInputMessage The input message.
	 * @param oOutputMessage The output message.
	 * @throws ASelectException If proccessing fails.
	 */
	private void handleKillTGTRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
		throws ASelectException
	{
		String sMethod = "handleKillTGTRequest";
		String sEncTGT = null;
		String sASelectServer = null;

		//get mandatory parameters
		try {
			sEncTGT = oInputMessage.getParam("tgt_blob");
			sASelectServer = oInputMessage.getParam("a-select-server");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameters");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		String sTGT = null;
		try {
			byte[] baTgtBlobBytes = CryptoEngine.getHandle().decryptTGT(sEncTGT);
			sTGT = Utils.toHexString(baTgtBlobBytes);
		}
		catch (ASelectException eAC) //decrypt failed
		{
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eAC);
		}
		catch (IllegalArgumentException eIA) //HEX conversion fails
		{
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eIA);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eIA);
		}

		// check if the TGT exists
		HashMap htTGTContext = _oTGTManager.getTGT(sTGT);
		if (htTGTContext == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unknown TGT");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT);
		}

		//check if request should be signed
		if (_applicationManager.isSigningRequired()) {
			// Note: we should do this earlier, but we don't have an app_id until now
			String sAppId = (String) htTGTContext.get("app_id");
			StringBuffer sbData = new StringBuffer(sASelectServer).append(sEncTGT);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "sbData=" + sbData);
			verifyApplicationSignature(oInputMessage, sbData.toString(), sAppId);
		}
		_systemLogger.log(Level.INFO, _sModule, sMethod, "KILL TICKET context=" + htTGTContext);

		//Kill the ticket granting ticket
		_oTGTManager.remove(sTGT);

		try {
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not set response parameter", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, eAC);
		}
	}

	// Bauke: added to support TGT refreshing
	private void handleUpgradeTGTRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
		throws ASelectException
	{
		String sMethod = "handleUpgradeTGTRequest";
		String sEncTGT = null;
		String sASelectServer = null;

		// Get mandatory parameters
		try {
			sEncTGT = oInputMessage.getParam("crypted_credentials");
			sASelectServer = oInputMessage.getParam("a-select-server");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameters");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		String sTGT = null;
		try {
			byte[] baTgtBlobBytes = CryptoEngine.getHandle().decryptTGT(sEncTGT);
			sTGT = Utils.toHexString(baTgtBlobBytes);
		}
		catch (ASelectException eAC) { //decrypt failed
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eAC);
		}
		catch (IllegalArgumentException eIA) { //HEX conversion fails
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eIA);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eIA);
		}

		// check if the TGT exists
		HashMap htTGTContext = _oTGTManager.getTGT(sTGT);
		if (htTGTContext == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unknown TGT");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT);
		}
		// check if request should be signed
		if (_applicationManager.isSigningRequired()) {
			// Note: we should do this earlier, but we don't have an app_id until now
			String sAppId = (String) htTGTContext.get("app_id");
			StringBuffer sbData = new StringBuffer(sASelectServer).append(sEncTGT);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Signing required, sbData=" + sbData);
			verifyApplicationSignature(oInputMessage, sbData.toString(), sAppId);
		}
		_systemLogger.log(Level.INFO, _sModule, sMethod, "Upgrade TICKET context=" + htTGTContext);

		// Send Session Sync to the Federation
		HashMap htResult = SessionSyncRequestSender.getSessionSyncParameters(_systemLogger);
		if (htResult == null || htResult.isEmpty()) {
			// No Session Sync handler, only update the ticket granting ticket
			_systemLogger.log(Level.INFO, _sModule, sMethod, "updateTGT only");
			_oTGTManager.updateTGT(sTGT, htTGTContext);
		}
		else {
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Send Sync to Federation");
			long updateInterval = (Long) htResult.get("update_interval");
			String _sSamlMessageType = (String) htResult.get("message_type");
			String _sFederationUrl = (String) htResult.get("federation_url");
			String _sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url");

			String verify_signature = (String) htResult.get("verify_signature");
			PublicKey pKey = null;
			if ("true".equalsIgnoreCase(verify_signature.trim())) {
				pKey = _metadataManager.getSigningKey(_configManager.getFederationURL());
			}

			String verify_interval = (String) htResult.get("verify_interval");
			String max_notbefore = (String) htResult.get("max_notbefore");
			String max_notonorafter = (String) htResult.get("max_notonorafter");
			Long l_max_notbefore = null;
			Long l_max_notonorafter = null;
			if (max_notbefore != null)
				l_max_notbefore = Long.parseLong((String) htResult.get("max_notbefore"));
			if (max_notonorafter != null)
				l_max_notonorafter = Long.parseLong((String) htResult.get("max_notonorafter"));

			//			SessionSyncRequestSender ss_req = new SessionSyncRequestSender(_systemLogger,
			//						_sServerUrl, updateInterval, _sSamlMessageType, _sFederationUrl);
			SessionSyncRequestSender ss_req = new SessionSyncRequestSender(_systemLogger, _sServerUrl, updateInterval,
					_sSamlMessageType, _sFederationUrl, pKey, l_max_notbefore, l_max_notonorafter, ("true"
							.equalsIgnoreCase(verify_interval.trim())) ? true : false);
			String ssReturn = ss_req.synchronizeSession(sEncTGT, true/*coded*/, true/*updateTGT*/);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "ssReturn=" + ssReturn);
		}
		try {
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not set response parameter", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, eAC);
		}
		_systemLogger.log(Level.INFO, _sModule, sMethod, "Ready");
	}

	/**
	 * This method handles the <code>request=verify_tgt</code> request. If the
	 * tgt of the user is valid, then this method returns the information of the
	 * user. 
	 * <br>
	 * @param oInputMessage The input message.
	 * @param oOutputMessage The output message.
	 * @throws ASelectException If proccessing fails.
	 */
	//
	// Bauke 20081201: added support for parameter "saml_attributes"
	//
	private void handleVerifyCredentialsRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
		throws ASelectException
	{
		String sMethod = "handleVerifyCredentialsRequest()";
		HashMap htTGTContext = null;
		String sRid = null;
		String sUid = null;
		String sResultCode = null;
		String sEncTgt = null;
		String sASelectServer = null;
		String sTGT = null;
		String sSamlAttributes = null;
		String sSignature = null;

		try {
			sEncTgt = oInputMessage.getParam("aselect_credentials");
			sASelectServer = oInputMessage.getParam("a-select-server");
			sRid = oInputMessage.getParam("rid");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameters");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		try {
			sSamlAttributes = oInputMessage.getParam("saml_attributes");
			sSignature = oInputMessage.getParam("signature");
		}
		catch (ASelectCommunicationException eAC) { // ignore absence
		}
		_systemLogger.log(Level.INFO, _sModule, sMethod, "a-select-server=" + sASelectServer + " rid=" + sRid
				+ " aselect_credentials(encrypted TGT)=" + sEncTgt + " saml_attributes=" + sSamlAttributes
				+ " signature=" + sSignature);

		try {
			byte[] baTgtBytes = CryptoEngine.getHandle().decryptTGT(sEncTgt);
			sTGT = Utils.toHexString(baTgtBytes);
		}
		catch (ASelectException eAC) // decrypt failed
		{
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "could not decrypt TGT", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eAC);
		}
		catch (Exception e) // HEX conversion fails
		{
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "could not decrypt TGT", e);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, e);
		}

		htTGTContext = _oTGTManager.getTGT(sTGT);
		_systemLogger.log(Level.INFO, _sModule, sMethod, "VERCRED ApplApi rid=" + sRid + ", TGTContext=" + htTGTContext
				+ ", inputMessage=" + oInputMessage);

		if (htTGTContext == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unknown TGT");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT);
		}

		// check rid
		if (!(sRid).equalsIgnoreCase((String) htTGTContext.get("rid"))) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid RID");

			StringBuffer sbBuffer = new StringBuffer("RID is other than expected. Received ");
			sbBuffer.append(sRid);
			sbBuffer.append(" but expected ");
			sbBuffer.append((String) htTGTContext.get("rid"));

			_systemLogger.log(Level.FINE, _sModule, sMethod, sbBuffer.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}

		// get app_id from TGT context.
		String sAppId = (String) htTGTContext.get("app_id");
		if (sAppId == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "invalid Application ID");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		// Check if request should be signed
		if (_applicationManager.isSigningRequired()) {
			// Note: we should do this earlier, but we don't have an app_id until now
			// Another NOTE: see to it that all data is put in sData sorted  on parameter name!
			StringBuffer sbData = new StringBuffer(sASelectServer).append(sEncTgt).append(sRid);
			if (sSamlAttributes != null)
				sbData = sbData.append(sSamlAttributes);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "sbData=" + sbData);
			verifyApplicationSignature(oInputMessage, sbData.toString(), sAppId);
		}

		// 20090305, Bauke: Accept DigiD protocol, check the shared secret
		Application aApp = _applicationManager.getApplication(sAppId);
		String sSharedSecret = aApp.getSharedSecret();
		if (sSharedSecret != null) {
			String sArg = oInputMessage.getParam("shared_secret");
			if (sArg == null || !sSharedSecret.equals(sArg)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Shared secret for app '" + sAppId
						+ "' does not match or is missing");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}

		try {
			oOutputMessage.setParam("rid", sRid);
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not set 'rid' response parameter", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, eAC);
		}

		sResultCode = (String) htTGTContext.get("result_code");
		if (sResultCode != null) // Resultcode avaliable in TGT context
		{
			if (sResultCode != Errors.ERROR_ASELECT_SUCCESS) // Error in context
			{
				_oTGTManager.remove(sTGT);
				throw new ASelectCommunicationException(sResultCode);
				// message with error code and rid is send in "processAPIRequest()"
			}
		}

		// Get other response parameters
		sUid = (String) htTGTContext.get("uid");
		String sAuthSPLevel = (String) htTGTContext.get("authsp_level");
		String sAuthSP = (String) htTGTContext.get("authsp");
		long lExpTime = 0;
		try {
			lExpTime = _oTGTManager.getExpirationTime(sTGT);
		}
		catch (ASelectStorageException eAS) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not fetch TGT timeout", eAS);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}

		// Gather attributes
		AttributeGatherer oAttributeGatherer = AttributeGatherer.getHandle();
		HashMap<String, Object> htAttribs = oAttributeGatherer.gatherAttributes(htTGTContext);
		String sToken = null;
		if (sSamlAttributes != null) {
			// Comma seperated list of attribute names was given
			String[] arrAttrNames = sSamlAttributes.split(",");
			HashMap htSelectedAttr = SamlTools.extractFromHashtable(arrAttrNames, htAttribs, true/*include*/);

			// Also include the original IdP token
			String sRemoteToken = (String) htTGTContext.get("saml_remote_token");
			if (sRemoteToken != null)
				htSelectedAttr.put("saml_remote_token", sRemoteToken);

			// Add Saml Token to the attributes, must be signed and base64 encoded
			sToken = SamlTools.createAttributeToken(_sServerUrl, sTGT, htSelectedAttr);
			htAttribs.put("saml_attribute_token", sToken);
		}
		String sSerializedAttributes = serializeAttributes(htAttribs);
		_systemLogger.log(Level.INFO, _sModule, sMethod, "VERCRED SerAttr="
				+ Utils.firstPartOf(sSerializedAttributes, 40) + " Token=" + Utils.firstPartOf(sToken, 40));

		try {
			oOutputMessage.setParam("app_id", sAppId);
			oOutputMessage.setParam("organization", (String) htTGTContext.get("organization"));
			oOutputMessage.setParam("app_level", (String) htTGTContext.get("app_level"));
			// Return both asp and authsp variables to remain compatible
			// with A-Select 1.3 and 1.4
			oOutputMessage.setParam("asp_level", sAuthSPLevel);
			oOutputMessage.setParam("asp", sAuthSP);
			oOutputMessage.setParam("authsp_level", sAuthSPLevel);
			oOutputMessage.setParam("authsp", sAuthSP);

			// 20090303, Bauke: added for DigiD-ization
			String sLevelName = aApp.getLevelName();
			if (sLevelName != null)
				oOutputMessage.setParam(sLevelName, sAuthSPLevel);

			if (_applicationManager.isUseOpaqueUid(sAppId)) {
				// the returned user ID must contain an opaque value
				MessageDigest oMessageDigest = null;
				try {
					oMessageDigest = MessageDigest.getInstance("SHA1");
					oMessageDigest.update(sUid.getBytes("UTF-8"));
					sUid = Utils.toHexString(oMessageDigest.digest());
				}
				catch (Exception e) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unable to generate SHA1 hash from UID", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
				}
			}

			oOutputMessage.setParam("uid", sUid);
			oOutputMessage.setParam("tgt_exp_time", new Long(lExpTime).toString());
			if (sSerializedAttributes != null)
				oOutputMessage.setParam("attributes", sSerializedAttributes);
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "VERCRED result_code==SUCCESS");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not set response parameters", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, eAC);
		}

		// Kill TGT if single sign-on is disabled
		if (!_configManager.isSingleSignOn())
			_oTGTManager.remove(sTGT);
	}

	/**
	 * Verify the application signing signature. <br>
	 * <br>
	 * 
	 * @param oInputMessage
	 *            The input message.
	 * @param sData
	 *            The data to validate upon.
	 * @param sAppId
	 *            The application ID.
	 * @throws ASelectException
	 *             If signature is invalid.
	 */
	private void verifyApplicationSignature(IInputMessage oInputMessage, String sData, String sAppId)
		throws ASelectException
	{
		String sMethod = "verifyApplicationSignature()";

		String sSignature = null;
		try {
			sSignature = oInputMessage.getParam("signature");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required 'signature' parameter", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		PublicKey pk = null;
		try {
			pk = _applicationManager.getSigningKey(sAppId);
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid application ID: \"" + sAppId
					+ "\". Could not find signing key for application.", e);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		if (!_cryptoEngine.verifyApplicationSignature(pk, sData, sSignature))
		// throws ERROR_ASELECT_INTERNAL_ERROR
		{
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Application:" + sAppId + " Invalid signature:"
					+ sSignature + " Key=" + pk);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}
}
