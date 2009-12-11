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
 * $Id: ApplicationAPIHandler.java,v 1.1.2.1 2007/03/05 11:35:04 maarten Exp $ 
 * 
 * Changelog:
 * $Log: ApplicationAPIHandler.java,v $
 * Revision 1.1.2.1  2007/03/05 11:35:04  maarten
 * SFS Request Handlers
 *
 * Revision 1.1.2.5  2006/12/14 14:13:42  maarten
 * Updated ARP
 *
 * Revision 1.1.2.4  2006/12/11 13:52:29  maarten
 * opaque id salt added to application handler
 *
 * Revision 1.1.2.3  2006/11/23 09:41:47  leon
 * fixed bug: Because sessions were not always updated when something changed, strange errors occurs when the session are stored in a DB.
 *
 * Revision 1.1.2.2  2006/11/22 09:27:20  maarten
 * Updated version
 * Updated home_organization functionality
 * Fixed signing bug
 *
 * Revision 1.1.2.1  2006/09/04 08:52:26  leon
 * SFS Handlers
 *
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

package org.aselect.server.request.handler.sfs.authentication;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.attributes.AttributeGatherer;
import org.aselect.server.authspprotocol.handler.AuthSPHandlerManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.communication.server.IOutputMessage;
import org.aselect.system.communication.server.IProtocolRequest;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Utils;

// TODO: Auto-generated Javadoc
/**
 * Handle API requests from Applications and A-Select Agents. <br>
 * <br>
 * <b>Description:</b> <br>
 * This class processes the following incoming application API calls:
 * <ul>
 * <li><code>authenticate</code>
 * <li><code>cross_authenticate</code>
 * <li><code>get_app_level</code>
 * <li><code>kill_tgt</code>
 * <li><code>verify_credentials</code>
 * </ul>
 * 
 * @author Alfa & Ariss
 */
public class ApplicationAPIHandler extends AbstractAPIRequestHandler
{
	// The managers and engine
	private ASelectConfigManager _configManager;
	private TGTManager _oTGTManager;
	private SessionManager _sessionManager;
	private ApplicationManager _applicationManager;
	private AuthSPHandlerManager _authSPManagerManager;
	private CryptoEngine _cryptoEngine;

	/**
	 * Create a new instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Calls
	 * {@link AbstractAPIRequestHandler#AbstractAPIRequestHandler(RequestParser, HttpServletRequest, HttpServletResponse, String, String)}
	 * and handles are obtained to relevant managers. <br>
	 * <br>
	 * 
	 * @param reqParser
	 *            The request parser to be used.
	 * @param servletRequest
	 *            The request.
	 * @param servletResponse
	 *            The response.
	 * @param sMyServerId
	 *            The A-Select Server ID.
	 * @param sMyOrg
	 *            The A-Select Server organisation.
	 * @throws ASelectCommunicationException
	 *             If communication fails.
	 */
	public ApplicationAPIHandler(RequestParser reqParser, HttpServletRequest servletRequest,
			HttpServletResponse servletResponse, String sMyServerId, String sMyOrg)
		throws ASelectCommunicationException {
		super(reqParser, servletRequest, servletResponse, sMyServerId, sMyOrg);

		// set variables and get handles
		_sModule = "ApplicationAPIHandler";
		_configManager = ASelectConfigManager.getHandle();
		_oTGTManager = TGTManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_applicationManager = ApplicationManager.getHandle();
		_authSPManagerManager = AuthSPHandlerManager.getHandle();
		_cryptoEngine = CryptoEngine.getHandle();

	}

	/**
	 * Processes all incoming application API calls. <br>
	 * <br>
	 * 
	 * @param oProtocolRequest
	 *            the o protocol request
	 * @param oInputMessage
	 *            the o input message
	 * @param oOutputMessage
	 *            the o output message
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.sfs.authentication.AbstractAPIRequestHandler#processAPIRequest(org.aselect.system.communication.server.IProtocolRequest,
	 *      org.aselect.system.communication.server.IInputMessage,
	 *      org.aselect.system.communication.server.IOutputMessage)
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
		String sRemoteOrg = null;
		String sForcedLogon = null;
		String sCountry = null;
		String sLanguage = null;

		String sArpTarget = null;
		String sLoginUrl = null;

		if (!_applicationManager.hasApplicationsConfigured()) {
			_systemLogger
					.log(Level.WARNING, _sModule, sMethod, "Invalid request since no applications are configured.");

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

		try {
			sArpTarget = oInputMessage.getParam("arp_target");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'arp_target' parameter found.", eAC);
		}

		try {
			sLoginUrl = oInputMessage.getParam("login_url");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'login_url' parameter found.", eAC);
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

		// check if request should be signed
		if (_applicationManager.isSigningRequired()) {
			// check signature
			StringBuffer sbData = new StringBuffer(sASelectServer);
			sbData.append(sAppId).append(sAppUrl);
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

		// Create Session
		htSessionContext = new HashMap();
		htSessionContext.put("app_id", sAppId);
		htSessionContext.put("app_url", sAppUrl);
		htSessionContext.put("level", intAppLevel);
		if (intMaxAppLevel != null)
			htSessionContext.put("max_level", intMaxAppLevel);
		htSessionContext.put("organization", _sMyOrg);

		if (sArpTarget != null)
			htSessionContext.put("arp_target", sArpTarget);

		if (sLoginUrl != null)
			htSessionContext.put("login_url", sLoginUrl);

		// organization and uid are stored in the session context with a
		// temporary identifier.
		// This because the values are not validated yet.
		// After validation, these values can be set as
		// 'user_id' and 'remote_organization'.
		if (sRemoteOrg != null)
			htSessionContext.put("forced_organization", sRemoteOrg);
		if (sUid != null)
			htSessionContext.put("forced_uid", sUid);

		// need to check if the request must be handled as a forced authentication
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

		sSessionId = _sessionManager.createSession(htSessionContext);
		if (sSessionId == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unable to create session");

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
		}

		try {
			String sAsURL = sbAsUrl.toString();
			oOutputMessage.setParam("rid", sSessionId);
			oOutputMessage.setParam("as_url", sAsURL);
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not set response parameter", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, eAC);
		}
	}

	/**
	 * This function handles the <code>request=get_app_level</code> request. <br>
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
	 * This function handles the <code>request=kill_tgt</code> request. <br>
	 * 
	 * @param oInputMessage
	 *            The input message.
	 * @param oOutputMessage
	 *            The output message.
	 * @throws ASelectException
	 *             If proccessing fails.
	 */
	private void handleKillTGTRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
		throws ASelectException
	{
		String sMethod = "handleKillTGTRequest()";
		String sEncTGT = null;
		String sASelectServer = null;

		// get mandatory parameters
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
			sTGT = Utils.byteArrayToHexString(baTgtBlobBytes);
		}
		catch (ASelectException eAC) // decrypt failed
		{
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eAC);
		}
		catch (IllegalArgumentException eIA) // HEX conversion fails
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

		// check if request should be signed
		if (_applicationManager.isSigningRequired()) {
			// Note: we should do this earlier, but we don't have an app_id until now
			String sAppId = (String) htTGTContext.get("app_id");
			StringBuffer sbData = new StringBuffer(sASelectServer).append(sEncTGT);
			verifyApplicationSignature(oInputMessage, sbData.toString(), sAppId);
		}

		// Kill the ticket granting ticket
		_oTGTManager.remove(sTGT);

		try {
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not set response parameter", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, eAC);
		}
	}

	/**
	 * This method handles the <code>request=verify_tgt</code> request. If the tgt of the user is valid, then this
	 * method returns the information of the user. <br>
	 * 
	 * @param oInputMessage
	 *            The input message.
	 * @param oOutputMessage
	 *            The output message.
	 * @throws ASelectException
	 *             If proccessing fails.
	 */
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
			byte[] baTgtBytes = CryptoEngine.getHandle().decryptTGT(sEncTgt);
			sTGT = Utils.byteArrayToHexString(baTgtBytes);
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
			// Note: we should do this earlier, but we don't have an
			// app_id until now

			StringBuffer sbData = new StringBuffer(sASelectServer).append(sEncTgt).append(sRid);
			verifyApplicationSignature(oInputMessage, sbData.toString(), sAppId);

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
		HashMap htAttribs = oAttributeGatherer.gatherAttributes(htTGTContext);
		String sSerializedAttributes = serializeAttributes(htAttribs);

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

			if (_applicationManager.isUseOpaqueUid(sAppId)) {
				// the returned user ID must contain an opaque value
				MessageDigest oMessageDigest = null;
				try {

					String sOrgPart = null;
					String sInput = null;
					String sSalt;

					// FIXME: Work around broken applicationManager getOptionalParam method.
					Object oApplications = _configManager.getSection(null, "applications");
					Object oApplication = _configManager.getSection(oApplications, "application", "id=" + sAppId);

					sSalt = _configManager.getParam(oApplication, "salt");
					int iTmp = sUid.indexOf("@");
					if (iTmp >= 0) {
						sOrgPart = sUid.substring(iTmp);
						sInput = sUid.substring(0, iTmp - 1);
					}
					else {
						sInput = sUid;
					}

					if (sSalt != null) {
						sInput += sSalt;
					}
					oMessageDigest = MessageDigest.getInstance("SHA1");
					oMessageDigest.update(sInput.getBytes("UTF-8"));
					sUid = Utils.byteArrayToHexString(oMessageDigest.digest());
					if (sOrgPart != null) {
						sUid += sOrgPart;
					}
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
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid signature");

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}

}
