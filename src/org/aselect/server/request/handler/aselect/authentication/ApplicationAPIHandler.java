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
 * @author Alfa & Ariss 14-11-2007 - Changes: - Added to support TGT refreshing, Agent will refresh TGT every time the
 *         application makes contact
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl)
 *         5-3-2009 - Added DigiD-ization, the handler will accept the DigiD request protocol
 */
public class ApplicationAPIHandler extends AbstractAPIRequestHandler
{
	// The managers and engine
	private TGTManager _oTGTManager;
	private SessionManager _sessionManager;
	private ApplicationManager _applicationManager;
	private AuthSPHandlerManager _authSPManagerManager;
	private CryptoEngine _cryptoEngine;
	private MetaDataManagerSp _metadataManager;
	protected String _sServerUrl;

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
	 * @throws ASelectException
	 *             * @throws ASelectCommunicationException the a select communication exception
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

		try {
			_sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);
		}
		catch (ASelectConfigException e) {
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			_metadataManager = MetaDataManagerSp.getHandle();
		}
		catch (ASelectException e) {
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_PARSE_ERROR + ":" + e.toString());
		}
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
	 * @see org.aselect.server.request.handler.aselect.authentication.AbstractAPIRequestHandler#processAPIRequest(org.aselect.system.communication.server.IProtocolRequest,
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
		// Not an API call:
		// else if (sAPIRequest.equals("alive")) {
		// handleUpgradeTGTRequest(oInputMessage, oOutputMessage);
		// }
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
	// 20090606, Bauke: functionality moved to BaseRequestHandler
	private void handleAuthenticateRequest(IProtocolRequest oProtocolRequest, IInputMessage oInputMessage,
			IOutputMessage oOutputMessage)
		throws ASelectException
	{
		String sMethod = "handleAuthenticateRequest";

		HashMap<String, String> hmRequest = new HashMap<String, String>();
		Utils.copyMsgValueToHashmap("app_id", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("app_url", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("a-select-server", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("uid", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("authsp", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("remote_organization", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("country", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("language", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("forced_authenticate", hmRequest, oInputMessage);  // 20100605 added (a String at this point)
		Utils.copyMsgValueToHashmap("forced_logon", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("check-signature", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("signature", hmRequest, oInputMessage);
		Utils.copyMsgValueToHashmap("shared_secret", hmRequest, oInputMessage);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "hmRequest=" + hmRequest);
		HashMap<String, String> hmResponse = handleAuthenticateAndCreateSession(hmRequest, null);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "hmResponse=" + hmResponse);

		try {
			String sValue = hmResponse.get("rid");
			if (sValue != null)
				oOutputMessage.setParam("rid", sValue);
			sValue = hmResponse.get("as_url");
			if (sValue != null)
				oOutputMessage.setParam("as_url", sValue);
			sValue = hmResponse.get("result_code");
			if (sValue != null)
				oOutputMessage.setParam("result_code", sValue);
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
		String sMethod = "handleKillTGTRequest";
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
		catch (ASelectException eAC) { // decrypt failed
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eAC);
		}
		catch (IllegalArgumentException eIA) { // HEX conversion fails
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
			_systemLogger.log(Level.INFO, _sModule, sMethod, "sbData=" + sbData);
			verifyApplicationSignature(oInputMessage, sbData.toString(), sAppId);
		}
		_systemLogger.log(Level.INFO, _sModule, sMethod, "KILL TICKET context=" + htTGTContext);

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

	// Bauke: added to support TGT refreshing
	/**
	 * Handle upgrade tgt request.
	 * 
	 * @param oInputMessage
	 *            the o input message
	 * @param oOutputMessage
	 *            the o output message
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleUpgradeTGTRequest(IInputMessage oInputMessage, IOutputMessage oOutputMessage)
		throws ASelectException
	{
		String sMethod = "handleUpgradeTGTRequest";
		String sEncTGT = null;
		String sASelectServer = null;
		String sLanguage = null;

		// Get mandatory parameters
		try {
			sEncTGT = oInputMessage.getParam("crypted_credentials");
			sASelectServer = oInputMessage.getParam("a-select-server");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameters");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		String sTgT = Utils.decodeCredentials(sEncTGT, _systemLogger);
		if (sTgT == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Can not decode credentials");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}

		// check if the TGT exists
		HashMap htTGTContext = _oTGTManager.getTGT(sTgT);
		if (htTGTContext == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unknown TGT");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT);
		}
		try {
			sLanguage = oInputMessage.getParam("language");
		}
		catch (ASelectCommunicationException eAC) {
		}
		
		// check if request should be signed
		if (_applicationManager.isSigningRequired()) {
			// Note: we should do this earlier, but we don't have an app_id until now
			String sAppId = (String) htTGTContext.get("app_id");
			StringBuffer sbData = new StringBuffer(sASelectServer).append(sEncTGT);
			if (sLanguage != null)
				sbData = sbData.append(sLanguage);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Signing required, sbData=" + sbData);
			verifyApplicationSignature(oInputMessage, sbData.toString(), sAppId);
		}
		_systemLogger.log(Level.INFO, _sModule, sMethod, "Upgrade TICKET context=" + htTGTContext);

		// 20091113, Bauke: overwrite user's preferred language taken from filter
		// Also if the filter does not pass a language, let it know our favourite!
		if (sLanguage != null) {
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Request language=" + sLanguage);
			htTGTContext.put("language", sLanguage);
		}
		else {
			sLanguage = (String) htTGTContext.get("language");
			if (sLanguage != null)
				oOutputMessage.setParam("language", sLanguage);
		}

		// 20090811, Bauke: Only saml20 needs this type of session sync
		HashMap htResult = null;
		String sAuthspType = (String) htTGTContext.get("authsp_type");
		if (sAuthspType != null && sAuthspType.equals("saml20")) {
			// Send Session Sync to the Federation
			htResult = SessionSyncRequestSender.getSessionSyncParameters(_systemLogger);
		}
		if (htResult == null || htResult.isEmpty()) {
			// No Session Sync handler, only update the ticket granting ticket
			_systemLogger.log(Level.INFO, _sModule, sMethod, "updateTGT only");
			_oTGTManager.updateTGT(sTgT, htTGTContext);
		}
		else {
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Send Sync to Federation");
			long updateInterval = (Long) htResult.get("update_interval");
			String sSamlMessageType = (String) htResult.get("message_type");
			// Bauke 20091029, take federation url from TGT
			String sFederationUrl = (String) htTGTContext.get("federation_url");
			// if (sFederationUrl == null) sFederationUrl = (String)htResult.get("federation_url");
			String sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);

			String verify_signature = (String) htResult.get("verify_signature");
			PublicKey pKey = null;
			if ("true".equalsIgnoreCase(verify_signature.trim())) {
				pKey = _metadataManager.getSigningKeyFromMetadata(sFederationUrl); // 20091029, was:
				// _configManager.getFederationURL());
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

			_systemLogger.log(Level.INFO, _sModule, sMethod, "sFederationUrl=" + sFederationUrl);
			String sSessionSyncUrl = MetaDataManagerSp.getHandle().getSessionSyncURL(sFederationUrl); // "/saml20_session_sync";
			SessionSyncRequestSender ss_req = new SessionSyncRequestSender(_systemLogger, sServerUrl, updateInterval,
					sSamlMessageType, sSessionSyncUrl, pKey, l_max_notbefore, l_max_notonorafter, ("true"
							.equalsIgnoreCase(verify_interval.trim())) ? true : false);
			String ssReturn = ss_req.synchronizeSession(sTgT, htTGTContext, /* true, coded */true/* updateTGT */);
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
	 * This method handles the <code>request=verify_tgt</code> request. If the tgt of the user is valid, then this
	 * method returns the information of the user. <br>
	 * 
	 * @param oInputMessage
	 *            The input message.
	 * @param oOutputMessage
	 *            The output message.
	 * @throws ASelectException
	 *             If processing fails.
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
			// Another NOTE: see to it that all data is put in sData sorted on parameter name!
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
		String sAuthSPLevel = (String) htTGTContext.get("sel_level");  // 20100323: was ("authsp_level");
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
			HashMap htSelectedAttr = SamlTools.extractFromHashtable(arrAttrNames, htAttribs, true/* include */);

			// Also include the original IdP token
			String sRemoteToken = (String) htTGTContext.get("saml_remote_token");
			if (sRemoteToken != null)
				htSelectedAttr.put("saml_remote_token", sRemoteToken);

			// Add Saml Token to the attributes, must be signed and base64 encoded
			sToken = SamlTools.createAttributeToken(_sServerUrl, sTGT, htSelectedAttr);
			htAttribs.put("saml_attribute_token", sToken);
		}
		String sSerializedAttributes = Utils.serializeAttributes(htAttribs);
		_systemLogger.log(Level.INFO, _sModule, sMethod, "VERCRED SerAttr="
				+ Utils.firstPartOf(sSerializedAttributes, 40) + " Token=" + Utils.firstPartOf(sToken, 40));

		try {
			oOutputMessage.setParam("app_id", sAppId);
			oOutputMessage.setParam("organization", (String) htTGTContext.get("organization"));
			oOutputMessage.setParam("app_level", (String) htTGTContext.get("app_level"));
			// Return both asp and authsp variables to remain compatible
			// with A-Select 1.3 and 1.4
			oOutputMessage.setParam("asp_level", sAuthSPLevel);
			oOutputMessage.setParam("authsp_level", sAuthSPLevel);
			oOutputMessage.setParam("sel_level", sAuthSPLevel);  // 20100323: added
			oOutputMessage.setParam("asp", sAuthSP);
			oOutputMessage.setParam("authsp", sAuthSP);

			// 20090303, Bauke: added for DigiD-ization, return level in the configured name: <level_name>
			String sLevelName = aApp.getLevelName();
			if (sLevelName != null)
				oOutputMessage.setParam(sLevelName, sAuthSPLevel);

			if (_applicationManager.isUseOpaqueUid(sAppId)) {
				// the returned user ID must contain an opaque value
				MessageDigest oMessageDigest = null;
				try {
					oMessageDigest = MessageDigest.getInstance("SHA1");
					oMessageDigest.update(sUid.getBytes("UTF-8"));
					sUid = Utils.byteArrayToHexString(oMessageDigest.digest());
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

		// 20090622, Bauke: when we would have removed the ticket when forced_authenticate is in effect
		// the following upgrade_tgt will fail and force a new authenication. Also note that
		// the login1 request will not use the TgT for SSO when "forced_authenticate" is true.

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
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid application ID: " + sAppId
					+ ". Could not find signing key for application.", e);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		if (!_cryptoEngine.verifyApplicationSignature(pk, sData, sSignature))
		// throws ERROR_ASELECT_INTERNAL_ERROR
		{
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid signature ID: " + sAppId + " signature: "
					+ sSignature + " Key=" + pk);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}
}
