/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license. See the included
 * LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE please contact SURFnet bv.
 * (http://www.surfnet.nl)
 */

/*
 * $Id: ASelectAPIHandler.java,v 1.1.2.1 2007/03/05 11:35:04 maarten Exp $
 * 
 * Changelog: 
 * $Log: ASelectAPIHandler.java,v $
 * Revision 1.1.2.1  2007/03/05 11:35:04  maarten
 * SFS Request Handlers
 *
 * Revision 1.1.2.8  2006/12/14 14:13:25  maarten
 * Updated ARP
 *
 * Revision 1.1.2.7  2006/11/28 10:56:32  leon
 * bugfix
 *
 * Revision 1.1.2.6  2006/11/28 10:07:37  leon
 * opaque id changed so, the organisation part of the user_id is not hashed
 *
 * Revision 1.1.2.5  2006/11/28 07:30:33  leon
 * *** empty log message ***
 *
 * Revision 1.1.2.4  2006/11/27 15:24:29  maarten
 * opaque id salt added
 *
 * Revision 1.1.2.3  2006/11/22 09:27:20  maarten
 * Updated version
 * Updated home_organization functionality
 * Fixed signing bug
 *
 * Revision 1.1.2.2  2006/09/05 07:20:01  leon
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2006/09/04 08:52:26  leon
 * SFS Handlers
 *
 * Revision 1.7  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.6  2006/03/20 12:27:01  martijn
 * level is stored in session as an Integer object
 *
 * Revision 1.5  2006/03/14 11:17:26  martijn
 * external_url renamed to redirect_url
 *
 * Revision 1.4  2006/03/13 14:02:21  martijn
 * added optional external_url support
 *
 * Revision 1.3  2006/03/09 15:00:08  martijn
 * resolved bug 113:
 * removed check if config item 'server' exists in local_servers organization section
 *
 * Revision 1.2  2006/02/28 08:52:59  jeroen
 * Adaptations for the redirectUrl and Bugfix for 113:
 *
 * ASelectAPIHandler -> handleAuthenticateRequest
 * Changed check for server into check for local organization id. Therefore
 * configuration of the server_id is no longer mandetory.
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
 * Revision 1.28  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.27  2005/09/07 12:46:13  erwin
 * Added "null" check for local level in cross A-Select (bug #91)
 *
 * Revision 1.26  2005/05/02 14:15:12  peter
 * code-style
 *
 * Revision 1.25  2005/04/27 13:04:48  erwin
 * AGENT -> SERVER Error codes.
 *
 * Revision 1.24  2005/04/15 14:03:54  peter
 * javadoc and comment
 *
 * Revision 1.23  2005/04/15 11:51:23  tom
 * Removed old logging statements
 *
 * Revision 1.22  2005/04/14 12:13:03  tom
 * Fixed javadoc error in handleVerifyCredentialsRequest
 *
 * Revision 1.21  2005/04/11 14:56:31  peter
 * code restyle
 *
 * Revision 1.20  2005/04/11 12:48:35  erwin
 * Added forced_logon functionality for local A-Select Servers
 *
 * Revision 1.19  2005/04/11 09:59:26  remco
 * added forced_logon parameter to signature verification
 *
 * Revision 1.18  2005/04/11 09:24:24  remco
 * also implemented forced_logon protocol change in cross (untested)
 *
 * Revision 1.17  2005/04/11 08:57:29  erwin
 * Added local A-Select signing support for cross A-Select.
 *
 * Revision 1.16  2005/04/08 11:58:19  martijn
 * fixed todo's
 *
 * Revision 1.15  2005/04/07 14:38:12  peter
 * added forced_authenticate
 *
 * Revision 1.14  2005/04/07 08:57:38  erwin
 * Added gather atributes support for remote A-Select servers.
 *
 * Revision 1.13  2005/04/07 06:37:12  erwin
 * Renamed "attribute" -> "param" to be compatible with configManager.
 *
 * Revision 1.12  2005/04/05 09:06:21  peter
 * solved fix me
 *
 * Revision 1.11  2005/04/01 15:18:13  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.10  2005/04/01 14:25:22  peter
 * cross aselect redesign
 *
 * Revision 1.9  2005/03/24 13:23:45  erwin
 * Improved URL encoding/decoding
 * (this is handled in communication package for API calls)
 *
 * Revision 1.8  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.7  2005/03/16 13:08:19  martijn
 * changed todo to fixme
 *
 * Revision 1.6  2005/03/15 16:00:28  tom
 * Fixed import errors
 *
 * Revision 1.5  2005/03/15 16:00:10  tom
 * Added Javadoc and Error handling
 *
 * Revision 1.4  2005/03/15 13:02:06  tom
 * my_url is now derived from local HttpServletRequest
 *
 * Revision 1.3  2005/03/15 12:50:51  peter
 * Removed uid check in handleCrossAuthenticate that was needed for proxy
 *
 * Revision 1.2  2005/03/15 08:35:52  tom
 * - Removed CrossASelectHandler (replaced with ASelectAPIIHandler)
 *
 * Revision 1.1  2005/03/15 08:21:41  tom
 * - Redesign of request handling
 * - Renamed from A-SelectLoginHandler
 *
 * Revision 1.12  2005/03/11 13:59:41  tom
 * Removed unused imports
 *
 * Revision 1.11  2005/03/11 13:59:07  tom
 * Removed TGT and Application Manager
 *
 * Revision 1.10  2005/03/11 13:58:01  tom
 * Added new Logger and Error handling
 *
 * Revision 1.9  2005/03/10 16:18:36  tom
 * Added new Authentication Logger
 * 
 * Revision 1.8  2005/03/09 17:08:54  remco
 * Fixed whole bunch of warnings
 * 
 * Revision 1.7  2005/03/09 09:24:50  erwin
 * Renamed and moved errors.
 * 
 * Revision 1.6  2005/03/08 11:51:36  remco
 * class variables renamed
 * 
 * Revision 1.5  2005/03/08 10:16:32  remco
 * javadoc added
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

import org.aselect.server.attributes.AttributeGatherer;
import org.aselect.server.authspprotocol.handler.AuthSPHandlerManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.crypto.CryptoEngine;
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
 * This class handles incoming API calls from local servers. <br>
 * <br>
 * <b>Description:</b> <br>
 * If this A-Select Servers is acting as Remote Server for other A-Select Servers (cross A-Select), the following
 * requests of Local Servers are handled here:
 * <ul>
 * <li><code>authenticate</code>
 * <li><code>verify_credentials</code>
 * </ul>
 * 
 * @author Alfa & Ariss
 */
public class ASelectAPIHandler extends AbstractAPIRequestHandler
{
	private SessionManager _sessionManager;
	private CrossASelectManager _crossASelectManager;
	private ASelectConfigManager _configManager;
	private TGTManager _tgtManager;
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
	public ASelectAPIHandler(RequestParser reqParser, HttpServletRequest servletRequest,
			HttpServletResponse servletResponse, String sMyServerId, String sMyOrg)
		throws ASelectCommunicationException {
		super(reqParser, servletRequest, servletResponse, sMyServerId, sMyOrg);

		_sModule = "ASelectAPIHandler";
		_sessionManager = SessionManager.getHandle();
		_crossASelectManager = CrossASelectManager.getHandle();
		_configManager = ASelectConfigManager.getHandle();
		_tgtManager = TGTManager.getHandle();
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
	@Override
	protected void processAPIRequest(IProtocolRequest oProtocolRequest, IInputMessage oInputMessage,
			IOutputMessage oOutputMessage)
		throws ASelectException
	{
		String sMethod = "processAPIRequest()";

		String sRequest = oInputMessage.getParam("request");

		if (sRequest.equals("authenticate")) {
			handleAuthenticateRequest(oProtocolRequest, oInputMessage, oOutputMessage);
		}
		else if (sRequest.equals("verify_credentials")) {
			handleVerifyCredentialsRequest(oInputMessage, oOutputMessage);
		}
		else {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unsupported API Call: " + sRequest);

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
		String sASelectServer = null;
		String sLocalASUrl = null;
		String sLocalOrgId = null;
		String sRequiredLevel = null;
		HashMap htSessionContext = null;
		String sLevel = null;
		String sUid = null;
		String sLanguage = null;
		String sCountry = null;
		String sRemoteServerId = null;

		String sArpTarget = null;

		if (!_crossASelectManager.localServersEnabled()) {
			// No trusted local servers configured.
			_systemLogger.log(Level.WARNING, _sModule, sMethod,
					"Invalid request since no local servers are configured.");

			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		try {
			// Since the request was forwarded by a local server
			// we do not know any application_id or url
			sLocalASUrl = oInputMessage.getParam("local_as_url");
			sLocalOrgId = oInputMessage.getParam("local_organization");
			sRequiredLevel = oInputMessage.getParam("required_level");
			sASelectServer = oInputMessage.getParam("a-select-server");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameters", eAC);

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		try {
			sRemoteServerId = oInputMessage.getParam("remote_organization");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'remote_organization' parameter found.", eAC);
			sRemoteServerId = null;
			// Do nothing
		}

		try {
			sUid = oInputMessage.getParam("uid");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'uid' parameter found.", eAC);
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

		// check if the request must be handled as a forced authentication
		Boolean boolForced = null;
		String sForcedLogon = null;
		try {
			sForcedLogon = oInputMessage.getParam("forced_logon");
			boolForced = new Boolean(sForcedLogon);
		}
		catch (ASelectCommunicationException e) {
			boolForced = new Boolean(false);
			_systemLogger.log(Level.FINE, _sModule, sMethod, "No optional 'forced_logon' parameter found.", e);
		}

		// TODO include other optional parameters as well (remco)
		if (_crossASelectManager.isLocalSigningRequired()) {
			StringBuffer sbData = new StringBuffer(sASelectServer);
			if (sArpTarget != null)
				sbData.append(sArpTarget);
			if (sCountry != null)
				sbData.append(sCountry);
			if (sForcedLogon != null)
				sbData.append(sForcedLogon);

			if (sLanguage != null)
				sbData.append(sLanguage);

			sbData.append(sLocalASUrl).append(sLocalOrgId);

			if (sRemoteServerId != null) {
				sbData.append(sRemoteServerId);
			}
			sbData.append(sRequiredLevel);

			if (sUid != null)
				sbData.append(sUid);

			verifyLocalASelectServerSignature(oInputMessage, sbData.toString(), sLocalOrgId);
		}

		sLevel = _crossASelectManager.getLocalParam(sLocalOrgId, "level");
		if (sLevel != null && Integer.parseInt(sLevel) > Integer.parseInt(sRequiredLevel))
			sRequiredLevel = sLevel;

		// Create Session
		htSessionContext = new HashMap();
		htSessionContext.put("local_organization", sLocalOrgId);
		htSessionContext.put("remote_session", "true");
		htSessionContext.put("local_as_url", sLocalASUrl);
		htSessionContext.put("level", new Integer(sRequiredLevel));
		htSessionContext.put("organization", _sMyOrg);

		// Uid is stored in the session context with a
		// temporary identifier.
		// This because the value is not validated yet.
		// After validation, the values can be set as
		// 'user_id'.
		if (sUid != null)
			htSessionContext.put("forced_uid", sUid);
		if (sCountry != null && sCountry.trim().length() > 0)
			htSessionContext.put("country", sCountry);
		if (sLanguage != null && sLanguage.trim().length() > 0)
			htSessionContext.put("language", sLanguage);

		if (sRemoteServerId != null && sRemoteServerId.trim().length() > 0)
			htSessionContext.put("forced_organization", sRemoteServerId);

		if (sArpTarget != null)
			htSessionContext.put("arp_target", sArpTarget);

		// need to check if the request must be handled as a forced authentication
		if (!boolForced.booleanValue() && _crossASelectManager.isForcedAuthenticateEnabled(sLocalOrgId)) {
			boolForced = new Boolean(true);
		}
		htSessionContext.put("forced_authenticate", boolForced);

		// Authentication OK
		StringBuffer sbAsUrl = new StringBuffer();
		String sAsUrl = _configManager.getRedirectURL();
		if (sAsUrl != null)
			sbAsUrl.append(sAsUrl);
		else
			sbAsUrl.append(oProtocolRequest.getTarget());

		Integer intMaxLevel = new Integer(99);
		Vector vAuthSPs = AuthSPHandlerManager.getHandle().getConfiguredAuthSPs(new Integer(sRequiredLevel),
				intMaxLevel);
		if (vAuthSPs.size() == 1 && AuthSPHandlerManager.getHandle().isDirectAuthSP((String) vAuthSPs.get(0))) {
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
	 * This method handles the <code>request=verify_credentials</code> request. If the tgt of the user is valid, then
	 * this method returns the information of the user to the local server. <br>
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
		String sASelectServer = null;
		String sEncTgt = null;
		String sTGT = null;

		try {
			sEncTgt = oInputMessage.getParam("aselect_credentials");
			sRid = oInputMessage.getParam("rid");
			sASelectServer = oInputMessage.getParam("a-select-server");
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

		htTGTContext = _tgtManager.getTGT(sTGT);

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

		// get local_organisation from TGT context.
		String sLocalOrg = (String) htTGTContext.get("local_organization");

		if (sLocalOrg == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "invalid local organization");

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		// Check if request should be signed
		if (_crossASelectManager.isLocalSigningRequired()) {
			StringBuffer sbData = new StringBuffer(sASelectServer);
			sbData.append(sEncTgt).append(sLocalOrg).append(sRid);
			verifyLocalASelectServerSignature(oInputMessage, sbData.toString(), sLocalOrg);
		}

		try {
			oOutputMessage.setParam("rid", sRid);
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not set 'rid' response parameter", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, eAC);
		}

		sResultCode = (String) htTGTContext.get("result_code");

		if (sResultCode != null) // Resultcode available in TGT context
		{
			if (sResultCode != Errors.ERROR_ASELECT_SUCCESS) // Error in context
			{
				_tgtManager.remove(sTGT);
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
			lExpTime = _tgtManager.getExpirationTime(sTGT);
		}
		catch (ASelectStorageException eAS) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not fetch TGT timeout", eAS);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}

		// Gather attributes
		AttributeGatherer oAttributeGatherer = AttributeGatherer.getHandle();
		HashMap htAttribs = oAttributeGatherer.gatherAttributes(htTGTContext);
		String sSerializedAttributes = org.aselect.server.utils.Utils.serializeAttributes(htAttribs);

		try {
			oOutputMessage.setParam("organization", (String) htTGTContext.get("organization"));
			oOutputMessage.setParam("app_level", (String) htTGTContext.get("app_level"));
			// Return both asp and authsp variables to remain compatible
			// with A-Select 1.3 and 1.4
			oOutputMessage.setParam("asp_level", sAuthSPLevel);
			oOutputMessage.setParam("asp", sAuthSP);
			oOutputMessage.setParam("authsp_level", sAuthSPLevel);
			oOutputMessage.setParam("authsp", sAuthSP);

			boolean bUseOpaqueId = false;
			try {
				String sUseOpaqueUid = _crossASelectManager.getOptionalLocalParam(sLocalOrg, "use_opaque_uid");
				bUseOpaqueId = new Boolean(sUseOpaqueUid).booleanValue();
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Invalid 'use_opaque_uid' parameter found in 'organization' config section", e);
			}

			if (bUseOpaqueId) {
				// the returned user ID must contain an opaque value
				MessageDigest oMessageDigest = null;
				try {

					String sOrgPart = null;
					String sInput = null;
					String sSalt = _crossASelectManager.getOptionalLocalParam(sLocalOrg, "salt");
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
		if (!ASelectConfigManager.getHandle().isSingleSignOn())
			_tgtManager.remove(sTGT);
	}

	/**
	 * Verify the local A-Select Server signing signature. <br>
	 * <br>
	 * 
	 * @param oInputMessage
	 *            The input message.
	 * @param sData
	 *            The data to validate upon.
	 * @param sOrg
	 *            The organisation of the local A-Select Server.
	 * @throws ASelectException
	 *             If signature is invalid.
	 */
	private void verifyLocalASelectServerSignature(IInputMessage oInputMessage, String sData, String sOrg)
		throws ASelectException
	{
		String sMethod = "verifyLocalASelectServerSignature()";

		String sSignature = null;
		try {
			sSignature = oInputMessage.getParam("signature");
		}
		catch (ASelectCommunicationException eAC) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required 'signature' parameter", eAC);

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		PublicKey oPublicKey = _crossASelectManager.getLocalASelectServerPublicKey(sOrg);
		if (oPublicKey == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod,
					"No local A-Select Server signing key found with alias: " + sOrg);

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		if (!_cryptoEngine.verifyApplicationSignature(oPublicKey, sData, sSignature)) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid signature");

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}
}
