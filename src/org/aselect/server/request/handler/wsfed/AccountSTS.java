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
 *
 * @author Bauke Hiemstra - www.anoigo.nl
 * 
 * Version 1.0 - 14-11-2007
 */
package org.aselect.server.request.handler.wsfed;

import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.*;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.utils.Utils;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.*;
import org.opensaml.SAMLException;
import org.opensaml.SAMLSubject;

//
// Account Partner = IdP
//
public class AccountSTS extends ProtoRequestHandler
{
	public final static String MODULE = "AccountSTS";
	private final static String RETURN_SUFFIX = "_return";
	private final static String SESSION_ID_PREFIX = ""; // 20081125 "wsfed_";

	private IClientCommunicator _oClientCommunicator;
	private TGTManager _oTGTManager;

	private String _sTemplate = null;
	private String _sPostTemplate = null;
	private String _sMyAppId;
	private String _sPassTransientId;
	private String _sIstsUrl;
	private String _sProviderId;
	private String _sNameIdFormat;
	// Removed 20080423: private String _sDefaultWreply;
	private String _sUserDomain;
	private String _sCookieDomain;
	protected HashMap _htSecLevels;
	protected HashMap _htSP_LoginReturn;
	protected HashMap _htSP_LogoutReturn;

	// protected HashMap _htSP_ErrorUrl;

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#getSessionIdPrefix()
	 */
	protected String getSessionIdPrefix()
	{
		return SESSION_ID_PREFIX;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#useConfigToCreateSamlBuilder()
	 */
	protected boolean useConfigToCreateSamlBuilder()
	{
		return true;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";
		_oTGTManager = TGTManager.getHandle();

		try {
			super.init(oServletConfig, oConfig);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "specific init processing");

			_oClientCommunicator = initClientCommunicator(oConfig);
			_sUserDomain = ASelectConfigManager.getParamFromSection(null, "aselect", "user_domain", false);
			if (_sUserDomain == null)
				_sUserDomain = "digid.nl";
			_sMyAppId = ASelectConfigManager.getParamFromSection(oConfig, "application", "id", true);
			_sPassTransientId = ASelectConfigManager.getSimpleParam(oConfig, "pass_transient_id", false);
			_sIstsUrl = ASelectConfigManager.getSimpleParam(oConfig, "ists_url", true);
			_sProviderId = ASelectConfigManager.getSimpleParam(oConfig, "provider_id", true);
			_sNameIdFormat = ASelectConfigManager.getSimpleParam(oConfig, "nameid_format", true);
			// _sDefaultWreply = Utils.getSimpleParam(oConfig, "default_wreply", true);
			_sTemplate = readTemplateFromConfig(oConfig, "template");

			_sCookieDomain = _configManager.getCookieDomain();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Cookie domain is: " + _sCookieDomain);

			_vIdPUrls = new Vector(); // Vector will contain 'url' key values
			_htIdPs = new HashMap(); // contains url->id
			getTableFromConfig(oConfig, _vIdPUrls, _htIdPs, "identity_providers", "idp", "url",/*->*/"id",
					true/* mandatory */, true/* unique values */);

			_htSecLevels = new HashMap(); // contains level -> urn
			getTableFromConfig(oConfig, null, _htSecLevels, "authentication_method", "security", "level",/*->*/"uri",
					false/* mandatory */, false/* unique values */);

			// We just parse the config multiple times, since it's only done once
			_htSP_LoginReturn = new HashMap();
			getTableFromConfig(oConfig, null, _htSP_LoginReturn, "service_providers", "sp", "uri",/*->*/
			"login_return_url", false/* mandatory */, false/* unique values */);

			_htSP_LogoutReturn = new HashMap();
			getTableFromConfig(oConfig, null, _htSP_LogoutReturn, "service_providers", "sp", "uri",/*->*/
			"logout_return_url", false/* mandatory */, false/* unique values */);

			_sPostTemplate = readTemplateFromConfig(oConfig, "post_template");
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	// https://idp.symdemo.com:8880/IDP-F?wa=wsignin1.0
	// wreply=https://sp.symspdemo.com:8780/SP-P
	// wct=2007-06-07T20:40:22Z
	// wtrealm=https://sp.symspdemo.com:8780/sp.xml
	//
	// Requestor IP/STS Challenge (Step 5)
	//
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.IRequestHandler#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process()";
		String sPathInfo = request.getPathInfo();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Path=" + sPathInfo);
		HandlerTools.logCookies(request, _systemLogger);

		if (sPathInfo.endsWith(RETURN_SUFFIX)) {
			return processReturn(request, response);
		}

		String sPwa = request.getParameter("wa"); // action
		String sPwreply = request.getParameter("wreply"); // response redirect URL, nog given by ADFS!
		String sPwctx = request.getParameter("wctx"); // context value, pass unchanged
		// String sPwct = request.getParameter("wct"); // current time
		String sPwtrealm = request.getParameter("wtrealm"); // requesting realm (resource accessed)
		String sPwhr = request.getParameter("whr"); // requestor's home realm (account partner's client realm)

		if (sPwa != null && sPwa.equals("wsignout1.0"))
			return processSignout(request, response);

		if (sPwa == null || !sPwa.equals("wsignin1.0")) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unknown or missing \"wa\" in call");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		// If we don't know the realm, kick them out
		if (sPwtrealm == null || !_htSP_LoginReturn.containsKey(sPwtrealm)) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unknown or missing \"wtrealm\" in call");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		String sReply = (String) _htSP_LoginReturn.get(sPwtrealm);
		// ADFS does not pass a 'wreply' parameter!!
		if (sPwreply == null) {
			sPwreply = sReply; // _sDefaultWreply; // "https://adfsresource.treyresearch.net/adfs/ls";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'wreply' parameter in request, using: " + sPwreply);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "wsfed_ap PATH=" + request.getPathInfo() + " "
				+ request.getMethod() + " " + request.getQueryString());

		HashMap htSessionData = new HashMap();
		if (sPwtrealm != null)
			htSessionData.put("wtrealm", sPwtrealm);
		if (sPwreply != null)
			htSessionData.put("wreply", sPwreply);
		if (sPwctx != null)
			htSessionData.put("wctx", sPwctx);

		// Look for a possible TGT
		// HashMap htCredentialsParams = getCredentialsFromCookie(request);
		// Bauke 20081209: getCredentialsFromCookie now returns a string
		String sTgt = getCredentialsFromCookie(request);
		// if (htCredentialsParams != null) {
		// String sTgt = (String)htCredentialsParams.get("tgt");
		if (sTgt != null) {
			HashMap htTGTContext = getContextFromTgt(sTgt, true); // Check expiration
			if (htTGTContext != null) { // Valid TGT context found
				// Update TGT timestamp
				_oTGTManager.updateTGT(sTgt, htTGTContext);
				// Return to the caller
				String sUid = (String) htTGTContext.get("uid");
				HashMap htAllAttributes = getAttributesFromTgtAndGatherer(htTGTContext);
				return postRequestorToken(request, response, sUid, htSessionData, htAllAttributes);
			}
		}
		// }
		// Start an authenticate request
		String sASelectURL = _sServerUrl;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Start Authenticate");

		// 20090606, Bauke: No longer implemented as external call
		HashMap htResponse = performAuthenticateRequest(sASelectURL, sPathInfo, RETURN_SUFFIX, _sMyAppId, false/*
																												 * don't
																												 * check
																												 * signature
																												 */,
				_oClientCommunicator);
		String sRid = (String) htResponse.get("rid");

		// We need this stuff when we come back
		storeSessionDataWithRid(response, htSessionData, SESSION_ID_PREFIX, sRid);

		// Let the user get himself identified
		String sActionUrl = sASelectURL + _sIstsUrl;
		String sReplyTo = sASelectURL + sPathInfo + RETURN_SUFFIX;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Form ActionUrl=" + sActionUrl);
		handleShowForm(_sTemplate, sPwhr, sActionUrl, sPwctx, sReplyTo, Tools.samlCurrentTime(), sASelectURL, sRid,
				_sASelectServerID, response);

		return new RequestState(null);
	}

	// Expect:
	// GET aselect_credentials=b...x&rid=770DE0D7302C36CA&a-select-server=aselectserver1
	//
	// Receive Resource Token - Step 9
	// OR: we can get here from the A-Select server directly (credentials are set in that case)
	// Return requestor token to the caller, must be POSTed
	//
	/**
	 * Process return.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @return the request state
	 * @throws ASelectException
	 *             the a select exception
	 */
	public RequestState processReturn(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "processReturn()";
		// Redirection from RP?
		String sPwa = request.getParameter("wa"); // action
		String sPwresult = request.getParameter("wresult"); // resource token

		// Redirection from A-Select server?
		String sUrlRid = request.getParameter("rid");
		// String sUrlServer = (String) request.getParameter("a-select-server");
		String sUrlTgt = (String) request.getParameter("aselect_credentials");

		_systemLogger
				.log(Level.INFO, MODULE, sMethod, "sPwa=" + sPwa + " wresult=" + sPwresult + " sUrlRid=" + sUrlRid);
		String sUid = null;
		String sTgt = null;
		HashMap htCredentials = null;
		HashMap htAttributes = null;
		try {
			if (sPwa != null && !sPwa.equals("")) {
				// From Resource Partner, get attributes from resource token
				htAttributes = extractUidAndAttributes(sPwresult);
				sUid = (String) htAttributes.get("uid");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "From Resource Partner, uid=" + sUid);
				// TODO check incoming token (signature?, time)
			}
			else {
				// From A-Select server
				sUrlTgt = decryptCredentials(sUrlTgt);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "From A-Select TGT="
						+ Tools.clipString(sUrlTgt, 40, true));

				// Get credentials and attributes using Cookie
				htCredentials = getASelectCredentials(request);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "getAselectCredentials: " + htCredentials);
				sUid = (String) htCredentials.get("uid");
				if (sUid == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'uid' found");
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}
				String sAttributes = (String) htCredentials.get("attributes");
				if (sAttributes != null)
					htAttributes = org.aselect.server.utils.Utils.deserializeAttributes(sAttributes);

				String sLevel = (String) htCredentials.get("authsp_level");
				String sTryLevel = (String) htAttributes.get("authsp_level");
				if (sTryLevel == null && sLevel != null) {
					htAttributes.put("auhsp_level", sLevel);
				}
				sTgt = (String) htCredentials.get("tgt");
			}
			String sTryUid = (String) htAttributes.get("uid");
			if (sTryUid == null)
				htAttributes.put("uid", sUid);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htAttributes=" + htAttributes + " pass_transient_id="
					+ _sPassTransientId);

			if (htCredentials == null) {
				// No credentials were made yet, Issue a TGT
				sTgt = createContextAndIssueTGT(response, null, _sASelectServerID, _sASelectOrganization, _sMyAppId,
						sTgt, htAttributes);

				// Create Token and POST it to the caller
				HashMap htSessionData = retrieveSessionDataFromRid(request, SESSION_ID_PREFIX);
				if (htSessionData == null)
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
				if ("true".equals(_sPassTransientId))
					htAttributes.put("transient_id", sTgt);
				return postRequestorToken(request, response, sUid, htSessionData, htAttributes);
			}
			else {
				if ("true".equals(_sPassTransientId))
					htAttributes.put("transient_id", sTgt);
				return postRequestorToken(request, response, sUid, htCredentials, htAttributes);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Post requestor token.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @param sUid
	 *            the s uid
	 * @param htSessionData
	 *            the ht session data
	 * @param htAttributes
	 *            the ht attributes
	 * @return the request state
	 * @throws ASelectException
	 *             the a select exception
	 */
	private RequestState postRequestorToken(HttpServletRequest request, HttpServletResponse response, String sUid,
			HashMap htSessionData, HashMap htAttributes)
		throws ASelectException
	{
		String sMethod = "postRequestorToken()";

		// Retrieve data stored in Step 5
		String sAudience = (String) htSessionData.get("wtrealm");
		String sPwreply = (String) htSessionData.get("wreply");
		String sPwctx = (String) htSessionData.get("wctx"); // context, must be returned unchanged
		_systemLogger.log(Level.INFO, MODULE, sMethod, "wtrealm=" + sAudience + " wreply=" + sPwreply + " wctx="
				+ sPwctx);
		// sPwctx = sPwctx.replaceAll("\\.*", "");

		try {
			String sSubjConf = SAMLSubject.CONF_BEARER; // default value
			String sLevel = sLevel = (String) htAttributes.get("sel_level");
			if (sLevel == null) sLevel = (String) htAttributes.get("authsp_level");
			if (sLevel == null) sLevel = (String) htAttributes.get("betrouwbaarheidsniveau");
			if (sLevel != null) {
				String urn = (String) _htSecLevels.get(sLevel);
				if (urn != null)
					sSubjConf = urn; // default when not found
			}
			String sRequestorToken = createRequestorToken(request, _sProviderId, sUid, _sUserDomain, _sNameIdFormat,
					sAudience, htAttributes, sSubjConf);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Token OUT: RequestorToken wresult=" + sRequestorToken);

			// Return Requestor Token - Step 6
			// POST to Requestor's STS (IdP): take wreply and wctx from Step 5
			String sInputs = buildHtmlInput("wa", "wsignin1.0");
			sInputs += buildHtmlInput("wctx", sPwctx);
			// sInputs += buildHtmlInput("whr", sProviderId); // ADFS?
			sInputs += buildHtmlInput("wresult", Tools.htmlEncode(sRequestorToken));

			// Kill the cookie so it can not be used again (to prevent loops)
			HandlerTools.delCookieValue(response, SESSION_ID_PREFIX + "rid", _sCookieDomain, _systemLogger);
			// To support wslogout, we need to store the realm with the browser
			HandlerTools.putCookieValue(response, SESSION_ID_PREFIX + "realm", sAudience, _sCookieDomain, -1,
					_systemLogger);

			// _systemLogger.log(Level.INFO, MODULE, sMethod, "Inputs=" + sInputs);
			handlePostForm(_sPostTemplate, sPwreply, sInputs, response);

			return new RequestState(null);
		}
		catch (SAMLException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "SAML Exception: ", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#serializeTheseAttributes(java.util.HashMap)
	 */
	public String serializeTheseAttributes(HashMap htAttribs)
		throws ASelectException
	{
		String sMethod = "serializeTheseAttributes";
		
		String sSerializedAttributes = Utils.serializeAttributes(htAttribs);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "sSerializedAttributes=" + sSerializedAttributes);
		return sSerializedAttributes;
	}

	/**
	 * Process signout.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @return the request state
	 * @throws ASelectException
	 *             the a select exception
	 */
	public RequestState processSignout(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "processSignout()";

		// First look for a possible TGT
		// HashMap htCredentialsParams = getCredentialsFromCookie(request);
		// Bauke 20081209: getCredentialsFromCookie now returns a string
		String sTgt = getCredentialsFromCookie(request);
		String sWtRealm = null;
		// if (htCredentialsParams != null) {
		// String sTgt = (String)htCredentialsParams.get("tgt");
		if (sTgt != null) {
			HashMap htTGTContext = getContextFromTgt(sTgt, false); // Don't check expiration
			if (htTGTContext != null) { // Valid TGT context found
				sWtRealm = (String) htTGTContext.get("wtrealm");
				_oTGTManager.remove(sTgt);
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "wtrealm=" + sWtRealm);
		// Remove the TGT cookie
		HandlerTools.delCookieValue(response, "aselect_credentials", _sCookieDomain, _systemLogger);
		// }

		try {
			// Find out where we need to send the user back to
			if (sWtRealm == null) {
				sWtRealm = HandlerTools.getCookieValue(request, SESSION_ID_PREFIX + "realm", _systemLogger);
			}
			String sReply = (String) _htSP_LogoutReturn.get(sWtRealm);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Used " + sWtRealm
					+ " to find return address, REDIRECT to SP=" + sReply);

			// To play it nice, we should clean-up the 'realm' cookie,
			// But ... ADFS sometimes seems to allow the user to logout when they're already logged out
			// in that case the 'realm' would come in handy to return the user, therefore ...
			// don't: delCookieValue(response, SESSION_ID_PREFIX+"realm", _sCookieDomain);

			response.sendRedirect(sReply.toString());
			return new RequestState(null);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_IO, e);
		}
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#destroy()
	 */
	public void destroy()
	{
	}
}
