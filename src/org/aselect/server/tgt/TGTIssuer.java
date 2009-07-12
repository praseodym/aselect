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
 * $Id: TGTIssuer.java,v 1.37 2006/04/26 12:18:59 tom Exp $ 
 * 
 * Changelog:
 * $Log: TGTIssuer.java,v $
 * Revision 1.37  2006/04/26 12:18:59  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.36  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.35.4.6  2006/03/20 12:28:28  martijn
 * level is stored in session as an Integer object
 *
 * Revision 1.35.4.5  2006/03/16 08:22:38  leon
 * Level changed from String to Integer
 *
 * Revision 1.35.4.4  2006/02/08 08:03:47  martijn
 * getSession() renamed to getSessionContext()
 *
 * Revision 1.35.4.3  2006/02/02 10:26:14  martijn
 * removed unused code
 *
 * Revision 1.35.4.2  2006/01/25 15:35:19  martijn
 * TGTManager rewritten
 *
 * Revision 1.35.4.1  2006/01/13 08:36:49  martijn
 * requesthandlers seperated from core
 *
 * Revision 1.35  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.34  2005/04/15 14:02:55  peter
 * javadoc and comment
 *
 * Revision 1.33  2005/04/11 08:38:50  erwin
 * - Fixed problem with cancel support for cross (app_id local_organization check)
 * - Removed commented code
 *
 * Revision 1.32  2005/04/07 13:56:24  martijn
 * made sendRedirect() public
 *
 * Revision 1.31  2005/04/07 13:42:41  tom
 * Added application id to error tgt (Required for signed requests)
 *
 * Revision 1.30  2005/04/07 13:18:58  peter
 * updated attributes in issueCrossTGT
 *
 * Revision 1.29  2005/04/07 13:15:48  martijn
 * update tgt needs always an update of the rid
 *
 * Revision 1.28  2005/04/07 12:12:21  martijn
 * fixed verifyTGT and changed sso_groups code
 *
 * Revision 1.27  2005/04/07 07:34:21  peter
 * optional oldTGT in issueCrossTGT
 *
 * Revision 1.26  2005/04/06 11:37:08  martijn
 * added an verifyTGT() method
 *
 * Revision 1.25  2005/04/06 08:58:12  martijn
 * code updates needed because of TGTIssuer code restyle
 *
 * Revision 1.24  2005/04/05 15:24:45  martijn
 * TGTIssuer.issueTGT() now only needs an optional old tgt and the printwriter isn't needed anymore
 *
 * Revision 1.23  2005/04/05 13:09:53  martijn
 * removes the old tgt if the user already has one in a forced authenticate cituation
 *
 * Revision 1.22  2005/04/05 09:12:09  peter
 * added cross proxy logica
 *
 * Revision 1.21  2005/04/01 14:24:28  peter
 * cross aselect redesign
 *
 * Revision 1.20  2005/03/21 08:38:02  remco
 * issueErrorTGT() now sends an a-select-servert paremeter along, just like the normal issueTGT()
 *
 * Revision 1.19  2005/03/18 13:43:35  remco
 * made credentials shorter (base64 encoding instead of hex representation)
 *
 * Revision 1.18  2005/03/17 14:08:48  remco
 * changed attribute functionality
 *
 * Revision 1.17  2005/03/17 07:59:28  erwin
 * The A-Select server ID is now set with the constructor,
 * instead of reading it from the configuration.
 * All possible errors are checked in the methods and
 * the fixme's are removed.
 *
 * Revision 1.16  2005/03/16 11:29:50  martijn
 * renamed todo's
 *
 * Revision 1.15  2005/03/16 11:15:50  martijn
 * Sessions will be verified after retrieving, if it fails an (session exprired) error will be returned
 *
 * Revision 1.14  2005/03/16 09:28:03  martijn
 * The config item 'cookie_domain' will now only be retrieved from the config at startup and not every time the ticket is issued.
 *
 * Revision 1.13  2005/03/14 11:15:06  tom
 * Moved killSession into catch statement, session should only be removed if authentication is succesfull
 *
 * Revision 1.12  2005/03/14 10:24:56  tom
 * Error TGT now only contains a RID and result_code
 *
 * Revision 1.11  2005/03/11 13:15:13  martijn
 * Renamed single-sign-on config item that now will be read once at startup of the config manager.
 *
 * Revision 1.10  2005/03/11 07:24:18  tom
 * Changed error in TGTContext to result_code
 *
 * Revision 1.9  2005/03/11 07:10:02  remco
 * "cancel" request -> "error" request
 *
 * Revision 1.8  2005/03/10 16:21:57  erwin
 * Improved error handling.
 *
 * Revision 1.7  2005/03/10 14:17:45  erwin
 * Improved Javadoc.
 *
 * Revision 1.6  2005/03/09 09:24:50  erwin
 * Renamed and moved errors.
 *
 * Revision 1.5  2005/03/08 14:34:02  martijn
 * Added javadoc and renamed variables to the coding standard
 * 
 */

package org.aselect.server.tgt;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletResponse;

import org.aselect.server.authspprotocol.handler.AuthSPHandlerManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.xsaml20.ServiceProvider;
import org.aselect.server.request.handler.xsaml20.idp.UserSsoSession;
import org.aselect.server.session.SessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;

/**
 * Issues ASelect TGT's.
 * <br><br>
 * <b>Description:</b><br>
 * Provides methods to issue Ticket Granting Tickets in A-Select.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 * 14-11-2007 - Changes:
 * - DigiD Gateway: transfer DigiD attributes
 * - Transfer select user id
 * 
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright Gemeente Den Haag (http://www.denhaag.nl) and UMC Nijmegen (http://www.umcn.nl)
 */
public class TGTIssuer
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "TGTIssuer";

	/**
	 * The configuration.
	 */
	private ASelectConfigManager _configManager;
	/**
	 * The system logger.
	 */
	private ASelectSystemLogger _systemLogger;

	/**
	 * The crypto engine.
	 */
	private CryptoEngine _cryptoEngine;

	private String _sServerId;

	private SessionManager _sessionManager;

	private TGTManager _tgtManager;

	private AuthSPHandlerManager _authSPHandlerManager;

	/**
	 * The default constructor.
	 * @param sServerId The A-Select server ID.
	 */
	public TGTIssuer(String sServerId) {
		//TODO All configuration reading in this class must be moved to this contructor (Martijn)
		_systemLogger = ASelectSystemLogger.getHandle();
		_configManager = ASelectConfigManager.getHandle();
		_cryptoEngine = CryptoEngine.getHandle();
		_sessionManager = SessionManager.getHandle();
		_tgtManager = TGTManager.getHandle();
		_authSPHandlerManager = AuthSPHandlerManager.getHandle();
		_sServerId = sServerId;
	}

	/**
	 * Creates a Cross TGT and redirects the user.
	 * <br><br>
	 * <b>Description:</b>
	 * <ul>
	 * 	<li>Creates a specific redirect url</li>
	 * 	<li>Sets the TGT as Cookie at the user</li>
	 * 	<li>Kills the old session</li>
	 *  <li>Redirect user to redirect url</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * 	<li>The <i>SessionManager</i> must be initialized</li>
	 * 	<li>The <i>TGTManager</i> must be initialized</li>
	 * 	<li>The <i>ASelectConfigManager</i> must be initialized</li>
	 * 	<li>The <i>ASelectSystemLogger</i> must be initialized</li>
	 * 	<li>The <i>CryptoEngine</i> must be initialized</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br>
	 * @param sRid The request id (session key)
	 * @param sAuthSP The AuthSP which the used to authenticate 
	 * @param htRemoteAttributes <code>HashMap</code> containing additional TGT 
	 * information
	 * @param oHttpServletResponse The servlet response that is used to redirect 
	 * to
	 * @param sOldTGT The aselect_credentials_tgt that is already set as a 
	 * cookie at the user (can be null if not present)
	 * @throws ASelectException if an error page must be shown
	 */
	public void issueCrossTGT(String sRid, String sAuthSP, HashMap htRemoteAttributes,
			HttpServletResponse oHttpServletResponse, String sOldTGT)
		throws ASelectException
	{
		// A 'cross TGT' is issued if this Server is acting as 'local'
		// A-Select Server. The user was authenticated at another
		// (remote) A-Select Server.
		String sMethod = "issueCrossTGT()";
		String sLevel = null;
		String sTgt = null;
		String sArpTarget = null; // added 1.5.4

		try {
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				StringBuffer sbFailed = new StringBuffer("No session found, session expired: ");
				sbFailed.append(sRid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Issue Cross TGT for RID: " + sRid);

			String sAppUrl = (String) htSessionContext.get("app_url");
			Integer intAppLevel = (Integer) htSessionContext.get("level");
			String sAppId = (String) htSessionContext.get("app_id");
			String sRemoteOrganization = (String) htSessionContext.get("remote_organization");

			// The following parameters are retrieved from the 'remote' Server. 
			String sUserId = (String) htRemoteAttributes.get("uid");
			String sUserOrganization = (String) htRemoteAttributes.get("organization");
			sLevel = (String) htRemoteAttributes.get("authsp_level");
			sAuthSP = (String) htRemoteAttributes.get("authsp");
			// Attributes that where released by the 'remote' A-Select Server
			// will be stored in the TGT.
			// This server might have configured a 'TGTAttributeRequestor' to
			// release these 'remote' attributes to the application.
			String sRemoteAttribs = (String) htRemoteAttributes.get("attributes");
			sArpTarget = (String) htSessionContext.get("arp_target");

			//TODO Check if double encode is needed (Martijn)
			if (sUserId != null) {
				String sEncodedUserId = URLEncoder.encode(sUserId, "UTF-8");
				sEncodedUserId = URLEncoder.encode(sEncodedUserId, "UTF-8");
			}
			String sLocalOrg = null;
			if (htSessionContext.get("remote_session") != null) {
				// A 'local' A-Select Server forwarded the authentication
				// request. This means that this Server is acting as a proxy server.
				// The application in not known by this A-Select Server.
				sAppUrl = (String) htSessionContext.get("local_as_url");
				// The 'organization' in a TGT always contains the organization
				// where the authentication was done.
				// The 'local_organization' is needed e.g. attribute release policies
				sLocalOrg = (String) htSessionContext.get("local_organization");
				StringBuffer sbAppID = new StringBuffer("[unknown@");
				sbAppID.append(sLocalOrg);
				sbAppID.append("]");

				sAppId = sbAppID.toString();
			}
			HashMap htTGTContext = new HashMap();

			// Bauke: copy DigiD data to the context
			// Prefix the field with "digid_" so the filter can recognize them
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htRemoteAttributes=" + htRemoteAttributes);
			Utils.copyHashmapValue("digid_uid", htTGTContext, htRemoteAttributes);
			Utils.copyHashmapValue("digid_betrouwbaarheidsniveau", htTGTContext, htRemoteAttributes);
			
			// The Saml20 protocol needs a return address:
			Utils.copyHashmapValue("sp_assert_url", htTGTContext, htRemoteAttributes);
			Utils.copyHashmapValue("name_id", htTGTContext, htRemoteAttributes);
			// Bauke 20081203: Store saml20 remote token in the context
			Utils.copyHashmapValue("saml_remote_token", htTGTContext, htRemoteAttributes);

			htTGTContext.put("uid", sUserId);
			htTGTContext.put("organization", sUserOrganization);
			htTGTContext.put("authsp_level", sLevel);
			htTGTContext.put("authsp", sAuthSP);
			htTGTContext.put("app_level", intAppLevel.toString());
			htTGTContext.put("app_id", sAppId);
			htTGTContext.put("rid", sRid);

			// If the 'organization' where the user was authenticated does not equal
			// the 'remote' server I was talking to, this 'remote' server also
			// forwarded the request which means the 'remote' servers acts as proxy.
			// This server might not even know the user's organization and stores the
			// 'proxy_organization' in the TGT.
			if (sRemoteOrganization != null && !sRemoteOrganization.equals(sUserOrganization))
				htTGTContext.put("proxy_organization", sRemoteOrganization);
			if (sRemoteAttribs != null)
				htTGTContext.put("remote_attributes", sRemoteAttribs);
			if (sLocalOrg != null)
				htTGTContext.put("local_organization", sLocalOrg);
			if (sArpTarget != null)
				htTGTContext.put("arp_target", sArpTarget);

			// RH, 20080619, sn
			// We will now only put the client_ip in the TGT if there is a non-zero value present in the sessioncontext
			String sClientIP = (String) htSessionContext.get("client_ip");
			if (sClientIP != null && !"".equals(sClientIP))
				htTGTContext.put("client_ip", sClientIP);
			// RH, 20080619, en

			// Bauke 20081110 copy RelayState to the TgT
			Utils.copyHashmapValue("RelayState", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("user_agent", htTGTContext, htSessionContext);

			// 20090617, Bauke:forced_authenticate specials
			Boolean bForcedAuthn = (Boolean)htSessionContext.get("forced_authenticate");
			if (bForcedAuthn == null) bForcedAuthn = false;
			if (bForcedAuthn)
				htTGTContext.put("forced_authenticate", bForcedAuthn);

			// 20090617, Bauke: not for forced_authenticate
			HashMap htOldTGTContext = null;
			if (!bForcedAuthn && sOldTGT != null) {
				htOldTGTContext = _tgtManager.getTGT(sOldTGT);
				if (htOldTGTContext != null) {
					HashMap htUpdate = verifyTGT(htOldTGTContext, htTGTContext);
					if (!htUpdate.isEmpty())
						htTGTContext.putAll(htUpdate);

					htTGTContext.put("rid", sRid);
					_tgtManager.updateTGT(sOldTGT, htTGTContext);
					sTgt = sOldTGT;
				}
			}

			// Create a new TGT, because there is no old TGT
			if (htOldTGTContext == null) {
				sTgt = _tgtManager.createTGT(htTGTContext);
				
				// Create cookie if single sign-on is enabled
				// 20090617, Bauke: not for forced_authenticate
				if (!bForcedAuthn && _configManager.isSingleSignOn())
					setASelectCookie(sTgt, sUserId, oHttpServletResponse);
			}
			
			// A tgt was just issued, report sensor data
			Tools.calculateAndReportSensorData(_configManager, _systemLogger, htSessionContext);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + sAppUrl);
			sendRedirect(sAppUrl, sTgt, sRid, oHttpServletResponse);
			_sessionManager.killSession(sRid);
		}
		catch (ASelectException e) {
			StringBuffer sbError = new StringBuffer("Issue TGT for request '");
			sbError.append(sRid).append("' failed");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw e;
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Issue TGT for request '");
			sbError.append(sRid).append("' failed due to internal error");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Creates a default TGT and redirects the user.
	 * <br><br>
	 * <b>Description:</b>
	 * <ul>
	 * 	<li>Creates a specific redirect url</li>
	 * 	<li>Sets the TGT as Cookie at the user</li>
	 * 	<li>Kills the old session</li>
	 *  <li>Redirect user to redirect url</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * 	<li>The <i>SessionManager</i> must be initialized</li>
	 * 	<li>The <i>TGTManager</i> must be initialized</li>
	 * 	<li>The <i>ASelectConfigManager</i> must be initialized</li>
	 * 	<li>The <i>ASelectSystemLogger</i> must be initialized</li>
	 * 	<li>The <i>CryptoEngine</i> must be initialized</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br>
	 * @param sRid The request id (session key)
	 * @param sAuthSP The AuthSP which the used to authenticate 
	 * @param htAdditional <code>HashMap</code> containing additional TGT 
	 * information
	 * @param oHttpServletResponse The servlet response that is used to redirect 
	 * to
	 * @param sOldTGT The aselect_credentials_tgt that is already set as a 
	 * cookie at the user (can be null if not exists)
	 * @throws ASelectException if an error page must be shown
	 */
	public void issueTGT(String sRid, String sAuthSP, HashMap htAdditional, HttpServletResponse oHttpServletResponse, String sOldTGT)
	throws ASelectException
	{
		String sMethod = "issueTGT()";
		String sLevel = null;
		String sArpTarget = null; // added 1.5.4

		try {
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found, session expired: " + sRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}
			String sAppUrl = (String) htSessionContext.get("app_url");
			String sLocalOrg = null;
			String sAppId = (String) htSessionContext.get("app_id");
			if (htSessionContext.get("remote_session") != null) {
				// A 'local' A-Select Server forwarded the authentication request.
				// The application in not known by this A-Select Server.
				sAppUrl = (String) htSessionContext.get("local_as_url");
				// The 'organization' in a TGT always contains the organization where the authentication was done.
				// The 'local_organization' is needed e.g. attribute release policies
				sLocalOrg = (String) htSessionContext.get("local_organization");
				StringBuffer sbAppID = new StringBuffer("[unknown@");
				sbAppID.append(sLocalOrg);
				sbAppID.append("]");
				sAppId = sbAppID.toString();
			}

			// Check Authentication result
			String sResult = (String) htSessionContext.get("result_code");
			if (sResult != null && !sResult.equals(Errors.ERROR_ASELECT_SUCCESS)) {
				// Authentication failed, but need to send decent <Response>
				sendRedirect(sAppUrl, null, sRid, oHttpServletResponse);
				// Must be killed by sAppUrl: _sessionManager.killSession(sRid);
				return;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Issue TGT for RID: " + sRid);

			String sUserId = (String) htSessionContext.get("user_id");
			String sOrganization = (String) htSessionContext.get("organization");
			HashMap htAllowedAuthsps = (HashMap) htSessionContext.get("allowed_user_authsps");
			Integer intAppLevel = (Integer) htSessionContext.get("level");
			Vector vSSOGroups = (Vector) htSessionContext.get("sso_groups");
			sLevel = (_authSPHandlerManager.getLevel(sAuthSP)).toString();
			sArpTarget = (String) htSessionContext.get("arp_target");
			try {
				Object oAuthSPSSection = _configManager.getSection(null, "authsps");
				Object oAuthSP = _configManager.getSection(oAuthSPSSection, "authsp", "id=" + sAuthSP);
				sLevel = _configManager.getParam(oAuthSP, "level");
			}
			catch (ASelectConfigException e) {
				//It is a "priviliged authsp" -> get level from context
				sLevel = ((Integer) htSessionContext.get("authsp_level")).toString();
			}

			HashMap htTGTContext = new HashMap();
			htTGTContext.put("uid", sUserId);
			htTGTContext.put("organization", sOrganization);
			htTGTContext.put("authsp_level", sLevel);
			htTGTContext.put("authsp", sAuthSP);
			htTGTContext.put("app_level", intAppLevel.toString());
			htTGTContext.put("app_id", sAppId);
			htTGTContext.put("rid", sRid);
			if (sArpTarget != null)
				htTGTContext.put("arp_target", sArpTarget);
			if (htAllowedAuthsps != null)
				htTGTContext.put("allowed_user_authsps", htAllowedAuthsps);
			if (sLocalOrg != null)
				htTGTContext.put("local_organization", sLocalOrg);
			if (vSSOGroups != null)
				htTGTContext.put("sso_groups", vSSOGroups);

			//overwrite or set additional properties in the newly created tgt context
			if (htAdditional != null)
				htTGTContext.putAll(htAdditional);

			// Bauke: copy from rid context
			Utils.copyHashmapValue("sel_uid", htTGTContext, htSessionContext);

			// 20090617, Bauke:forced_authenticate specials
			Boolean bForcedAuthn = (Boolean)htSessionContext.get("forced_authenticate");
			if (bForcedAuthn == null) bForcedAuthn = false;
			if (bForcedAuthn)
				htTGTContext.put("forced_authenticate", bForcedAuthn);

			HashMap htOldTGTContext = null;
			UserSsoSession ssoSession = null;
			// 20090617, Bauke: not for forced_authenticate
			if (!bForcedAuthn && sOldTGT != null) {
				htOldTGTContext = _tgtManager.getTGT(sOldTGT);
				if (htOldTGTContext != null) {
					HashMap htUpdate = verifyTGT(htOldTGTContext, htTGTContext);
					if (!htUpdate.isEmpty())
						htTGTContext.putAll(htUpdate);

					htTGTContext.put("rid", sRid);
					ssoSession = (UserSsoSession) htOldTGTContext.get("sso_session");
				}
			}

			// Bauke: added for xsaml20
			Utils.copyHashmapValue("sp_assert_url", htTGTContext, htSessionContext);
			String sIssuer = (String) htSessionContext.get("sp_issuer");
			if (sIssuer != null) {
				// SSO Sessions in effect
				htTGTContext.put("sp_issuer", sIssuer);
				Utils.copyHashmapValue("sp_rid", htTGTContext, htSessionContext);
				if (ssoSession == null) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "NEW SSO session for "+sUserId+" issuer="+sIssuer);
					ssoSession = new UserSsoSession(sUserId, ""); // sTgt);
				}
				ServiceProvider sp = new ServiceProvider(sIssuer);
				ssoSession.addServiceProvider(sp);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "SSO session " + ssoSession);
				htTGTContext.put("sso_session", ssoSession);
			}

			// Bauke, 20081209 added for ADFS / WS-Fed
			Utils.copyHashmapValue("wreply", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("wtrealm", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("wctx", htTGTContext, htSessionContext);

			// RH, 20080619, sn
			// We will now only put the client_ip in the TGT if there is a non-zero value present in the sessioncontext
			Utils.copyHashmapValue("client_ip", htTGTContext, htSessionContext);
			// RH, 20080619, en

			// Bauke 20081110 copy RelayState to the TgT
			Utils.copyHashmapValue("RelayState", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("user_agent", htTGTContext, htSessionContext);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Store TGT " + htTGTContext);
			String sTgt = null;
			if (htOldTGTContext == null) {
				// Create a new TGT, must set "name_id" to the sTgt value
				sTgt = _tgtManager.createTGT(htTGTContext);

				// Create cookie if single sign-on is enabled
				// 20090617, Bauke: not for forced_authenticate
				if (!bForcedAuthn && _configManager.isSingleSignOn())
					setASelectCookie(sTgt, sUserId, oHttpServletResponse);
			}
			else { // Update the old TGT
				sTgt = sOldTGT;
				_tgtManager.updateTGT(sOldTGT, htTGTContext);
			}

			// A tgt was just issued, report sensor data
			Tools.calculateAndReportSensorData(_configManager, _systemLogger, htSessionContext);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + sAppUrl);
			sendRedirect(sAppUrl, sTgt, sRid, oHttpServletResponse);
			
			_sessionManager.killSession(sRid);
		}
		catch (ASelectException e) {
			StringBuffer sbError = new StringBuffer("Issue TGT for request '");
			sbError.append(sRid).append("' failed");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw e;
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Issue TGT for request '");
			sbError.append(sRid).append("' failed due to internal error");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Creates an error TGT and redirects the user.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Creates a new TGT containing the error code that 
	 * occured during authentication. This error code 
	 * will be returned to the web application during the
	 * verify_credentials API call.
	 * <br><br>
	 * <b>Description:</b>
	 * <ul>
	 *  <li>Creates a specific redirect url</li>
	 *  <li>Set the error code</li>
	 *  <li>Kills the old session</li>
	 *  <li>Redirect user to redirect url</li>
	 * </ul>
	 * 
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * 	<li>The <i>SessionManager</i> must be initialized</li>
	 * 	<li>The <i>TGTManager</i> must be initialized</li>
	 * 	<li>The <i>ASelectSystemLogger</i> must be initialized</li>
	 * 	<li>The <i>CryptoEngine</i> must be initialized</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br>
	 * @param sRid The request id (session key)
	 * @param sResultCode The error code that occurred and will be returned to 
	 * the webapplication application
	 * @param oHttpServletResponse The servlet response that is used to redirect 
	 * to
	 * @throws ASelectException if an error page must be shown
	 */
	public void issueErrorTGT(String sRid, String sResultCode, HttpServletResponse oHttpServletResponse)
		throws ASelectException
	{
		String sMethod = "issueErrorTGT()";
		SessionManager sessionManager = null;

		try {
			sessionManager = SessionManager.getHandle();
			TGTManager oTGTManager = TGTManager.getHandle();

			HashMap htSessionContext = sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				StringBuffer sbFailed = new StringBuffer("No session found, session expired: ");
				sbFailed.append(sRid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}

			String sAppUrl = (String) htSessionContext.get("app_url");

			if (htSessionContext.get("remote_session") != null) {
				// If the request was forwarded by a local A-Select Server
				// this server is in fact the application where to redirect to.
				String sLocalASUrl = (String) htSessionContext.get("local_as_url");
				sAppUrl = sLocalASUrl;
			}

			HashMap htTGTContext = new HashMap();

			// Error TGT only contains rid and result_code
			String sAppId = (String) htSessionContext.get("app_id");
			if (sAppId != null)
				htTGTContext.put("app_id", sAppId);
			String sLocalOrg = (String) htSessionContext.get("local_organization");
			if (sLocalOrg != null)
				htTGTContext.put("local_organization", sLocalOrg);
			htTGTContext.put("rid", sRid);
			htTGTContext.put("result_code", sResultCode);

			// We will now always put the client_ip in the TGT
			// There should always be a client_ip in the sessioncontext
			htTGTContext.put("client_ip", htSessionContext.get("client_ip"));
			String sAgent = (String) htSessionContext.get("user_agent");
			if (sAgent != null)
				htTGTContext.put("user_agent", sAgent);

			String sTgt = oTGTManager.createTGT(htTGTContext);
			sendRedirect(sAppUrl, sTgt, sRid, oHttpServletResponse);
			sessionManager.killSession(sRid);
		}
		catch (ASelectException e) {
			StringBuffer sbError = new StringBuffer("Issue cancel TGT for request '");
			sbError.append(sRid).append("' failed");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw e;
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Issue cancel TGT for request '");
			sbError.append(sRid).append("' failed due to internal error");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Redirect the user to the supplied application url with the given TGT and 
	 * RID.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * <li>adds an & or ? to the application url</li>
	 * <li>encrypts the given tgt</li>
	 * <li>redirects the user</li>    
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * <li><i>sAppUrl</i> may not be <code>null</code></li>
	 * <li><i>sTgt</i> may not be <code>null</code></li>
	 * <li><i>oHttpServletResponse</i> may not be <code>null</code></li>
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br>
	 * @param sAppUrl application url to send the redirect to
	 * @param sTgt TGT that will be sent with the redirect
	 * @param sRid RID that will be sent with the redirect
	 * @param oHttpServletResponse the user that will be redirected
	 * @throws ASelectException if the user could not be redirected
	 */
	public void sendRedirect(String sAppUrl, String sTgt, String sRid, HttpServletResponse oHttpServletResponse)
		throws ASelectException
	{
		String sMethod = "sendRedirect()";
		StringBuffer sbRedirect = null;

		try { // Check whether the application url contains cgi parameters
			if (sAppUrl.indexOf("?") > 0)
				sAppUrl += "&";
			else
				sAppUrl += "?";

			String sEncryptedTgt = (sTgt == null) ? "" : _cryptoEngine.encryptTGT(Utils.stringToHex(sTgt));
			sbRedirect = new StringBuffer(sAppUrl);
			sbRedirect.append("aselect_credentials=");
			sbRedirect.append(sEncryptedTgt);
			sbRedirect.append("&rid=");
			sbRedirect.append(sRid);
			sbRedirect.append("&a-select-server=");
			sbRedirect.append(_sServerId);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT to: " + sbRedirect);
			oHttpServletResponse.sendRedirect(sbRedirect.toString());
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not send redirect to user: ");
			sbError.append(sbRedirect.toString());
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/*
	 * Sets the A-Select Cookie (aselect_credentials) containing the A-Select credentials
	 */
	public void setASelectCookie(String sTgt, String sUserId, HttpServletResponse oHttpServletResponse)
		throws ASelectException
	{
		String sMethod = "setASelectCookie()";
		try {
			//      DONE(Bauke) uid and a-select-server do not have to be part of the credentials (martijn)
			/*	        StringBuffer sbCredentials = new StringBuffer("tgt=");
			 sbCredentials.append(sTgt);
			 sbCredentials.append("&uid=");
			 sbCredentials.append(sUserId);
			 sbCredentials.append("&a-select-server=");
			 sbCredentials.append(_sServerId);
			 */
			// Bauke 20080617 only store tgt value from now on
			String sCookieDomain = _configManager.getCookieDomain();
			HandlerTools.putCookieValue(oHttpServletResponse, "aselect_credentials", sTgt, sCookieDomain, -1,
					_systemLogger);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not create an A-Select cookie for user: " + sUserId, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/*
	 * verifies the old tgt with new tgt context
	 * verifies the following items: 
	 * - app_level 
	 */
	private HashMap verifyTGT(HashMap htOldTGTContext, HashMap htNewTGTContext)
	{
		HashMap htReturn = new HashMap();
		// check if the user already has a ticket
		// only if the application requires forced this is useful

		//verify authsp_level
		String sOldAuthSPLevel = (String) htOldTGTContext.get("authsp_level");
		String sNewAuthSPLevel = (String) htNewTGTContext.get("authsp_level");
		if (sOldAuthSPLevel != null && sNewAuthSPLevel != null) {
			int iOldAuthSPLevel = new Integer(sOldAuthSPLevel).intValue();
			int iNewAuthSPLevel = new Integer(sNewAuthSPLevel).intValue();
			if (iOldAuthSPLevel > iNewAuthSPLevel) {
				//overwrite level, if user already has a ticket with 
				//a higher level 
				htReturn.put("authsp_level", sOldAuthSPLevel);
			}
		}
		return htReturn;
	}
}