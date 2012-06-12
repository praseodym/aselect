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

import java.io.PrintWriter;

import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletResponse;

import org.aselect.server.attributes.AttributeGatherer;
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
 * Issues ASelect TGT's. <br>
 * <br>
 * <b>Description:</b><br>
 * Provides methods to issue Ticket Granting Tickets in A-Select. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - DigiD Gateway: transfer DigiD attributes - Transfer select user id
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl) and UMC Nijmegen
 *         (http://www.umcn.nl)
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
	 * 
	 * @param sServerId
	 *            The A-Select server ID.
	 */
	public TGTIssuer(String sServerId)
	{
		_systemLogger = ASelectSystemLogger.getHandle();
		_configManager = ASelectConfigManager.getHandle();
		_cryptoEngine = CryptoEngine.getHandle();
		_sessionManager = SessionManager.getHandle();
		_tgtManager = TGTManager.getHandle();
		_authSPHandlerManager = AuthSPHandlerManager.getHandle();
		_sServerId = sServerId;
	}

	/**
	 * Creates a Cross TGT and redirects the user. <br>
	 * <br>
	 * <b>Description:</b>
	 * <ul>
	 * <li>Creates a specific redirect url</li>
	 * <li>Sets the TGT as Cookie at the user</li>
	 * <li>Kills the old session</li>
	 * <li>Redirect user to redirect url</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The <i>SessionManager</i> must be initialized</li>
	 * <li>The <i>TGTManager</i> must be initialized</li>
	 * <li>The <i>ASelectConfigManager</i> must be initialized</li>
	 * <li>The <i>ASelectSystemLogger</i> must be initialized</li>
	 * <li>The <i>CryptoEngine</i> must be initialized</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sRid
	 *            The request id (session key)
	 * @param htSessionContext
	 *            the session context, must be available from the caller
	 * @param sAuthSP
	 *            The AuthSP which the used to authenticate
	 * @param htRemoteAttributes
	 *            <code>HashMap</code> containing additional TGT information
	 * @param oHttpServletResponse
	 *            The servlet response that is used to redirect to
	 * @param sOldTGT
	 *            The aselect_credentials_tgt that is already set as a cookie at the user (can be null if not present)
	 * @throws ASelectException
	 *             if an error page must be shown
	 */
	// 20120403, Bauke: added htSessionContext
	public void issueCrossTGTandRedirect(String sRid, HashMap htSessionContext, String sAuthSP, HashMap htRemoteAttributes,
			HttpServletResponse oHttpServletResponse, String sOldTGT)
		throws ASelectException
	{
		// A 'cross TGT' is issued if this Server is acting as 'local' A-Select Server.
		// The user was authenticated at another (remote) A-Select Server.
		String sMethod = "issueCrossTGT()";
		String sTgt = null;
		String sArpTarget = null; // added 1.5.4

		try {
			// 20120403, Bauke: session is passed as a parameter:
			// HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				StringBuffer sbFailed = new StringBuffer("No session found, session expired: ");
				sbFailed.append(sRid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Issue Cross TGT for RID: " + sRid);

			// Session is present
			String sAppUrl = (String) htSessionContext.get("app_url");
			String sAppId = (String) htSessionContext.get("app_id");
			String sRemoteOrganization = (String) htSessionContext.get("remote_organization");

			// The following parameters are retrieved from the 'remote' Server.
			String sUserId = (String) htRemoteAttributes.get("uid");
			String sUserOrganization = (String) htRemoteAttributes.get("organization");
			sArpTarget = (String) htSessionContext.get("arp_target");

			String sLocalOrg = null;
			if (htSessionContext.get("remote_session") != null) {
				// A 'local' A-Select Server forwarded the authentication request.
				// This means that this Server is acting as a proxy server.
				// The application in not known by this A-Select Server.
				sAppUrl = (String) htSessionContext.get("local_as_url");
				// The 'organization' in a TGT always contains the organization where the authentication was done.
				// The 'local_organization' is needed e.g. attribute release policies
				sLocalOrg = (String) htSessionContext.get("local_organization");
				StringBuffer sbAppID = new StringBuffer("[unknown@").append(sLocalOrg).append("]");
				sAppId = sbAppID.toString();
			}

			_systemLogger.log(Level.FINE, MODULE, sMethod, "htRemoteAttributes=" + htRemoteAttributes);
			HashMap htTGTContext = new HashMap();
			// The Saml20 protocol needs a return address:
			Utils.copyHashmapValue("sp_assert_url", htTGTContext, htRemoteAttributes);
			Utils.copyHashmapValue("name_id", htTGTContext, htRemoteAttributes);
			// Bauke 20081203: Store saml20 remote token in the context
			Utils.copyHashmapValue("saml_remote_token", htTGTContext, htRemoteAttributes);

			Utils.copyHashmapValue("authsp_type", htTGTContext, htRemoteAttributes);
			Utils.copyHashmapValue("authsp_level", htTGTContext, htRemoteAttributes);
			Utils.copyHashmapValue("sel_level", htTGTContext, htRemoteAttributes);
			Utils.copyHashmapValue("authsp", htTGTContext, htRemoteAttributes);
			htTGTContext.put("uid", sUserId);
			htTGTContext.put("organization", sUserOrganization);
			Integer intAppLevel = (Integer) htSessionContext.get("level");
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

			if (sLocalOrg != null)
				htTGTContext.put("local_organization", sLocalOrg);
			if (sArpTarget != null)
				htTGTContext.put("arp_target", sArpTarget);

			// RH, 20080619, We will now only put the client_ip in the TGT if there is a non-zero value present in the sessioncontext
			String sClientIP = (String) htSessionContext.get("client_ip");
			if (sClientIP != null && !"".equals(sClientIP))
				htTGTContext.put("client_ip", sClientIP);

			// 20090811, Bauke: save authsp_type for use by the Saml20 session sync
			Utils.copyHashmapValue("authsp_type", htTGTContext, htSessionContext);

			// Bauke 20081110 copy RelayState to the TgT
			Utils.copyHashmapValue("RelayState", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("user_agent", htTGTContext, htSessionContext);
			// Bauke 20091029, for multiple saml IdPs
			Utils.copyHashmapValue("federation_url", htTGTContext, htSessionContext);
			// 20120606, Bauke: connect sessions
			Utils.copyHashmapValue("usi", htTGTContext, htSessionContext);

			// Attributes that where released by the 'remote' A-Select Server will be stored in the TGT.
			// This server might have configured a 'TGTAttributeRequestor' to
			// release these 'remote' attributes to the application.
			
			// 20100228, Bauke: changed from "remote_attributes" to "attributes"
			String sRemoteAttributes = (htRemoteAttributes==null)? null: (String)htRemoteAttributes.get("attributes");
			HashMap htSerAttributes = (sRemoteAttributes==null)? null: org.aselect.server.utils.Utils.deserializeAttributes(sRemoteAttributes);
			// 20100228, Bauke: when a remote system has changed the language, copy it here
			Utils.copyHashmapValue("language", htTGTContext, htSessionContext);  // default
			if (htSerAttributes != null) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "htAttributes lang="+htSerAttributes.get("language"));
				Utils.copyHashmapValue("language", htTGTContext, htSerAttributes);  // copy remote version over it
			}

			// 20090617, Bauke:forced_authenticate specials
			Boolean bForcedAuthn = (Boolean) htSessionContext.get("forced_authenticate");
			if (bForcedAuthn == null)
				bForcedAuthn = false;
			if (bForcedAuthn)
				htTGTContext.put("forced_authenticate", bForcedAuthn);

			// 20090617, Bauke: not for forced_authenticate
			HashMap htOldTGTContext = null;
			if (!bForcedAuthn && sOldTGT != null) {
				htOldTGTContext = _tgtManager.getTGT(sOldTGT);
				if (htOldTGTContext != null) {
					HashMap htUpdate = compareOldTGTLevels(htOldTGTContext, htTGTContext);
					if (!htUpdate.isEmpty())
						htTGTContext.putAll(htUpdate);

					htTGTContext.put("rid", sRid);
					_tgtManager.updateTGT(sOldTGT, htTGTContext);
					sTgt = sOldTGT;
				}
			}

			// Create a new TGT, when there is no old one
			if (htOldTGTContext == null) {
				sTgt = _tgtManager.createTGT(htTGTContext);

				// Create cookie if single sign-on is enabled
				// 20090617, Bauke: not for forced_authenticate
				if (!bForcedAuthn && _configManager.isSingleSignOn())
					setASelectCookie(sTgt, sUserId, oHttpServletResponse);
			}

			// A tgt was just issued, report sensor data
			Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_tgt", sRid, htSessionContext, sTgt, true);
			_sessionManager.setDeleteSession(htSessionContext, _systemLogger);  // 20120403, Bauke: was killSession()
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + sAppUrl);
			String sLang = (String)htTGTContext.get("language");
			sendTgtRedirect(sAppUrl, sTgt, sRid, oHttpServletResponse, sLang);
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
	 * Creates a default TGT and redirects the user. <br>
	 * <br>
	 * <b>Description:</b>
	 * <ul>
	 * <li>Creates a specific redirect url</li>
	 * <li>Sets the TGT as Cookie at the user</li>
	 * <li>Kills the old session</li>
	 * <li>Redirect user to redirect url</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The <i>SessionManager</i> must be initialized</li>
	 * <li>The <i>TGTManager</i> must be initialized</li>
	 * <li>The <i>ASelectConfigManager</i> must be initialized</li>
	 * <li>The <i>ASelectSystemLogger</i> must be initialized</li>
	 * <li>The <i>CryptoEngine</i> must be initialized</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sRid
	 *            The request id (session key)
	 * @param htSessionContext
	 *            the session context, must be available from the caller
	 * @param sAuthSP
	 *            The AuthSP which the used to authenticate
	 * @param htAdditional
	 *            <code>HashMap</code> containing additional TGT information
	 * @param oHttpServletResponse
	 *            The servlet response that is used to redirect to
	 * @param sOldTGT
	 *            The aselect_credentials_tgt that is already set as a cookie at the user (can be null if not exists)
	 * @throws ASelectException
	 *             if an error page must be shown
	 */
	// 20120403, Bauke: added htSessionContext
	public String issueTGTandRedirect(String sRid, HashMap htSessionContext, String sAuthSP, HashMap htAdditional, HttpServletResponse oHttpServletResponse, String sOldTGT, boolean redirectToo)
	throws ASelectException
	{
		String sMethod = "issueTGTandRedirect";

		try {
			// 20120403, Bauke: session is passed as a parameter:
			// HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found, session expired: " + sRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}
			String sLocalOrg = null;
			String sAppId = (String) htSessionContext.get("app_id");
			
			String sAppUrl = (String) htSessionContext.get("app_url");
			if (htSessionContext.get("remote_session") != null) {
				// A 'local' A-Select Server forwarded the authentication request.
				// The application in not known by this A-Select Server.
				sAppUrl = (String) htSessionContext.get("local_as_url");
				// The 'organization' in a TGT always contains the organization where the authentication was done.
				// The 'local_organization' is needed e.g. attribute release policies
				sLocalOrg = (String) htSessionContext.get("local_organization");
				sAppId = "[unknown@" + sLocalOrg + "]";
			}

			// Check Authentication result
			String sResult = (String) htSessionContext.get("result_code");
			if (sResult != null && !sResult.equals(Errors.ERROR_ASELECT_SUCCESS)) {
				// Authentication failed, no TGT issued, but need to send decent <Response>
				_systemLogger.log(Level.INFO, MODULE, sMethod, "no success, redirect to "+sAppUrl);
				String sLang = (String)htSessionContext.get("language");  // we have no TGT Context yet
				sendTgtRedirect(sAppUrl, null, sRid, oHttpServletResponse, sLang);
				// Session must be killed by sAppUrl: _sessionManager.killSession(sRid);
				return null;
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Issue TGT for RID: " + sRid+" redirectToo="+redirectToo);
			HashMap<String,Object> htTGTContext = new HashMap<String,Object>();
			htTGTContext.put("rid", sRid);
			htTGTContext.put("app_id", sAppId);
			if (sLocalOrg != null)
				htTGTContext.put("local_organization", sLocalOrg);

			String sUserId = (String) htSessionContext.get("user_id");
			htTGTContext.put("uid", sUserId);
			String sOrganization = (String) htSessionContext.get("organization");
			htTGTContext.put("organization", sOrganization);
			if (sAuthSP != null)
				htTGTContext.put("authsp", sAuthSP);
			
			// "authsp_level" is taken from the authsp configuration
			String sAuthspLevel = null;
			if (sAuthSP != null) {
				sAuthspLevel = (_authSPHandlerManager.getLevel(sAuthSP)).toString();
				try {
					Object oAuthSPSSection = _configManager.getSection(null, "authsps");
					Object oAuthSP = _configManager.getSection(oAuthSPSSection, "authsp", "id=" + sAuthSP);
					sAuthspLevel = _configManager.getParam(oAuthSP, "level");
				}
				catch (ASelectConfigException e) {
					// It is a "privileged authsp" -> use default level from context
					sAuthspLevel = ((Integer) htSessionContext.get("authsp_level")).toString();
				}
			}
			if (sAuthspLevel != null) {
				htTGTContext.put("authsp_level", sAuthspLevel);
				htTGTContext.put("sel_level", sAuthspLevel);  // 20100812: set default value
			}
			// possible override from user session, could be higher, but should not be lower
			// I don't expect sel_level to be in htSessionContext, but rather in htAdditional
			Utils.copyHashmapValue("sel_level", htTGTContext, htSessionContext);
			
			// Requested level from the application
			Integer intAppLevel = (Integer) htSessionContext.get("level");
			htTGTContext.put("app_level", intAppLevel.toString());
			
			HashMap htAllowedAuthsps = (HashMap) htSessionContext.get("allowed_user_authsps");
			if (htAllowedAuthsps != null)
				htTGTContext.put("allowed_user_authsps", htAllowedAuthsps);
			Vector vSSOGroups = (Vector) htSessionContext.get("sso_groups");
			if (vSSOGroups != null)
				htTGTContext.put("sso_groups", vSSOGroups);
			Utils.copyHashmapValue("arp_target", htTGTContext, htSessionContext);
			
			// overwrite or set additional properties in the newly created tgt context
			if (htAdditional != null) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "htAdditional="+htAdditional);
				htTGTContext.putAll(htAdditional);
			}
			
			// 20111020, Bauke: "sel_level" correction, should at least be equal to "authsp_level"!
			String sSelLevel = (String)htTGTContext.get("sel_level");
			sAuthspLevel = (String)htTGTContext.get("authsp_level");
			if (sSelLevel != null && sAuthspLevel != null) {
				if (Integer.parseInt(sSelLevel) < Integer.parseInt(sAuthspLevel)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "UPGRADE sel_level to "+sAuthspLevel);
					htTGTContext.put("sel_level", sAuthspLevel);
				}
			}

			// 20100228, Bauke: changed from "remote_attributes" to "attributes"
			String sRemoteAttributes = (htAdditional==null)? null: (String) htAdditional.get("attributes");
			HashMap htSerAttributes = (sRemoteAttributes==null)? null: org.aselect.server.utils.Utils.deserializeAttributes(sRemoteAttributes);
			// 20100228, Bauke: when a remote system has changed the language, copy it here
			_systemLogger.log(Level.FINE, MODULE, sMethod, "htSessionContext lang="+htSessionContext.get("language")+" htTGTContext lang="+htTGTContext.get("language"));
			Utils.copyHashmapValue("language", htTGTContext, htSessionContext);  // default
			if (htSerAttributes != null) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "htAttributes lang="+htSerAttributes.get("language"));
				Utils.copyHashmapValue("language", htTGTContext, htSerAttributes);  // copy remote version over it
			}
			_systemLogger.log(Level.FINE, MODULE, sMethod, "htTGTContext lang="+htTGTContext.get("language"));
			
			// Bauke: copy from rid context
			Utils.copyHashmapValue("sel_uid", htTGTContext, htSessionContext);
			// 20090811, Bauke: save authsp_type for use by the Saml20 session sync
			Utils.copyHashmapValue("authsp_type", htTGTContext, htSessionContext);

			// 20090617, Bauke:forced_authenticate specials
			Boolean bForcedAuthn = (Boolean) htSessionContext.get("forced_authenticate");
			if (bForcedAuthn == null)
				bForcedAuthn = false;
			if (bForcedAuthn)
				htTGTContext.put("forced_authenticate", bForcedAuthn);

			HashMap htOldTGTContext = null;
			UserSsoSession ssoSession = null;
			// 20090617, Bauke: not for forced_authenticate
			if (!bForcedAuthn && sOldTGT != null) {
				htOldTGTContext = _tgtManager.getTGT(sOldTGT);
				if (htOldTGTContext != null) {
					// Higher old level takes precedence
					HashMap htUpdate = compareOldTGTLevels(htOldTGTContext, htTGTContext);
					if (!htUpdate.isEmpty())
						htTGTContext.putAll(htUpdate);
					htTGTContext.put("rid", sRid);
					ssoSession = (UserSsoSession) htOldTGTContext.get("sso_session");
				}
			}

			// Bauke: added for xsaml20
			Utils.copyHashmapValue("sp_assert_url", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("sp_reqbinding", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("sp_reqsigning", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("sp_audience", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("sp_addkeyname", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("sp_addcertificate", htTGTContext, htSessionContext);

			Utils.copyHashmapValue("sp_rid", htTGTContext, htSessionContext);
			ensureSessionPresence(sUserId, htTGTContext, htSessionContext, ssoSession);
			
			// Bauke, 20081209 added for ADFS / WS-Fed
			Utils.copyHashmapValue("wreply", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("wtrealm", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("wctx", htTGTContext, htSessionContext);

			// RH, 20080619: Copy the client_ip in the TGT
			Utils.copyHashmapValue("client_ip", htTGTContext, htSessionContext);

			// Bauke 20081110 copy RelayState to the TgT
			Utils.copyHashmapValue("RelayState", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("user_agent", htTGTContext, htSessionContext);
			// Bauke 20091029, for multiple saml IdPs
			Utils.copyHashmapValue("federation_url", htTGTContext, htSessionContext);
			// 20120606, Bauke: connect sessions
			Utils.copyHashmapValue("usi", htTGTContext, htSessionContext);
			
			// 20100210, Bauke: Organization selection is here
			AttributeGatherer ag = AttributeGatherer.getHandle();
			HashMap<String,String> hUserOrganizations = ag.gatherOrganizations(htTGTContext);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "UserOrgs="+hUserOrganizations);
			
			// Also places org_id in the TGT context:
			boolean mustChooseOrg = Utils.handleOrganizationChoice(htTGTContext, hUserOrganizations);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "MustChoose="+mustChooseOrg+" Store TGT=" + htTGTContext);
			String sTgt = null;
			if (htOldTGTContext == null) {
				// Create a new TGT, must set "name_id" to the sTgt value
				sTgt = _tgtManager.createTGT(htTGTContext);

				// Create cookie if single sign-on is enabled
				// 20090617, Bauke: but not for forced_authenticate
				if (!bForcedAuthn && _configManager.isSingleSignOn())
					setASelectCookie(sTgt, sUserId, oHttpServletResponse);
			}
			else { // Update the old TGT
				_tgtManager.updateTGT(sOldTGT, htTGTContext);
				sTgt = sOldTGT;
			}
			
			// 20100210, Bauke: Present the Organization selection to the user
			// Leaves the Rid session in place, needed for the application url
			if (mustChooseOrg) {
				// The user must choose his organization
				String sSelectForm = org.aselect.server.utils.Utils.presentOrganizationChoice(_configManager, htSessionContext,
						sRid, (String)htTGTContext.get("language"), hUserOrganizations);
				oHttpServletResponse.setContentType("text/html");
				
				Tools.pauseSensorData(_configManager, _systemLogger, htSessionContext);
				//_sessionManager.updateSession(sRid, htSessionContext); // Write session
				// done by pauseSensorData(): _sessionManager.setUpdateSession(htSessionContext, _systemLogger);  // 20120403, Bauke: was updateSession()
				PrintWriter pwOut = oHttpServletResponse.getWriter();
				pwOut.println(sSelectForm);
				pwOut.close();
				return sTgt;
			}
			
			if (redirectToo) {
				// No organization selection, the tgt was just issued, report sensor data
				// remove the session and send the user to the application
				Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_tgt", sRid, htSessionContext, sTgt, true);
				_sessionManager.setDeleteSession(htSessionContext, _systemLogger);  // 20120403, Bauke: was killSession()
				
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + sAppUrl);
				String sLang = (String)htTGTContext.get("language");
				sendTgtRedirect(sAppUrl, sTgt, sRid, oHttpServletResponse, sLang);
			}
			return sTgt;
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

	// Looks very much like code in the ApplicationBrowserHandler
	/**
	 * Ensure session presence.
	 * 
	 * @param sUserId
	 *            the s user id
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param htSessionContext
	 *            the ht session context
	 * @param ssoSession
	 *            the sso session
	 */
	private void ensureSessionPresence(String sUserId, HashMap htTGTContext, HashMap htSessionContext,
			UserSsoSession ssoSession)
	{
		String sMethod = "ensureSessionPresence";

		String sIssuer = (String) htSessionContext.get("sp_issuer");
		if (sIssuer != null) {
			// SSO Sessions in effect
			htTGTContext.put("sp_issuer", sIssuer);
			if (ssoSession == null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "NEW SSO session for " + sUserId + " issuer=" + sIssuer);
				ssoSession = new UserSsoSession(sUserId, ""); // sTgt);
			}
			ServiceProvider sp = new ServiceProvider(sIssuer);
			ssoSession.addServiceProvider(sp);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "UPD SSO session " + ssoSession);
			htTGTContext.put("sso_session", ssoSession);
		}
	}

	/**
	 * Creates an error TGT and redirects the user. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new TGT containing the error code that occured during authentication. This error code will be returned
	 * to the web application during the verify_credentials API call. <br>
	 * <br>
	 * <b>Description:</b>
	 * <ul>
	 * <li>Creates a specific redirect url</li>
	 * <li>Set the error code</li>
	 * <li>Kills the old session</li>
	 * <li>Redirect user to redirect url</li>
	 * </ul>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The <i>SessionManager</i> must be initialized</li>
	 * <li>The <i>TGTManager</i> must be initialized</li>
	 * <li>The <i>ASelectSystemLogger</i> must be initialized</li>
	 * <li>The <i>CryptoEngine</i> must be initialized</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sRid
	 *            The request id (session key)
	 * @param htSessionContext
	 *            the session context, must be available from the caller
	 * @param sResultCode
	 *            The error code that occurred and will be returned to the webapplication application
	 * @param oHttpServletResponse
	 *            The servlet response that is used to redirect to
	 * @throws ASelectException
	 *             if an error page must be shown
	 */
	// 20120403, Bauke: added htSessionContext
	public void issueErrorTGTandRedirect(String sRid, HashMap htSessionContext, String sResultCode, HttpServletResponse oHttpServletResponse)
		throws ASelectException
	{
		String sMethod = "issueErrorTGT";
		SessionManager sessionManager = null;

		try {
			sessionManager = SessionManager.getHandle();
			TGTManager oTGTManager = TGTManager.getHandle();

			// 20120403, Bauke: session is passed as a parameter:
			// HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
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
			// 20120606, Bauke: connect sessions
			Utils.copyHashmapValue("usi", htTGTContext, htSessionContext);

			// We will now always put the client_ip in the TGT
			// There should always be a client_ip in the sessioncontext
			htTGTContext.put("client_ip", htSessionContext.get("client_ip"));
			String sAgent = (String) htSessionContext.get("user_agent");
			if (sAgent != null)
				htTGTContext.put("user_agent", sAgent);

			String sTgt = oTGTManager.createTGT(htTGTContext);
			// A tgt was just issued, report sensor data
			Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_tgt", sRid, htSessionContext, sTgt, true);
			sessionManager.setDeleteSession(htSessionContext, _systemLogger);  // 20120403, Bauke: was killSession
			String sLang = (String)htTGTContext.get("language");
			sendTgtRedirect(sAppUrl, sTgt, sRid, oHttpServletResponse, sLang);
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
	 * Redirect the user to the supplied application url with the given TGT and RID. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * <li>adds an & or ? to the application url</li> <li>encrypts the given tgt</li> <li>redirects the user</li> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li><i>sAppUrl</i> may not be <code>null</code></li> <li><i>sTgt</i> may not be <code>null</code></li> <li>
	 * <i>oHttpServletResponse</i> may not be <code>null</code></li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sAppUrl
	 *            application url to send the redirect to
	 * @param sTgt
	 *            TGT that will be sent with the redirect
	 * @param sRid
	 *            RID that will be sent with the redirect
	 * @param oHttpServletResponse
	 *            the user that will be redirected
	 * @throws ASelectException
	 *             if the user could not be redirected
	 */
	// 20100228, Bauke: added language to redirect
	public void sendTgtRedirect(String sAppUrl, String sTgt, String sRid, HttpServletResponse oHttpServletResponse, String sLanguage)
	throws ASelectException
	{
		String sMethod = "sendRedirect";
		StringBuffer sbRedirect = null;

		// NOTE: the SessionContext is already killed (therefore no pauseSensorData())
		try {
			// Remove aselect_specials from the URL, not intended for the application
			String sSpecials = Utils.getParameterValueFromUrl(sAppUrl, "aselect_specials");
			if (Utils.hasValue(sSpecials)) {
				sAppUrl = sAppUrl.replace("aselect_specials="+sSpecials, "");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "1="+sAppUrl);
				sAppUrl = sAppUrl.replace("&&", "&");
				if (sAppUrl.endsWith("&"))
					sAppUrl = sAppUrl.substring(0, sAppUrl.length()-1);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "2="+sAppUrl);
			}
			else 
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No aselect_specials");
			
			// Check whether the application url contains cgi parameters
			if (sAppUrl.indexOf("?") > 0)
				sAppUrl += "&";
			else
				sAppUrl += "?";

			String sEncryptedTgt = (sTgt == null) ? "" : _cryptoEngine.encryptTGT(Utils.hexStringToByteArray(sTgt));
			sbRedirect = new StringBuffer(sAppUrl);
			sbRedirect.append("aselect_credentials=").append(sEncryptedTgt);
			// Note, this rid's session could well have been deleted
			if (sRid !=null)
				sbRedirect.append("&rid=").append(sRid);
			sbRedirect.append("&a-select-server=").append(_sServerId);
			if (sLanguage != null)
				sbRedirect.append("&language=").append(sLanguage);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT to: " + sbRedirect);
			oHttpServletResponse.sendRedirect(sbRedirect.toString());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not send redirect to: "
					+ ((sbRedirect == null) ? "null" : sbRedirect.toString()), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Sets the A-Select Cookie (aselect_credentials) containing the A-Select credentials
	 * 
	 * @param sTgt
	 *            the tgt
	 * @param sUserId
	 *            the user id
	 * @param oHttpServletResponse
	 *            the http servlet response
	 * @throws ASelectException
	 */
	public void setASelectCookie(String sTgt, String sUserId, HttpServletResponse oHttpServletResponse)
	throws ASelectException
	{
		String sMethod = "setASelectCookie";
		try {
			// DONE(Bauke) uid and a-select-server do not have to be part of the credentials (martijn)
			/*
			 * StringBuffer sbCredentials = new StringBuffer("tgt="); sbCredentials.append(sTgt);
			 * sbCredentials.append("&uid="); sbCredentials.append(sUserId); sbCredentials.append("&a-select-server=");
			 * sbCredentials.append(_sServerId);
			 */
			// Bauke 20080617 only store tgt value from now on
			String sCookieDomain = _configManager.getCookieDomain();
			HandlerTools.putCookieValue(oHttpServletResponse, "aselect_credentials", sTgt, sCookieDomain, null, -1, _systemLogger);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create an A-Select cookie for user: " + sUserId, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Compare old and new TGTs.
	 * Verifies authsp_level and sel_level.
	 * 
	 * @param htOldTGTContext
	 *            the ht old tgt context
	 * @param htNewTGTContext
	 *            the ht new tgt context
	 * @return the hash map
	 */
	private HashMap compareOldTGTLevels(HashMap htOldTGTContext, HashMap htNewTGTContext)
	{
		HashMap htReturn = new HashMap();
		// verify authsp_level (level specified in the Auhtsp configuration)
		String sOldValue = (String) htOldTGTContext.get("authsp_level");
		String sNewValue = (String) htNewTGTContext.get("authsp_level");
		if (sOldValue != null && sNewValue != null) {
			int iOldAuthSPLevel = new Integer(sOldValue).intValue();
			int iNewAuthSPLevel = new Integer(sNewValue).intValue();
			if (iOldAuthSPLevel > iNewAuthSPLevel) {
				// Overwrite level, if user already has a ticket with a higher level
				htReturn.put("authsp_level", sOldValue);
			}
		}
		// 20100321, Bauke: Added sel_level (level chosen by the user)
		sOldValue = (String) htOldTGTContext.get("sel_level");
		sNewValue = (String) htNewTGTContext.get("sel_level");
		if (sOldValue != null && sNewValue != null) {
			int iOldAuthSPLevel = new Integer(sOldValue).intValue();
			int iNewAuthSPLevel = new Integer(sNewValue).intValue();
			if (iOldAuthSPLevel > iNewAuthSPLevel) {
				// Overwrite level, if user already has a ticket with a higher level
				htReturn.put("sel_level", sOldValue);
			}
		}
		return htReturn;
	}
}