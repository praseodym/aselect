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
 * $Id: TGTIssuer.java,v 1.37.8.2 2006/12/14 14:18:30 maarten Exp $ 
 * 
 * Changelog:
 * $Log: TGTIssuer.java,v $
 * Revision 1.37.8.2  2006/12/14 14:18:30  maarten
 * Updated ARP
 *
 * Revision 1.37.8.1  2006/11/22 09:25:42  maarten
 * Updated version
 * Attribute gathering by home_organization added
 *
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

package org.aselect.server.tgt.saml20;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.saml20.common.SessionKeys;
import org.aselect.server.request.handler.saml20.common.Utils;
import org.aselect.server.request.handler.saml20.idp.authentication.SAML20ArtifactManager;
import org.aselect.server.request.handler.saml20.idp.authentication.SAML20ArtifactManagerLocator;
import org.aselect.server.request.handler.saml20.idp.authentication.SSOSessionManager;
import org.aselect.server.request.handler.saml20.idp.authentication.ServiceProvider;
import org.aselect.server.request.handler.saml20.idp.authentication.UserSsoSession;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;

/**
 * Issues ASelect TGT's. <br>
 * <br>
 * <b>Description:</b><br>
 * Provides methods to issue Ticket Granting Tickets in A-Select. <br>
 * <br>
 * 
 * @author Atos Origin
 * 
 */
public class TGTIssuer
{
	private static final String MODULE = "saml20.TGTIssuer";

	private ASelectConfigManager _configManager;

	private ASelectSystemLogger _systemLogger;

	private String _sServerId;

	private SessionManager _sessionManager;

	private TGTManager _tgtManager;

	public static final String COOKIE_NAME = "aselect_credentials";

	/**
	 * The default constructor.
	 * 
	 * @param sServerId
	 *                The A-Select server ID.
	 */
	public TGTIssuer(String sServerId) {
		_systemLogger = ASelectSystemLogger.getHandle();
		_configManager = ASelectConfigManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_tgtManager = TGTManager.getHandle();
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
	 * <b>Concurrency issues:</b> <br> - <br>
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
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param sRid
	 *                The request id (session key)
	 * @param sAuthSP
	 *                The AuthSP which the used to authenticate
	 * @param htRemoteAttributes
	 *                <code>Hashtable</code> containing additional TGT
	 *                information
	 * @param oHttpServletResponse
	 *                The servlet response that is used to redirect to
	 * @param sOldTGT
	 *                The aselect_credentials_tgt that is already set as a
	 *                cookie at the user (can be null if not present)
	 * @throws ASelectException
	 *                 if an error page must be shown
	 */
	@SuppressWarnings("unchecked")
	public void issueCrossTGT(String sRid, String sAuthSP, Hashtable htRemoteAttributes,
			HttpServletResponse oHttpServletResponse, String sOldTGT)
		throws ASelectException
	{
		// A 'cross TGT' is issued if this Server is acting as 'local'
		// A-Select Server. The user was authenticated at another
		// (remote) A-Select Server.
		String sMethod = "issueCrossTGT()";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		String sLevel = null;
		String sTgt = null;
		String sArpTarget = null;

		try {
			Hashtable htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				StringBuffer sbFailed = new StringBuffer("No session found, session expired: ");
				sbFailed.append(sRid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}

			// String sAppUrl = (String)htSessionContext.get("app_url");
			String sAppUrl = (String) htSessionContext.get("assertion_consumer_service_url");
			Integer intAppLevel = (Integer) htSessionContext.get("level");
			String sAppId = (String) htSessionContext.get("app_id");
			String sRemoteOrganization = (String) htSessionContext.get("remote_organization");

			// The following parameters are retrieved from the 'remote'
			// Server.
			String sUserId = (String) htRemoteAttributes.get("uid");
			String sUserOrganization = (String) htRemoteAttributes.get("organization");
			sLevel = (String) htRemoteAttributes.get("betrouwbaarheidsniveau");
			sAuthSP = (String) htRemoteAttributes.get("authsp");
			// Attributes that where released by the 'remote' A-Select
			// Server
			// will be stored in the TGT.
			// This server might have configured a 'TGTAttributeRequestor'
			// to
			// release these 'remote' attributes to the application.
			String sRemoteAttribs = (String) htRemoteAttributes.get("attributes");
			sArpTarget = (String) htSessionContext.get("arp_target");

			// TODO Check if double encode is needed (Martijn)
			if (sUserId != null) {
				String sEncodedUserId = URLEncoder.encode(sUserId, "UTF-8");
				sEncodedUserId = URLEncoder.encode(sEncodedUserId, "UTF-8");
			}
			String sLocalOrg = null;
			if (htSessionContext.get("remote_session") != null) {
				// A 'local' A-Select Server forwarded the authentication
				// request. This means that this Server is acting as
				// a proxy server.
				// The application in not known by this A-Select Server.
				sAppUrl = (String) htSessionContext.get("local_as_url");
				// The 'organization' in a TGT always contains the organization
				// where the authentication was done.
				// The 'local_organization' is needed e.g. attribute release
				// policies
				sLocalOrg = (String) htSessionContext.get("local_organization");
				StringBuffer sbAppID = new StringBuffer("[unknown@");
				sbAppID.append(sLocalOrg);
				sbAppID.append("]");

				sAppId = sbAppID.toString();
			}
			Hashtable htTGTContext = new Hashtable();
			htTGTContext.put("uid", sUserId);
			htTGTContext.put("organization", sUserOrganization);
			htTGTContext.put("betrouwbaarheidsniveau", sLevel);
			htTGTContext.put("authsp", sAuthSP);
			htTGTContext.put("app_level", intAppLevel.toString());
			htTGTContext.put("app_id", sAppId);
			htTGTContext.put("rid", sRid);

			// If the 'organization' where the user was authenticated does
			// not equal
			// the 'remote' server I was talking to, this 'remote' server
			// also
			// forwarded the request which means the 'remote' servers acts
			// as proxy.
			// This server might not even know the user's organization and
			// stores the
			// 'proxy_organization' in the TGT.
			if (sArpTarget != null)
				htTGTContext.put("arp_target", sArpTarget);
			if (sRemoteOrganization != null && !sRemoteOrganization.equals(sUserOrganization))
				htTGTContext.put("proxy_organization", sRemoteOrganization);
			if (sRemoteAttribs != null)
				htTGTContext.put("remote_attributes", sRemoteAttribs);
			if (sLocalOrg != null)
				htTGTContext.put("local_organization", sLocalOrg);

			Hashtable htOldTGTContext = null;
			if (sOldTGT != null) {
				htOldTGTContext = _tgtManager.getTGT(sOldTGT);
				if (htOldTGTContext != null) {
					Hashtable htUpdate = verifyTGT(htOldTGTContext, htTGTContext);
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

				// create cookie if single sign-on is enabled
				if (_configManager.isSingleSignOn())
					setASelectCookie(sTgt, sUserId, oHttpServletResponse);
			}
			sendSAMLArtifactRedirect(sAppUrl, sRid, htSessionContext, sTgt, htTGTContext, oHttpServletResponse);

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
	 * <b>Concurrency issues:</b> <br> - <br>
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
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param sRid
	 *                The request id (session key)
	 * @param sAuthSP
	 *                The AuthSP which the used to authenticate
	 * @param htAdditional
	 *                <code>Hashtable</code> containing additional TGT
	 *                information
	 * @param oHttpServletResponse
	 *                The servlet response that is used to redirect to
	 * @param sOldTGT
	 *                The aselect_credentials_tgt that is already set as a
	 *                cookie at the user (can be null if not exists)
	 * @throws ASelectException
	 *                 if an error page must be shown
	 */
	@SuppressWarnings("unchecked")
	public void issueTGT(String sRid, String sAuthSP, Hashtable htAdditional, HttpServletResponse oHttpServletResponse,
			String sOldTGT)
		throws ASelectException
	{
		String sMethod = "issueTGT()";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		String sLevel = null;
		String sTgt = null;
		// String sArpTarget = null; TODO Volgens mij gebruiken we dit niet, en
		// kan dus weg 16-10-07 HW

		try {
			Hashtable htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				StringBuffer sbFailed = new StringBuffer("No session found, session expired: ");
				sbFailed.append(sRid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}

			// sArpTarget = (String) htSessionContext.get("arp_target");
			// TODO Volgens mij gebruiken we dit niet, en kan dus weg
			// 16-10-07 HW
			// String sAppUrl = (String)htSessionContext.get("app_url");
			String sAppUrl = (String) htSessionContext.get("assertion_consumer_service_url");
			String sUserId = (String) htSessionContext.get("user_id");
			String sOrganization = (String) htSessionContext.get("organization");
			String sAppId = (String) htSessionContext.get("app_id");
			Hashtable htAllowedAuthsps = (Hashtable) htSessionContext.get("allowed_user_authsps");
			Integer intAppLevel = (Integer) htSessionContext.get("level");
			// Vector vSSOGroups = (Vector)
			// htSessionContext.get("sso_groups"); TODO Volgens mij
			// gebruiken we dit niet, en kan dus weg 16-10-07 HW
			sLevel = (String) htSessionContext.get("assigned_betrouwbaarheidsniveau");
			/*
			 * sLevel =
			 * (_authSPHandlerManager.getLevel(sAuthSP)).toString(); try {
			 * Object oAuthSPSSection = _configManager.getSection(null,
			 * "authsps"); Object oAuthSP =
			 * _configManager.getSection(oAuthSPSSection, "authsp", "id=" +
			 * sAuthSP); sLevel = _configManager.getParam(oAuthSP, "level"); }
			 * catch (ASelectConfigException e) { //It is a "priviliged
			 * authsp" -> get level from context sLevel =
			 * ((Integer)htSessionContext.get("authsp_level")).toString(); }
			 */
			// TODO Check if double encode is needed (Martijn)
			String sEncodedUserId = URLEncoder.encode(sUserId, "UTF-8");
			sEncodedUserId = URLEncoder.encode(sEncodedUserId, "UTF-8");

			// TODO Volgens mij gebruiken we dit niet, en kan dus weg
			// 16-10-07 HW
			/*
			 * >>>>>>>>>>>>>>>>>>> String sLocalOrg = null; if
			 * (htSessionContext.get("remote_session") != null) { // A
			 * 'local' A-Select Server forwarded the authentication //
			 * request. // The application in not known by this A-Select
			 * Server. sAppUrl = (String)
			 * htSessionContext.get("local_as_url"); // The 'organization'
			 * in a TGT always contains the organization // where the
			 * authentication was done. // The 'local_organization' is
			 * needed e.g. attribute release // policies sLocalOrg =
			 * (String) htSessionContext.get("local_organization");
			 * StringBuffer sbAppID = new StringBuffer("[unknown@");
			 * sbAppID.append(sLocalOrg); sbAppID.append("]");
			 * 
			 * sAppId = sbAppID.toString(); } <<<<<<<<<<<<<<<<<<<<<<<<<<
			 */

			Hashtable htTGTContext = new Hashtable();
			htTGTContext.put("uid", sUserId);
			htTGTContext.put("organization", sOrganization);
			// htTGTContext.put("authsp_level", sLevel);
			htTGTContext.put("betrouwbaarheidsniveau", sLevel);
			htTGTContext.put("authsp", sAuthSP);
			htTGTContext.put("app_level", intAppLevel.toString());
			htTGTContext.put("app_id", sAppId);
			htTGTContext.put("rid", sRid);
			// if (sArpTarget != null)
			// htTGTContext.put("arp_target", sArpTarget); TODO Volgens mij
			// gebruiken we dit niet, en kan dus weg 16-10-07 HW
			if (htAllowedAuthsps != null)
				htTGTContext.put("allowed_user_authsps", htAllowedAuthsps);
			// if (sLocalOrg != null)
			// htTGTContext.put("local_organization", sLocalOrg); TODO
			// Volgens mij gebruiken we dit niet, en kan dus weg 16-10-07 HW
			// if (vSSOGroups != null)
			// htTGTContext.put("sso_groups", vSSOGroups); TODO Volgens mij
			// gebruiken we dit niet, en kan dus weg 16-10-07 HW

			// overwrite or set additional properties in the newly created
			// tgt context
			if (htAdditional != null)
				htTGTContext.putAll(htAdditional);

			Hashtable htOldTGTContext = null;
			String sOldUser = null;
			/* >>OUA-9 */
			boolean updated = false;
			/* OUA-9<< */
			if (sOldTGT != null) {
				htOldTGTContext = _tgtManager.getTGT(sOldTGT);
				if (htOldTGTContext != null) {
					sOldUser = (String)htOldTGTContext.get("uid");
					Hashtable htUpdate = verifyTGT(htOldTGTContext, htTGTContext);
					if (!htUpdate.isEmpty()) {
						htTGTContext.putAll(htUpdate);
						/* >>OUA-9 */
						updated = true;
						/* OUA-9<< */
					}

					htTGTContext.put("rid", sRid);
					_tgtManager.updateTGT(sOldTGT, htTGTContext);
					sTgt = sOldTGT;
				}
			}

			// Create a new TGT, because there is no old TGT
			if (htOldTGTContext == null) {
				sTgt = _tgtManager.createTGT(htTGTContext);

				// create cookie if single sign-on is enabled
				if (_configManager.isSingleSignOn()) {
					setASelectCookie(sTgt, sUserId, oHttpServletResponse);
					SSOSessionManager ssoSessionManager = SSOSessionManager.getHandle();

					String sUid = (String) htAdditional.get("uid");
					UserSsoSession session = new UserSsoSession(sUid, sTgt);
					String authSpCredentials = (String) htAdditional.get("asp_credentials");
					ServiceProvider sp = new ServiceProvider();
					String issuer = (String) htSessionContext.get("sp_issuer");
					sp.setServiceProviderUrl(issuer);
					sp.setLastSessionSync(new java.util.Date().getTime());
					session.addServiceProvider(sp);
					session.setAspCredentials(authSpCredentials);
					ssoSessionManager.putSsoSession(session);
				}
			}

			/* >>OUA-9 */
			if (updated) {
				setASelectCookie(sTgt, sUserId, oHttpServletResponse);
				SSOSessionManager ssoSessionManager = SSOSessionManager.getHandle();

				String sUid = (String) htAdditional.get("uid");
				if (sOldUser != null && !sOldUser.equals(sUid)) {
					ssoSessionManager.remove(sOldUser);
				}
				UserSsoSession session = new UserSsoSession(sUid, sTgt);
				String authSpCredentials = (String) htAdditional.get("asp_credentials");
				ServiceProvider sp = new ServiceProvider();
				sp.setServiceProviderUrl(sAppUrl);
				sp.setLastSessionSync(new java.util.Date().getTime());
				session.addServiceProvider(sp);
				session.setAspCredentials(authSpCredentials);
				ssoSessionManager.putSsoSession(session);
			}
			/* OUA-9<< */

			_systemLogger.log(Level.INFO, MODULE, sMethod, "IDP TGT: " + sTgt);
			Hashtable<String, String> htTGT = _tgtManager.getTGT(sTgt);

			Enumeration<String> keys = htTGT.keys();
			while (keys.hasMoreElements()) {
				String key = keys.nextElement();
				Object oValue = htTGT.get(key);
				String sValue = "";
				if (oValue instanceof String)
					sValue = (String) oValue;

				_systemLogger.log(Level.INFO, MODULE, sMethod, "     " + key + " = " + sValue);
			}

			sendSAMLArtifactRedirect(sAppUrl, sRid, htSessionContext, sTgt, htTGTContext, oHttpServletResponse);

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
	 * Creates an error TGT and redirects the user. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new TGT containing the error code that occured during
	 * authentication. This error code will be returned to the web
	 * application during the verify_credentials API call. <br>
	 * <br>
	 * <b>Description:</b>
	 * <ul>
	 * <li>Creates a specific redirect url</li>
	 * <li>Set the error code</li>
	 * <li>Kills the old session</li>
	 * <li>Redirect user to redirect url</li>
	 * </ul>
	 * 
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The <i>SessionManager</i> must be initialized</li>
	 * <li>The <i>TGTManager</i> must be initialized</li>
	 * <li>The <i>ASelectSystemLogger</i> must be initialized</li>
	 * <li>The <i>CryptoEngine</i> must be initialized</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param sRid
	 *                The request id (session key)
	 * @param sResultCode
	 *                The error code that occurred and will be returned to
	 *                the webapplication application
	 * @param oHttpServletResponse
	 *                The servlet response that is used to redirect to
	 * @throws ASelectException
	 *                 if an error page must be shown
	 */
	@SuppressWarnings("unchecked")
	public void issueErrorTGT(String sRid, String sResultCode, HttpServletResponse oHttpServletResponse)
		throws ASelectException
	{
		String sMethod = "issueErrorTGT()";
		SessionManager sessionManager = null;

		try {
			sessionManager = SessionManager.getHandle();
			TGTManager oTGTManager = TGTManager.getHandle();

			Hashtable htSessionContext = sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				StringBuffer sbFailed = new StringBuffer("No session found, session expired: ");
				sbFailed.append(sRid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}

			// String sAppUrl = (String)htSessionContext.get("app_url");
			String sAppUrl = (String) htSessionContext.get("assertion_consumer_service_url");

			if (htSessionContext.get("remote_session") != null) {
				// If the request was forwarded by a local A-Select Server
				// this server is in fact the application where to redirect to.
				String sLocalASUrl = (String) htSessionContext.get("local_as_url");
				sAppUrl = sLocalASUrl;
			}

			Hashtable htTGTContext = new Hashtable();

			// Error TGT only contains rid and result_code
			String sAppId = (String) htSessionContext.get("app_id");
			if (sAppId != null)
				htTGTContext.put("app_id", sAppId);
			String sLocalOrg = (String) htSessionContext.get("local_organization");
			if (sLocalOrg != null)
				htTGTContext.put("local_organization", sLocalOrg);
			htTGTContext.put("rid", sRid);
			htTGTContext.put("result_code", sResultCode);
			String sTgt = oTGTManager.createTGT(htTGTContext);

			sendSAMLArtifactRedirect(sAppUrl, sRid, htSessionContext, sTgt, htTGTContext, oHttpServletResponse);

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

	@SuppressWarnings("unchecked")
	public void sendSAMLArtifactRedirect(String sAppUrl, String sRid, Hashtable htSessionContext,
			String sTgt, Hashtable htTGTContext, HttpServletResponse oHttpServletResponse)
		throws ASelectException
	{
		String sMethod = "sendSAMLArtifactRedirect()";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		try {
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException e) {
			_systemLogger
					.log(Level.WARNING, MODULE, sMethod, "There is a problem initializing the OpenSAML library", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		String sRedirectUrl = "";
		try {
			String sServerUrl = (String) htSessionContext.get("server_url");
			String sAuthspLevel = (String) htTGTContext.get("betrouwbaarheidsniveau");
			String sUid = (String) htTGTContext.get("uid");

			XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

			XMLObjectBuilder stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);
			XSString attributeAuthspLevelValue = (XSString) stringBuilder.buildObject(
					AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
			attributeAuthspLevelValue.setValue(sAuthspLevel);

			SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory
					.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
			Attribute attributeAuthspLevel = attributeBuilder.buildObject();
			attributeAuthspLevel.setName("betrouwbaarheidsniveau");
			attributeAuthspLevel.getAttributeValues().add(attributeAuthspLevelValue);

			XSString attributeUidValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
					XSString.TYPE_NAME);
			attributeUidValue.setValue(sUid);

			Attribute attributeUid = attributeBuilder.buildObject();
			attributeUid.setName("uid");
			attributeUid.getAttributeValues().add(attributeUidValue);

			SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) builderFactory
					.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
			AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
			attributeStatement.getAttributes().add(attributeUid);
			attributeStatement.getAttributes().add(attributeAuthspLevel);

			SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
					.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
			String sAutnContextClassRefURI = org.aselect.server.request.handler.saml20.common.Utils
					.convertLevelToAuthnContextClassRefURI(sAuthspLevel, _systemLogger, MODULE);
			authnContextClassRef.setAuthnContextClassRef(sAutnContextClassRefURI);

			SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory
					.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
			AuthnContext authnContext = authnContextBuilder.buildObject();
			authnContext.setAuthnContextClassRef(authnContextClassRef);

			SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory
					.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
			AuthnStatement authnStatement = authnStatementBuilder.buildObject();
			authnStatement.setAuthnInstant(new DateTime());
			authnStatement.setAuthnContext(authnContext);

			SAMLObjectBuilder<Audience> audienceBuilder = (SAMLObjectBuilder<Audience>) builderFactory
					.getBuilder(Audience.DEFAULT_ELEMENT_NAME);
			Audience audience = audienceBuilder.buildObject();
			audience.setAudienceURI((String) htSessionContext.get("sp_issuer"));

			SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory
					.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
			AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
			audienceRestriction.getAudiences().add(audience);

			SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) builderFactory
					.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
			Conditions conditions = conditionsBuilder.buildObject();
			// TODO is dit plus 1 uur? en moet dit configurabel zijn?
			conditions.setNotOnOrAfter(new DateTime().plusHours(1));
			// TODO is dit min 5 min? en moet dit configurabel zijn?
			conditions.setNotBefore(new DateTime().minusMinutes(5));
			conditions.getAudienceRestrictions().add(audienceRestriction);

			SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
					.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
			SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
			// TODO is dit plus 1 uur? en moet dit configurabel zijn?
			subjectConfirmationData.setNotOnOrAfter(new DateTime().plusHours(1));
			subjectConfirmationData.setRecipient((String) htSessionContext.get("sp_assert_url"));

			// Bauke: added for OpenSSO 20080329
			String sSPRid = (String) htSessionContext.get("sp_rid");
			subjectConfirmationData.setInResponseTo(sSPRid);

			SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory
					.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
			SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
			// TODO is deze constante ergens vandaan te halen?
			subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
			subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

			SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) builderFactory
					.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
			NameID nameID = nameIDBuilder.buildObject();
			nameID.setFormat(NameIDType.PERSISTENT);
			nameID.setNameQualifier(sServerUrl);
			nameID.setValue(/*sTgt);  // REPLACES: */ (String)htTGTContext.get("uid"));  // NameID setting!!
			_systemLogger.log(Level.INFO, MODULE, sMethod, "nameID="+Utils.firstPartOf(nameID.getValue()));
			SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
					.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
			Subject subject = subjectBuilder.buildObject();
			subject.setNameID(nameID);
			subject.getSubjectConfirmations().add(subjectConfirmation);

			SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
			assertionIssuer.setFormat(NameIDType.ENTITY);
			assertionIssuer.setValue(sServerUrl);

			SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
					.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
			Assertion assertion = assertionBuilder.buildObject();

			assertion.setID(org.aselect.server.request.handler.saml20.common.Utils.generateIdentifier(_systemLogger,
					MODULE));
			assertion.setIssueInstant(new DateTime());
			assertion.setVersion(SAMLVersion.VERSION_20);
			assertion.setIssuer(assertionIssuer);
			assertion.setSubject(subject);
			assertion.setConditions(conditions);
			assertion.getAuthnStatements().add(authnStatement);
			assertion.getAttributeStatements().add(attributeStatement);

			SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
					.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
			StatusCode statusCode = statusCodeBuilder.buildObject();
			statusCode.setValue(StatusCode.SUCCESS_URI);

			SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
					.getBuilder(Status.DEFAULT_ELEMENT_NAME);
			Status status = statusBuilder.buildObject();
			status.setStatusCode(statusCode);

			SAMLObjectBuilder<Issuer> responseIssuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer responseIssuer = responseIssuerBuilder.buildObject();
			responseIssuer.setFormat(NameIDType.ENTITY);
			responseIssuer.setValue(sServerUrl);

			SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory
					.getBuilder(Response.DEFAULT_ELEMENT_NAME);
			Response response = responseBuilder.buildObject();

			response.setInResponseTo(sSPRid);
			response.setID(sRid);
			response.setIssueInstant(new DateTime());
			response.setVersion(SAMLVersion.VERSION_20);
			response.setStatus(status);
			response.setIssuer(responseIssuer);
			response.getAssertions().add(assertion);

			SAML20ArtifactManager artifactManager = SAML20ArtifactManagerLocator.getArtifactManager();
			String sArtifact = artifactManager.buildArtifact(response, (String) htSessionContext.get("server_url"),
					(String) htTGTContext.get("rid"));
			artifactManager.sendArtifact(sArtifact, response, sAppUrl, oHttpServletResponse);

		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"There is a problem with sending the redirect message to : '" + sRedirectUrl + "'", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/*
	 * sets the A-Select Cookie (aselect_credentials) containing the
	 * A-Select credentials
	 */
	private void setASelectCookie(String sTgt, String sUserId, HttpServletResponse oHttpServletResponse)
		throws ASelectException
	{
		String sMethod = "setASelectCookie()";
		try {
			// TODO uid and a-select-server doesn't have to be part of the
			// credentials (martijn)
			StringBuffer sbCredentials = new StringBuffer("tgt=");
			sbCredentials.append(sTgt);
			sbCredentials.append("&uid=");
			sbCredentials.append(sUserId);
			sbCredentials.append("&a-select-server=");
			sbCredentials.append(_sServerId);

			Cookie oCredentialsCookie = new Cookie("aselect_credentials", sbCredentials.toString());

			String sCookieDomain = _configManager.getCookieDomain();
			if (sCookieDomain != null)
				oCredentialsCookie.setDomain(sCookieDomain);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Add Aselect Cookie=" + oCredentialsCookie.getName()
					+ " Domain=" + sCookieDomain + " Path=" + oCredentialsCookie.getPath());
			oHttpServletResponse.addCookie(oCredentialsCookie);
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not create an A-Select cookie for user: ");
			sbError.append(sUserId);
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/*
	 * verifies the old tgt with new tgt context verifies the following
	 * items: - app_level
	 */
	@SuppressWarnings("unchecked")
	private Hashtable verifyTGT(Hashtable htOldTGTContext, Hashtable htNewTGTContext)
	{
		Hashtable htReturn = new Hashtable();
		// check if the user already has a ticket
		// only if the application requires forced this is useful

		// verify betrouwbaarheidsniveau
		String sOldAuthSPLevel = (String) htOldTGTContext.get("betrouwbaarheidsniveau");
		String sNewAuthSPLevel = (String) htNewTGTContext.get("betrouwbaarheidsniveau");
		if (sOldAuthSPLevel != null && sNewAuthSPLevel != null) {
			int iOldAuthSPLevel = new Integer(sOldAuthSPLevel).intValue();
			int iNewAuthSPLevel = new Integer(sNewAuthSPLevel).intValue();
			if (iOldAuthSPLevel > iNewAuthSPLevel) {
				// overwrite level, if user already has a ticket with a higher level
				htReturn.put("betrouwbaarheidsniveau", sOldAuthSPLevel);
			}
		}
		/* >>OUA-9 */
		String sOldAuthSPUid = (String) htOldTGTContext.get("uid");
		String sNewAuthSPUid = (String) htNewTGTContext.get("uid");
		if (!sOldAuthSPUid.equals(sNewAuthSPUid)) {
			htReturn.put("uid", sNewAuthSPUid);
		}
		/* OUA-9<< */

		return htReturn;
	}
}