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
 * $Id: ApplicationBrowserHandler.java,v 1.19 2006/05/03 10:10:45 tom Exp $ 
 * 
 * Changelog:
 * $Log: ApplicationBrowserHandler.java,v $
 * Revision 1.19  2006/05/03 10:10:45  tom
 * Removed Javadoc version
 *
 * Revision 1.18  2006/04/26 09:17:32  leon
 * fixed bug #202
 *
 * Revision 1.17  2006/04/07 07:35:36  leon
 * javadoc added and small bugfix
 *
 * Revision 1.16  2006/04/06 08:43:18  leon
 * removed function
 *
 * Revision 1.15  2006/04/05 12:56:43  leon
 * *** empty log message ***
 *
 * Revision 1.14  2006/03/21 07:35:03  leon
 * Code cleaning
 *
 * Revision 1.13  2006/03/20 12:27:01  martijn
 * level is stored in session as an Integer object
 *
 * Revision 1.12  2006/03/20 11:27:57  martijn
 * updateTemplate() has been moved to ConfigManager
 *
 * Revision 1.11  2006/03/20 10:12:21  leon
 * function renamed
 *
 * Revision 1.10  2006/03/20 10:09:12  leon
 * moved direct login to handler
 *
 * Revision 1.9  2006/03/16 14:47:41  martijn
 * fixed bug in calling updateTemplate in handleLogout
 *
 * Revision 1.8  2006/03/16 10:46:29  martijn
 * added support for showing optional application info in user info page
 *
 * Revision 1.7  2006/03/16 10:34:24  martijn
 * added support for showwing optional application info in html templates
 *
 * Revision 1.6  2006/03/16 08:18:18  leon
 * extra functions for direct login handling
 *
 * Revision 1.5  2006/03/14 11:24:44  martijn
 * fixed support for optional application info tags in login1 and login2
 *
 * Revision 1.4  2006/03/09 12:37:33  jeroen
 * Adaptations for NiceName (partly implemented)
 *
 * Revision 1.3  2006/03/07 14:30:33  leon
 * some redundant code removed.
 *
 * Revision 1.2  2006/03/07 14:18:04  leon
 * If user not is found in the local UDB it is now possible to swich to cross mode
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.4  2006/02/08 08:07:34  martijn
 * getSession() renamed to getSessionContext()
 *
 * Revision 1.3  2006/02/02 10:26:56  martijn
 * changes after refactor
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
 * Revision 1.53  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.52  2005/09/07 08:28:51  erwin
 * Fixed problem with popup configuration handling (bug #77)
 *
 * Revision 1.51  2005/05/04 14:22:06  martijn
 * updates logging
 *
 * Revision 1.50  2005/05/04 09:34:59  martijn
 * bugfixes, improved logging
 *
 * Revision 1.49  2005/05/03 07:38:02  erwin
 * Added UID check in create TGT
 *
 * Revision 1.48  2005/04/28 09:11:30  erwin
 * Reformatted if/else structure in handleLogin1
 *
 * Revision 1.47  2005/04/27 14:17:14  erwin
 * - Added URL decoding for uid
 * - Added AuthSP level check
 *
 * Revision 1.46  2005/04/27 07:07:32  erwin
 * log level changed for "failed to retrieve..."
 *
 * Revision 1.45  2005/04/15 14:04:31  peter
 * javadoc and comment
 *
 * Revision 1.44  2005/04/12 11:21:44  peter
 * undo last commit (1.43)
 *
 * Revision 1.43  2005/04/12 10:13:44  peter
 * fixed sso_groups bug
 *
 * Revision 1.42  2005/04/11 14:56:31  peter
 * code restyle
 *
 * Revision 1.41  2005/04/11 12:53:18  peter
 * Solved cross issues:
 * - Handle logout now redirects to remote A-Select Server in case of cross.
 * - Logged out form is now static and has no dynamic [message] tag anymore.
 *
 * Revision 1.40  2005/04/11 09:36:31  erwin
 * Added useRemoteSigning() as check.
 *
 * Revision 1.39  2005/04/11 09:24:24  remco
 * also implemented forced_logon protocol change in cross (untested)
 *
 * Revision 1.38  2005/04/11 08:57:29  erwin
 * Added local A-Select signing support for cross A-Select.
 *
 * Revision 1.37  2005/04/08 12:41:12  martijn
 * fixed todo's
 *
 * Revision 1.36  2005/04/08 08:06:08  peter
 * if user already has a TGT check if an optional requested uid equals the one in the TGT
 *
 * Revision 1.35  2005/04/08 07:56:13  erwin
 * Added localisation support for cross A-Select.
 *
 * Revision 1.34  2005/04/07 14:39:45  peter
 * added forced_authenticate; redesign of login1 in case of valid TGT
 *
 * Revision 1.33  2005/04/07 12:14:34  martijn
 * added single sign-on groups
 *
 * Revision 1.32  2005/04/07 07:37:38  peter
 * forced logon for cross aselect
 *
 * Revision 1.31  2005/04/07 06:37:12  erwin
 * Renamed "attribute" -> "param" to be compatible with configManager.
 *
 * Revision 1.30  2005/04/06 11:40:28  peter
 * Added support for optional uid in request authenticate
 *
 * Revision 1.29  2005/04/05 15:25:08  martijn
 * TGTIssuer.issueTGT() now only needs an optional old tgt and the printwriter isn't needed anymore
 *
 * Revision 1.28  2005/04/05 13:12:29  martijn
 * save old_tgt if forced authenticate and user has already a tgt
 *
 * Revision 1.27  2005/04/05 11:30:44  martijn
 * added todo
 *
 * Revision 1.26  2005/04/05 09:11:15  peter
 * added cross proxy logica in showuserinfo (logout page)
 *
 * Revision 1.25  2005/04/05 08:17:03  martijn
 * added todo for handleIPLogin1
 *
 * Revision 1.24  2005/04/05 07:50:11  martijn
 * added forced_authenticate
 *
 * Revision 1.23  2005/04/04 12:33:34  erwin
 * Added a todo for error handling.
 *
 * Revision 1.22  2005/04/01 14:26:58  peter
 * cross aselect redesign
 *
 * Revision 1.21  2005/03/24 13:23:45  erwin
 * Improved URL encoding/decoding
 * (this is handled in communication package for API calls)
 *
 * Revision 1.20  2005/03/22 15:19:22  peter
 * handleCrossLogin makes use of the CrossSelectorManager
 *
 * Revision 1.18  2005/03/18 13:43:35  remco
 * made credentials shorter (base64 encoding instead of hex representation)
 *
 * Revision 1.17  2005/03/17 15:27:58  tom
 * Fixed javadoc
 *
 * Revision 1.16  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.15  2005/03/17 13:42:34  tom
 * Minor code style fix
 *
 * Revision 1.14  2005/03/17 07:58:43  erwin
 * The A-Select server ID is now set with the constructor,
 * instead of reading it from the configuration.
 *
 * Revision 1.13  2005/03/16 13:30:05  erwin
 * Application manager was null and protected, this is fixed.
 *
 * Revision 1.12  2005/03/16 12:52:10  tom
 * - Fixed javadoc
 *
 * Revision 1.11  2005/03/16 12:50:50  martijn
 * changed some todo's to fixme's
 *
 * Revision 1.10  2005/03/16 10:00:07  peter
 * Fixed Cross TGT if it already exists.
 *
 * Revision 1.9  2005/03/16 09:28:03  martijn
 * The config item 'cookie_domain' will now only be retrieved from the config at startup and not every time the ticket is issued.
 *
 * Revision 1.8  2005/03/15 16:04:10  erwin
 * Added TODo
 *
 * Revision 1.7  2005/03/15 15:29:04  martijn
 * renamed special authsp to privileged application
 *
 * Revision 1.6  2005/03/15 10:52:01  tom
 * Fixed import errors
 *
 * Revision 1.5  2005/03/15 10:51:41  tom
 * - Added new Abstract class functionality
 * - Added Javadoc
 *
 * Revision 1.4  2005/03/15 10:10:36  tom
 * Small Javadoc changes
 *
 * Revision 1.3  2005/03/15 10:06:52  tom
 * Added JavaDoc and Error Handling
 *
 * Revision 1.2  2005/03/15 08:29:56  tom
 * Added new tgt_exp_time handling
 *
 * Revision 1.1  2005/03/15 08:21:19  tom
 * Redesign of request handling
 *
 * Revision 1.18  2005/03/14 10:17:21  tom
 * Changed return parameters in cancel to match new error request
 *
 * Revision 1.17  2005/03/14 10:05:34  martijn
 * config item 'select_form_show_always' is renamed to 'always_show_select_form' in 'authsps' config section
 *
 * Revision 1.16  2005/03/14 09:39:04  peter
 * code-styling and error handling
 *
 * Revision 1.15  2005/03/10 16:44:12  erwin
 * Made compatible with new UDBConnectorFactory
 *
 * Revision 1.14  2005/03/10 14:17:45  erwin
 * Improved Javadoc.
 *
 * Revision 1.13  2005/03/09 17:08:54  remco
 * Fixed whole bunch of warnings
 *
 * Revision 1.12  2005/03/09 15:16:51  martijn
 * fixed bug in getAuthsps(): if the hashtable returned by the udbconnector doesn't contain a key=user_authsps with value=Hashtable, then a wrong error message was logged.
 *
 * Revision 1.11  2005/03/09 15:11:20  martijn
 * added fixme in getAuthsps()
 *
 * Revision 1.10  2005/03/09 09:24:50  erwin
 * Renamed and moved errors.
 *
 * Revision 1.9  2005/03/08 10:16:32  remco
 * javadoc added
 *
 * Revision 1.8  2005/03/08 10:03:40  remco
 * javadoc added
 *
 * Revision 1.3  2005/03/08 09:51:53  remco
 * javadoc added
 *
 *
 */

package org.aselect.server.request.handler.saml20.sp.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.tgt.saml20.SpTGTIssuer;
import org.aselect.server.tgt.saml20.TGTIssuer;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.server.udb.UDBConnectorFactory;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.AuthenticationLogger;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.utils.Utils;

/**
 * This class handles login requests coming from applications through a users
 * browser. <br>
 * <br>
 * <b>Description:</b> <br>
 * This Class handles the following requests:
 * <ul>
 * <li><code>logout</code></li>
 * <li><code>login1</code></li>
 * <li><code>login2</code></li>
 * <li><code>login3</code></li>
 * <li><code>ip_login</code></li>
 * <li><code>direct_loginx</code></li>
 * <li><code>cross_login</code></li>
 * <li><code>create_tgt</code></li>
 * </ul>
 * <br>
 * If no request is sent the user info (if available) page is shown
 * 
 * @author Alfa & Ariss
 * 
 */
// @SuppressWarnings("all")
public class ApplicationBrowserHandler extends AbstractBrowserRequestHandler
{
	private static final String MODULE = "ApplicationBrowserHandler";

	private Hashtable _htSessionContext;

	private ApplicationManager _applicationManager;

	private CrossASelectManager _crossASelectManager;

	private CryptoEngine _cryptoEngine;

	// private final String _sUID = "digid_user"; //Dummy user_id to bypass
	// the window for user_id

	/**
	 * Constructor for ApplicationBrowserHandler. <br>
	 * 
	 * @param servletRequest
	 *                The request.
	 * @param servletResponse
	 *                The response.
	 * @param sMyServerId
	 *                The A-Select Server ID.
	 * @param sMyOrg
	 *                The A-Select Server organisation.
	 */
	public ApplicationBrowserHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sMyServerId, String sMyOrg) {
		super(servletRequest, servletResponse, sMyServerId, sMyOrg);
		_sModule = "ApplicationBrowserHandler()";
		_applicationManager = ApplicationManager.getHandle();
		_crossASelectManager = CrossASelectManager.getHandle();
		_cryptoEngine = CryptoEngine.getHandle();
	}

	/**
	 * process application browser requests <br>
	 * <br>
	 * 
	 * @see org.aselect.server.request.handler.saml20.sp.authentication.AbstractBrowserRequestHandler#processBrowserRequest(java.util.Hashtable,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter)
	 */
	public void processBrowserRequest(Hashtable htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
		throws ASelectException
	{
		String sRequest;
		String sRid;
		String sMethod = "processBrowserRequest()";

		sRequest = (String) htServiceRequest.get("request");
		_systemLogger.log(Level.INFO, _sModule, sMethod, "ApplBrowREQ sRequest=" + sRequest + ", htServiceRequest="
				+ htServiceRequest);

		if (sRequest == null) {
			// show info page if nothing to do
			if (htServiceRequest.containsKey("aselect_credentials_uid"))
				showUserInfo(htServiceRequest, _servletResponse);
			else
				{  // Bauke: original code
	                String sServerInfoForm = _configManager.getForm("serverinfo");
	                sServerInfoForm = Utils.replaceString(sServerInfoForm, "[message]", " ");
	                pwOut.println(sServerInfoForm);
                }
		}
		else if (sRequest.equals("logout")) {
			handleLogout(htServiceRequest, _servletResponse, pwOut);
		}
		else {
			// Precondition
			sRid = (String) htServiceRequest.get("rid");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing RID parameter");

				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Precondition
			// If a valid session is found, it will be valid during the
			// whole
			// servlet request handling.
			_htSessionContext = _sessionManager.getSessionContext(sRid);

			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid RID: " + sRid);

				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			String sDirectAuthSP = (String) _htSessionContext.get("direct_authsp");

			if (sDirectAuthSP != null && !(sRequest.indexOf("direct_login") >= 0)) {
				_systemLogger
						.log(Level.WARNING, _sModule, sMethod, "Probably tampered request with rid='" + sRid + "'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			if (sRequest.equals("login1")) {
				handleLogin1(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("cross_login")) {
				handleCrossLogin(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("create_tgt")) {
				handleCreateTGT(htServiceRequest, _servletResponse);
			}
			else {
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
	}

	/**
	 * Handles the <code>request=login1</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * First user request. If the user already has a valid TGT, the user is
	 * redirected back to the application (or the local A-Select Server in
	 * case of cross A-Select).<br>
	 * If no valid TGT is found, the user is presented an HTML page asking
	 * for a user name. The HTML page implements a HTML-form that will POST
	 * a <code>request=login2</code>. If the user is not from this
	 * organizatio, the HTML-form might POST a
	 * <code>request=cross_login</code> instead. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * A session with a <code>rid</code> should be created first using:
	 * <ul>
	 * <li><code>ApplicationRequestHandler.handleAuthenticateRequest()</code>
	 * <li><code>ApplicationRequestHandler.handleCrossAuthenticateRequest()</code>
	 * </ul>
	 * <code>htLoginRequest</code> should contain this <code>rid</code>
	 * parameter. <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param htServiceRequest
	 *                Hashtable containing request parameters
	 * @param servletResponse
	 *                Used to send (HTTP) information back to user
	 * @param pwOut
	 *                Used to write information back to the user (HTML)
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	private void handleLogin1(Hashtable htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
		throws ASelectException
	{
		String sMethod = "handleLogin1()";
		String sRid = null;

		// _htSessionContext.put("forced_uid", _sUID); //At this moment we don't
		// need an userId from the user.

		_systemLogger.log(Level.INFO, _sModule, sMethod, "Login1 SesContext:" + _htSessionContext + ", ServReq:"
				+ htServiceRequest);
		try {
			sRid = (String) htServiceRequest.get("rid");

			// check if user already has a tgt so that he/she doesnt need to
			// be authenticated again
			if (_configManager.isSingleSignOn() && htServiceRequest.containsKey("aselect_credentials_tgt")
					&& htServiceRequest.containsKey("aselect_credentials_uid")
					&& htServiceRequest.containsKey("aselect_credentials_server_id")) {
				String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
				String sUid = (String) htServiceRequest.get("aselect_credentials_uid");
				String sServerId = (String) htServiceRequest.get("aselect_credentials_server_id");

				// check if a request was done for an other user-id
				String sForcedUid = (String) _htSessionContext.get("forced_uid");
				if (sForcedUid != null && !sUid.equals(sForcedUid))
				// user_id does not match
				{
					_tgtManager.remove(sTgt);
				}
				else {
					if (checkCredentials(sTgt, sUid, sServerId))
					// valid credentials/level/SSO group
					{
						_systemLogger.log(Level.INFO, _sModule, sMethod, "CheckCred OK");
						Boolean boolForced = (Boolean) _htSessionContext.get("forced_authenticate");
						if (!boolForced.booleanValue()) {
							// valid tgt, no forced_authenticate
							// redirect to application as user has already a
							// valid tgt
							String sRedirectUrl;
							if (_htSessionContext.get("remote_session") == null) {
								sRedirectUrl = (String) _htSessionContext.get("app_url");
							}
							else {
								sRedirectUrl = (String) _htSessionContext.get("local_as_url");
							}
							// update TGT with app_id or local_organization
							// needed for attribute gathering in verify_tgt
							Hashtable htTGTContext = _tgtManager.getTGT(sTgt);

							String sAppId = (String) _htSessionContext.get("app_id");
							if (sAppId != null)
								htTGTContext.put("app_id", sAppId);

							String sLocalOrg = (String) _htSessionContext.get("local_organization");
							if (sLocalOrg != null)
								htTGTContext.put("local_organization", sLocalOrg);

							htTGTContext.put("rid", sRid);
							_tgtManager.updateTGT(sTgt, htTGTContext);
							SpTGTIssuer oTGTIssuer = new SpTGTIssuer(_sMyServerId);

							_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR " + sRedirectUrl);
							oTGTIssuer.sendRedirect(sRedirectUrl, sTgt, sRid, servletResponse);
							_sessionManager.killSession(sRid);
							return;
						}
					}
					_systemLogger.log(Level.INFO, _sModule, sMethod, "TGT found but not sufficient");
					// TGT found but not sufficient.
					// Authenicate with same user-id that was stored in TGT
					Hashtable htTGTContext = _tgtManager.getTGT(sTgt);

					// If TGT was issued in cross mode, the user now has to
					// authenticate with a higher level in cross mode again
					String sTempOrg = (String) htTGTContext.get("proxy_organization");
					if (sTempOrg == null)
						sTempOrg = (String) htTGTContext.get("organization");

					// User was originally authenticated at this A-Select Server
					// The userid is already known from the TGT
					htServiceRequest.put("user_id", sUid); // Is dit
					// bruikbaar????
					String sAsUrl = _configManager.getRedirectURL();
					// Is the <redirect_url> in aselect.xml
					sAsUrl = sAsUrl + "?request=interrupt&rid=" + sRid;
					// The target of the appropriate handler must be
					// "target='\?request=SAML20.*'"
					servletResponse.sendRedirect(sAsUrl);
					return;
				}
			}
			_systemLogger.log(Level.INFO, _sModule, sMethod, "no TGT found or killed (other uid)");
			// no TGT found or killed (other uid)
			if (!_configManager.isUDBEnabled() || _htSessionContext.containsKey("forced_organization")) {
				handleCrossLogin(htServiceRequest, servletResponse, pwOut);
				return;
			}
			String sForcedUid = (String) _htSessionContext.get("forced_uid");
			if (sForcedUid != null) {
				htServiceRequest.put("user_id", sForcedUid);
			}

			String sAsUrl = _configManager.getRedirectURL();
			// Is the <redirect_url> in aselect.xml
			sAsUrl = sAsUrl + "?request=interrupt&rid=" + sRid;
			// The target of the appropriate handler must be
			// "target='\?request=interrupt.*'"
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Redirect " + sAsUrl);
			servletResponse.sendRedirect(sAsUrl);
			return;
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * This method handles the <code>request=cross_login</code> user request.
	 * <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * If the user already has a tgt and it is valid for the current
	 * application, then the user does not need be authenticated again. The user
	 * is redirected back to the application. If the user's tgt is not valid,
	 * then the remote A-Select Server is contacted by sending a
	 * <code>request=cross_authenticate_aselect</code> request. If the remote
	 * A-Select Server is contacted successfully, the user is redirected to him
	 * so that the user can be authenticated there. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br> - <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param htServiceRequest
	 *            Hashtable containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            PrintWriter that might be needed by the
	 *            <code>ISelectorHandler</code>
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	private void handleCrossLogin(Hashtable htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
		throws ASelectException
	{
		String sRemoteOrg = null;
		String sUid = null;
		String sMethod = "handleCrossLogin()";

		_systemLogger.log(Level.INFO, _sModule, sMethod, "CrossLogin htServiceRequest=" + htServiceRequest);
		try {
			// is cross enabled? (configuration)
			if (!_crossASelectManager.remoteServersEnabled()) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Cross A-Select is disabled since it is not (properly) configured.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG);
			}

			String sLocalRid = (String) htServiceRequest.get("rid");
			Integer intAppLevel = (Integer) _htSessionContext.get("level");
			if (intAppLevel == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "could not fetch level from session context.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}

			sRemoteOrg = (String) _htSessionContext.get("forced_organization");

			// check if the request was done for a specific user_id
			sUid = (String) _htSessionContext.get("forced_uid");
			if (sRemoteOrg == null) {
				if (!_crossASelectManager.isCrossSelectorEnabled()) {
					_systemLogger
							.log(Level.WARNING, _sModule, sMethod,
									"Dynamic 'cross_selector' is disabled, parameter 'remote_organization' is required but not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG);
				}

				// No optional parameter 'remote_organization found
				// Determine the remote organization
				Hashtable htIdentification;

				// some selector handlers may need the user_id if it is known
				// already
				if (sUid != null) {
					htServiceRequest.put("user_id", sUid);
				}
				try {
					// CrossASelectManager oIdentificationFactory =
					// CrossASelectManager.getHandle();
					htIdentification = _crossASelectManager.getSelectorHandler().getRemoteServerId(htServiceRequest,
							servletResponse, pwOut);
				}
				catch (ASelectException ace) {
					_systemLogger
							.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve the remote server id.", ace);

					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG, ace);
				}
				if (htIdentification == null) {
					// The handler was not ready yet and presented a HTML
					// form
					// to the end user to gather more information
					// this form will POST 'request=cross_authenticate'
					// again.
					return;
				}
				sRemoteOrg = (String) htIdentification.get("organization_id");
				String sTemp = (String) htIdentification.get("user_id");

				// Selector handler might have translated the user_id
				if (sTemp != null)
					sUid = (String) htIdentification.get("user_id");
			}
			_htSessionContext.put("remote_organization", sRemoteOrg);
			_sessionManager.put(sLocalRid, _htSessionContext);

			Object oRemoteServer;
			String sRemoteAsUrl;
			String sRemoteServer;

			try {
				// continue cross a-select login processing
				String sResourcegroup = _crossASelectManager.getRemoteParam(sRemoteOrg, "resourcegroup");
				if (sResourcegroup == null) {
					StringBuffer sbWarning = new StringBuffer("Unknown organization '");
					sbWarning.append(sRemoteOrg);
					sbWarning.append("'");
					_systemLogger.log(Level.SEVERE, _sModule, sMethod, sbWarning.toString());
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG);
				}
				SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
				oRemoteServer = oSAMResource.getAttributes();
				sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
				sRemoteServer = _crossASelectManager.getRemoteParam(sRemoteOrg, "server");
			}
			catch (ASelectSAMException ase) {
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.", ase);

				throw ase;
			}
			catch (ASelectConfigException ace) {
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read config.", ace);

				throw ace;
			}

			StringBuffer sbMyAppUrl = new StringBuffer();
			sbMyAppUrl.append((String) htServiceRequest.get("my_url"));
			sbMyAppUrl.append("?local_rid=").append(sLocalRid);

			RawCommunicator oCommunicator = new RawCommunicator(_systemLogger); // Default
			// =
			// API
			// communciation

			Hashtable htRequestTable = new Hashtable();
			Hashtable htResponseTable = new Hashtable();
			htRequestTable.put("request", "authenticate");

			Boolean boolForced = (Boolean) _htSessionContext.get("forced_authenticate");
			htRequestTable.put("forced_logon", boolForced.toString());
			htRequestTable.put("local_as_url", sbMyAppUrl.toString());

			Object oASelectConfig = _configManager.getSection(null, "aselect");
			String sMyOrgId = _configManager.getParam(oASelectConfig, "organization");
			htRequestTable.put("local_organization", sMyOrgId);

			Integer intLevel = (Integer) _htSessionContext.get("level");
			htRequestTable.put("required_level", intLevel.toString());
			htRequestTable.put("a-select-server", sRemoteServer);

			if (sUid != null) {
				htRequestTable.put("uid", sUid);
			}
			String sCountry = (String) _htSessionContext.get("country");
			if (sCountry != null) {
				htRequestTable.put("country", sCountry);
			}
			String sLanguage = (String) _htSessionContext.get("language");
			if (sLanguage != null) {
				htRequestTable.put("language", sLanguage);
			}

			// check if request should be signed
			if (_crossASelectManager.useRemoteSigning()) {
				_cryptoEngine.signRequest(htRequestTable);
			}

			htResponseTable = oCommunicator.sendMessage(htRequestTable, sRemoteAsUrl);

			if (htResponseTable.isEmpty()) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not reach remote A-Select Server: "
						+ sRemoteAsUrl);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			String sResultCode = (String) htResponseTable.get("result_code");
			if (sResultCode == null) {
				StringBuffer sbWarning = new StringBuffer("Invalid response from remote A-Select Server '");
				sbWarning.append(sRemoteServer);
				sbWarning.append("' (missing: 'result_code')");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
				StringBuffer sbWarning = new StringBuffer("A-Select Server '");
				sbWarning.append(sRemoteServer);
				sbWarning.append("' returned error: '");
				sbWarning.append(sResultCode);
				sbWarning.append("'.");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
				throw new ASelectException(sResultCode);
			}

			// check the response of the A-Select Server
			String sRemoteRid = (String) htResponseTable.get("rid");
			String sRemoteLoginUrl = (String) htResponseTable.get("as_url");
			if ((sRemoteRid == null) || (sRemoteLoginUrl == null)) {
				StringBuffer sbWarning = new StringBuffer("Invalid response from remote A-Select Server: ");
				sbWarning.append(sRemoteServer);
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			try {
				StringBuffer sbUrl = new StringBuffer(sRemoteLoginUrl);
				sbUrl.append("&rid=").append(sRemoteRid);
				sbUrl.append("&a-select-server=").append(sRemoteServer);

				servletResponse.sendRedirect(sbUrl.toString());
			}
			catch (IOException e) {
				StringBuffer sbWarning = new StringBuffer("Failed to redirect user to: ");
				sbWarning.append(sRemoteServer);
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString(), e);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
			}
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * This method handles the <code>request=logout</code> user request.
	 * <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The request can be used to logout a user by destroying his/her TGT.
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * Valid TGT <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * TGT is destroyed <br>
	 * 
	 * @param htServiceRequest
	 *                Hashtable containing request parameters
	 * @param servletResponse
	 *                Used to send (HTTP) information back to user
	 * @param pwOut
	 *                Used to write information back to the user (HTML)
	 * @throws ASelectException
	 */
	private void handleLogout(Hashtable htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
		throws ASelectException
	{
		String sMethod = "handleLogout()";
		String sLoggedOutForm = _configManager.getForm("loggedout");

		try {
			String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
			Hashtable htTGTContext = _tgtManager.getTGT(sTgt);

			if (htTGTContext != null) {
				_tgtManager.remove(sTgt);

				Cookie cKillCookie = new Cookie(SpTGTIssuer.COOKIE_NAME, "jimmmorrisonisalive");
				String sCookieDomain = _configManager.getCookieDomain();
				if (sCookieDomain != null) {
					cKillCookie.setDomain(sCookieDomain);
				}

				_systemLogger.log(Level.INFO, MODULE, sMethod, "Delete Cookie=" + SpTGTIssuer.COOKIE_NAME + " domain="
						+ sCookieDomain);
				servletResponse.addCookie(cKillCookie);

				String sRemoteAsUrl = null;
				String sRemoteOrg = null;

				sRemoteOrg = (String) htTGTContext.get("proxy_organization");
				if (sRemoteOrg == null)
					sRemoteOrg = (String) htTGTContext.get("organization");

				if (!sRemoteOrg.equals(_sMyOrg)) {
					try {
						CrossASelectManager oCrossASelectManager = CrossASelectManager.getHandle();
						String sResourcegroup = oCrossASelectManager.getRemoteParam(sRemoteOrg, "resourcegroup");
						SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
						Object oRemoteServer = oSAMResource.getAttributes();
						sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
					}
					catch (ASelectException ae) {
						_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.", ae);
						sRemoteAsUrl = null;
					}
				}
				if (sRemoteAsUrl != null) {
					servletResponse.sendRedirect(sRemoteAsUrl);
					return;
				}
			}

			sLoggedOutForm = _configManager.updateTemplate(sLoggedOutForm, htTGTContext);

			pwOut.println(sLoggedOutForm);

		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * This method handles the <code>request=create_tgt</code> user
	 * request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This request can be used to create TGTs for users without actually
	 * authentication them. This can only be used by priviliged applications
	 * which simply redirect the user with the correct information to the
	 * A-Select-Server with the request to create a TGT. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * Signed request and a valid public key located in the priviliged
	 * keystore <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * A TGT wil be created <br>
	 * 
	 * @param htServiceRequest
	 *                Hashtable containing request parameters
	 * @param servletResponse
	 *                Used to send (HTTP) information back to user
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	private void handleCreateTGT(Hashtable htServiceRequest, HttpServletResponse servletResponse)
		throws ASelectException
	{
		String sMethod = "handleCreateTGTRequest()";
		AuthenticationLogger authenticationLogger = ASelectAuthenticationLogger.getHandle();

		try {
			// get output writer
			// Read expected parameters
			String sRid = (String) htServiceRequest.get("rid");
			String sUID = (String) htServiceRequest.get("uid");
			String sPrivilegedApplication = (String) htServiceRequest.get("app_id");
			String sSignature = (String) htServiceRequest.get("signature");
			String sAuthspLevel = (String) htServiceRequest.get("level");

			// Verify parameters
			if ((sRid == null) || (sUID == null) || (sPrivilegedApplication == null) || (sSignature == null)
					|| (sAuthspLevel == null)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Invalid request received: one or more parameters are missing.");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Verify signature
			try {
				sSignature = URLDecoder.decode(sSignature, "UTF-8");
				sUID = URLDecoder.decode(sUID, "UTF-8");
			}
			catch (UnsupportedEncodingException eUE)
			// Interne fout UTF-8 niet ondersteund
			{
				_systemLogger
						.log(Level.WARNING, _sModule, sMethod, "Internal error: request could not be decoded", eUE);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			StringBuffer sbBuffer = new StringBuffer();
			sbBuffer.append(sRid).append(sUID);
			sbBuffer.append(sPrivilegedApplication).append(sAuthspLevel);
			if (!CryptoEngine.getHandle().verifyPrivilegedSignature(sPrivilegedApplication, sbBuffer.toString(),
					sSignature)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request received: invalid signature.");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);

			}

			// Get session context
			Hashtable htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request received: invalid session.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}

			// check authsp_level
			try {
				int iLevel = Integer.parseInt(sAuthspLevel);
				if (iLevel < 0) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod,
							"Invalid request received: invalid AuthSP level.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
			}
			catch (NumberFormatException eNF) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request received: invalid AuthSP level.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST, eNF);
			}

			// check user ID
			IUDBConnector oUDBConnector = null;
			try {
				oUDBConnector = UDBConnectorFactory.getUDBConnector();
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to connect with UDB.", e);
				throw e;
			}

			if (!oUDBConnector.isUserEnabled(sUID)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request received: Unknown UID.");
				throw new ASelectException(Errors.ERROR_ASELECT_UDB_UNKNOWN_USER);
			}

			// Extend session context
			htSessionContext.put("user_id", sUID);
			htSessionContext.put("authsp", sPrivilegedApplication);
			htSessionContext.put("authsp_level", sAuthspLevel);

			if (!_sessionManager.updateSession(sRid, htSessionContext)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Invalid request received: could not update session.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}

			// Log succesful authentication
			authenticationLogger.log(new Object[] {
				"Login", sUID, (String) htServiceRequest.get("client_ip"), _sMyOrg, sPrivilegedApplication, "granted"
			});

			// Issue TGT
			SpTGTIssuer tgtIssuer = new SpTGTIssuer(_sMyServerId);
			tgtIssuer.issueTGT(sRid, sPrivilegedApplication, null, servletResponse, null);

		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Private method to check whether the user's tgt is valid and satisfies
	 * the required level for the current application. <br>
	 * 
	 * @param sTgt
	 *                The ticket granting ticket.
	 * @param sUid
	 *                The user ID.
	 * @param sServerId
	 *                The server ID.
	 * @return True if credentials are valid, otherwise false.
	 */
	private boolean checkCredentials(String sTgt, String sUid, String sServerId)
	{
		String sMethod = "checkCredentials()";
		Hashtable htTGTContext = null;
		String sTGTLevel;
		Integer intRequiredLevel;

		try {
			if (_tgtManager.containsKey(sTgt)) {
				htTGTContext = _tgtManager.getTGT(sTgt);
			}
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, e.getMessage());
		}
		if (htTGTContext == null) {
			return false;
		}

		if (!((String) htTGTContext.get("uid")).equals(sUid)) {
			return false;
		}

		if (!sServerId.equals(_sMyServerId)) {
			return false;
		}

		// check single sign-on groups
		Vector vCurSSOGroups = (Vector) _htSessionContext.get("sso_groups");
		Vector vOldSSOGroups = (Vector) htTGTContext.get("sso_groups");
		if (vCurSSOGroups != null && vOldSSOGroups != null) {
			if (!vCurSSOGroups.isEmpty() && !vOldSSOGroups.isEmpty()) {
				if (!_applicationManager.isValidSSOGroup(vCurSSOGroups, vOldSSOGroups))
					return false;
			}
		}

		intRequiredLevel = (Integer) _htSessionContext.get("level");

		sTGTLevel = (String) htTGTContext.get("authsp_level");
		if (Integer.parseInt(sTGTLevel) >= intRequiredLevel.intValue()) {
			return true;
		}
		// user did have a tgt but the level is not high enough
		// so continue authenticate
		return false;
	}

	/**
	 * Show the user info contained in the TGT context of the user. Requires
	 * a valid TGT. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 * @param response
	 * @throws ASelectException
	 */
	private void showUserInfo(Hashtable htServiceRequest, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "showUserInfo()";
		PrintWriter pwOut = null;

		try {
			// get output writer
			pwOut = response.getWriter();

			String sUserId = (String) htServiceRequest.get("aselect_credentials_uid");
			String sMyUrl = (String) htServiceRequest.get("my_url");
			String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");

			String sUserInfoForm = _configManager.getForm("userinfo");
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[uid]", sUserId);
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[a-select-server]", _sMyServerId);
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[aselect_url]", sMyUrl);

			// toevoeging van encrypted credentials
			String sTemp = CryptoEngine.getHandle().encryptTGT(Utils.stringToHex(sTgt));
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_blob]", sTemp);

			Hashtable htTGTContext = _tgtManager.getTGT(sTgt);
			try {
				long lExpTime = _tgtManager.getExpirationTime(sTgt);
				sTemp = new Date(lExpTime).toString();
				sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_exp_time]", sTemp);
			}
			catch (ASelectStorageException e) {
				sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_exp_time]", "[unknown]");
			}

			sTemp = (String) htTGTContext.get("app_id");
			if (sTemp == null)
				sTemp = "[unknown]";
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[app]", sTemp);

			sUserInfoForm = _configManager.updateTemplate(sUserInfoForm, htTGTContext);

			sTemp = (String) htTGTContext.get("authsp");
			if (sTemp != null) {
				try {
					Object authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"),
							"authsp", "id=" + sTemp);
					sTemp = _configManager.getParam(authSPsection, "friendly_name");
				}
				catch (ASelectConfigException eAC) {
					sTemp = "[unknown]";
				}
			}
			else {
				sTemp = "[unknown]";
			}

			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[authsp]", sTemp);

			sTemp = (String) htTGTContext.get("authsp_level");
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_level]", sTemp);

			sTemp = (String) htTGTContext.get("proxy_organization");
			if (sTemp == null)
				sTemp = (String) htTGTContext.get("organization");

			String sRemoteAsUrl = null;
			if (!sTemp.equals(_sMyOrg)) {
				try {
					CrossASelectManager oCrossASelectManager = CrossASelectManager.getHandle();
					String sResourcegroup = oCrossASelectManager.getRemoteParam(sTemp, "resourcegroup");
					SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
					Object oRemoteServer = oSAMResource.getAttributes();
					sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
				}
				catch (ASelectException ae) {
					_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.", ae);
					sRemoteAsUrl = null;
				}
			}
			if (sRemoteAsUrl == null) {
				sUserInfoForm = Utils.replaceString(sUserInfoForm, "[org]", sTemp);
			}
			else {
				String sTemp3 = "<A HREF=\"" + sRemoteAsUrl + "\">" + sTemp + "</A>";
				sUserInfoForm = Utils.replaceString(sUserInfoForm, "[org]", sTemp3);
			}
			pwOut.println(sUserInfoForm);
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Error writing output", eIO);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

}
