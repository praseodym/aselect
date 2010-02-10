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
 * fixed bug in getAuthsps(): if the hashtable returned by the udbconnector doesn't contain a key=user_authsps with value=HashMap, then a wrong error message was logged.
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
 */

package org.aselect.server.request.handler.aselect.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse; //import org.aselect.system.servlet.HtmlInfo;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.authspprotocol.IAuthSPDirectLoginProtocolHandler;
import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.authspprotocol.handler.AuthSPHandlerManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.xsaml20.ServiceProvider;
import org.aselect.server.request.handler.xsaml20.idp.UserSsoSession;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.server.tgt.TGTManager;
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
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;

/**
 * This class handles login requests coming from applications through a users browser. <br>
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
 * @author Alfa & Ariss 7-10-2008 - HtmlInfo de-activated 18-9-2008 - HtmlInfo integrated in A-Select (replaces
 *         tolk_htmlinfo) 14-11-2007 - Changes: - Support tolk_htmlinfo request: shows header info in a html page -
 *         DigiD Gateway integration - Added login25 method and some other changes to support SIAM "VerkeersPlein"
 *         authsp selection
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl) and UMC Nijmegen
 *         (http://www.umcn.nl)
 */
public class ApplicationBrowserHandler extends AbstractBrowserRequestHandler
{
	private HashMap _htSessionContext = null;
	private ApplicationManager _applicationManager;
	private CrossASelectManager _crossASelectManager;
	private AuthSPHandlerManager _authspHandlerManager;
	private CryptoEngine _cryptoEngine;
	private String _sConsentForm = null;

	/**
	 * Constructor for ApplicationBrowserHandler. <br>
	 * 
	 * @param servletRequest
	 *            The request.
	 * @param servletResponse
	 *            The response.
	 * @param sMyServerId
	 *            The A-Select Server ID.
	 * @param sMyOrg
	 *            The A-Select Server organisation.
	 */
	public ApplicationBrowserHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sMyServerId, String sMyOrg) {
		super(servletRequest, servletResponse, sMyServerId, sMyOrg);
		_sModule = "ApplicationBrowserHandler";
		_systemLogger.log(Level.INFO, _sModule, _sModule, "== create == user language=" + _sUserLanguage);
		_applicationManager = ApplicationManager.getHandle();
		_authspHandlerManager = AuthSPHandlerManager.getHandle();
		_crossASelectManager = CrossASelectManager.getHandle();
		_cryptoEngine = CryptoEngine.getHandle();
	}

	/**
	 * Process application browser requests.<br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.aselect.authentication.AbstractBrowserRequestHandler#processBrowserRequest(java.util.HashMap,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter)
	 */
	public void processBrowserRequest(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "processBrowserRequest";

		String sRequest = (String) htServiceRequest.get("request");
		_systemLogger.log(Level.INFO, _sModule, sMethod, "ApplBrowREQ sRequest=" + sRequest + ", htServiceRequest="
				+ htServiceRequest + " user language=" + _sUserLanguage);
		String sReqLanguage = (String) htServiceRequest.get("language");
		if (sReqLanguage != null && !sReqLanguage.equals("")) {
			_sUserLanguage = sReqLanguage;
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Set user language=" + _sUserLanguage + " from Request");
		}

		// Bauke, 20090929: added localization, do this asap.
		String sRid = (String) htServiceRequest.get("rid");
		if (sRid != null) {
			_htSessionContext = _sessionManager.getSessionContext(sRid);
			if (sReqLanguage != null && !sReqLanguage.equals("")) {
				_htSessionContext.put("language", sReqLanguage);
				_sessionManager.updateSession(sRid, _htSessionContext); // store language for posterity
			}
			// Copy language & country to session if not present yet (session takes precedence)
			Utils.transferLocalization(_htSessionContext, _sUserLanguage, _sUserCountry);
			// And copy language back
			_sUserLanguage = (String) _htSessionContext.get("language"); // override
			_systemLogger.log(Level.INFO, _sModule, sMethod, "After transfer user language=" + _sUserLanguage);
		}

		if (sRequest == null) {
			// Show info page if nothing else to do
			String sUrl = (String) htServiceRequest.get("my_url");
			_systemLogger.log(Level.INFO, _sModule, sMethod, "ApplBrowREQ null request sUrl=" + sUrl);

			if (htServiceRequest.containsKey("aselect_credentials_uid"))
				showUserInfo(htServiceRequest, _servletResponse);
			else {
				String sServerInfoForm = _configManager.getForm("serverinfo", _sUserLanguage, _sUserCountry);
				sServerInfoForm = Utils.replaceString(sServerInfoForm, "[message]", " ");

				try {
					Object aselect = _configManager.getSection(null, "aselect");
					String sFriendlyName = ASelectConfigManager.getSimpleParam(aselect, "organization_friendly_name",
							false);
					sServerInfoForm = Utils.replaceString(sServerInfoForm, "[organization_friendly]", sFriendlyName);
				}
				catch (Exception e) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Configuration error: " + e);
				}
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Serverinfo [" + sServerInfoForm + "]");
				pwOut.println(sServerInfoForm);
			}
		}
		else if (sRequest.equals("logout")) {
			handleLogout(htServiceRequest, _servletResponse, pwOut);
		}
		else if (sRequest.equals("org_choice")) {
			handleOrgChoice(htServiceRequest, _servletResponse);
		}
		else if (sRequest.equals("alive")) {
			pwOut.println("<html><body>Server is ALIVE</body></html>");
		}
		else {
			// Precondition
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing RID parameter");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Precondition
			// If a valid session is found, it will be valid during the whole servlet request handling.
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid RID: " + sRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			String sDirectAuthSP = (String) _htSessionContext.get("direct_authsp");
			if (sDirectAuthSP != null && !(sRequest.indexOf("direct_login") >= 0)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"'direct_authsp' found, but not a 'direct_login' request, rid='" + sRid + "'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			if (sRequest.equals("login1")) {
				handleLogin1(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("login2")) {
				handleLogin2(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("login3")) {
				handleLogin3(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("cross_login")) {
				handleCrossLogin(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("login25")) {
				handleLogin25(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("ip_login")) {
				handleIPLogin1(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.indexOf("direct_login") >= 0) {
				handleDirectLogin(htServiceRequest, _servletResponse, pwOut);
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
	 * Handles the <code>request=org_choice</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Store the user's organization choice in the TGT and redirect the user
	 * to the application he desires.
	 * TGT has already been issued, Rid is still present (contains the application url)
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleOrgChoice(HashMap htServiceRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "handleOrgChoice";
		
		String sRid = (String)htServiceRequest.get("rid");
		String sOrgId = (String)htServiceRequest.get("org_id");
		String sTgt = (String)htServiceRequest.get("aselect_credentials_tgt");
		if (sRid == null || sOrgId == null || sTgt == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing request parameter");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_systemLogger.log(Level.INFO, _sModule, sMethod, "OrgChoice="+sOrgId);

		// Stop the user-time pause
		Tools.pauseSensorData(_systemLogger, _htSessionContext);
		// No need to write the session, it's used below by calculateAndReportSensorData()
		
		// Store the chosen organization in the TGT
		TGTManager oTGTManager = TGTManager.getHandle();
		HashMap<String,Object> htTGTContext = oTGTManager.getTGT(sTgt);
		if (htTGTContext == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Cannot get TGT");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		htTGTContext.put("org_id", sOrgId);
		oTGTManager.updateTGT(sTgt, htTGTContext);

		// The tgt was just issued and updated, report sensor data
		Tools.calculateAndReportSensorData(_configManager, _systemLogger, _htSessionContext);
		_sessionManager.killSession(sRid);
		
		String sAppUrl = (String)_htSessionContext.get("app_url");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + sAppUrl);
		
		_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR " + sAppUrl);
		TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
		oTGTIssuer.sendRedirect(sAppUrl, sTgt, sRid, servletResponse);
	}

	/**
	 * Handles the <code>request=direct_login</code> requests. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * All the requests which contains direct_login (e.g. direct_login1, direct_login2) will be handled by this function
	 * and send to the direct authsp handler. <code>request=cross_login</code> instead. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * A session with a <code>rid</code> should be created first using:
	 * <ul>
	 * <li><code>ApplicationRequestHandler.handleAuthenticateRequest()</code>
	 * </ul>
	 * <code>htLoginRequest</code> should contain this <code>rid</code> parameter. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleDirectLogin(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleDirectLogin()";
		String sRid = null;

		_systemLogger.log(Level.INFO, _sModule, sMethod, "====");
		try {
			sRid = (String) htServiceRequest.get("rid");
			String sAuthSPId = (String) _htSessionContext.get("direct_authsp");
			if (sAuthSPId == null) {
				sAuthSPId = (String) htServiceRequest.get("authsp");
				if (sAuthSPId != null)
					_htSessionContext.put("direct_authsp", sAuthSPId);
			}
			if (sAuthSPId == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Missing 'direct_authsp' in session and request, rid='" + sRid + "'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			IAuthSPDirectLoginProtocolHandler oProtocolHandler = _authspHandlerManager
					.getAuthSPDirectLoginProtocolHandler(sAuthSPId);

			// check if user already has a tgt so that he/she doesnt need to be authenticated again
			if (_configManager.isSingleSignOn() && htServiceRequest.containsKey("aselect_credentials_tgt")
					&& htServiceRequest.containsKey("aselect_credentials_uid")
					&& htServiceRequest.containsKey("aselect_credentials_server_id")) {
				String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
				String sUid = (String) htServiceRequest.get("aselect_credentials_uid");
				String sServerId = (String) htServiceRequest.get("aselect_credentials_server_id");

				// check if a request was done for another user-id
				String sForcedUid = (String) _htSessionContext.get("forced_uid");

				_systemLogger.log(Level.INFO, _sModule, sMethod, "DLOGIN sTgt=" + sTgt + "sUid=" + sUid + "sServerId="
						+ sServerId + "sForcedUid=" + sForcedUid);
				if (sForcedUid != null && !sUid.equals(sForcedUid)) // user_id does not match
				{
					_tgtManager.remove(sTgt);
				}
				else {
					if (checkCredentials(sTgt, sUid, sServerId)) // valid credentials/level/SSO group
					{
						Boolean boolForced = (Boolean) _htSessionContext.get("forced_authenticate");
						if (boolForced == null)
							boolForced = false;
						_systemLogger.log(Level.INFO, _sModule, sMethod, "CheckCred OK forced=" + boolForced);
						if (!boolForced.booleanValue()) {
							// valid tgt, no forced_authenticate
							// redirect to application as user has already a valid tgt
							String sRedirectUrl;
							if (_htSessionContext.get("remote_session") == null) {
								sRedirectUrl = (String) _htSessionContext.get("app_url");
							}
							else {
								sRedirectUrl = (String) _htSessionContext.get("local_as_url");
							}
							// update TGT with app_id or local_organization
							// needed for attribute gathering in verify_tgt
							HashMap htTGTContext = _tgtManager.getTGT(sTgt);

							String sAppId = (String) _htSessionContext.get("app_id");
							if (sAppId != null)
								htTGTContext.put("app_id", sAppId);

							String sLocalOrg = (String) _htSessionContext.get("local_organization");
							if (sLocalOrg != null)
								htTGTContext.put("local_organization", sLocalOrg);

							htTGTContext.put("rid", sRid);
							_tgtManager.updateTGT(sTgt, htTGTContext);
							TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);

							_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR " + sRedirectUrl);
							oTGTIssuer.sendRedirect(sRedirectUrl, sTgt, sRid, servletResponse);
							_sessionManager.killSession(sRid);
							return;
						}
					}
					// TGT found but not sufficient.
					// Authenicate with same user-id that was stored in TGT
					HashMap htTGTContext = _tgtManager.getTGT(sTgt);

					// If TGT was issued in cross mode, the user now has to
					// authenticate with a higher level in cross mode again
					String sTempOrg = (String) htTGTContext.get("proxy_organization");
					if (sTempOrg == null)
						sTempOrg = (String) htTGTContext.get("organization");
					if (!sTempOrg.equals(_sMyOrg)) {
						_htSessionContext.put("forced_uid", sUid);
						_htSessionContext.put("forced_organization", sTempOrg);
						handleCrossLogin(htServiceRequest, servletResponse, pwOut);
						return;
					}
					// User was originally authenticated at this A-Select Server
					// The userid is already known from the TGT
					htServiceRequest.put("user_id", sUid);
					// showDirectLoginForm(htServiceRequest,pwOut);
					oProtocolHandler.handleDirectLoginRequest(htServiceRequest, servletResponse, pwOut, _sMyServerId,
							_sUserLanguage, _sUserCountry);
					return;
				}
			}
			// no TGT found or killed (other uid)
			if (!_configManager.isUDBEnabled() || _htSessionContext.containsKey("forced_organization")) {
				handleCrossLogin(htServiceRequest, servletResponse, pwOut);
				return;
			}
			String sForcedUid = (String) _htSessionContext.get("forced_uid");
			if (sForcedUid != null) {
				htServiceRequest.put("user_id", sForcedUid);
				// showDirectLoginForm(htServiceRequest,pwOut);
			}
			oProtocolHandler.handleDirectLoginRequest(htServiceRequest, servletResponse, pwOut, _sMyServerId,
					_sUserLanguage, _sUserCountry);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error: ", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Handles the <code>request=login1</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * First user request. If the user already has a valid TGT, the user is redirected back to the application (or the
	 * local A-Select Server in case of cross A-Select).<br>
	 * If no valid TGT is found, the user is presented an HTML page asking for a user name. The HTML page implements a
	 * HTML-form that will POST a <code>request=login2</code>. If the user is not from this organizatio, the HTML-form
	 * might POST a <code>request=cross_login</code> instead. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * A session with a <code>rid</code> should be created first using:
	 * <ul>
	 * <li><code>ApplicationRequestHandler.handleAuthenticateRequest()</code>
	 * <li><code>ApplicationRequestHandler.handleCrossAuthenticateRequest()</code>
	 * </ul>
	 * <code>htLoginRequest</code> should contain this <code>rid</code> parameter. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogin1(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
		throws ASelectException
	{
		String sMethod = "handleLogin1";
		String sRid = null;
		StringBuffer sbUrl;

		_systemLogger.log(Level.INFO, _sModule, sMethod, "Login1 SessionContext:" + _htSessionContext
				+ ", ServiceRequest:" + htServiceRequest);
		try {
			sRid = (String) htServiceRequest.get("rid");

			// Check if user already has a tgt so that he/she doesnt need to be authenticated again
			if (_configManager.isSingleSignOn() && htServiceRequest.containsKey("aselect_credentials_tgt")
					&& htServiceRequest.containsKey("aselect_credentials_uid")
					&& htServiceRequest.containsKey("aselect_credentials_server_id")) {
				String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
				String sUid = (String) htServiceRequest.get("aselect_credentials_uid");
				String sServerId = (String) htServiceRequest.get("aselect_credentials_server_id");

				// Check if a request was done for a different user-id
				String sForcedUid = (String) _htSessionContext.get("forced_uid");
				_systemLogger
						.log(Level.INFO, _sModule, sMethod, "SSO branch uid=" + sUid + " forced_uid=" + sForcedUid);
				if (sForcedUid != null && !sForcedUid.equals("saml20_user") && !sForcedUid.equals("siam_user")
						&& !sUid.equals(sForcedUid)) // user_id does not match
				{
					_tgtManager.remove(sTgt);
				}
				else {
					if (checkCredentials(sTgt, sUid, sServerId)) // valid credentials/level/SSO group
					{
						Boolean boolForced = (Boolean) _htSessionContext.get("forced_authenticate");
						if (boolForced == null)
							boolForced = false;
						_systemLogger.log(Level.INFO, _sModule, sMethod, "CheckCred OK forced=" + boolForced);
						if (!boolForced.booleanValue()) {
							// valid tgt, no forced_authenticate
							// redirect to application as user has already a valid tgt
							String sRedirectUrl;
							if (_htSessionContext.get("remote_session") == null) {
								sRedirectUrl = (String) _htSessionContext.get("app_url");
							}
							else if (_htSessionContext.get("sp_assert_url") != null) {
								// xsaml20 addition
								sRedirectUrl = (String) _htSessionContext.get("sp_assert_url");
							}
							else {
								sRedirectUrl = (String) _htSessionContext.get("local_as_url");
							}
							// update TGT with app_id or local_organization
							// needed for attribute gathering in verify_tgt
							HashMap htTGTContext = _tgtManager.getTGT(sTgt);

							htTGTContext.put("rid", sRid);
							Utils.copyHashmapValue("local_organization", htTGTContext, _htSessionContext);
							// Copy sp_rid as well: xsaml20
							Utils.copyHashmapValue("sp_rid", htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("RelayState", htTGTContext, _htSessionContext);
							_systemLogger.log(Level.INFO, _sModule, sMethod, "UPD rid=" + sRid);

							// Add the SP to SSO administration - xsaml20
							String sAppId = (String) _htSessionContext.get("app_id");
							String sTgtAppId = (String) htTGTContext.get("app_id");
							String spIssuer = (String) _htSessionContext.get("sp_issuer");
							// Utils.copyHashmapValue("app_id", htTGTContext, _htSessionContext);
							if (sAppId != null) {
								if (spIssuer == null || sTgtAppId == null)
									htTGTContext.put("app_id", sAppId);
							}
							if (spIssuer != null) { // saml20 sessions
								htTGTContext.put("sp_issuer", spIssuer); // save latest issuer
								UserSsoSession ssoSession = (UserSsoSession) htTGTContext.get("sso_session");
								if (ssoSession == null) {
									_systemLogger.log(Level.INFO, MODULE, sMethod, "NEW SSO session for " + sUid
											+ " issuer=" + spIssuer);
									ssoSession = new UserSsoSession(sUid, ""); // sTgt);
								}
								ServiceProvider sp = new ServiceProvider(spIssuer);
								ssoSession.addServiceProvider(sp);
								_systemLogger.log(Level.INFO, _sModule, sMethod, "UPD SSO session " + ssoSession);
								htTGTContext.put("sso_session", ssoSession);
							}

							// Overwrite with the latest value of sp_assert_url,
							// so the customer can reach his home-SP again.
							Utils.copyHashmapValue("sp_assert_url", htTGTContext, _htSessionContext);

							_tgtManager.updateTGT(sTgt, htTGTContext);
							_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR " + sRedirectUrl);

							// 20090313, Bauke: add info screen for the user, shows SP's already logged in
							ASelectConfigManager configManager = ASelectConfigManager.getHandle();
							if (spIssuer != null && configManager.getUserInfoSettings().contains("session"))
								showSessionInfo(htServiceRequest, servletResponse, pwOut, sRedirectUrl, sTgt,
										htTGTContext, sRid, spIssuer);
							else {
								TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
								oTGTIssuer.sendRedirect(sRedirectUrl, sTgt, sRid, servletResponse);
								_sessionManager.killSession(sRid);
							}
							return;
						}
					}
					// TGT found but not sufficient or forced_authenticate
					_systemLogger.log(Level.INFO, _sModule, sMethod, "TGT found but not sufficient");

					if (!handleUserConsent(htServiceRequest, servletResponse, pwOut, sRid))
						return; // No consent, Quit

					// Authenicate with same user-id that was stored in TGT
					HashMap htTGTContext = _tgtManager.getTGT(sTgt);

					// If TGT was issued in cross mode, the user now has to
					// authenticate with a higher level in cross mode again
					String sTempOrg = (String) htTGTContext.get("proxy_organization");
					if (sTempOrg == null)
						sTempOrg = (String) htTGTContext.get("organization");
					if (!sTempOrg.equals(_sMyOrg) && // 20090111, Bauke Added test below:
							_crossASelectManager.isCrossSelectorEnabled() && _configManager.isCrossFallBackEnabled()) {
						_htSessionContext.put("forced_uid", sUid);
						_htSessionContext.put("forced_organization", sTempOrg);
						_systemLogger.log(Level.INFO, _sModule, sMethod, "To CROSS MyOrg=" + _sMyOrg + " != org="
								+ sTempOrg);
						handleCrossLogin(htServiceRequest, servletResponse, pwOut);
						return;
					}
					// User was originally authenticated at this A-Select Server
					// The userid is already known from the TGT
					htServiceRequest.put("user_id", sUid);
					handleLogin2(htServiceRequest, servletResponse, pwOut);
					return;
				}
			}
			_systemLogger.log(Level.INFO, _sModule, sMethod, "no TGT found or killed (other uid)");
			if (!handleUserConsent(htServiceRequest, servletResponse, pwOut, sRid))
				return; // Quit

			// 20090120, Bauke store Client IP and User Agent in the Session
			// Note the current session is available through _htSessionContext
			Utils.copyHashmapValue("client_ip", _htSessionContext, htServiceRequest);
			Utils.copyHashmapValue("user_agent", _htSessionContext, htServiceRequest);
			// TODO: could be that handleUserConsent() also saved the session, should be optimized
			_sessionManager.update(sRid, _htSessionContext); // Will also update SensorData changed in
			// handleUserConsent()

			// no TGT found or killed (other uid)
			if (!_configManager.isUDBEnabled() || _htSessionContext.containsKey("forced_organization")) {
				_systemLogger.log(Level.INFO, _sModule, sMethod, "To Cross 2");
				handleCrossLogin(htServiceRequest, servletResponse, pwOut);
				return;
			}
			String sForcedUid = (String) _htSessionContext.get("forced_uid");
			String sForcedAuthsp = (String) _htSessionContext.get("forced_authsp");
			if (sForcedUid != null || sForcedAuthsp != null) {
				if (sForcedUid != null)
					htServiceRequest.put("user_id", sForcedUid);
				if (sForcedAuthsp != null)
					htServiceRequest.put("forced_authsp", sForcedAuthsp);
				handleLogin2(htServiceRequest, servletResponse, pwOut);
				return;
			}

			// Show login (user_id) form
			_systemLogger.log(Level.INFO, _sModule, sMethod, "show LOGIN form");
			String sLoginForm = _configManager.getForm("login", _sUserLanguage, _sUserCountry);
			sLoginForm = Utils.replaceString(sLoginForm, "[rid]", sRid);
			sLoginForm = Utils.replaceString(sLoginForm, "[aselect_url]", (String) htServiceRequest.get("my_url"));
			sLoginForm = Utils.replaceString(sLoginForm, "[a-select-server]", _sMyServerId);
			sLoginForm = Utils.replaceString(sLoginForm, "[request]", "login2");
			sLoginForm = Utils.replaceString(sLoginForm, "[cross_request]", "cross_login");

			sbUrl = new StringBuffer((String) htServiceRequest.get("my_url")).append("?request=error").append(
					"&result_code=").append(Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=").append(
					_sMyServerId).append("&rid=").append(sRid);
			sLoginForm = Utils.replaceString(sLoginForm, "[cancel]", sbUrl.toString());
			sLoginForm = _configManager.updateTemplate(sLoginForm, _htSessionContext);
			servletResponse.setContentType("text/html");
			pwOut.println(sLoginForm);
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
	 * Show session info.
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @param sRedirectUrl
	 *            the s redirect url
	 * @param sTgt
	 *            the s tgt
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param sRid
	 *            the s rid
	 * @param spUrl
	 *            the sp url
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void showSessionInfo(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut,
			String sRedirectUrl, String sTgt, HashMap htTGTContext, String sRid, String spUrl)
		throws ASelectException
	{
		final String sMethod = "showSessionInfo";
		long now = new Date().getTime();

		_systemLogger.log(Level.INFO, _sModule, sMethod, "redirect url=" + sRedirectUrl);
		String sInfoForm = _configManager.getForm("session_info", _sUserLanguage, _sUserCountry);
		sInfoForm = Utils.replaceString(sInfoForm, "[aselect_url]", sRedirectUrl);
		sInfoForm = Utils.replaceString(sInfoForm, "[a-select-server]", _sMyServerId);
		sInfoForm = Utils.replaceString(sInfoForm, "[rid]", sRid);

		String sEncryptedTgt = (sTgt == null) ? "" : _cryptoEngine.encryptTGT(Utils.hexStringToByteArray(sTgt));
		sInfoForm = Utils.replaceString(sInfoForm, "[aselect_credentials]", sEncryptedTgt);

		String sCreateTime = (String) htTGTContext.get("createtime");
		long lCreateTime = 0;
		try {
			lCreateTime = Long.parseLong(sCreateTime);
		}
		catch (Exception exc) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "CreateTime was not set");
		}

		ASelectConfigManager oConfigManager = ASelectConfigManager.getHandle();
		Object oTicketSection = oConfigManager.getSection(null, "storagemanager", "id=tgt");
		String sTimeOut = ASelectConfigManager.getSimpleParam(oTicketSection, "timeout", false);
		if (sTimeOut != null) {
			long timeOutTime = Long.parseLong(sTimeOut);
			timeOutTime = timeOutTime * 1000;
			long secondsToGo = (lCreateTime + timeOutTime - now) / 1000;
			long minutesToGo = secondsToGo / 60;
			if (minutesToGo < 0)
				minutesToGo = 0;
			long hoursToGo = minutesToGo / 60;
			minutesToGo -= 60 * hoursToGo;
			sInfoForm = Utils.replaceString(sInfoForm, "[hours_left]", Long.toString(hoursToGo));
			sInfoForm = Utils.replaceString(sInfoForm, "[minutes_left]", String.format("%02d", minutesToGo));
		}
		String sFriendlyName = ApplicationManager.getHandle().getFriendlyName(spUrl);
		if (sFriendlyName == null)
			sFriendlyName = spUrl;
		sInfoForm = Utils.replaceString(sInfoForm, "[current_sp]", sFriendlyName);

		String sOtherSPs = "";
		UserSsoSession ssoSession = (UserSsoSession) htTGTContext.get("sso_session");
		if (ssoSession != null) {
			List<ServiceProvider> spList = ssoSession.getServiceProviders();
			for (ServiceProvider sp : spList) {
				String sOtherUrl = sp.getServiceProviderUrl();
				if (!spUrl.equals(sOtherUrl)) {
					sFriendlyName = ApplicationManager.getHandle().getFriendlyName(sOtherUrl);
					if (sFriendlyName == null)
						sFriendlyName = sOtherUrl;
					sOtherSPs += sFriendlyName + "<br/>";
				}
			}
		}
		sInfoForm = Utils.replaceString(sInfoForm, "[other_sps]", sOtherSPs);
		sInfoForm = _configManager.updateTemplate(sInfoForm, _htSessionContext);
		servletResponse.setContentType("text/html");
		pwOut.println(sInfoForm);
	}

	// Return: true when user consent is already available, else false
	//
	/**
	 * Handle user consent.
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @param sRid
	 *            the s rid
	 * @return true, if successful
	 * @throws ASelectException
	 *             the a select exception
	 */
	private boolean handleUserConsent(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut,
			String sRid)
		throws ASelectException
	{
		String COOKIE_NAME = "user_consent";
		final String sMethod = "handleUserConsent";

		ASelectConfigManager configManager = ASelectConfigManager.getHandle();
		String sUserInfo = configManager.getUserInfoSettings();
		if (!sUserInfo.contains("consent")) // No "consent" or "save_consent"
			return true;

		Boolean setConsentCookie = sUserInfo.contains("save_consent");
		if (setConsentCookie) {
			String sUserConsent = HandlerTools.getCookieValue(_servletRequest, COOKIE_NAME, _systemLogger);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "user_consent=" + sUserConsent);
			if (sUserConsent != null && sUserConsent.equals("true"))
				return true;
		}
		// "consent" or "save_consent" is present

		// We need the user's consent to continue
		String sReqConsent = (String) htServiceRequest.get("consent");
		if ("true".equals(sReqConsent) || "false".equals(sReqConsent)) {
			Tools.resumeSensorData(_systemLogger, _htSessionContext);
			_sessionManager.update(sRid, _htSessionContext); // Write session
		}
		if ("true".equals(sReqConsent)) { // new consent given
			if (setConsentCookie) {
				// Remember the user's answer by setting a Consent Cookie
				String sCookieDomain = _configManager.getCookieDomain();
				HandlerTools.putCookieValue(servletResponse, COOKIE_NAME, "true", sCookieDomain, 157680101,
						_systemLogger); // some 5 years
			}
			return true;
		}
		if ("false".equals(sReqConsent)) { // User did not give his consent
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_CANCEL);
		}

		// Display the consent form
		Tools.pauseSensorData(_systemLogger, _htSessionContext);
		_sessionManager.update(sRid, _htSessionContext); // Write session
		String sFriendlyName = "";
		try {
			Object aselect = _configManager.getSection(null, "aselect");
			sFriendlyName = ASelectConfigManager.getSimpleParam(aselect, "organization_friendly_name", false);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Configuration error: " + e);
		}
		// Ask for consent by presenting the userconsent.html form
		try {
			_sConsentForm = _configManager.loadHTMLTemplate(_configManager.getWorkingdir(), "userconsent",
					_sUserLanguage, _sUserCountry);
			_sConsentForm = Utils.replaceString(_sConsentForm, "[version]", Version.getVersion());
			_sConsentForm = Utils.replaceString(_sConsentForm, "[organization_friendly]", sFriendlyName);
			_sConsentForm = Utils.replaceString(_sConsentForm, "[request]", "login1");
			_sConsentForm = Utils.replaceString(_sConsentForm, "[rid]", sRid);
			_sConsentForm = Utils.replaceString(_sConsentForm, "[a-select-server]", _sMyServerId);
			_sConsentForm = Utils.replaceString(_sConsentForm, "[consent]", "true");

			String sAsUrl = _configManager.getRedirectURL();
			_sConsentForm = Utils.replaceString(_sConsentForm, "[aselect_url]", sAsUrl);
			StringBuffer sCancel = new StringBuffer(sAsUrl).append("?request=login1").append("&rid=").append(sRid)
					.append("&a-select-server=").append(_sMyServerId).append("&consent=false");
			_sConsentForm = Utils.replaceString(_sConsentForm, "[cancel]", sCancel.toString());

			servletResponse.setContentType("text/html");
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Display ConsentForm");
			pwOut.println(_sConsentForm);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to display ConsentForm: ", e);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
			}
		}
		return false; // means: Consent Form displayed, no consent available yet
	}

	/**
	 * Handles the <code>request=login2</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The request created by the HTML page presented by the <code>handleLogin1</code> function, is verified here.<br>
	 * For the entered user-id a lookup is done in the user database to determine all enabled AuthSP's for this user.
	 * For every AuthSP a verification is done if it matches the required level.<br>
	 * All valid AuthSP's are presnted to the user by means of a 'drop-down' list in a HTML page. This HTML page will
	 * POST a <code>request=login3</code>.<br>
	 * Depending on the A-Select configuration <code>always_show_select_form</code> the request can be parsed to
	 * <code>handleLogin3()</code> immediately if only one valid AuthSP is found. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogin2(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
		throws ASelectException
	{
		String sRid = null;
		String sUid = null;
		String sMethod = "handleLogin2()";

		StringBuffer sb;
		_systemLogger.log(Level.INFO, _sModule, sMethod, "Login2 " + htServiceRequest);
		try {
			sRid = (String) htServiceRequest.get("rid");
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			String sAuthsp = (String) htSessionContext.get("forced_authsp"); // 20090111, Bauke from SessionContext not
			// ServiceRequest
			if (sAuthsp != null) {
				// Bauke 20080511: added
				// Redirect to the AuthSP's ISTS
				String sAsUrl = _configManager.getRedirectURL(); // <redirect_url> in aselect.xml
				sAsUrl = sAsUrl + "/" + sAuthsp + "?rid=" + sRid; // e.g. saml20_ists
				_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR to " + sAsUrl + " forced_authsp=" + sAuthsp);
				servletResponse.sendRedirect(sAsUrl);
				return;
			}
			// Has done it's work if present, note that getAuthsps() will store the session
			htSessionContext.remove("forced_uid");

			sUid = (String) htServiceRequest.get("user_id");
			if (sUid == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request, missing parmeter 'user_id'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// If uid contains any spaces, they where transformed to '+'
			// Now first set it back to spaces
			try {
				sUid = URLDecoder.decode(sUid, "UTF-8");
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to decode user id.");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}

			try {
				getAuthsps(sRid, sUid);
			}
			catch (ASelectException e) {
				if (_crossASelectManager.isCrossSelectorEnabled() && _configManager.isCrossFallBackEnabled()) {
					handleCrossLogin(htServiceRequest, servletResponse, pwOut);
					return;
				}
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve AuthSPs of user " + sUid);
				throw e;
			}

			// Bauke: added shortcut when using "Verkeersplein" method
			String sFixedAuthsp = (String) _htSessionContext.get("fixed_authsp");
			if (sFixedAuthsp != null) {
				_systemLogger.log(Level.INFO, _sModule, sMethod, "fixed_authsp=" + sFixedAuthsp);
				htServiceRequest.put("authsp", sFixedAuthsp);
				// Also save entered uid as 'sel_uid'
				String sUserId = (String) _htSessionContext.get("user_id");
				if (sUserId != null) {
					htServiceRequest.put("sel_uid", sUserId);
					_htSessionContext.put("sel_uid", sUserId);
				}
				String sFixedUid = (String) _htSessionContext.get("fixed_uid");
				if (sFixedUid != null) {
					// From here on use the fixed_uid as 'user_id'
					_systemLogger.log(Level.INFO, _sModule, sMethod, "Fixed user_id=" + sFixedUid);
					htServiceRequest.put("user_id", sFixedUid);
					_htSessionContext.put("user_id", sFixedUid);
				}
				handleLogin3(htServiceRequest, servletResponse, pwOut);
				return;
			}

			// We now have the list of authsps that the user may use
			// Show the selectform
			HashMap htAuthsps = (HashMap) _htSessionContext.get("allowed_user_authsps");
			// should the user be bothered with the selection form
			// if it is only able to choose from 1 method?
			_systemLogger.log(Level.INFO, _sModule, sMethod, "User=" + sUid + " Authsps=" + htAuthsps);
			if (htAuthsps.size() == 1) {
				try {
					String sFormShow = _configManager.getParam(_configManager.getSection(null, "authsps"),
							"always_show_select_form");
					if (sFormShow.equalsIgnoreCase("false")) {
						// continue with login3
						Set keys = htAuthsps.keySet();
						for (Object s : keys) {
							htServiceRequest.put("authsp", (String) s);
							break;
						}
						handleLogin3(htServiceRequest, servletResponse, pwOut);
						return;
					}
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod,
							"Failed to retrieve config 'always_show_select_form'. Using default (yes).");
				}
			}
			// end only 1 valid authsp

			// Multiple candidates, present the select.html form
			String sSelectForm = _configManager.getForm("select", _sUserLanguage, _sUserCountry);
			sSelectForm = Utils.replaceString(sSelectForm, "[rid]", sRid);
			sSelectForm = Utils.replaceString(sSelectForm, "[a-select-server]", _sMyServerId);
			sSelectForm = Utils.replaceString(sSelectForm, "[user_id]", sUid);
			sSelectForm = Utils.replaceString(sSelectForm, "[aselect_url]", (String) htServiceRequest.get("my_url"));
			sSelectForm = Utils.replaceString(sSelectForm, "[request]", "login3");

			String sFriendlyName = "";
			String sAuthspName = "";
			sb = new StringBuffer();

			Set<String> keys = htAuthsps.keySet();
			for (Object s : keys) {
				sAuthspName = (String) s;
				try {
					Object authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"),
							"authsp", "id=" + sAuthspName);
					sFriendlyName = _configManager.getParam(authSPsection, "friendly_name");
					sb.append("<OPTION VALUE=").append(sAuthspName).append(">");
					sb.append(sFriendlyName);
					sb.append("</OPTION>");
				}
				catch (ASelectConfigException ace) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve config for AuthSPs.");
					throw ace;
				}
			}
			sSelectForm = Utils.replaceString(sSelectForm, "[allowed_user_authsps]", sb.toString());

			// Create the Cancel action:
			sb = new StringBuffer((String) htServiceRequest.get("my_url")).append("?request=error").append(
					"&result_code=").append(Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=").append(
					_sMyServerId).append("&rid=").append(sRid);

			sSelectForm = Utils.replaceString(sSelectForm, "[cancel]", sb.toString());
			sSelectForm = _configManager.updateTemplate(sSelectForm, _htSessionContext);
			// _systemLogger.log(Level.FINER, _sModule, sMethod, "Form select=["+sSelectForm+"]");
			pwOut.println(sSelectForm);
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
	 * This methods handles the <code>request=login3</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The user has now chosen a method for authentication and is ready to be redirected to the AuthSP's authentication
	 * page. <br>
	 * The protocol handler for the AuthSP is instantiated and that object will compute the request for authentication
	 * (e.g., it will also sign the request). The actual method that does this is <code>startAuthentication</code>.<br>
	 * If everything is ok, the user is redirected through the <code>servletResponse.sendRedirect()</code> method with a
	 * signed request for the AuthSP. <br>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogin3(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
		throws ASelectException
	{
		String sRid = null;
		String sAuthsp = null;
		String sMethod = "handleLogin3";
		String sRedirectUrl = null;
		String sPopup = null;

		_systemLogger.log(Level.INFO, _sModule, sMethod, "Login3 " + htServiceRequest);
		try {
			sRid = (String) htServiceRequest.get("rid");
			sAuthsp = (String) htServiceRequest.get("authsp");
			if (sAuthsp == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request, missing parmeter 'authsp'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			sRedirectUrl = startAuthentication(sRid, htServiceRequest);

			try {
				Object authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp",
						"id=" + sAuthsp);
				try {
					sPopup = _configManager.getParam(authSPsection, "popup");
				}
				catch (ASelectConfigException e) {
					// No popup configured -> sPopup is null allready
				}
				_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR " + sRedirectUrl);
				if (sPopup == null || sPopup.equalsIgnoreCase("false")) {
					servletResponse.sendRedirect(sRedirectUrl);
					return;
				}

				// must use popup so show the popup page
				String sPopupForm = _configManager.getForm("popup", _sUserLanguage, _sUserCountry);
				sPopupForm = Utils.replaceString(sPopupForm, "[authsp_url]", sRedirectUrl);
				String strFriendlyName = _configManager.getParam(authSPsection, "friendly_name");
				sPopupForm = Utils.replaceString(sPopupForm, "[authsp]", strFriendlyName);
				sPopupForm = _configManager.updateTemplate(sPopupForm, _htSessionContext);
				pwOut.println(sPopupForm);
				return;
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve config for AuthSPs.");
				throw new ASelectException(e.getMessage());
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to redirect user.");
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
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
	 * This method handles the <code>request=cross_login</code> user request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * If the user already has a tgt and it is valid for the current application, then the user does not need be
	 * authenticated again. The user is redirected back to the application. If the user's tgt is not valid, then the
	 * remote A-Select Server is contacted by sending a <code>request=cross_authenticate_aselect</code> request. If the
	 * remote A-Select Server is contacted successfully, the user is redirected to him so that the user can be
	 * authenticated there. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            PrintWriter that might be needed by the <code>ISelectorHandler</code>
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleCrossLogin(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
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
			_systemLogger.log(Level.INFO, _sModule, sMethod, "XLOGIN sLocalRid=" + sLocalRid + ", intAppLevel="
					+ intAppLevel + ", sRemoteOrg=" + sRemoteOrg + ", forced_uid=" + sUid);

			if (sRemoteOrg == null) {
				if (!_crossASelectManager.isCrossSelectorEnabled()) {
					_systemLogger
							.log(Level.WARNING, _sModule, sMethod,
									"Dynamic 'cross_selector' is disabled, parameter 'remote_organization' is required but not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG);
				}

				// No optional parameter 'remote_organization found
				// Determine the remote organization
				HashMap htIdentification;

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
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve the remote server id.");
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG, ace);
				}
				if (htIdentification == null) {
					_systemLogger.log(Level.INFO, _sModule, sMethod, "XLOGIN !htIdentification");
					// The handler was not ready yet and presented a HTML form
					// to the end user to gather more information
					// this form will POST 'request=cross_authenticate' again.
					return;
				}
				sRemoteOrg = (String) htIdentification.get("organization_id");
				String sTemp = (String) htIdentification.get("user_id");
				_systemLogger.log(Level.INFO, _sModule, sMethod, "XLOGIN htIdentification=" + htIdentification);

				// Selector handler might have translated the user_id
				if (sTemp != null)
					sUid = (String) htIdentification.get("user_id");
			}
			_htSessionContext.put("remote_organization", sRemoteOrg);

			// storage_manager_fix_for_lost_fields
			if (!_sessionManager.updateSession(sLocalRid, _htSessionContext)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "could not update session context");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

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
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.");
				throw ase;
			}
			catch (ASelectConfigException ace) {
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read config.");
				throw ace;
			}

			StringBuffer sbMyAppUrl = new StringBuffer();
			sbMyAppUrl.append((String) htServiceRequest.get("my_url"));
			sbMyAppUrl.append("?local_rid=").append(sLocalRid);

			RawCommunicator oCommunicator = new RawCommunicator(_systemLogger); // Default = API communciation

			HashMap htRequestTable = new HashMap();
			HashMap htResponseTable = new HashMap();
			htRequestTable.put("request", "authenticate");

			Boolean boolForced = (Boolean) _htSessionContext.get("forced_authenticate"); // a Boolean
			if (boolForced == null)
				boolForced = false;
			htRequestTable.put("forced_logon", boolForced.toString()); // and this is a String!
			htRequestTable.put("local_as_url", sbMyAppUrl.toString());

			Object oASelectConfig = _configManager.getSection(null, "aselect");
			String sMyOrgId = _configManager.getParam(oASelectConfig, "organization");
			htRequestTable.put("local_organization", sMyOrgId);

			Integer intLevel = (Integer) _htSessionContext.get("level");
			htRequestTable.put("required_level", intLevel.toString());
			htRequestTable.put("level", intLevel); // 20090111, Bauke added
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
			_systemLogger.log(Level.INFO, _sModule, sMethod, "XLOGIN htRequestTable=" + htRequestTable);

			htResponseTable = oCommunicator.sendMessage(htRequestTable, sRemoteAsUrl);
			if (htResponseTable.isEmpty()) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not reach remote A-Select Server: "
						+ sRemoteAsUrl);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, _sModule, sMethod, "XLOGIN htResponseTable=" + htResponseTable);

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

				_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR " + sbUrl);
				servletResponse.sendRedirect(sbUrl.toString());
			}
			catch (IOException e) {
				StringBuffer sbWarning = new StringBuffer("Failed to redirect user to: ");
				sbWarning.append(sRemoteServer);
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
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
	 * This method handles the <code>request=ip_login</code> user request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The request can be used to authenticate user by means of the IP AuthSP without the need to know a user-id. If the
	 * user already has a tgt and it is valid for the current application, then the user does not need be authenticated
	 * again. The user is redirected back to the application. If everything is ok, the request is forwarded to
	 * <code>handleLogin3()</code> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             TODO add support for cross and force_authenticate (martijn)
	 */
	private void handleIPLogin1(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
		throws ASelectException
	{
		String sMethod = "handleIPLogin1()";
		String sRid = null;
		Integer intRequiredLevel = null;
		String sLevel = null;
		HashMap htAllowedAuthsps = new HashMap();

		StringBuffer sb;

		_systemLogger.log(Level.INFO, _sModule, sMethod, "IPLogin1");
		try {
			sRid = (String) htServiceRequest.get("rid");

			// check if user already has a tgt so that he/she doesnt need to
			// be authenticated again

			// TODO IP login is not used when a user already has a TGT (Peter)
			// IP login is not used when a user already has a TGT. The origin
			// ip-range will never be forced when already authenticated with an
			// AuthSP with a higher level
			if (_configManager.isSingleSignOn() && htServiceRequest.containsKey("aselect_credentials_tgt")
					&& htServiceRequest.containsKey("aselect_credentials_uid")
					&& htServiceRequest.containsKey("aselect_credentials_server_id")) {
				String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
				String sUid = (String) htServiceRequest.get("aselect_credentials_uid");
				String sServerId = (String) htServiceRequest.get("aselect_credentials_server_id");

				// TODO Check if TGT already exists for user id (Peter)
				// If a user_id was provided in the request
				// we have to check here if the already existing
				// TGT is for the same user-id
				// see CVS
				if (checkCredentials(sTgt, sUid, sServerId)) {

					// redirect to application as user has already a valid tgt
					if (_htSessionContext.get("cross_authenticate") != null) {
						// redirect to application as user has already a valid
						// tgt
						if (_htSessionContext.get("cross_authenticate") != null) {
							// Cross A-Select does not implement 'verify_credentials'
							// The TGT should be created now, TGTIssuer will redirect to local A-Select Server

							// TODO Check if a new TGT must be created (Peter)
							// A new TGT is created because the TGTIssuer implements the redirect with a create
							// signature.
							// It is not logical to create a new TGT.
							_htSessionContext.put("user_id", sUid);

							// RH, should be set through AbstractBrowserRequestHandler
							// but this seems to be the wrong one (AbstractBrowserRequestHandler sets the idp address)
							_systemLogger.log(Level.INFO, _sModule, sMethod, "_htSessionContext client_ip was "
									+ _htSessionContext.get("client_ip"));
							_htSessionContext.put("client_ip", get_servletRequest().getRemoteAddr());
							_systemLogger.log(Level.INFO, _sModule, sMethod, "_htSessionContext client_ip is now "
									+ _htSessionContext.get("client_ip"));

							_sessionManager.writeSession(sRid, _htSessionContext);

							HashMap htTgtContext = _tgtManager.getTGT(sTgt);
							String sAuthsp = (String) htTgtContext.get("authsp");

							// kill existing tgt
							_tgtManager.remove(sTgt);

							// issue new one but with the same lifetime as the existing one
							HashMap htAdditional = new HashMap();
							// FIXME StorageManager can't update timestamp, this doesn't work. (Erwin, Peter)
							// htAdditional.put("tgt_exp_time", htTgtContext.get("tgt_exp_time"));

							TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
							oTGTIssuer.issueTGT(sRid, sAuthsp, htAdditional, servletResponse, null);
							return;
						}
					}

					try {
						String sRedirectUrl = (String) _htSessionContext.get("app_url");
						sRedirectUrl = URLDecoder.decode(sRedirectUrl, "UTF-8");
						sb = new StringBuffer(sRedirectUrl);

						// check whether the application url contains cgi parameters
						if (sRedirectUrl.indexOf("?") > 0) {
							sb.append("&");
						}
						else {
							sb.append("?");
						}

						sUid = URLEncoder.encode(sUid, "UTF-8");
						sUid = URLEncoder.encode(sUid, "UTF-8");

						String sEncTgt = CryptoEngine.getHandle().encryptTGT(Utils.hexStringToByteArray(sTgt));
						sb.append("aselect_credentials=").append(sEncTgt);
						sb.append("_").append(sUid).append("_");
						sb.append(sServerId);
						sb.append("&rid=").append(sRid);

						_sessionManager.killSession(sRid);

						_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR " + sb);
						servletResponse.sendRedirect(sb.toString());
					}
					catch (UnsupportedEncodingException e) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to encode user id.");
						throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
					}
					catch (IOException e) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to redirect user.");
						throw new ASelectException(Errors.ERROR_ASELECT_IO, e);
					}
				}
			}

			// get the required level of the application
			intRequiredLevel = _applicationManager.getRequiredLevel((String) _htSessionContext.get("app_id"));

			// check if IP AuthSP is enabled
			Object authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp",
					"id=Ip");

			sLevel = _configManager.getParam(authSPsection, "level");

			if (sLevel == null || Integer.parseInt(sLevel) < intRequiredLevel.intValue()) {
				sb = new StringBuffer(sMethod);
				sb.append("Could not perform IP authentication. Reason : ");

				// log this error in system log
				if (sLevel == null) {
					sb.append("The IP AuthSP is not (properly) configured.");
				}
				else {
					sb.append("The IP authsp security level is too low for application '"
							+ (String) _htSessionContext.get("app_id") + "'.");
				}
				_systemLogger.log(Level.INFO, _sModule, sMethod, sb.toString());

				throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}
			htAllowedAuthsps.put("Ip", htServiceRequest.get("client_ip"));
			_htSessionContext.put("allowed_user_authsps", htAllowedAuthsps);
			_htSessionContext.put("user_id", htServiceRequest.get("client_ip"));
			_sessionManager.writeSession(sRid, _htSessionContext);

			// go for IP authsp
			htServiceRequest.put("authsp", "Ip");
			handleLogin3(htServiceRequest, servletResponse, pwOut);
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
	 * This method handles the <code>request=logout</code> user request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The request can be used to logout a user by destroying his/her TGT. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * Valid TGT <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * TGT is destroyed <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogout(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
		throws ASelectException
	{
		String sMethod = "handleLogout";
		String sLoggedOutForm = _configManager.getForm("loggedout", _sUserLanguage, _sUserCountry);

		try {
			String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
			HashMap htTGTContext = _tgtManager.getTGT(sTgt);

			if (htTGTContext != null) {
				_tgtManager.remove(sTgt);

				String sCookieDomain = _configManager.getCookieDomain();
				HandlerTools.delCookieValue(servletResponse, "aselect_credentials", sCookieDomain, _systemLogger);

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
						_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.");
						sRemoteAsUrl = null;
					}
				}
				_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR " + sRemoteAsUrl + "," + " _sMyOrg=" + _sMyOrg
						+ ", sRemoteOrg=" + sRemoteOrg);
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
	 * This method handles the <code>request=create_tgt</code> user request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This request can be used to create TGTs for users without actually authentication them. This can only be used by
	 * priviliged applications which simply redirect the user with the correct information to the A-Select-Server with
	 * the request to create a TGT. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * Signed request and a valid public key located in the priviliged keystore <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * A TGT wil be created <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleCreateTGT(HashMap htServiceRequest, HttpServletResponse servletResponse)
		throws ASelectException
	{
		String sMethod = "handleCreateTGTRequest()";
		AuthenticationLogger authenticationLogger = ASelectAuthenticationLogger.getHandle();

		_systemLogger.log(Level.INFO, _sModule, sMethod, "CreateTGTRequest");
		try {
			// get output writer
			// Read expected parameters
			String sRid = (String) htServiceRequest.get("rid");
			String sUID = (String) htServiceRequest.get("uid");
			String sPrivilegedApplication = (String) htServiceRequest.get("app_id");
			String sSignature = (String) htServiceRequest.get("signature");
			String sAuthspLevel = (String) htServiceRequest.get("level"); // NOTE: String!!

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
			catch (UnsupportedEncodingException eUE) { // Interne fout UTF-8 niet ondersteund
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error: request could not be decoded");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			StringBuffer sbBuffer = new StringBuffer();
			sbBuffer.append(sRid).append(sUID);
			sbBuffer.append(sPrivilegedApplication).append(sAuthspLevel);
			if (!CryptoEngine.getHandle().verifyPrivilegedSignature(sPrivilegedApplication, sbBuffer.toString(),
					sSignature)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Application:" + sPrivilegedApplication
						+ " Invalid signature:" + sSignature);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Get session context
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
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
			TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
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
	 * Get the AuthSP servers. Private method that fetches the authentication service providers from the user database
	 * of the A-Select Servers. The user may have been registered or entitled to use several authentication service
	 * providers. But only the ones that satisfy the level for the current application are returned by filtering the
	 * authsp's with lower levels out.
	 * 
	 * @param sRid
	 *            The RID.
	 * @param sUid
	 *            the s uid
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void getAuthsps(String sRid, String sUid)
		throws ASelectException
	{
		String sMethod = "getAuthsps";
		HashMap htUserAuthsps = new HashMap();

		try {
			IUDBConnector oUDBConnector = null;
			try {
				oUDBConnector = UDBConnectorFactory.getUDBConnector();
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to connect with UDB.", e);
				throw e;
			}

			HashMap htUserProfile = oUDBConnector.getUserProfile(sUid);
			if (!((String) htUserProfile.get("result_code")).equals(Errors.ERROR_ASELECT_SUCCESS)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to get user profile.");
				throw new ASelectException((String) htUserProfile.get("result_code"));
			}
			htUserAuthsps = (HashMap) htUserProfile.get("user_authsps");
			if (htUserAuthsps == null) {
				// should never happen
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "INTERNAL ERROR");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, _sModule, sMethod, "uid=" + sUid + " profile=" + htUserProfile
					+ " user_authsps=" + htUserAuthsps + " SessionContext=" + _htSessionContext);

			// which level is required for the application?
			// 20090110, Bauke added required_level!
			Integer intMaxLevel = (Integer) _htSessionContext.get("max_level"); // 'max_level' can be null
			Integer intLevel = (Integer) _htSessionContext.get("level");
			String sRequiredLevel = (String) _htSessionContext.get("required_level");

			Integer intRequiredLevel = (sRequiredLevel == null) ? intLevel : Integer.valueOf(sRequiredLevel);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "required_level=" + intRequiredLevel + " level="
					+ intLevel + " maxlevel=" + intMaxLevel);

			// fetch the authsps that the user has registered for and
			// satisfy the level for the current application
			Vector vAllowedAuthSPs;
			vAllowedAuthSPs = _authspHandlerManager.getConfiguredAuthSPs(intRequiredLevel, intMaxLevel);
			// getAllowedAuthSPs(intRequiredLevel.intValue(), htUserAuthsps);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Configured AuthSPs=" + vAllowedAuthSPs);
			if (vAllowedAuthSPs == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "INTERNAL ERROR" + sUid);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			HashMap htAllowedAuthsps = new HashMap();
			for (int i = 0; i < vAllowedAuthSPs.size(); i++) {
				String sAuthSP = (String) vAllowedAuthSPs.elementAt(i);
				if (htUserAuthsps.containsKey(sAuthSP)) {
					htAllowedAuthsps.put(sAuthSP, htUserAuthsps.get(sAuthSP));
				}
			}
			if (htAllowedAuthsps.size() == 0) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "No valid AuthSPs found for user: " + sUid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_USER_NOT_ALLOWED);
			}
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Allowed AuthSPs " + htAllowedAuthsps);

			_htSessionContext.put("allowed_user_authsps", htAllowedAuthsps);
			_htSessionContext.put("user_id", sUid);

			// RH, should be set through AbstractBrowserRequestHandler
			// but this seems to be the wrong one (AbstractBrowserRequestHandler
			// sets the idp address on the idp)
			_systemLogger.log(Level.INFO, _sModule, sMethod, "_htSessionContext client_ip was "
					+ _htSessionContext.get("client_ip"));
			_htSessionContext.put("client_ip", get_servletRequest().getRemoteAddr());
			_systemLogger.log(Level.INFO, _sModule, sMethod, "_htSessionContext client_ip is now "
					+ _htSessionContext.get("client_ip"));

			if (!_sessionManager.writeSession(sRid, _htSessionContext)) {
				// logged in sessionmanager
				throw new ASelectException(Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
			}
			return;// Errors.ERROR_ASELECT_SUCCESS;
		}
		catch (ASelectException e) {
			throw e;
		}
	}

	/**
	 * This method will instantiate the protocol handler for the selected AuthSP. The protocol handler will compose a
	 * redirect url and return it. This method will return this redirect url. Some AuthSP's will require a signed
	 * request from the A-Select Server. The protocol handler will be responsible for placing it.
	 * 
	 * @param sRid
	 *            The RID.
	 * @param htLoginRequest
	 *            The request parameters.
	 * @return The error code.
	 * @throws ASelectException
	 *             the a select exception
	 */
	private String startAuthentication(String sRid, HashMap htLoginRequest)
		throws ASelectException
	{
		String sMethod = "startAuthentication";
		HashMap htAllowedAuthsps;
		String sAuthsp = null;

		sAuthsp = (String) htLoginRequest.get("authsp");

		htAllowedAuthsps = (HashMap) _htSessionContext.get("allowed_user_authsps");
		if (htAllowedAuthsps == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "allowed_user_authsps not found in session context");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		if (!htAllowedAuthsps.containsKey(sAuthsp)) {
			StringBuffer sbError = new StringBuffer("Invalid/unknown authsp id in request: ");
			sbError.append(sAuthsp);
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbError.toString());
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		// _systemLogger.log(Level.INFO, _sModule, sMethod, "session="+_htSessionContext+" login="+htLoginRequest);
		_htSessionContext.put("authsp", sAuthsp);
		_htSessionContext.put("my_url", htLoginRequest.get("my_url"));

		// RH, should be set through AbstractBrowserRequestHandler
		// but this seems to be the wrong one (AbstractBrowserRequestHandler sets the idp address on the idp)
		_systemLogger.log(Level.INFO, _sModule, sMethod, "_htSessionContext client_ip was "
				+ _htSessionContext.get("client_ip") + ", set to " + get_servletRequest().getRemoteAddr());
		_htSessionContext.put("client_ip", get_servletRequest().getRemoteAddr());

		Tools.pauseSensorData(_systemLogger, _htSessionContext);
		if (!_sessionManager.writeSession(sRid, _htSessionContext)) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not write session context");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		// everything seems okay -> instantiate the protocol handler for
		// the selected authsp and let it compute a signed authentication request
		IAuthSPProtocolHandler oProtocolHandler;
		try {
			Object oAuthSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp",
					"id=" + sAuthsp);

			String sHandlerName = _configManager.getParam(oAuthSPsection, "handler");

			Class oClass = Class.forName(sHandlerName);
			oProtocolHandler = (IAuthSPProtocolHandler) oClass.newInstance();

			// Get authsps config and retrieve active resource from SAMAgent
			String strRG = _configManager.getParam(oAuthSPsection, "resourcegroup");
			SAMResource mySAMResource = ASelectSAMAgent.getHandle().getActiveResource(strRG);
			Object objAuthSPResource = mySAMResource.getAttributes();
			oProtocolHandler.init(oAuthSPsection, objAuthSPResource);
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to retrieve config for AuthSPs.");
			throw new ASelectException(e.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to initialize handler AuthSPHandler.");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		// let the protocol handler for the authsp do its work
		HashMap htResponse = oProtocolHandler.computeAuthenticationRequest(sRid);
		String sResultCode = (String) htResponse.get("result");
		if (sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
			return (String) htResponse.get("redirect_url");
		}
		_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to create redirect url.");
		throw new ASelectException(sResultCode);
	}

	/**
	 * Private method to check whether the user's tgt is valid and satisfies the required level for the current
	 * application. <br>
	 * 
	 * @param sTgt
	 *            The ticket granting ticket.
	 * @param sUid
	 *            The user ID.
	 * @param sServerId
	 *            The server ID.
	 * @return True if credentials are valid, otherwise false.
	 */
	private boolean checkCredentials(String sTgt, String sUid, String sServerId)
	{
		String sMethod = "checkCredentials()";
		HashMap htTGTContext;
		String sTGTLevel;
		Integer intRequiredLevel;

		htTGTContext = _tgtManager.getTGT(sTgt);
		if (htTGTContext == null) {
			return false;
		}
		if (!((String) htTGTContext.get("uid")).equals(sUid)) {
			return false;
		}
		if (!sServerId.equals(_sMyServerId)) {
			return false;
		}
		_systemLogger.log(Level.INFO, _sModule, sMethod, "checkCred SSO");

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
		_systemLogger.log(Level.INFO, _sModule, sMethod, "checkCred level, requires: " + intRequiredLevel);

		sTGTLevel = (String) htTGTContext.get("authsp_level");
		if (Integer.parseInt(sTGTLevel) >= intRequiredLevel.intValue()) {
			return true;
		}
		// user did have a tgt but the level is not high enough
		// so continue authenticate
		return false;
	}

	/**
	 * Show the user info contained in the TGT context of the user. Requires a valid TGT. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param response
	 *            the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void showUserInfo(HashMap htServiceRequest, HttpServletResponse response)
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

			String sUserInfoForm = _configManager.getForm("userinfo", _sUserLanguage, _sUserCountry);
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[uid]", sUserId);
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[a-select-server]", _sMyServerId);
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[aselect_url]", sMyUrl);

			String sTemp;
			HashMap htTGTContext = _tgtManager.getTGT(sTgt);
			try {
				long lExpTime = _tgtManager.getExpirationTime(sTgt);
				sTemp = new Date(lExpTime).toString();
				sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_exp_time]", sTemp);
			}
			catch (ASelectStorageException e) {
				sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_exp_time]", "[unknown]");
			}

			// In case the SAML20 logout procedure reaches this handler:
			String sEncTgt = CryptoEngine.getHandle().encryptTGT(Utils.hexStringToByteArray(sTgt));
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_blob]", sEncTgt);
			// End of SAML20 patch

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
				// 20090113, Bauke: This is only mandatory when we reached "organization" using cross!
				try {
					CrossASelectManager oCrossASelectManager = CrossASelectManager.getHandle();
					String sResourcegroup = oCrossASelectManager.getRemoteParam(sTemp, "resourcegroup");
					if (sResourcegroup != null) {
						SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
						Object oRemoteServer = oSAMResource.getAttributes();
						try {
							sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
						}
						catch (ASelectConfigException e) {
							_systemLogger.log(Level.INFO, _sModule, sMethod, "Remote url not available");
						}
					}
					else
						_systemLogger.log(Level.INFO, _sModule, sMethod, "Remote resourcegroup not available");
				}
				catch (ASelectException ae) {
					_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.");
				}
				catch (Exception ae) { // Bauke: added
					_systemLogger.log(Level.INFO, _sModule, sMethod, "Not a 'cross' organization: " + sTemp);
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
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Error writing output");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	// Bauke - Verkeersplein functionality added
	//
	/**
	 * Handle login25.
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogin25(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
		throws ASelectException
	{
		String sMethod = "handleLogin25()";
		String sRid = null;
		String sAuthsp = null;
		String sUid = null, sUserId = null, sForcedUid = null;

		try {
			sAuthsp = (String) htServiceRequest.get("authsp");
			sRid = (String) htServiceRequest.get("rid");
			sUid = (String) _htSessionContext.get("uid");
			sUserId = (String) _htSessionContext.get("user_id");
			sForcedUid = (String) _htSessionContext.get("forced_uid");
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Login25 uid=" + sUid + " user_id=" + sUserId
					+ " forced_uid=" + sForcedUid + " authsp=" + sAuthsp);
			if (sAuthsp == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request, missing parmeter 'authsp'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			if (sUid != null)
				_htSessionContext.remove("uid"); // forces the user to enter a user id
			if (sUserId != null)
				_htSessionContext.remove("user_id");
			if (sForcedUid != null)
				_htSessionContext.remove("forced_uid");
			_htSessionContext.put("fixed_authsp", sAuthsp); // must be present
			if (sForcedUid != null)
				_htSessionContext.put("fixed_uid", sForcedUid);

			if (!_sessionManager.updateSession(sRid, _htSessionContext)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Invalid request received: could not update session.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}
			_systemLogger.log(Level.INFO, _sModule, sMethod, "htSessionContext=" + _htSessionContext);
			handleLogin1(htServiceRequest, servletResponse, pwOut);
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}
}
