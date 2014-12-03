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
 * $Id: SFSSelectorHandler.java,v 1.1.2.9 2006/12/14 14:17:51 maarten Exp $
 * 
 * Changelog:
 * $Log: SFSSelectorHandler.java,v $
 * Revision 1.1.2.9  2006/12/14 14:17:51  maarten
 * Minor text changes
 *
 * Revision 1.1.2.8  2006/11/29 14:23:44  leon
 * small changes
 *
 * Revision 1.1.2.7  2006/11/29 12:22:01  maarten
 * Added multiple friendly name functionality
 *
 * Revision 1.1.2.6  2006/11/28 12:57:43  leon
 * fixed bug in SFSSelectorHandler.
 *
 * Revision 1.1.2.5  2006/09/29 09:02:53  maarten
 * Updated version
 *
 * Revision 1.1.2.4  2006/09/22 10:58:00  maarten
 * Updated version
 *
 * Revision 1.1.2.3  2006/09/05 14:39:18  leon
 * *** empty log message ***
 *
 * Revision 1.1.2.2  2006/09/05 08:43:28  maarten
 * Updated version
 *
 * Revision 1.1.2.1  2006/09/04 11:04:21  leon
 * 2 new cross selector handlers added
 *
 * Revision 1.3  2006/04/26 12:17:40  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.2  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.1.2.9  2006/04/07 07:58:29  leon
 * updated javadoc
 *
 * Revision 1.1.2.8  2006/04/06 11:19:15  martijn
 * again added update for optional application information in showAuthenticationForm()
 *
 * Revision 1.1.2.7  2006/04/06 07:50:30  leon
 * extra logging rule added
 *
 * Revision 1.1.2.6  2006/04/04 11:04:57  erwin
 * Removed warnings.
 *
 * Revision 1.1.2.5  2006/03/28 08:11:37  leon
 * *** empty log message ***
 *
 * Revision 1.1.2.4  2006/03/28 08:10:59  leon
 * small improvements added after unit testing
 *
 * Revision 1.1.2.3  2006/03/20 11:09:17  martijn
 * added optional template tag support
 *
 * Revision 1.1.2.2  2006/03/16 08:42:07  leon
 * removed unused import
 *
 * Revision 1.1.2.1  2006/02/15 08:11:17  leon
 * New Regex cross selector handler added
 *
 */

package org.aselect.server.cross.selectorhandler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.cross.ISelectorHandler;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;


/**
 * This class handles the remote A-Select Server selection by checking the user id against configured regular
 * expressions. <br>
 * <br>
 * <b>Description:</b> <br>
 * The submitted user_id will be checked against the configured regular expressions, on a match the user will be send to
 * the corresponding remote A-Select server.
 * 
 * @author Alfa & Ariss
 */

public class SFSSelectorHandler implements ISelectorHandler
{
	// Name of this module, used for logging
	private static final String MODULE = "SFSSelectorHandler";
	//private String _sCrossRegexSelectorPage;
	private String _sFriendlyName;
	private ASelectConfigManager _configManager;
	private ASelectSystemLogger _systemLogger;
	private HashMap _htSFSOrganizations = null;
	private Vector _vPatterns;
	private String _sMyServerId;
	private String _sMyOrgId;
	private CrossASelectManager _crossAselectManager;
	// RM_26_01
	private static final int COOKIE_AGE = 3153600;

	/**
	 * Initialization of this Handler. Initializes global class-variables that are needed within the whole handler
	 * instance.<br>
	 * <br>
	 * 
	 * @param oHandlerConfig
	 *            the o handler config
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.cross.ISelectorHandler#init(java.lang.Object)
	 */
	public void init(Object oHandlerConfig)
	throws ASelectException
	{
		String sMethod = "init";
		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			_configManager = ASelectConfigManager.getHandle();
			_vPatterns = new Vector();
			Object oExpressionsConfig = null;
			Object oRegexConfig = null;
			_htSFSOrganizations = new HashMap();
			_crossAselectManager = CrossASelectManager.getHandle();
			try {
				Object oASelectConfig = _configManager.getSection(null, "aselect");
				_sMyServerId = _configManager.getParam(oASelectConfig, "server_id");
				_sFriendlyName = _configManager.getParam(oASelectConfig, "organization_friendly_name");
				_sMyOrgId = _configManager.getParam(oASelectConfig, "organization");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to load basic A-Select configuration", e);
				throw new ASelectConfigException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			try {  // pre-load the default
				Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(), null/*subdir*/,
						"sfscrossselect", null/*language*/, _configManager.getOrgFriendlyName(), Version.getVersion());
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to load SFS Cross Selector HTML templates.", e);
				throw new ASelectConfigException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			try {
				oExpressionsConfig = _configManager.getSection(oHandlerConfig, "expressions");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'expressions' found.", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
			try {
				oRegexConfig = _configManager.getSection(oExpressionsConfig, "regex");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'regex found' in 'expressions'", e);
				throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
			}
			while (oRegexConfig != null) {
				HashMap htPattern = new HashMap();
				String sPattern = null;
				String sRemoteId = null;
				try {
					sPattern = _configManager.getParam(oRegexConfig, "value");
					sRemoteId = _configManager.getParam(oRegexConfig, "remote_organization");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No config item 'value' or 'remote_organization' found.", e);
					throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
				}
				try {
					Pattern oPattern = Pattern.compile(sPattern);
					htPattern.put("pattern", oPattern);
					htPattern.put("organization_id", sRemoteId);
					_vPatterns.add(htPattern);

				}
				catch (Exception e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Pattern '" + sPattern + "' is not a valid regex", e);
					throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
				}
				oRegexConfig = _configManager.getNextSection(oRegexConfig);
			}

			Object oSfsConfig = null;
			try {
				oSfsConfig = _configManager.getSection(null, "sfs");

			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No extra sfs configuration found, skipping.");
			}

			if (oSfsConfig != null) {
				try {
					Object oIdpCfg = null;

					try {
						oIdpCfg = _configManager.getSection(oSfsConfig, "idp");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.INFO, MODULE, sMethod,
								"No \"idp\" entries configured in \"sfs\" section.");
						oIdpCfg = null;
					}

					while (oIdpCfg != null) {
						HashMap ht = new HashMap();
						String sFriendlyName = _configManager.getParam(oIdpCfg, "friendly_name");
						ht.put("friendly_name", sFriendlyName);
						String sOrganization = _configManager.getParam(oIdpCfg, "organization");
						ht.put("organization", sOrganization);
						String sType = null;
						;
						try {
							sType = _configManager.getParam(oIdpCfg, "type");
							if (sType == null)
								sType = "aselect";
						}
						catch (Exception e) {
							sType = "aselect";
						}
						ht.put(("type"), sType);
						if (sType.equals("aselect")) {
							ht.put("relay", _configManager.getParam(oIdpCfg, "relay"));
							if (!sOrganization.equals(_sMyOrgId))
								_htSFSOrganizations.put(sFriendlyName, ht);
						}
						oIdpCfg = _configManager.getNextSection(oIdpCfg);
					}
				}
				catch (ASelectConfigException e) {
					throw e;
				}
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize the SFS selector handler", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Gets the home organization.
	 * 
	 * @param sHomeOrganization
	 *            the s home organization
	 * @return the home organization
	 */
	private HashMap getHomeOrganization(String sHomeOrganization)
	{
		HashMap htResult = null;

		Set keys = _htSFSOrganizations.keySet();
		for (Object s : keys) {
			String sFriendlyName = (String) s;
			// Enumeration enumSfsServers = _htSFSOrganizations.keys();
			// while (enumSfsServers.hasMoreElements()) {
			// String sFriendlyName = (String) enumSfsServers.nextElement();
			HashMap ht = (HashMap) _htSFSOrganizations.get(sFriendlyName);
			String sOrganization = (String) ht.get("organization");
			if (sOrganization.equals(sHomeOrganization)) {
				htResult = new HashMap();
				String sRelay = (String) ht.get("relay");
				if ((sRelay != null)) {
					// only useful for a-select
					htResult.put("organization_id", sRelay);
				}
				else {
					htResult.put("organization_id", sOrganization);
				}
				htResult.put("home_organization", sHomeOrganization);
				break;
			}
		}
		return htResult;
	}

	/**
	 * Returns the remote A-Select Server and optionally a user id. This handler will return <b>NULL</b> if no remote
	 * server is known yet (first time). Id no user_id is provided the user is presented a login form where he/she can
	 * submit his/her username, this will be matched against the configured regular expressions and on the first match
	 * the corresponding remote organization id will be put in a hashtable and returned to the A-Select subsystem. <br>
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @return the remote server id
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.cross.ISelectorHandler#getRemoteServerId(java.util.HashMap,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter)
	 */
	public HashMap getRemoteServerId(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "getRemoteServerId";
		String sErrorMessage = null;
		int i = 0;
		boolean matchFound = false;
		HashMap htResult = null;

		String sUsername = (String) htServiceRequest.get("user_id");
		String sRemoteServer = (String) htServiceRequest.get("remote_server");
		String sHomeOrganization = (String) htServiceRequest.get("home_organization");

		if (sUsername != null && !sUsername.trim().equals("")) {
			try {
				while (i < _vPatterns.size() && !matchFound) {
					HashMap htPattern = (HashMap) _vPatterns.get(i);
					Pattern oPattern = (Pattern) htPattern.get("pattern");
					Matcher matcher = oPattern.matcher(sUsername);
					matchFound = matcher.matches();
					if (matchFound) {
						String sRemoteId = (String) htPattern.get("organization_id");
						htResult = new HashMap();
						htResult.put("organization_id", sRemoteId);
						htResult.put("user_id", sUsername);
					}
					i++;
				}
				if (htResult == null) {
					sErrorMessage = Errors.ERROR_ASELECT_UNKNOWN_USER;
				}
			}
			catch (Exception e) {
				sErrorMessage = Errors.ERROR_ASELECT_UNKNOWN_USER;
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "get remote server id failed. ", e);
			}
		}
		else if (sHomeOrganization != null && !sHomeOrganization.trim().equals("")) {
			htResult = getHomeOrganization(sHomeOrganization);
			if (htResult != null) {
				if (sUsername != null && !sUsername.trim().equals("")) {
					htResult.put("user_id", sUsername);
				}
			}
			else {
				sErrorMessage = Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG;
			}
		}
		else if (sRemoteServer != null && !sRemoteServer.trim().equals("")) {
			HashMap htAvailableRemoteServers = _crossAselectManager.getRemoteServers();
			if (htAvailableRemoteServers.containsKey(sRemoteServer.trim())) {
				htResult = new HashMap();
				htResult.put("organization_id", sRemoteServer);

				Cookie oDefaultIdpCookie = new Cookie("aselect_home_idp", sRemoteServer);
				oDefaultIdpCookie.setMaxAge(COOKIE_AGE);
				servletResponse.addCookie(oDefaultIdpCookie);
			}
			else {
				htResult = getHomeOrganization(sRemoteServer);
				if (htResult != null) {
					if (sUsername != null && !sUsername.trim().equals("")) {
						htResult.put("user_id", sUsername);
					}
				}
				else {
					sErrorMessage = Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG;
				}
			}
		}

		if (htResult == null) {
			String sDefaultIdp = (String) htServiceRequest.get("aselect_home_idp");
			showAuthenticationForm(htServiceRequest, pwOut, sErrorMessage, sDefaultIdp);
		}

		return htResult;
	}

	// private function which shows the authentication form if no user_id was provided
	/**
	 * Show authentication form.
	 * 
	 * @param htServiceRequest
	 *            the service request
	 * @param pwOut
	 *            the pw out
	 * @param sErrorCode
	 *            the s error code
	 * @param sDefaultHomeIdp
	 *            the s default home idp
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void showAuthenticationForm(HashMap htServiceRequest, PrintWriter pwOut, String sErrorCode, String sDefaultHomeIdp)
	throws ASelectException
	{
		String sMethod = "showAuthenticationForm";

		try {
			String sRid = (String) htServiceRequest.get("rid");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "parameter 'rid' not found in service request");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			String sMyUrl = (String) htServiceRequest.get("my_url");
			if (sMyUrl == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "parameter 'my_url' not found in service request");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			
			String sLanguage = (String) htServiceRequest.get("language");
			String sLoginForm = Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(), null/*subdir*/,
						"sfscrossselect", sLanguage, _configManager.getOrgFriendlyName(), Version.getVersion());
			
			sLoginForm = Utils.replaceString(sLoginForm, "[rid]", sRid);
			sLoginForm = Utils.replaceString(sLoginForm, "[aselect_url]", sMyUrl);
			sLoginForm = Utils.replaceString(sLoginForm, "[request]", "cross_login");
			sLoginForm = Utils.replaceString(sLoginForm, "[a-select-server]", _sMyServerId);

			String sErrorMessage = null;
			if (sErrorCode != null) {
				sErrorMessage = _configManager.getErrorMessage(MODULE, sErrorCode, sLanguage, "");
				sLoginForm = Utils.replaceString(sLoginForm, "[error_message]", sErrorMessage);
				sLoginForm = Utils.replaceString(sLoginForm, "[language]", sLanguage);
			}
			else {
				sLoginForm = Utils.replaceString(sLoginForm, "[error_message]", "");
			}

			StringBuffer sbUrl = new StringBuffer((String) htServiceRequest.get("my_url")).append("?request=error")
					.append("&result_code=").append(Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=")
					.append(_sMyServerId).append("&rid=").append(sRid);
			sLoginForm = Utils.replaceString(sLoginForm, "[cancel]", sbUrl.toString());

			sLoginForm = Utils.replaceString(sLoginForm, "[cross_request]", "cross_login");

			HashMap htServers = _crossAselectManager.getRemoteServers();
			sLoginForm = Utils.replaceString(sLoginForm, "[available_remote_servers]", getRemoteServerHTML(htServers,
					sDefaultHomeIdp));

			HashMap htSessionContext = SessionManager.getHandle().getSessionContext(sRid);
			String sSpecials = Utils.getAselectSpecials(htSessionContext, true/*decode too*/, _systemLogger);
			sLoginForm = Utils.handleAllConditionals(sLoginForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);
			if (htSessionContext != null)
				sLoginForm = _configManager.updateTemplate(sLoginForm, htSessionContext, null);

			pwOut.println(sLoginForm);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not show select form", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Gets the remote server html.
	 * 
	 * @param htServers
	 *            the ht servers
	 * @param sDefaultRemoteOrg
	 *            the s default remote org
	 * @return the remote server html
	 */
	private String getRemoteServerHTML(HashMap htServers, String sDefaultRemoteOrg)
	{
		String sMethod = "getRemoteServerHTML";
		
		String sResult = new String();
		String sOrganization;
		String sFriendlyName;
		HashMap htAllServers = new HashMap();

		Set keys = _htSFSOrganizations.keySet();
		for (Object s : keys) {
			sFriendlyName = (String) s;

			// Enumeration enumSfsServers = _htSFSOrganizations.keys();
			// while (enumSfsServers.hasMoreElements()) {
			// sFriendlyName = (String) enumSfsServers.nextElement();
			HashMap ht = (HashMap) _htSFSOrganizations.get(sFriendlyName);
			sOrganization = (String) ht.get("organization");
			htAllServers.put(sFriendlyName, sOrganization);
		}

		keys = htServers.keySet();
		for (Object s : keys) {
			sOrganization = (String) s;
			// Enumeration enumRemoteServers = htServers.keys();
			// while (enumRemoteServers.hasMoreElements())
			// {
			// sOrganization = (String)enumRemoteServers.nextElement();
			sFriendlyName = (String) htServers.get(sOrganization);

			try { // Already exsists, what to do?
				if (!htAllServers.containsKey(sFriendlyName)) {
					String sDisplay = CrossASelectManager.getHandle().getRemoteParam(sOrganization, "display");
					if ((sDisplay == null) || (sDisplay.equalsIgnoreCase("true"))) {
						htAllServers.put(sFriendlyName, sOrganization);
					}
				}
				else {
					_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Server identification conflict in config: "
							+ sFriendlyName);
				}
			}
			catch (Exception e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not show select form", e);
			}

		}

		keys = htAllServers.keySet();
		for (Object s : keys) {
			sFriendlyName = (String) s;
			// Enumeration enumAllServers = htAllServers.keys();
			// while (enumAllServers.hasMoreElements()) {
			// sFriendlyName = (String) enumAllServers.nextElement();
			sOrganization = (String) htAllServers.get(sFriendlyName);

			if (sDefaultRemoteOrg != null && sDefaultRemoteOrg.equals(sOrganization)) {
				sResult += "<OPTION VALUE='" + sOrganization + "' selected=\"selected\">" + sFriendlyName
						+ "</OPTION>\n";
			}
			else {
				sResult += "<OPTION VALUE='" + sOrganization + "'>" + sFriendlyName + "</OPTION>\n";
			}
		}
		return sResult;
	}
}