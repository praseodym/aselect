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
 * $Id: RegexSelectorHandler.java,v 1.3 2006/04/26 12:17:40 tom Exp $
 * 
 * Changelog:
 * $Log: RegexSelectorHandler.java,v $
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
import java.util.Vector;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.cross.ISelectorHandler;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

// TODO: Auto-generated Javadoc
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

public class RegexSelectorHandler implements ISelectorHandler
{
	// Name of this module, used for logging
	private static final String MODULE = "RegexSelectorHandler";
	private String _sCrossRegexSelectorPage;
	private String _sFriendlyName;
	private ASelectConfigManager _configManager;
	private ASelectSystemLogger _systemLogger;
	private Vector _vPatterns;
	private String _sMyServerId;
	private static final String ERROR_ASELECT_REGEX_SELECTOR_ORGANIZATION_UNKNOWN = "REGEX001";

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
		String sMethod = "init()";
		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			_configManager = ASelectConfigManager.getHandle();
			_vPatterns = new Vector();
			Object oExpressionsConfig = null;
			Object oRegexConfig = null;
			try {
				Object oASelectConfig = _configManager.getSection(null, "aselect");
				_sMyServerId = _configManager.getParam(oASelectConfig, "server_id");
				_sFriendlyName = _configManager.getParam(oASelectConfig, "organization_friendly_name");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to load basic A-Select configuration", e);
				throw new ASelectConfigException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			try {
				loadHTMLTemplates();
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Failed to load Regex Cross Selector HTML templates.", e);
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
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize the regex selector handler", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
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
		String sMethod = "getRemoteServerId()";
		int i = 0;
		boolean matchFound = false;
		String sRemoteId = null;
		HashMap htResult = null;
		String sUsername = (String) htServiceRequest.get("user_id");
		if (sUsername == null) {
			showAuthenticationForm(htServiceRequest, pwOut, "");
			return null;
		}
		try {
			while (i < _vPatterns.size() && !matchFound) {
				HashMap htPattern = (HashMap) _vPatterns.get(i);
				Pattern oPattern = (Pattern) htPattern.get("pattern");
				Matcher matcher = oPattern.matcher(sUsername);
				matchFound = matcher.matches();
				if (matchFound) {
					htResult = new HashMap();
					sRemoteId = (String) htPattern.get("organization_id");
					htResult.put("organization_id", sRemoteId);
					htResult.put("user_id", sUsername);
				}
				i++;
			}
			if (!matchFound) {
				showAuthenticationForm(htServiceRequest, pwOut, ERROR_ASELECT_REGEX_SELECTOR_ORGANIZATION_UNKNOWN);
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No organization found for user: " + sUsername);
			}
		}

		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "get remote server id failed. ", e);
		}
		return htResult;
	}

	// Private function which loads the HTML Templates
	/**
	 * Load html templates.
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void loadHTMLTemplates()
		throws ASelectException
	{
		String sWorkingdir = new StringBuffer(_configManager.getWorkingdir()).append(File.separator).append("conf")
				.append(File.separator).append("html").append(File.separator).toString();

		_sCrossRegexSelectorPage = loadHTMLTemplate(sWorkingdir + "regexselect.html");

		_sCrossRegexSelectorPage = Utils.replaceString(_sCrossRegexSelectorPage, "[version]", Version.getVersion());
		_sCrossRegexSelectorPage = Utils.replaceString(_sCrossRegexSelectorPage, "[organization_friendly]",
				_sFriendlyName);
	}

	// Private funtion which load the HTML template on location sLocation.
	/**
	 * Load html template.
	 * 
	 * @param sLocation
	 *            the s location
	 * @return the string
	 * @throws ASelectException
	 *             the a select exception
	 */
	private String loadHTMLTemplate(String sLocation)
		throws ASelectException
	{
		String sTemplate = new String();
		String sLine;
		BufferedReader brIn = null;
		String sMethod = "loadHTMLTemplate()";
		try {
			brIn = new BufferedReader(new InputStreamReader(new FileInputStream(sLocation)));
			while ((sLine = brIn.readLine()) != null) {
				sTemplate += sLine + "\n";
			}
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not load '");
			sbError.append(sLocation).append("'HTML template.");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		finally {
			try {
				brIn.close();
			}
			catch (Exception e) {
				StringBuffer sbError = new StringBuffer("Could not close '");
				sbError.append(sLocation).append("' FileInputStream.");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			}
		}
		return sTemplate;
	}

	// private function which shows the authentication form if no user_id was provided
	/**
	 * Show authentication form.
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param pwOut
	 *            the pw out
	 * @param sErrorCode
	 *            the s error code
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void showAuthenticationForm(HashMap htServiceRequest, PrintWriter pwOut, String sErrorCode)
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

			String sLoginForm = _sCrossRegexSelectorPage;

			sLoginForm = Utils.replaceString(sLoginForm, "[rid]", sRid);
			sLoginForm = Utils.replaceString(sLoginForm, "[aselect_url]", sMyUrl);
			sLoginForm = Utils.replaceString(sLoginForm, "[request]", "cross_login");
			sLoginForm = Utils.replaceString(sLoginForm, "[a-select-server]", _sMyServerId);
			sLoginForm = Utils.replaceString(sLoginForm, "[error_message]", _configManager.getErrorMessage(sErrorCode));

			StringBuffer sbUrl = new StringBuffer((String) htServiceRequest.get("my_url")).append("?request=error")
					.append("&result_code=").append(Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=")
					.append(_sMyServerId).append("&rid=").append(sRid);
			sLoginForm = Utils.replaceString(sLoginForm, "[cancel]", sbUrl.toString());

			sLoginForm = Utils.replaceString(sLoginForm, "[cross_request]", "cross_login");

			HashMap htSession = SessionManager.getHandle().getSessionContext(sRid);
			if (htSession != null)
				sLoginForm = _configManager.updateTemplate(sLoginForm, htSession);

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
}