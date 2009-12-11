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
 * $Id: IdpSelectorHandler.java,v 1.1.2.5 2006/12/14 14:17:12 maarten Exp $ 
 * 
 * Changelog:
 * $Log: IdpSelectorHandler.java,v $
 * Revision 1.1.2.5  2006/12/14 14:17:12  maarten
 * Fixed cookie age
 *
 * Revision 1.1.2.4  2006/11/29 14:23:44  leon
 * small changes
 *
 * Revision 1.1.2.3  2006/09/29 09:02:53  maarten
 * Updated version
 *
 * Revision 1.1.2.2  2006/09/05 14:29:52  maarten
 * Updated version
 *
 * Revision 1.1.2.1  2006/09/05 08:43:28  maarten
 * Updated version
 *
 * Revision 1.1.2.1  2006/09/04 11:04:21  leon
 * 2 new cross selector handlers added
 *
 * Revision 1.1.2.1  2006/08/18 09:21:36  maarten
 * Initial version
 *
 * Revision 1.6  2006/04/26 12:17:40  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.5  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.4.4.2  2006/04/04 09:00:27  erwin
 * Added single-quotes in option values. (fixed bug #160)
 *
 * Revision 1.4.4.1  2006/03/20 11:09:17  martijn
 * added optional template tag support
 *
 * Revision 1.4  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/05/04 09:34:59  martijn
 * bugfixes, improved logging
 *
 * Revision 1.2  2005/04/15 14:02:23  peter
 * javadoc
 *
 * Revision 1.1  2005/04/07 06:27:06  peter
 * package rename
 *
 * Revision 1.1  2005/04/01 14:22:57  peter
 * cross aselect redesign
 *
 * Revision 1.1  2005/03/22 15:12:58  peter
 * Initial version
 *
 */

package org.aselect.server.cross.selectorhandler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Level;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.cross.ISelectorHandler;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.session.SessionManager;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.utils.Utils;

// TODO: Auto-generated Javadoc
/**
 * This class handles the remote A-Select Server selection by means of a user HTML form. <br>
 * <br>
 * <b>Description:</b> <br>
 * This handler will present the user a 'dropdown box' containing all configured remote_servers.<br>
 * This Class is accessed two times within an cross authentication request.<br>
 * - In the first request a HTML form is presented with a list of all configured remote servers.<br>
 * - The HTML form will post the remote server selection and will be put here in a hashtable. <br>
 * <br>
 * 
 * @author Alfa & Ariss
 */
public class IdpSelectorHandler implements ISelectorHandler
{
	// Name of this module, used for logging
	private static final String MODULE = "IdpSelectorHandler";

	private CrossASelectManager _crossASelectManager;
	private ASelectConfigManager _configManager;
	private ASelectSystemLogger _systemLogger;
	private RawCommunicator _oCommunicator;

	private String _sMyServerId = null;
	private String _sFriendlyName = null;
	private String _sHTMLSelectForm = null;
	private String _sIdPQueryServerId = null;
	private String _sIdPQueryServerResourceGroup = null;
	private String _sIdPQueryServerRequest = null;
	private String _sIdPQueryServerSharedSecret = null;

	private static final int COOKIE_AGE = 31536000; // TODO: Cookie is set to be about a years time(not counting leap
	// years), should be configurable?(seconds, not leap years)

	private static final String _sHtmlTemplateName = "idpcrossselect.html";

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
			_crossASelectManager = CrossASelectManager.getHandle();
			_configManager = ASelectConfigManager.getHandle();
			_systemLogger = ASelectSystemLogger.getHandle();

			_oCommunicator = new RawCommunicator(_systemLogger);

			Object oASelectConfig = _configManager.getSection(null, "aselect");
			_sMyServerId = _configManager.getParam(oASelectConfig, "server_id");
			_sFriendlyName = _configManager.getParam(oASelectConfig, "organization_friendly_name");

			Object oIpdQueryServerConfig = null;
			try {
				oIpdQueryServerConfig = _configManager.getSection(oHandlerConfig, "idp_query_server");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "no section 'idp_query_server' found.");
				throw e;
			}
			try {
				_sIdPQueryServerId = _configManager.getParam(oIpdQueryServerConfig, "id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "no param 'resourcegroup' found.");
				throw e;
			}
			try {
				_sIdPQueryServerRequest = _configManager.getParam(oIpdQueryServerConfig, "request");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "no param 'request' found.");
				throw e;
			}
			try {
				_sIdPQueryServerSharedSecret = _configManager.getParam(oIpdQueryServerConfig, "shared_secret");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "no param 'shared_secret' found, using none.");
			}
			try {
				getIdpQueryServerResourceGroup();
			}
			catch (ASelectException e) {
				throw e;
			}

			loadHTMLTemplates();
		}
		catch (ASelectException e) {
			// Already handled.
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize the default selector handler", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Returns the remote A-Select Server. This handler presents the user with a selection form that is used to
	 * determine the remote organization and returns the selected organization to the A-Select sub system. <br>
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
		String sMethod = "IdpSelectorHandler.getRemoteServerId()";
		HashMap htReturn = null;

		String sRemoteOrg = (String) htServiceRequest.get("remote_organization");
		String sHomeIdpFriendlyName = (String) htServiceRequest.get("home_idp");
		String sHomeOrg = (String) htServiceRequest.get("home_organization");
		String sUid = (String) htServiceRequest.get("user_id");

		_systemLogger.log(Level.FINER, MODULE, sMethod, "remote_organization: " + sRemoteOrg);
		_systemLogger.log(Level.FINER, MODULE, sMethod, "home_idp: " + sHomeIdpFriendlyName);
		_systemLogger.log(Level.FINER, MODULE, sMethod, "home_organization: " + sHomeOrg);
		_systemLogger.log(Level.FINER, MODULE, sMethod, "user_id: " + sUid);

		if ((sRemoteOrg != null) && (!sRemoteOrg.equalsIgnoreCase(""))) {
			htReturn = new HashMap();
			htReturn.put("organization_id", sRemoteOrg);

			if ((sHomeOrg != null && (!sHomeOrg.equalsIgnoreCase("")))) {
				htReturn.put("home_idp", sHomeOrg);
				if (sUid != null) {
					htReturn.put("user_id", sUid);
				}
			}
			return htReturn;
		}

		if (sUid != null) {
			htReturn = new HashMap();
			htReturn.put("user_id", sUid);
			htReturn.put("organization_id", _sIdPQueryServerId);
			return htReturn;
		}

		if (sHomeIdpFriendlyName == null || sHomeIdpFriendlyName.equalsIgnoreCase("")) {
			HashMap htServers = handleIdpApiCall();
			String sDefaultIdp = (String) htServiceRequest.get("aselect_home_idp");

			showSelectForm(htServiceRequest, pwOut, htServers, sDefaultIdp);
		}
		else {
			htReturn = new HashMap();
			Cookie oDefaultIdpCookie = new Cookie("aselect_home_idp", sHomeIdpFriendlyName);
			oDefaultIdpCookie.setMaxAge(COOKIE_AGE);
			servletResponse.addCookie(oDefaultIdpCookie);

			HashMap htServers = handleIdpApiCall();
			htReturn.put("organization_id", _sIdPQueryServerId);
			String sHomeIdpOrgId = (String) htServers.get(sHomeIdpFriendlyName);
			htReturn.put("home_idp", sHomeIdpOrgId);
			if (sUid != null) {
				htReturn.put("user_id", sUid);
			}
		}
		return htReturn;
	}

	/**
	 * Show select form.
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param pwOut
	 *            the pw out
	 * @param htServers
	 *            the ht servers
	 * @param sDefaultRemoteOrg
	 *            the s default remote org
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void showSelectForm(HashMap htServiceRequest, PrintWriter pwOut, HashMap htServers, String sDefaultRemoteOrg)
		throws ASelectException
	{
		String sMethod = "showSelectForm()";
		try {
			String sSelectForm = _sHTMLSelectForm;
			String sRemoteServerUrl = null;
			String sRid = (String) htServiceRequest.get("rid");
			String sMyUrl = (String) htServiceRequest.get("my_url");

			try {
				sRemoteServerUrl = getIdpQueryServerUrl();
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error occured during retrieving IdpQueryUrl");
				throw e;
			}

			String sUrl = new StringBuffer(sMyUrl).append("?request=error").append("&result_code=").append(
					Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=").append(_sMyServerId)
					.append("&rid=").append((String) htServiceRequest.get("rid")).toString();

			sSelectForm = Utils.replaceString(sSelectForm, "[rid]", sRid);
			sSelectForm = Utils.replaceString(sSelectForm, "[aselect_url]", sMyUrl);
			sSelectForm = Utils.replaceString(sSelectForm, "[request]", "cross_login");
			sSelectForm = Utils.replaceString(sSelectForm, "[a-select-server]", _sMyServerId);
			sSelectForm = Utils.replaceString(sSelectForm, "[remote_server]", sRemoteServerUrl);
			sSelectForm = Utils.replaceString(sSelectForm, "[cancel]", sUrl);

			sSelectForm = Utils.replaceString(sSelectForm, "[available_home_idps]", getRemoteServerHTML(htServers,
					sDefaultRemoteOrg));

			// Update template with the optional requestor information
			HashMap htSession = SessionManager.getHandle().getSessionContext(sRid);
			if (htSession != null)
				sSelectForm = _configManager.updateTemplate(sSelectForm, htSession);

			pwOut.println(sSelectForm);

		}
		catch (ASelectException e) {
			// Already logged.
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unexpected runtime error occured.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
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
		String sMethod = "getRemoteServerHTML()";
		String sResult = null;

		// Enumeration enumServers = htServers.keys();
		// ArrayList keyList = Collections.list(enumServers);
		// Collections.sort(keyList);
		// enumServers = Collections.enumeration(keyList);

		Set<String> keys = htServers.keySet();
		SortedSet sortedKeys = new TreeSet<String>(keys);
		for (Object s : sortedKeys) {
			String sFriendlyName = (String) s;
			// while (enumServers.hasMoreElements())
			// {
			// sFriendlyName = (String)enumServers.nextElement();

			if (sDefaultRemoteOrg != null && sDefaultRemoteOrg.equals(sFriendlyName)) {
				sResult += "<OPTION VALUE='" + sFriendlyName + "' selected=\"selected\">" + sFriendlyName
						+ "</OPTION>\n";
			}
			else {
				sResult += "<OPTION VALUE='" + sFriendlyName + "'>" + sFriendlyName + "</OPTION>\n";
			}
		}
		_systemLogger.log(Level.FINER, MODULE, sMethod, "Leaving function.");
		return sResult;
	}

	/**
	 * Loads all HTML Templates needed. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * At initialization all HTML templates are loaded once.<br>
	 * 
	 * @throws ASelectException
	 * <br>
	 * <br>
	 *             <b>Concurrency issues:</b> <br>
	 *             Run once at startup. <br>
	 * <br>
	 *             <b>Preconditions:</b> <br>
	 *             Manager and ISelectorHandler should be initialized. <br>
	 * <br>
	 *             <b>Postconditions:</b> <br>
	 *             Global HashMap _htHtmlTemplates variabele contains the templates. <br>
	 */
	private void loadHTMLTemplates()
		throws ASelectException
	{
		String sMethod = "loadHTMLTemplates()";
		try {

			String sWorkingdir = new StringBuffer(_configManager.getWorkingdir()).append(File.separator).append("conf")
					.append(File.separator).append("html").append(File.separator).toString();

			_sHTMLSelectForm = loadHTMLTemplate(sWorkingdir + _sHtmlTemplateName);

			_sHTMLSelectForm = Utils.replaceString(_sHTMLSelectForm, "[version]", Version.getVersion());
			_sHTMLSelectForm = Utils.replaceString(_sHTMLSelectForm, "[organization_friendly]", _sFriendlyName);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unexpected runtime error occurred :", e);
			throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}

	}

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

	/**
	 * Gets the idp query server resource group.
	 * 
	 * @return the idp query server resource group
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void getIdpQueryServerResourceGroup()
		throws ASelectException
	{
		String sMethod = "getIdpQueryServerResourceGroup()";
		if (!_crossASelectManager.getRemoteServers().containsKey(_sIdPQueryServerId)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"There's no 'organization' found within the remote_servers section with id: '" + _sIdPQueryServerId
							+ "'");
			throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
		}
		try {
			Object oCrossConfig = _configManager.getSection(null, "cross_aselect");
			Object oRemoteServersConfig = _configManager.getSection(oCrossConfig, "remote_servers");
			Object oRemoteServerConfig = _configManager.getSection(oRemoteServersConfig, "organization", "id="
					+ _sIdPQueryServerId);
			_sIdPQueryServerResourceGroup = _configManager.getParam(oRemoteServerConfig, "resourcegroup");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Error occured by retrieving 'resourcegroup' of the remote organization with id: '"
							+ _sIdPQueryServerId + "'");
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unexpected runtime error occured.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

	}

	/**
	 * Gets the idp query server url.
	 * 
	 * @return the idp query server url
	 * @throws ASelectException
	 *             the a select exception
	 */
	private String getIdpQueryServerUrl()
		throws ASelectException
	{
		String sMethod = "getUrl()";
		String sUrl = null;

		SAMResource sRemoteServers = null;
		try {
			try {
				sRemoteServers = ASelectSAMAgent.getHandle().getActiveResource(_sIdPQueryServerResourceGroup);
			}
			catch (ASelectSAMException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Error occured during retrieving active resource in resourcegroup: '"
								+ _sIdPQueryServerResourceGroup + "'.");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			Object objAuthSPResource = sRemoteServers.getAttributes();
			try {
				sUrl = _configManager.getParam(objAuthSPResource, "url");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No resource retrieved for: '"
						+ _sIdPQueryServerResourceGroup + "'.");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception occured", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return sUrl;
	}

	/**
	 * Handle idp api call.
	 * 
	 * @return the hash map
	 * @throws ASelectException
	 *             the a select exception
	 */
	private HashMap handleIdpApiCall()
		throws ASelectException
	{
		String sMethod = "handleIdpApiCall()";
		HashMap htResult = null;
		String sRemoteServerUrl = getIdpQueryServerUrl();
		HashMap htRequest = new HashMap();
		htRequest.put("request", _sIdPQueryServerRequest);
		if (_sIdPQueryServerSharedSecret != null)
			htRequest.put("shared_secret", _sIdPQueryServerSharedSecret);

		try {
			htResult = _oCommunicator.sendMessage(htRequest, sRemoteServerUrl);
		}
		catch (ASelectCommunicationException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error occured during communication");
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}
		String sResultCode = (String) htResult.get("result_code");
		if ((sResultCode == null) || !sResultCode.trim().equalsIgnoreCase(Errors.ERROR_ASELECT_SUCCESS)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid result from remote A-Selectserver: "
					+ sResultCode);
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}

		String sEncodedCgiString = (String) htResult.get("result");
		String sCgiString = null;
		try {
			sCgiString = URLDecoder.decode(sEncodedCgiString, "UTF-8");
		}
		catch (UnsupportedEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "");
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}

		HashMap htServers = Utils.convertCGIMessage(sCgiString);

		return htServers;
	}

}