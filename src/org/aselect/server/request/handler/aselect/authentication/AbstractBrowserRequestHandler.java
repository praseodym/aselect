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
 * $Id: AbstractBrowserRequestHandler.java,v 1.9 2006/05/03 10:10:18 tom Exp $ 
 * 
 * Changelog:
 * $Log: AbstractBrowserRequestHandler.java,v $
 * Revision 1.9  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.8  2006/04/12 09:23:53  martijn
 * added optional application config items in error page
 *
 * Revision 1.7  2006/04/06 11:07:48  leon
 * removed function which was commented out.
 *
 * Revision 1.6  2006/03/20 11:16:50  martijn
 * updateTemplate() method is moved to ConfigManager
 *
 * Revision 1.5  2006/03/17 13:17:21  martijn
 * updateTemplate now replaces tags starting with 'requestor_' instead of 'application_'
 *
 * Revision 1.4  2006/03/17 07:43:05  martijn
 * isShowAppUrl() has been changed to isShowUrl()
 *
 * Revision 1.3  2006/03/16 14:48:30  martijn
 * fixed updateTemplate(): now empy strings are placed in templates when no session context is available
 *
 * Revision 1.2  2006/03/16 10:34:46  martijn
 * added support for showwing optional application info in html templates
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
 * Revision 1.10  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.9  2005/04/27 12:16:58  erwin
 * Fixed problem with '"' surrounded cookies.
 *
 * Revision 1.8  2005/04/26 15:13:18  erwin
 * IF -> ID in error
 *
 * Revision 1.7  2005/04/05 07:48:24  martijn
 * variable rename to coding standard
 *
 * Revision 1.6  2005/03/17 15:27:58  tom
 * Fixed javadoc
 *
 * Revision 1.5  2005/03/17 15:18:00  tom
 * Organized imports
 *
 * Revision 1.4  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.3  2005/03/17 07:57:04  erwin
 * Added Javadoc for protected method/variables.
 *
 * Revision 1.2  2005/03/16 12:52:10  tom
 * - Fixed javadoc
 *
 * Revision 1.1  2005/03/15 10:50:42  tom
 * Initial version
 *
 */

package org.aselect.server.request.handler.aselect.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.BasicRequestHandler;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * Abstract browser request handler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class can be used as a base class for request handlers which handle browser requests. The
 * <code>AbstractBrowserRequestHandler</code> also contains the helper functions used by the different request handlers <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>AbstractBrowserRequestHandler</code> implementation for a single request. <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - DigiD Gateway update - Cookie handling update
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl) and UMC Nijmegen
 *         (http://www.umcn.nl)
 */
public abstract class AbstractBrowserRequestHandler extends BasicRequestHandler implements IAuthnRequestHandler
{
	/** The module name. Can be overwritten in sub classes */
	protected String _sModule = "AbstractBrowserRequestHandler";

	/** The system logger is in BasicRequestHandler */
	/** The configuration Manager is in BasicRequestManager */

	/** The session manager. */
	protected SessionManager _sessionManager;

	/** The TGT manager. */
	protected TGTManager _tgtManager;

	/** The request. */
	protected HttpServletRequest _servletRequest;
	/** The response. */
	protected HttpServletResponse _servletResponse;

	/** The server ID */
	protected String _sMyServerId;

	/** The origanisation */
	protected String _sMyOrg;

	protected String _sUserLanguage = "";
	protected String _sUserCountry = "";

	/**
	 * Construct an instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Handles are obtained to relevant managers. <br>
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
	public AbstractBrowserRequestHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sMyServerId, String sMyOrg)
	{
		String sMethod = "AbstractBrowserRequestHandler";

		_systemLogger = ASelectSystemLogger.getHandle();
		_configManager = ASelectConfigManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_tgtManager = TGTManager.getHandle();

		_sMyServerId = sMyServerId;
		_sMyOrg = sMyOrg;

		_servletRequest = servletRequest;
		_servletResponse = servletResponse;

		// Localization
		Locale loc = servletRequest.getLocale();
		_sUserLanguage = loc.getLanguage();
		_sUserCountry = loc.getCountry();
		_systemLogger.log(Level.INFO, _sModule, sMethod, "Locale: _" + _sUserLanguage + "_" + _sUserCountry);
	}

	/**
	 * This function processes browser requests <br>
	 * <br>
	 * .
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.aselect.authentication.IAuthnRequestHandler#processRequest()
	 */
	public void processRequest()
	throws ASelectException
	{
		String sMethod = "processRequest()";
		PrintWriter pwOut = null;
		HashMap htServiceRequest = null;
		try {
			pwOut = _servletResponse.getWriter();

			_servletResponse.setContentType("text/html");
			htServiceRequest = createServiceRequest(_servletRequest);
			String sRequest = (String) htServiceRequest.get("request");
			_systemLogger.log(Level.INFO, _sModule, sMethod, "AbstBrowREQ "+_servletRequest.getMethod()+
					" htServiceRequest=" + htServiceRequest);

			// only check a-select-server if request != null
			if (sRequest != null && !sRequest.equals("alive")) {
				String sServerId = (String) htServiceRequest.get("a-select-server");
				_systemLogger.log(Level.INFO, _sModule, sMethod, "AbstBrowREQ _sMyServerId=" + _sMyServerId
						+ ", sServerId=" + sServerId);
				if (sServerId == null) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod,
							"Missing required parameter \"a-select-server\"");
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				else if (!sServerId.equals(_sMyServerId)) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid \"a-select-server\" parameter: "
							+ sServerId);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_ID_MISMATCH);
				}
			}
			processBrowserRequest(htServiceRequest, _servletResponse, pwOut);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "AbstBrowREQ Done");
		}
		catch (ASelectException ae) {
			showErrorPage(ae.getMessage(), htServiceRequest, pwOut);
		}
		catch (IOException ioe) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "IO Exception", ioe);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, ioe);
		}
		catch (Exception e) {
			// produces a stack trace on FINEST level, when 'e' is given as a separate argument to log()
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Internal error: "+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		// don't close pwOut, so the caller can still inform the user of an error
	}

	/**
	 * Prosesses the API request. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            Hashttable containing request parameters
	 * @param servletResponse
	 *            Used to send information (HTTP) back to the user
	 * @param pwOut
	 *            Used to send information back to the user (HTML)
	 * @throws ASelectException
	 *             If processing fails and no response is send to the client.
	 */
	abstract protected void processBrowserRequest(HashMap htServiceRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut)
		throws ASelectException;

	/**
	 * Shows the main A-Select Error page with the appropriate errors. <br>
	 * <br>
	 * 
	 * @param sErrorCode
	 *            the s error code
	 * @param htServiceRequest
	 *            the ht service request
	 * @param pwOut
	 *            the pw out
	 */
	protected void showErrorPage(String sErrorCode, HashMap htServiceRequest, PrintWriter pwOut)
	{
		String sMethod = "showErrorPage";

		String sErrorMessage = _configManager.getErrorMessage(sErrorCode, _sUserLanguage, _sUserCountry);
		_systemLogger.log(Level.INFO, _sModule, sMethod, "FORM[error] " + sErrorCode + ":" + sErrorMessage);
		try {
			String sErrorForm = _configManager.getForm("error", _sUserLanguage, _sUserCountry);
			sErrorForm = Utils.replaceString(sErrorForm, "[error]", sErrorCode);  // obsoleted 20100817
			sErrorForm = Utils.replaceString(sErrorForm, "[error_code]", sErrorCode);
			sErrorForm = Utils.replaceString(sErrorForm, "[error_message]", sErrorMessage);
			sErrorForm = Utils.replaceString(sErrorForm, "[language]", _sUserLanguage);

			HashMap htSessionContext = null;
			String sRid = (String) htServiceRequest.get("rid");
			if (sRid != null) {
				htSessionContext = _sessionManager.getSessionContext(sRid);
			}
			if (htSessionContext != null) {
				String sSpecials = Utils.getAselectSpecials(htSessionContext, true/*decode too*/, _systemLogger);
				sErrorForm = Utils.handleAllConditionals(sErrorForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);
			}
			sErrorForm = _configManager.updateTemplate(sErrorForm, htSessionContext);  // accepts a null Session!
			//_systemLogger.log(Level.INFO, _sModule, sMethod, "FORM="+sErrorForm);
			pwOut.println(sErrorForm);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Could not show error page with error: " + sErrorCode, e);
		}
	}

	/**
	 * Retrieve A-Select credentials. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Reads the A-Select credentials from a Cookie and put them into a <code>HashMap</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>servletRequest != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param servletRequest
	 *            The Request which should contain the Cookie.
	 * @return The A-Slect credentials in a <code>HashMap</code>.
	 */
	protected HashMap getASelectCredentials(HttpServletRequest servletRequest)
	{
		String sMethod = "getASelectCredentials()";
		HashMap htCredentials = new HashMap();

		// check for credentials that might be present
		// Bauke 20080618, we only store the tgt value from now on
		String sTgt = HandlerTools.getCookieValue(servletRequest, "aselect_credentials", _systemLogger);
		if (sTgt == null) {
			return null;
		}

		/*
		 * HashMap sCredentialsParams = Utils.convertCGIMessage(sCredentialsCookie); if (sCredentialsParams == null) {
		 * return null; } String sTgt = (String)sCredentialsParams.get("tgt"); String sUserId =
		 * (String)sCredentialsParams.get("uid"); String sServerId = (String)sCredentialsParams.get("a-select-server");
		 * if ((sTgt == null) || (sUserId == null) || (sServerId == null)) { return null; } if
		 * (!sServerId.equals(_sMyServerId)) { return null; }
		 */
		HashMap htTGTContext = _tgtManager.getTGT(sTgt);
		if (htTGTContext == null) {
			return null;
		}
		/*
		 * if (!sUserId.equals(htTGTContext.get("uid"))) { return null; }
		 */
		String sUserId = (String) htTGTContext.get("uid");
		if (sUserId == null)
			return null;

		htCredentials.put("aselect_credentials_tgt", sTgt);
		if (sUserId != null)
			htCredentials.put("aselect_credentials_uid", sUserId);
		htCredentials.put("aselect_credentials_server_id", _sMyServerId); // Bauke 20080618 was: sServerId);
		return htCredentials;
	}

	/**
	 * This function converts a <code>servletRequest</code> to a <code>HashMap</code> by extracting the parameters from
	 * the <code>servletRequest</code> and inserting them into a <code>HashMap</code>. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            Contains request parameters
	 * @return HashMap containing request parameters.
	 */
	private HashMap createServiceRequest(HttpServletRequest servletRequest)
	{
		// Extract parameters into htServiceRequest
		HashMap htServiceRequest = null;
		if (servletRequest.getMethod().equalsIgnoreCase("GET")) {
			htServiceRequest = Utils.convertCGIMessage(servletRequest.getQueryString());
		}
		else {
			htServiceRequest = new HashMap();
			String sParameter, sValue;
			Enumeration eParameters = servletRequest.getParameterNames();
			while (eParameters.hasMoreElements()) {
				sParameter = (String) eParameters.nextElement();
				sValue = servletRequest.getParameter(sParameter);
				if (sValue != null) {
					htServiceRequest.put(sParameter, sValue);
				}
			}
		}

		htServiceRequest.put("my_url", servletRequest.getRequestURL().toString());
		String sClientIp = servletRequest.getRemoteAddr();
		if (sClientIp != null)
			htServiceRequest.put("client_ip", servletRequest.getRemoteAddr());
		String sAgent = servletRequest.getHeader("User-Agent");
		if (sAgent != null)
			htServiceRequest.put("user_agent", sAgent);
		HashMap htCredentials = getASelectCredentials(servletRequest);
		if (htCredentials != null) {
			htServiceRequest.put("aselect_credentials_tgt", htCredentials.get("aselect_credentials_tgt"));
			htServiceRequest.put("aselect_credentials_uid", htCredentials.get("aselect_credentials_uid"));
			htServiceRequest.put("aselect_credentials_server_id", _sMyServerId);
		}
		return htServiceRequest;
	}

	/**
	 * Gets the _servlet request.
	 * 
	 * @return the _servlet request
	 */
	public synchronized HttpServletRequest get_servletRequest()
	{
		return _servletRequest;
	}
}
