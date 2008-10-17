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

package org.aselect.server.request.handler.saml20.sp.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.tgt.saml20.SpTGTIssuer;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Utils;

/**
 * Abstract browser request handler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class can be used as a base class for request handlers which handle
 * browser requests. The <code>AbstractBrowserRequestHandler</code> also
 * contains the helper functions used by the different request handlers <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>AbstractBrowserRequestHandler</code> implementation for a
 * single request. <br>
 * 
 * @author Alfa & Ariss
 * 
 */
public abstract class AbstractBrowserRequestHandler implements IRequestHandler
{
	/** The module name. Can be overwritten in sub classes */
	protected String _sModule = "AbstractBrowserRequestHandler";

	/** The system logger. */
	protected ASelectSystemLogger _systemLogger;

	/** The configuration. */
	protected ASelectConfigManager _configManager;

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

	/**
	 * Construct an instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Handles are obtained to relevant managers. <br>
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
	public AbstractBrowserRequestHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sMyServerId, String sMyOrg) {
		_configManager = ASelectConfigManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_tgtManager = TGTManager.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();

		_sMyServerId = sMyServerId;
		_sMyOrg = sMyOrg;

		_servletRequest = servletRequest;
		_servletResponse = servletResponse;
	}

	/**
	 * This function processes browser requests <br>
	 * <br>
	 * 
	 * @see org.aselect.server.request.handler.saml20.sp.authentication.IRequestHandler#processRequest()
	 */
	public void processRequest()
		throws ASelectException
	{
		String sMethod = "processRequest()";
		PrintWriter pwOut = null;
		Hashtable htServiceRequest = null;
		try {
			pwOut = _servletResponse.getWriter();

			_servletResponse.setContentType("text/html");

			htServiceRequest = createServiceRequest(_servletRequest);

			String sRequest = (String) htServiceRequest.get("request");

			// only check a-select-server if request == null
			if (sRequest != null) {
				String sServerId = (String) htServiceRequest.get("a-select-server");

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
		}
		catch (ASelectException ae) {
			showErrorPage(ae.getMessage(), htServiceRequest, pwOut);
		}
		catch (IOException ioe) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "IO Exception", ioe);

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, ioe);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Internal error", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
		}
	}

	/**
	 * Prosesses the API request. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *                Hashttable containing request parameters
	 * @param servletResponse
	 *                Used to send information (HTTP) back to the user
	 * @param pwOut
	 *                Used to send information back to the user (HTML)
	 * @throws ASelectException
	 *                 If processing fails and no response is send to the
	 *                 client.
	 */
	abstract protected void processBrowserRequest(Hashtable htServiceRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut)
		throws ASelectException;

	/**
	 * Shows the main A-Select Error page with the approprate errors. <br>
	 * <br>
	 * 
	 * @param sErrorCode
	 * @param htServiceRequest
	 * @param pwOut
	 */
	protected void showErrorPage(String sErrorCode, Hashtable htServiceRequest, PrintWriter pwOut)
	{
		String sMethod = "showErrorPage()";
		try {
			String sErrorForm = _configManager.getForm("error");
			sErrorForm = Utils.replaceString(sErrorForm, "[error]", sErrorCode);
			sErrorForm = Utils.replaceString(sErrorForm, "[error_message]", _configManager.getErrorMessage(sErrorCode));

			String sRid = (String) htServiceRequest.get("rid");
			if (sRid != null)
				sErrorForm = _configManager.updateTemplate(sErrorForm, _sessionManager.getSessionContext(sRid));

			Hashtable htSession = null;
			if (sRid != null)
				htSession = SessionManager.getHandle().getSessionContext(sRid);

			sErrorForm = _configManager.updateTemplate(sErrorForm, htSession);

			pwOut.println(sErrorForm);
		}
		catch (Exception e) {
			_systemLogger
					.log(Level.SEVERE, _sModule, sMethod, "Could not show error page with error: " + sErrorCode, e);
		}
	}

	/**
	 * Retrieve A-Select credentials. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Reads the A-Select credentials from a Cookie and put them into a
	 * <code>Hashtable</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>servletRequest != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param servletRequest
	 *                The Request which should contain the Cookie.
	 * @return The A-Slect credentials in a <code>Hashtable</code>.
	 */
	@SuppressWarnings("unchecked")
	protected Hashtable getASelectCredentials(HttpServletRequest servletRequest)
	{
		String sMethod = "getASelectCredentials";
		Hashtable htCredentials = new Hashtable();

		// check for credentials that might be present
		Cookie[] aCookies = servletRequest.getCookies();

		if (aCookies == null) {
			return null;
		}

		String sCredentialsCookie = null;

		for (int i = 0; i < aCookies.length; i++) {
			if (aCookies[i].getName().equals(SpTGTIssuer.COOKIE_NAME)) {
				sCredentialsCookie = aCookies[i].getValue();
				// remove '"' surrounding cookie if applicable
				int iLength = sCredentialsCookie.length();
				if (sCredentialsCookie.charAt(0) == '"' && sCredentialsCookie.charAt(iLength - 1) == '"') {
					sCredentialsCookie = sCredentialsCookie.substring(1, iLength - 1);
				}
			}
		}
		if (sCredentialsCookie == null) {
			return null;
		}

		Hashtable sCredentialsParams = Utils.convertCGIMessage(sCredentialsCookie);
		if (sCredentialsParams == null) {
			return null;
		}
		String sTgt = (String) sCredentialsParams.get("tgt");
		String sUserId = (String) sCredentialsParams.get("uid");
		String sServerId = (String) sCredentialsParams.get("a-select-server");
		if ((sTgt == null) || (sUserId == null) || (sServerId == null)) {
			return null;
		}
		if (!sServerId.equals(_sMyServerId)) {
			return null;
		}

		Hashtable htTGTContext = null;
		try {
			if (_tgtManager.containsKey(sTgt)) {
				htTGTContext = _tgtManager.getTGT(sTgt);
			}
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, e.getMessage());
		}
		if (htTGTContext == null) {
			return null;
		}
		if (!sUserId.equals(htTGTContext.get("uid"))) {
			return null;
		}

		htCredentials.put("aselect_credentials_tgt", sTgt);
		htCredentials.put("aselect_credentials_uid", sUserId);
		htCredentials.put("aselect_credentials_server_id", sServerId);
		return htCredentials;
	}

	/**
	 * This function converts a <code>servletRequest</code> to a
	 * <code>Hashtable</code> by extracting the parameters from the
	 * <code>servletRequest</code> and inserting them into a
	 * <code>Hashtable</code>. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *                Contains request parameters
	 * @return Hashtable containing request parameters.
	 */
	@SuppressWarnings("unchecked")
	private Hashtable createServiceRequest(HttpServletRequest servletRequest)
	{
		// Extract parameters into htServiceRequest
		Hashtable htServiceRequest = null;
		if (servletRequest.getMethod().equalsIgnoreCase("GET")) {
			htServiceRequest = Utils.convertCGIMessage(servletRequest.getQueryString());
		}
		else {
			htServiceRequest = new Hashtable();
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
		htServiceRequest.put("client_ip", servletRequest.getRemoteAddr());
		Hashtable htCredentials = getASelectCredentials(servletRequest);
		if (htCredentials != null) {
			htServiceRequest.put("aselect_credentials_tgt", htCredentials.get("aselect_credentials_tgt"));
			htServiceRequest.put("aselect_credentials_uid", htCredentials.get("aselect_credentials_uid"));
			htServiceRequest.put("aselect_credentials_server_id", _sMyServerId);
		}

		return htServiceRequest;
	}
}
