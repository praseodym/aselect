/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.server.request.handler.xsaml20.idp;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.ServiceProvider;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.Audit;
import org.aselect.system.utils.Utils;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.util.XMLHelper;

// TODO: Auto-generated Javadoc
/**
 * IdP SLO Service Single Logout entry using HTTP-Redirect
 */
// Example configuration
// <handler id="saml20_slo"
// class="org.aselect.server.request.handler.xsaml20.idp.Xsaml20_SLO_Redirect"
// target="/saml20_slo.*" >
// </handler>
//
public class Xsaml20_SLO_Redirect extends Saml20_BrowserHandler
{
	private final static String MODULE = "idp.Xsaml20_SLO_Redirect";
	// private final static String SESSION_ID_PREFIX = "saml20_";
	private final String LOGOUTREQUEST = "LogoutRequest";

	private boolean _bTryRedirectLogoutFirst = true;
	private int _iRedirectLogoutTimeout = 30;

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		super.init(oServletConfig, oConfig);

		String sTryRedirect = ASelectConfigManager.getSimpleParam(oConfig, "try_redirect_logout_first", false);
		if (sTryRedirect != null && !sTryRedirect.equals("true"))
			_bTryRedirectLogoutFirst = false;

		try {
			_iRedirectLogoutTimeout = new Integer(_configManager.getParam(oConfig, "redirect_logout_timeout"))
					.intValue();
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_logout_timeout' found in 'handler' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Send a LogoutRequests to one of the other involved SPs When control returns here, the next SP will be handled.
	 * After the last one the TGT will be destroyed.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @param samlMessage
	 *            the saml message
	 * @throws ASelectException
	 *             the a select exception
	 */
	@Override
	protected void handleSpecificSaml20Request(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			SignableSAMLObject samlMessage)
		throws ASelectException
	{
		String sMethod = "handleSpecificSaml20Request";
		String pathInfo = httpRequest.getPathInfo();
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request received === Path=" + pathInfo);

		try {
			LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "received SAMLRequest: \n"
					+ XMLHelper.prettyPrintXML(logoutRequest.getDOM()));

			PrintWriter pwOut = httpResponse.getWriter();
			Response errorResponse = validateLogoutRequest(logoutRequest, httpRequest);
			if (errorResponse != null) {
				String errorMessage = "Something wrong in SAML communication";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
				pwOut.write(errorMessage);
				return;
			}
			// Now the message is OK
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SAMLRequest=" + httpRequest.getParameter("SAMLRequest"));
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RelayState=" + httpRequest.getParameter("RelayState"));
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SigAlg=" + httpRequest.getParameter("SigAlg"));
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Signature=" + httpRequest.getParameter("Signature"));
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Destination=" + logoutRequest.getDestination());
			String sConsent = httpRequest.getParameter("consent");
			String sInitiatingSP = logoutRequest.getIssuer().getValue();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "consent=" + sConsent + " SP=" + sInitiatingSP);

			String sNameID = logoutRequest.getNameID().getValue();
			TGTManager tgtManager = TGTManager.getHandle();
			HashMap htTGTContext = tgtManager.getTGT(sNameID);

			// 20090525, Bauke: also save RelayState in the TGT for the logout response
			// 20091118, Bauke: ignore "empty" RelayState (came from logout_info.html)
			// Note: we still have it in 'httpRequest'
			String sRelayState = httpRequest.getParameter("RelayState"); // is null if missing
			if (sRelayState != null && sRelayState.equals("[RelayState]"))
				sRelayState = null;
			if (sRelayState != null)
				htTGTContext.put("RelayState", sRelayState);
			else
				htTGTContext.remove("RelayState");

			// If user consent is needed, first show the logout_info.html
			ASelectConfigManager configManager = ASelectConfigManager.getHandle();
			if (!"true".equals(sConsent) && configManager.getUserInfoSettings().contains("logout")) {
				// if (sRelayState != null) // saved RelayState in the TGT
				tgtManager.updateTGT(sNameID, htTGTContext);
				showLogoutInfo(httpRequest, httpResponse, pwOut, sInitiatingSP, logoutRequest.getDestination(),
						htTGTContext, sRelayState);
				return;
			}

			// Delete the IdP client cookie
			String sCookieDomain = _configManager.getCookieDomain();
			HandlerTools.delCookieValue(httpResponse, "aselect_credentials", sCookieDomain, _systemLogger);
			// NOTE: cookie GOES, TGT STAYS in admin (contains the sessions)!!
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Removed cookie for domain: " + sCookieDomain);

			// Will save TGT (including the RelayState) as well
			// 20090616, Bauke: save initiator ID for the logout response
			String sRequestID = logoutRequest.getID();
			logoutNextSessionSP(httpRequest, httpResponse, logoutRequest, sInitiatingSP, sRequestID,
					_bTryRedirectLogoutFirst, _iRedirectLogoutTimeout, htTGTContext, null);
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request handled " + pathInfo);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Show logout info.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @param pwOut
	 *            the pw out
	 * @param sInitiatingSP
	 *            the s initiating sp
	 * @param sRedirectUrl
	 *            the s redirect url
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param sRelayState
	 *            the s relay state
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void showLogoutInfo(HttpServletRequest httpRequest, HttpServletResponse httpResponse, PrintWriter pwOut,
			String sInitiatingSP, String sRedirectUrl, HashMap htTGTContext, String sRelayState)
		throws ASelectException
	{
		final String sMethod = "showLogoutInfo";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "redirect_url=" + sRedirectUrl);
		String sInfoForm = _configManager.getForm("logout_info", _sUserLanguage, _sUserCountry);
		sInfoForm = Utils.replaceString(sInfoForm, "[aselect_url]", sRedirectUrl);
		sInfoForm = Utils.replaceString(sInfoForm, "[SAMLRequest]", httpRequest.getParameter("SAMLRequest"));
		if (sRelayState != null)
			sInfoForm = Utils.replaceString(sInfoForm, "[RelayState]", sRelayState);
		sInfoForm = Utils.replaceString(sInfoForm, "[SigAlg]", httpRequest.getParameter("SigAlg"));
		sInfoForm = Utils.replaceString(sInfoForm, "[Signature]", httpRequest.getParameter("Signature"));
		sInfoForm = Utils.replaceString(sInfoForm, "[consent]", "true");

		String sFriendlyName = ApplicationManager.getHandle().getFriendlyName(sInitiatingSP);
		if (sFriendlyName == null)
			sFriendlyName = sInitiatingSP;
		sInfoForm = Utils.replaceString(sInfoForm, "[current_sp]", sFriendlyName);

		String sOtherSPs = "";
		UserSsoSession ssoSession = (UserSsoSession) htTGTContext.get("sso_session");
		if (ssoSession != null) {
			List<ServiceProvider> spList = ssoSession.getServiceProviders();
			for (ServiceProvider sp : spList) {
				String sOtherUrl = sp.getServiceProviderUrl();
				if (!sInitiatingSP.equals(sOtherUrl)) {
					sFriendlyName = ApplicationManager.getHandle().getFriendlyName(sOtherUrl);
					if (sFriendlyName == null)
						sFriendlyName = sOtherUrl;
					sOtherSPs += sFriendlyName + "<br/>";
				}
			}
		}
		sInfoForm = Utils.replaceString(sInfoForm, "[other_sps]", sOtherSPs);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "display form");

		// sInfoForm = _configManager.updateTemplate(sInfoForm, _htSessionContext);
		httpResponse.setContentType("text/html");
		pwOut.println(sInfoForm);
		pwOut.close();
	}

	/**
	 * Validate logout request.
	 * 
	 * @param logoutRequest
	 *            the logout request
	 * @param httpRequest
	 *            the http request
	 * @return the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private Response validateLogoutRequest(LogoutRequest logoutRequest, HttpServletRequest httpRequest)
		throws ASelectException
	{
		String sMethod = "validateLogoutRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		Response errorResponse = null;
		String sInResponseTo = logoutRequest.getID(); // Is required in SAMLsyntax
		String sDestination = logoutRequest.getDestination();
		String sStatusCode = "";
		String sStatusMessage = "";
		if (sDestination == null) {
			sDestination = "UnkownDestination";
			sStatusCode = StatusCode.INVALID_ATTR_NAME_VALUE_URI;
			sStatusMessage = "The 'Destination' attribute found in element LogoutRequest of SAML message was null";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage);
			return errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
		}
		if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(logoutRequest)) {
			sStatusCode = StatusCode.REQUEST_DENIED_URI;
			sStatusMessage = "Time interval in element LogoutRequest not valid";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage);
			return errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
		}

		_systemLogger.log(Level.INFO, MODULE, sMethod, sMethod + " successful");
		return errorResponse;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler#retrieveIssuer(java.lang.String, org.opensaml.common.SignableSAMLObject)
	 */
	@Override
	public Issuer retrieveIssuer(String elementName, SignableSAMLObject samlMessage)
	{
		if (elementName.equals(LOGOUTREQUEST)) {
			LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
			return logoutRequest.getIssuer();
		}
		return null;
	}
}