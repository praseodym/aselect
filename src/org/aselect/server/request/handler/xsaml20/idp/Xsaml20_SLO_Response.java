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

import java.io.IOException;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler;
import org.aselect.server.request.handler.xsaml20.SamlHistoryManager;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;


//
// IdP SLO Http Response Handler
//
public class Xsaml20_SLO_Response extends Saml20_BrowserHandler
{
	private static final String MODULE = "idp.LogoutResponseHandler";
	private final String LOGOUTRESPONSE = "LogoutResponse";

	private int _iRedirectLogoutTimeout = 30;
	private boolean _bTryRedirectLogoutFirst = true;
	private boolean _bSkipInvalidRedirects = false;

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler#destroy()
	 */
	@Override
	public void destroy()
	{
	}

	/**
	 * Init for class LogoutResponseHandler. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig.
	 * @param oConfig
	 *            Object.
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		super.init(oServletConfig, oConfig);
		String sMethod = "init()";

		String sValue = ASelectConfigManager.getSimpleParam(oConfig, "try_redirect_logout_first", false);
		if (sValue != null && !sValue.equals("true"))
			_bTryRedirectLogoutFirst = false;

		// 20121220, Bauke: added ability to skip bad metadata entries
		sValue = ASelectConfigManager.getSimpleParam(oConfig, "_bSkipInvalidRedirects", false);  // default is false
		if ("true".equals(sValue))
			_bSkipInvalidRedirects = true;

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
	 * Tell caller the XML type we want recognized
	 * Overrides the abstract method called in handleSAMLMessage().
	 * 
	 * @return
	 *		the XML type
	 */
	protected String retrieveXmlType()
	{
		return LOGOUTRESPONSE;
	}

	//
	// Signature was checked
	//
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler#handleSpecificSaml20Request(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, org.opensaml.common.SignableSAMLObject)
	 */
	@Override
	protected void handleSpecificSaml20Request(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			SignableSAMLObject samlMessage, String sRelayState)
	throws ASelectException
	{
		String sMethod = "handleSpecificSaml20Request";
		LogoutResponse logoutResponse = (LogoutResponse) samlMessage;

		// check if the logoutResponse was successful
		String status = logoutResponse.getStatus().getStatusCode().getValue();
		if (!status.equals(StatusCode.SUCCESS_URI)) {
			// not much we can do about it, we continue logging out
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "LogoutResponse failed, StatusCode=" + status);
		}

		// determine which user belongs to this response
		String sTgT = logoutResponse.getInResponseTo();
		if (sTgT.startsWith("_"))
			sTgT = sTgT.substring(1);
		Element element = (Element) SamlHistoryManager.getHandle().get(sTgT);

		// Get the original LogoutRequest sent by the initiating SP
		XMLObject originalRequest = null;
		try {
			originalRequest = SamlTools.unmarshallElement(element);
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error while unmarshalling " + element, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		if (!(originalRequest instanceof LogoutRequest)) {
			// Must be a LogoutRequest
			String msg = "LogoutRequest expected from SamlMessageHistory but received: " + originalRequest.getClass();
			_systemLogger.log(Level.INFO, MODULE, sMethod, msg);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		LogoutRequest originalLogoutRequest = (LogoutRequest) originalRequest;
		// String uid = originalLogoutRequest.getNameID().getValue();

		///////////////////////////////////////
		_systemLogger.log(Level.FINER, MODULE, sMethod, "originalLogoutRequest.getIssuer().getValue(): " +originalLogoutRequest.getIssuer().getValue() 
				+ ", logoutResponse.getIssuer().getValue()" +  logoutResponse.getIssuer().getValue());
		if (originalLogoutRequest.getIssuer().getValue().equals(logoutResponse.getIssuer().getValue())) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutResponse initiated by ourselves, no need to logoutNextSessionSP, redirecting user to: " + sRelayState);
			// if sRelayState = null maybe present the loggedout form?
			try {
				httpResponse.sendRedirect(sRelayState);
			}
			catch (IOException e) {
				throw	new ASelectCommunicationException("Could not redirect user", e);
			}
			return;
		}
		///////////////////////////////////////
		logoutNextSessionSP(httpRequest, httpResponse, originalLogoutRequest, null, null,
				_bTryRedirectLogoutFirst, _bSkipInvalidRedirects, _iRedirectLogoutTimeout, null, logoutResponse.getIssuer());
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler#retrieveIssuer(java.lang.String, org.opensaml.common.SignableSAMLObject)
	 */
	@Override
	public Issuer retrieveIssuer(String elementName, SignableSAMLObject samlMessage)
	{
		if (elementName.equals(LOGOUTRESPONSE)) {
			LogoutResponse logoutResponse = (LogoutResponse) samlMessage;
			return logoutResponse.getIssuer();
		}
		return null;
	}
}
