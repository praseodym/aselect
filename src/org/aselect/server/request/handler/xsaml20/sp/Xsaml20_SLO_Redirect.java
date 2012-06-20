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
package org.aselect.server.request.handler.xsaml20.sp;

import java.io.PrintWriter;
import java.security.PublicKey;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.LogoutResponseSender;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.Saml20_RedirectDecoder;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.sp.MetaDataManagerSp;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.util.XMLHelper;


//
// SP Soap Logout Request Handler
// Handles IdP requests using HTTP redirect
//
public class Xsaml20_SLO_Redirect extends Saml20_BaseHandler
{
	private final static String MODULE = "sp.Xsaml20_SLO_Redirect";
	private static final String LOGOUTREQUEST = "LogoutRequest";

	/**
	 * Init for class Saml20_BaseHandler. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig
	 * @param oHandlerConfig
	 *            Object
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
	throws ASelectException
	{
		super.init(oServletConfig, oHandlerConfig);
	}

	/**
	 * Dit is stap 7 van SLO. We hebben zojuist een saml LogoutRequest ontvangen en gaan deze nu verwerken. Dit houdt
	 * in: We loggen de gebruiker hier uit en maken hier melding van naar de federatie idp.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @return the request state
	 * @throws ASelectException
	 *             the a select exception
	 */
	/**
	 * Process logout request. <br>
	 * 
	 * @param request
	 *            HttpServletRequest
	 * @param response
	 *            HttpServletResponse
	 * @throws ASelectException
	 *             If processing of logout request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		if (request.getParameter("SAMLRequest") != null) {
			handleSAMLRequest(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + request.getQueryString()
					+ " not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		return null;
	}

	/**
	 * Handle saml request.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleSAMLRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
	throws ASelectException
	{
		String sMethod = "handleSAMLRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		try {
			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(httpRequest));

			Saml20_RedirectDecoder decoder = new Saml20_RedirectDecoder();
			decoder.decode(messageContext);

			SignableSAMLObject samlMessage = (SignableSAMLObject) messageContext.getInboundSAMLMessage();
			_systemLogger.log(Level.INFO, MODULE, sMethod, XMLHelper.prettyPrintXML(samlMessage.getDOM()));

			String elementName = samlMessage.getElementQName().getLocalPart();

			// get the issuer
			Issuer issuer;
			if (elementName.equals(LOGOUTREQUEST)) {
				LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
				issuer = logoutRequest.getIssuer();
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage: "
						+ XMLHelper.prettyPrintXML(samlMessage.getDOM()) + " is not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			String sEntityId = issuer.getValue();

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do logoutRequest signature verification="
					+ is_bVerifySignature());
			if (is_bVerifySignature()) {
				// The SAMLRequest must be signed, if not the message can't be trusted
				// and a responsemessage is send to the browser
				if (!SamlTools.isSigned(httpRequest)) {
					String errorMessage = "SAML message must be signed.";
					// TODO Why do we send return message here and throw
					// exception in all other cases?
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					PrintWriter pwOut = httpResponse.getWriter();
					pwOut.write(errorMessage);
					return;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML message IS signed.");
				MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
				PublicKey publicKey = metadataManager.getSigningKeyFromMetadata(sEntityId);
				if (publicKey == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "PublicKey for entityId: " + sEntityId
							+ " not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found PublicKey for entityId: " + sEntityId);
				if (!SamlTools.verifySignature(publicKey, httpRequest)) {
					String errorMessage = "Signing of SAML message is not correct.";
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					PrintWriter pwOut = httpResponse.getWriter();
					pwOut.write(errorMessage);
					return;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Signature is correct.");
			}

			// The signature is OK and the message can be processed
			if (elementName.equals(LOGOUTREQUEST)) {
				LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
				// now check the validity of the supplied time interval (if present)
				if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(logoutRequest)) {
					String errorMessage = "Time interval of SAML message is not valid.";
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					PrintWriter pwOut = httpResponse.getWriter();
					pwOut.write(errorMessage);
					return;
				}
				handleLogoutRequest(httpRequest, httpResponse, logoutRequest);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage: "
						+ XMLHelper.prettyPrintXML(samlMessage.getDOM()) + " is not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);

			}
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
	 * TO: De aangesproken SP vernietigt de lokale serversessie en clientcookie.De SP redirect de gebruiker naar de
	 * federatie-idp logoutservice met een LogoutResponse
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @param logoutRequest
	 *            the logout request
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogoutRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			LogoutRequest logoutRequest)
	throws ASelectException
	{
		String sMethod = "handleLogoutRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		// Destroy the local session
		String sNameID = logoutRequest.getNameID().getValue();
		int found = removeTgtByNameID(sNameID);
		if (found == 0) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "NO TGT FOUND");
		}

		// Delete the client cookie
		String sCookieDomain = _configManager.getCookieDomain();
		HandlerTools.delCookieValue(httpResponse, "aselect_credentials", sCookieDomain, _systemLogger);

		// Redirect the user to the federation-idp LogoutService with a LogoutResponse
		String issuer = logoutRequest.getIssuer().getValue();
		String statusCode = StatusCode.SUCCESS_URI;
		String myEntityId = _sServerUrl;

		MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
		String logoutResponseLocation = metadataManager.getResponseLocation(issuer,
				SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		if (logoutResponseLocation == null) {
			// if responselocation does not exist, use location
			logoutResponseLocation = metadataManager.getLocation(issuer,
					SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		}
		LogoutResponseSender sender = new LogoutResponseSender();
		sender.sendLogoutResponse(logoutResponseLocation, myEntityId, statusCode, logoutRequest.getID(), null,
				httpRequest, httpResponse);
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	@Override
	public void destroy()
	{
	}
}
