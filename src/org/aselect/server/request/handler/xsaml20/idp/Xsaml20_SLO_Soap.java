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

import java.io.StringReader;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.SoapManager;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.ServiceProvider;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

//
// IdP Soap Logout Request Handler
// Handles request from the SP using Soap
//
public class Xsaml20_SLO_Soap extends Saml20_BaseHandler
{
	private final static String MODULE = "Xsaml20_SLO_Soap";
	private static final String SOAP_TYPE = "text/xml";
	// private static final String CONTENT_TYPE = "text/xml; charset=utf-8";
	private SystemLogger _oSystemLogger = _systemLogger;
	private String _sRedirectUrl;
	private static final String LOGOUTREQUEST = "LogoutRequest";

	// private boolean _bVerifySignature = true; // RH, 20080602, o, Is now done by Saml20_BaseHandler

	/**
	 * Init for class Xsaml20_SLO_Soap. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig.
	 * @param oHandlerConfig
	 *            Object.
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		super.init(oServletConfig, oHandlerConfig);
		_oSystemLogger = _systemLogger;

		try {
			ConfigManager oConfigManager = ASelectConfigManager.getHandle();
			Object aselectSection = oConfigManager.getSection(null, "aselect");
			_sRedirectUrl = _configManager.getParam(aselectSection, "redirect_url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_url' found in 'aselect' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Process logout request. <br>
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If processing of logout request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process";
		String sContentType = request.getContentType();
		_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Process Logout request, content=" + sContentType);

		if (sContentType != null && sContentType.startsWith(SOAP_TYPE)) {
			handleSOAPLogoutRequest(request, response);
		}
		return null;
	}

	/**
	 * Handle soap logout request.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleSOAPLogoutRequest(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "handleSOAPLogoutRequest";
		try {
			/*
			 * ServletInputStream input = request.getInputStream(); BufferedInputStream bis = new
			 * BufferedInputStream(input); char b = (char) bis.read(); StringBuffer sb = new StringBuffer(); while
			 * (bis.available() != 0) { sb.append(b); b = (char) bis.read(); } String sReceivedSoap = sb.toString();
			 */
			String sReceivedSoap = Tools.stream2string(request.getInputStream()); // RH, 20080715, n
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Received SOAP:\n" + sReceivedSoap);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(sReceivedSoap);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			Node eltArtifactResolve = SamlTools.getNode(elementReceivedSoap, LOGOUTREQUEST);

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);
			LogoutRequest logoutRequest = (LogoutRequest) unmarshaller.unmarshall((Element) eltArtifactResolve);

			// Check signature of LogoutRequest
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do LogoutRequest signature verification=" + is_bVerifySignature());
			String initiatingSP = logoutRequest.getIssuer().getValue();
			if (is_bVerifySignature()) {
				MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
				PublicKey pkey = metadataManager.getSigningKeyFromMetadata(initiatingSP);
				if (pkey == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "PublicKey for entityId: " + initiatingSP + " not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found PublicKey for entityId: " + initiatingSP);
				if (checkSignature(logoutRequest, pkey)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutRequest was signed OK");
				}
				else {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "LogoutRequest was NOT signed OK");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST); // Kick 'm out
				}
			}
			if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(logoutRequest)) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "LogoutRequest time interval was NOT valid");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST); // Kick 'm out
			}
			// Destroy local session
			String sNameID = logoutRequest.getNameID().getValue();
			removeSessionFromFederation(sNameID, initiatingSP);

			// Send LogoutResponse using SOAP
			String returnUrl = logoutRequest.getIssuer().getValue();
			String requestId = logoutRequest.getID();

			// Create LogoutResponse
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Send Logout Response to: " + returnUrl);
			String statusCode = StatusCode.SUCCESS_URI;

			LogoutResponse logoutResponse = SamlTools.buildLogoutResponse(_sRedirectUrl, statusCode, requestId);
			// always sign the logoutResponse
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the logoutResponse >======");
			logoutResponse = (LogoutResponse)SamlTools.signSamlObject(logoutResponse, "sha1");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the logoutResponse ======<");

			SoapManager soapManager = new SoapManager();
			Envelope envelope = soapManager.buildSOAPMessage(logoutResponse);
			Element envelopeElem = SamlTools.marshallMessage(envelope);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Send SAML response:\n" + XMLHelper.nodeToString(envelopeElem));
			SamlTools.sendSOAPResponse(response, XMLHelper.nodeToString(envelopeElem));  // x_LogoutReq_x Sp
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/*
	 * Deze methode haalt de sp's op uit de tgt manager als de sp die meegegeven wordt de laatste is kill de volledige
	 * tgt en anders haal alleen de meegeleverde sp uit de lijst van sp's
	 */
	/**
	 * Remove the session from federation. <br>
	 * 
	 * @param sNameID
	 *            String with user id.
	 * @param initiatingSP
	 *            the initiating sp
	 * @throws ASelectException
	 *             If remove session fails.
	 */
	public void removeSessionFromFederation(String sNameID, String initiatingSP)
		throws ASelectException
	{
		String _sMethod = "removeSessionFromFederation";
		String sCred = Utils.firstPartOf(sNameID, 30);
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - NameID=" + sCred + " Remove SP=" + initiatingSP);

		TGTManager tgtManager = TGTManager.getHandle();
		HashMap htTGTContext = tgtManager.getTGT(sNameID);
		if (htTGTContext == null) {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - NameID=" + sCred + " TGT not found");
			return;
		}
		UserSsoSession sso = (UserSsoSession) htTGTContext.get("sso_session");
		List<ServiceProvider> spList = sso.getServiceProviders();
		sso.setLogoutInitiator(initiatingSP);

		// SSOSessionManager ssoSessionManager = SSOSessionManager.getHandle();
		// UserSsoSession ssoSession = ssoSessionManager.getSsoSession(sNameID);
		// List<ServiceProvider> spList = ssoSession.getServiceProviders();
		// credentials = ssoSession.getTgtId();
		/*
		 * Check is there are more sp's if not then remove whole tgt else check is sp is the first in the active list
		 */
		if (spList.size() == 1) {
			// if (tgtManager.containsKey(sNameID)) {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - One SP, Remove TGT=" + sCred + " and uid="
					+ sNameID);
			tgtManager.remove(sNameID);
			// ssoSessionManager.remove(sNameID);
			// // TODO: could kill SLOTimer task for 'sNameID' at this point
			// }
			// else {
			// _oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - One SP, but no TGT found");
			// ssoSessionManager.remove(sNameID);
			// TODO: could kill SLOTimer task for 'sNameID' at this point
			// }
		}
		else if (spList.size() > 1) {
			for (ServiceProvider sp : spList) {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - Multiple SP's Url="
						+ sp.getServiceProviderUrl());
				if (sp.getServiceProviderUrl().equals(initiatingSP)) {
					// if (tgtManager.containsKey(sNameID)) {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - Remove SP=" + sp.getServiceProviderUrl()
							+ "for TGT=" + sCred);
					sso.removeServiceProvider(sp.getServiceProviderUrl());
					// overwrite the session (needed for database storage)
					htTGTContext.put("sso_session", sso);
					tgtManager.updateTGT(sNameID, htTGTContext);
					// ssoSessionManager.putSsoSession(ssoSession);
					break;
					// }
				}
			}
		}
		else {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - List of SP's is empty");
		}
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	@Override
	public void destroy()
	{
	}
}
