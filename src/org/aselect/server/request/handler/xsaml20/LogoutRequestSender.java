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
package org.aselect.server.request.handler.xsaml20;

import java.security.PrivateKey;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Node;

public class LogoutRequestSender
{
	private final static String MODULE = "LogoutRequestSender";
	private ASelectSystemLogger _systemLogger;
	private PrivateKey privateKey;

	/**
	 * Instantiates a new logout request sender.
	 */
	public LogoutRequestSender()
	{
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
		privateKey = _configManager.getDefaultPrivateKey();
	}

	/**
	 * Sends a LogoutRequest.
	 * 
	 * @param sServiceProviderUrl
	 *            the service provider url
	 * @param sNameID
	 *            the name id
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @param sTgT
	 *            the TGT
	 * @param sIssuerUrl
	 *            the issuer url
	 * @param reason
	 *            the reason
	 * @param sLogoutReturnUrl
	 *            the logout return url
	 * @param  List<String>sessionindexes
	 * 				optional list of sessionindexes to kill
	 * @throws ASelectException
	 *             the A-select exception
	 */
	public void sendLogoutRequest(HttpServletRequest request, HttpServletResponse response, String sTgT,
			String sServiceProviderUrl, String sIssuerUrl, String sNameID, String reason, String sLogoutReturnUrl)
		throws ASelectException
	{	// for backward compatibility
		sendLogoutRequest(request, response, sTgT, sServiceProviderUrl, sIssuerUrl, sNameID, reason, sLogoutReturnUrl, null);
	}
	
	@SuppressWarnings("unchecked")
	public void sendLogoutRequest(HttpServletRequest request, HttpServletResponse response, String sTgT,
			String sServiceProviderUrl, String sIssuerUrl, String sNameID, String reason, String sLogoutReturnUrl, List<String>sessionindexes)
		throws ASelectException
	{
		String sMethod = "sendLogoutRequest";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Send LogoutRequest to: " + sServiceProviderUrl);
		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();

//		LogoutRequest logoutRequest = SamlTools.buildLogoutRequest(sServiceProviderUrl, sTgT, sNameID, sIssuerUrl, reason);
		LogoutRequest logoutRequest = SamlTools.buildLogoutRequest(sServiceProviderUrl, sTgT, sNameID, sIssuerUrl, reason, sessionindexes);
		// TODO setValidityInterval with only NotOnOrAfter, but we need this from calling object (from aselect.xml)
		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
				.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		// samlEndpoint.setBinding(HTTPPostEncoder.BINDING_URI);
		samlEndpoint.setLocation(sServiceProviderUrl);
		String sAppUrl = request.getRequestURL().toString();
		samlEndpoint.setResponseLocation(sAppUrl);

		HttpServletResponseAdapter outTransport = SamlTools.createHttpServletResponseAdapter(response, sServiceProviderUrl);
		// 20090627, Bauke: need headers too
		outTransport.setHeader("Pragma", "no-cache");
		outTransport.setHeader("Cache-Control", "no-cache, no-store");

		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setOutboundSAMLMessage(logoutRequest);
		messageContext.setPeerEntityEndpoint(samlEndpoint);

		// 20090627, Bauke: pass return url, will be used by the Logout Response handler
		// 20091105, Bauke: always pass a RelayState, will make the consent forms easier to implement
		// 20091118, Bauke: 20091105, bad decision, turn it back
		if (sLogoutReturnUrl != null) { // && !"".equals(sLogoutReturnUrl))
			messageContext.setRelayState(sLogoutReturnUrl);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Set RelayState=" + sLogoutReturnUrl);
		}
		// else
		// messageContext.setRelayState("none");

		BasicX509Credential credential = new BasicX509Credential();
		credential.setPrivateKey(privateKey);
		messageContext.setOutboundSAMLMessageSigningCredential(credential);

		MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(messageContext.getOutboundSAMLMessage());
		Node node = null;
		try {
			node = marshaller.marshall(messageContext.getOutboundSAMLMessage());
		}
		catch (MarshallingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception marshalling SAML message");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		String msg = XMLHelper.prettyPrintXML(node);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "About to send: " + msg);

		// Store it in the history
		SamlHistoryManager history = SamlHistoryManager.getHandle();
		history.put(sTgT, logoutRequest.getDOM());

		HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
		try {
			encoder.encode(messageContext);
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception encoding (and sending) SAML message");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}
}
