package org.aselect.server.request.handler.xsaml20;

import java.security.PrivateKey;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.LogoutResponse;
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

public class LogoutResponseSender
{
	private final static String MODULE = "LogoutResponseSender";
	private ASelectSystemLogger _systemLogger;
	private PrivateKey privateKey;

	public LogoutResponseSender() {
		_systemLogger = ASelectSystemLogger.getHandle();
		privateKey = ASelectConfigManager.getHandle().getDefaultPrivateKey();
	}

	/**
	 * Send Logout Response. <br>
	 * 
	 * @param logoutResponseLocation
	 *                String with location to send response .
	 * @param issuer
	 *                String with Issuer url.
	 * @param statusCode
	 *                String with ???.
	 * @param inResponseTo
	 *                String with ???.
	 * @param request
	 *                HttpServletRequest.
	 * @param response
	 *                HttpServletResponse.
	 * @throws ASelectException
	 *                 If sending fails.
	 */
	@SuppressWarnings("unchecked")
	public void sendLogoutResponse(String logoutResponseLocation, String issuer, String statusCode,
			String inResponseTo, HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "sendLogoutResponse()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Send LogoutResponse to: " + logoutResponseLocation);

		LogoutResponse logoutResponse = SamlTools.buildLogoutResponse(issuer, statusCode, inResponseTo);

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
				.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		samlEndpoint.setLocation(logoutResponseLocation);
		String sAppUrl = request.getRequestURL().toString();
		samlEndpoint.setResponseLocation(sAppUrl);

//		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response); // RH 20080529, o
		HttpServletResponseAdapter outTransport = SamlTools.createHttpServletResponseAdapter(response, logoutResponseLocation); // RH 20080529, n
		// RH 20081113, set appropriate headers
		outTransport.setHeader("Pragma", "no-cache");
		outTransport.setHeader("Cache-Control", "no-cache, no-store");
		
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setOutboundSAMLMessage(logoutResponse);
		messageContext.setPeerEntityEndpoint(samlEndpoint);
		// 20081109: messageContext.setRelayState("relay");

		BasicX509Credential credential = new BasicX509Credential();

		credential.setPrivateKey(privateKey);
		messageContext.setOutboundSAMLMessageSigningCredential(credential);

		MarshallerFactory factory = Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(messageContext.getOutboundSAMLMessage());
		Node node = null;
		try {
			node = marshaller.marshall(messageContext.getOutboundSAMLMessage());
		}
		catch (MarshallingException e) {
			_systemLogger.log(Level.WARNING, "Exception in marshalling of SAML message");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		String msg = XMLHelper.prettyPrintXML(node);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "About to send: \n" + msg);

		// store it in de history
		SamlHistoryManager history = SamlHistoryManager.getHandle();
		history.put(logoutResponse.getID(), logoutResponse.getDOM());

		HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
		try {
			encoder.encode(messageContext);
		}
		catch (MessageEncodingException e) {
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}
}
