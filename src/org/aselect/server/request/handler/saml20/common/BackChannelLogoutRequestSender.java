package org.aselect.server.request.handler.saml20.common;

import java.io.StringReader;
import java.net.URLDecoder;
import java.util.logging.Level;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public class BackChannelLogoutRequestSender
{
	private final static String MODULE = "BackChannelLogoutRequestSender";

	private static final String LOGOUTRESPONSE = "LogoutResponse";

	private ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();

	/**
	 * Send Logout Request. <br>
	 * 
	 * @param serviceProviderUrl
	 *            String with SP url.
	 * @param issuerUrl
	 *            String with Issuer url.
	 * @param user
	 *            String with user id.
	 * @param reason
	 *            String with logout reason.
	 * @throws ASelectException
	 *             If sending fails.
	 */
	public void sendLogoutRequest(String serviceProviderUrl, String issuerUrl, String user, String reason)
		throws ASelectException
	{
		String sMethod = "sendLogoutRequest";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Send backchannel LogoutRequest to " + serviceProviderUrl
				+ " for user: " + user);

		LogoutRequestBuilder logoutRequestBuilder = new LogoutRequestBuilder();
		LogoutRequest logoutRequest = logoutRequestBuilder.buildLogoutRequest(serviceProviderUrl, user, issuerUrl,
				reason);

		SOAPManager soapManager = new SOAPManager();
		Envelope envelope = soapManager.buildSOAPMessage(logoutRequest);

		Element envelopeElem = null;
		try {
			NodeHelper nodeHelper = new NodeHelper();
			envelopeElem = nodeHelper.marshallMessage(envelope);
			//String msg = XMLHelper.prettyPrintXML(envelopeElem);
			//_systemLogger.log(Level.INFO, MODULE, sMethod, "sending message: " + msg);
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception during marshallling of envelope");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		try {
			// Send/Receive the SOAP message
			String resp = soapManager.sendSOAP(XMLHelper.nodeToString(envelopeElem), serviceProviderUrl);
			String sSamlResponse = URLDecoder.decode(resp, "UTF-8");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received response: " + sSamlResponse);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(sSamlResponse);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			NodeHelper nodeHelper = new NodeHelper();
			Node eltArtifactResolve = nodeHelper.getNode(elementReceivedSoap, LOGOUTRESPONSE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Artifact retrieved");
			// XMLHelper.nodeToString(eltArtifactResolve));

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);

			LogoutResponse logoutResponse = (LogoutResponse) unmarshaller.unmarshall((Element) eltArtifactResolve);
			StatusCode statusCode = logoutResponse.getStatus().getStatusCode();
			if (!statusCode.getValue().equals(StatusCode.SUCCESS_URI)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Backchannel logout NOT succesful. Received statuscode=" + statusCode.getValue() + " from "
								+ serviceProviderUrl);
			}
			else {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Backchannel logout for " + serviceProviderUrl
						+ " was succesful");
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The encoding 'UTF-8' is not supported", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}
}
