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

import java.io.StringReader;
import java.security.PublicKey;
import java.util.List;
import java.util.logging.Level;

import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
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

public class SoapLogoutRequestSender
{
	private final static String MODULE = "SoapLogoutRequestSender";
	private static final String LOGOUTRESPONSE = "LogoutResponse";
	private ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
	
	private SSLSocketFactory sslSocketFactory = null;


	
	public SoapLogoutRequestSender() {
	}
	
	
	public SoapLogoutRequestSender(SSLSocketFactory socketFactory ) {
		this.sslSocketFactory = socketFactory;
	}

	
	/**
	 * Send Logout Request. <br>
	 * 
	 * @param serviceProviderUrl
	 *            String with SP url.
	 * @param issuerUrl
	 *            String with Issuer url.
	 * @param sNameID
	 *            String with NameID.
	 * @param reason
	 *            String with logout reason.
	 * @throws ASelectException
	 *             If sending fails.
	 */

	@Deprecated
	   /**
     * @deprecated
     * use sendSoapLogoutRequest(String serviceProviderUrl, String issuerUrl, String sNameID, String reason, PublicKey pkey)
     * 
     */
	public void sendSoapLogoutRequest(String serviceProviderUrl, String issuerUrl, String sNameID, String reason)
		throws ASelectException
	{
		sendSoapLogoutRequest(serviceProviderUrl, issuerUrl, sNameID, reason, null);
	}

	/**
	 * Send Logout Request. <br>
	 * 
	 * @param serviceProviderUrl
	 *            String with SP url.
	 * @param issuerUrl
	 *            String with Issuer url.
	 * @param sNameID
	 *            String with NameID.
	 * @param reason
	 *            String with logout reason.
	 * @param pkey
	 *            Public key to verify SOAP response with, if null do not verify response
	 * @throws ASelectException
	 *             If sending fails.
	 */
	public void sendSoapLogoutRequest(String serviceProviderUrl, String issuerUrl, String sNameID, String reason, PublicKey pkey)
	throws ASelectException
	{
		 sendSoapLogoutRequest(serviceProviderUrl, issuerUrl, sNameID, reason, pkey, null);
	}
	
	
	/**
	 * Send Logout Request. <br>
	 * 
	 * @param serviceProviderUrl
	 *            String with SP url.
	 * @param issuerUrl
	 *            String with Issuer url.
	 * @param sNameID
	 *            String with NameID.
	 * @param reason
	 *            String with logout reason.
	 * @param pkey
	 *            Public key to verify SOAP response with, if null do not verify response
	 * @param  List<String>sessionindexes
	 * 				optional list of sessionindexes to kill
	 * @throws ASelectException
	 *             If sending fails.
	 */
	public void sendSoapLogoutRequest(String serviceProviderUrl, String issuerUrl, String sNameID, String reason, PublicKey pkey, List<String> sessionindexes)
	throws ASelectException
	{
		String sMethod = "sendSoapLogoutRequest";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Send backchannel LogoutRequest to " + serviceProviderUrl
				+ " for user: " + sNameID);

//		LogoutRequest logoutRequest = SamlTools.buildLogoutRequest(serviceProviderUrl, null, sNameID, issuerUrl, reason);	// RH, 20120201, o
		LogoutRequest logoutRequest = SamlTools.buildLogoutRequest(serviceProviderUrl, null, sNameID, issuerUrl, reason, sessionindexes);// RH, 20120201, n
		// IMPROVE: SamlTools.setValidityInterval with only NotOnOrAfter, but we need this from calling object
		
		// Always sign the logoutRequest
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the logoutRequest >======");
		logoutRequest = (LogoutRequest)SamlTools.signSamlObject(logoutRequest);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the logoutRequest ======<");

//		SoapManager soapManager = new SoapManager();
		SoapManager soapManager = new SoapManager(sslSocketFactory);	// sslSocketFactory may be null
		
		Envelope envelope = soapManager.buildSOAPMessage(logoutRequest);

		Element envelopeElem = null;
		try {
			envelopeElem = SamlTools.marshallMessage(envelope);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Sending SOAP message:\n" + XMLHelper.nodeToString(envelopeElem));
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception during marshallling of envelope");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		try {  // Send/Receive the SOAP message
			String sSamlResponse = soapManager.sendSOAP(XMLHelper.nodeToString(envelopeElem), serviceProviderUrl);  // x_LogoutRequest_x
			 // 20100812: was not sent through the URL, so don't decode: 
			// String sSamlResponse = URLDecoder.decode(resp, "UTF-8");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received response:\n" + sSamlResponse);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(sSamlResponse);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			Node eltArtifactResolve = SamlTools.getNode(elementReceivedSoap, LOGOUTRESPONSE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutResponse retrieved");
			// XMLHelper.nodeToString(eltArtifactResolve));

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);

			LogoutResponse logoutResponse = (LogoutResponse) unmarshaller.unmarshall((Element) eltArtifactResolve);

			if (pkey != null) { // if there is a key supplied by the calling class, check it
				if (SamlTools.checkSignature(logoutResponse, pkey)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutResponse was signed OK");
				}
				else {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "LogoutResponse was NOT signed OK");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
			}
			else {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No signature verification required on LogoutResponse");
			}
			StatusCode statusCode = logoutResponse.getStatus().getStatusCode();
			if (!statusCode.getValue().equals(StatusCode.SUCCESS_URI)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Backchannel logout NOT successful. Statuscode="
						+ statusCode.getValue() + " from " + serviceProviderUrl);
			}
			else {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Backchannel logout for " + serviceProviderUrl
						+ " was successful");
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Backchannel logout failed", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}
}
