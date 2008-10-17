package org.aselect.server.request.handler.saml20.common;

import java.net.MalformedURLException;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.saml20.idp.metadata.MetaDataManagerIDP;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class BackChannelLogoutResponseSender
{

	private static final String MODULE = "BackChannelLogoutResponseSender";

	private ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();

	/**
	 * Send Logout Response.
	 * <br>
	 * @param serviceProvider String with SP url.
	 * @param issuerUrl String with Issuer url.
	 * @param user String with user id.
	 * @param statusCodeValue String with ???.
	 * @param inResponseTo String with ???.
	 * @throws ASelectException If sending fails.
	 */
	public void sendLogoutResponse(String serviceProvider, String issuerUrl, String user, String statusCodeValue,
			String inResponseTo)
	throws ASelectException
	{
		String sMethod = "sendLogoutResponse";
		LogoutResponseBuilder logoutResponseBuilder = new LogoutResponseBuilder();
		LogoutResponse logoutResponse = logoutResponseBuilder.buildLogoutResponse(issuerUrl, statusCodeValue,
				inResponseTo);

		if (serviceProvider == null)
			return;
		SOAPManager soapManager = new SOAPManager();
		Envelope envelope = soapManager.buildSOAPMessage(logoutResponse);

		Element envelopeElem = null;
		try {
			NodeHelper nodeHelper = new NodeHelper();
			envelopeElem = nodeHelper.marshallMessage(envelope);
			String msg = XMLHelper.prettyPrintXML(envelopeElem);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Sending message: " + msg);
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		try {
			// get response location from metadata
			MetaDataManagerIDP metadataManager = MetaDataManagerIDP.getHandle();
			String responseLocation = metadataManager.getResponseLocation(serviceProvider,
					SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_SOAP11_BINDING_URI);
			if (responseLocation == null) {
				responseLocation = metadataManager.getLocation(serviceProvider,
					SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_SOAP11_BINDING_URI);
			}

			// Send the SOAP message, we don't expect an answer
			_systemLogger.log(Level.INFO, MODULE, sMethod, "responseLocation="+responseLocation);
			if (responseLocation != null)
				soapManager.sendSOAP(XMLHelper.nodeToString(envelopeElem), responseLocation);
			else
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No location to send to, skipped!");
		}
		catch (MalformedURLException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Bad URL: "+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unexpected "+e.getClass()+" exception: "+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}
}
