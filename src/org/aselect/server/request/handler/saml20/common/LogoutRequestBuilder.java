package org.aselect.server.request.handler.saml20.common;

import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.xml.XMLObjectBuilderFactory;

public class LogoutRequestBuilder
{

	private final static String MODULE = "LogoutRequestBuilder";

	private ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();

	/**
	 * Build Logout Request
	 * <br>
	 * @param serviceProviderUrl String with SP url.
	 * @param user String with user id.
	 * @param issuerUrl String with Issuer url.
	 * @param reason String with logout reason.
	 * @throws ASelectException If building logout request fails.
	 */
	@SuppressWarnings("unchecked")
	public LogoutRequest buildLogoutRequest(String serviceProviderUrl, String user, String issuerUrl, String reason)
		throws ASelectException
	{
		String sMethod = "buildLogoutRequest()";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		LogoutRequest logoutRequest = null;

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		SAMLObjectBuilder<LogoutRequest> logoutRequestBuilder = (SAMLObjectBuilder<LogoutRequest>) builderFactory
				.getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME);
		logoutRequest = logoutRequestBuilder.buildObject();
		// verplichte velden
		logoutRequest.setID(Utils.generateIdentifier(_systemLogger, MODULE));
		logoutRequest.setVersion(SAMLVersion.VERSION_20);
		logoutRequest.setIssueInstant(new DateTime());

		// een van de volgende 3 is verplicht baseId, encryptedId, nameId
		SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) builderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameId = nameIdBuilder.buildObject();
		nameId.setValue(user); // geef user name mee
		logoutRequest.setNameID(nameId);

		// optionele velden
		logoutRequest.setReason(reason);
		logoutRequest.setDestination(serviceProviderUrl);

		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerUrl);
		logoutRequest.setIssuer(issuer);

		return logoutRequest;

	}
}
