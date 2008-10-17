package org.aselect.server.request.handler.saml20.common;

import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Node;

public class LogoutResponseBuilder
{

	private static final String MODULE = "LogoutResponseBuilder";

	/**
	 * Build Logout Response.
	 * <br>
	 * @param issuer String with issuer.
	 * @param statusCodeValue String with ???.
	 * @param inResponseTo String with ???.
	 * @throws ASelectException If building logout response fails.
	 */
	@SuppressWarnings("unchecked")
	public LogoutResponse buildLogoutResponse(String issuer, String statusCodeValue, String inResponseTo)
		throws ASelectException
	{
		String sMethod = "buildLogoutResponse()";
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		SAMLObjectBuilder<LogoutResponse> logoutResponseBuilder = (SAMLObjectBuilder<LogoutResponse>) builderFactory
				.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
		LogoutResponse logoutResponse = logoutResponseBuilder.buildObject();

		// verplichte velden:

		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		String random;
		try {
			random = Utils.generateIdentifier(systemLogger, MODULE);
		}
		catch (ASelectException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage());
			// if generator failed we can use this
			random = "random" + Math.random();
		}
		logoutResponse.setID(random);
		// gebruiken
		logoutResponse.setVersion(SAMLVersion.VERSION_20);
		logoutResponse.setIssueInstant(new DateTime());

		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
				.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status status = statusBuilder.buildObject();
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue(statusCodeValue);
		status.setStatusCode(statusCode);
		logoutResponse.setStatus(status);

		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuerObject = issuerBuilder.buildObject();
		issuerObject.setValue(issuer);
		logoutResponse.setIssuer(issuerObject);

		logoutResponse.setInResponseTo(inResponseTo);

		MarshallerFactory factory = Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(logoutResponse);
		try {
			Node node = marshaller.marshall(logoutResponse);
			String msg = XMLHelper.prettyPrintXML(node);
			systemLogger.log(Level.INFO, MODULE, sMethod, "built message: \n" + msg);
		}
		catch (MarshallingException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception marhalling message: " + e.getMessage());
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return logoutResponse;

	}
}
