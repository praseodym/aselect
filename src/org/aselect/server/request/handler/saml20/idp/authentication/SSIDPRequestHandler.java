package org.aselect.server.request.handler.saml20.idp.authentication;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.URLEncoder;
import java.util.Calendar;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml20.common.NodeHelper;
import org.aselect.server.request.handler.saml20.common.SOAPManager;
import org.aselect.server.request.handler.saml20.common.Utils;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Action;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml2.core.DecisionTypeEnumeration;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class SSIDPRequestHandler extends AbstractRequestHandler
{
	private TGTManager _oTGTManager = TGTManager.getHandle();

	private final static String MODULE = "SSIDPRequestHandler";

	private static final String AUTHZDECISIONQUERY = "AuthzDecisionQuery";

	private SystemLogger _oSystemLogger = _systemLogger;

	/**
	 * Init for SSIDPRequestHandler. <br>
	 * 
	 * @param oServletConfig
	 *            The Servlet Config.
	 * @param oHandlerConfig
	 *            The Handler Config.
	 * @throws ASelectException
	 *             If initialisation fails.
	 */
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		super.init(oServletConfig, oHandlerConfig);
		_oSystemLogger = _systemLogger;
	}

	/**
	 * Process synchronization message. <br>
	 * 
	 * @param request
	 *            The HttpServletRequest.
	 * @param response
	 *            The HttpServletResponse.
	 * @throws ASelectException
	 *             If initialisation fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String _sMethod = "process";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "-- SS IDP RequestHandler --");

		if (request.getContentType().startsWith("text/xml")) {
			String docReceived = readRequest(request);
			String uid = null;
			String sp = null;
			String credentials = null;

			boolean samlMessage = determineMessageType(docReceived);

			if (samlMessage) {
				// Handle request to get uid
				AuthzDecisionQuery authzDecisionQuery = handleSAMLRequest(docReceived);
				uid = getUserFromSAML(authzDecisionQuery);
				sp = getServiceProviderFromSAML(authzDecisionQuery);
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SAML uid === " + uid + " SAML sp ===" + sp);
			}
			else {
				// Handle XACML Request
				Document xacmlDocument = handleXACMLRequest(docReceived);
				uid = getUserFromXAML(xacmlDocument);
				sp = getServiceProviderFromXACML(xacmlDocument);
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "XACML uid === " + uid + " XACML sp ===" + sp);
			}

			if (uid != null) {
				credentials = this.getCredentials(uid);
				// result can be null
			}
			else {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "No uid found in SAML message from SP");
			}
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "UID in IPD ===" + uid + " SP in IPD ===" + sp
					+ " CREDENTIALS in IPD ===" + credentials);
			
			try {
				if (uid != null && credentials != null && sp != null) {
					// Update update time for sp
					this.changeUpdateTimeSp(uid, sp, credentials);
				}
				else {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "UID, SP or Credentials not available (uid=" + uid
							+ " sp=" + sp + " credentials=" + credentials + ")");
					throw new ASelectException("Not permitted");  // send refusal (handled by catch clause below)
				}
				if (samlMessage) {
					this.sendSAMLResponse(request, response, uid, true);
				}
				else {
					this.sendXACMLResponse(request, response, uid, true);
				}
			}
			catch (ASelectException as) {
				if (samlMessage) {
					this.sendSAMLResponse(request, response, uid, false);
				}
				else {
					this.sendXACMLResponse(request, response, uid, false);
				}
				_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "failed to update on federation", as);
			}
		}
		return null;
	}

	/*
	 * Methode haalt de credentials van de user op
	 */
	private String getCredentials(String user)
	{
		String credentials = null;
		SSOSessionManager sso;
		try {
			sso = SSOSessionManager.getHandle();
		}
		catch (ASelectException e) {
			return null;
		}
		UserSsoSession session = sso.getSsoSession(user);
		if (session == null)
			return null;
		credentials = session.getTgtId();
		return credentials;
	}

	/*
	 * Methode update het session obj van de user
	 */
	private void updateSSOSession(String user)
		throws ASelectException
	{
		SSOSessionManager sso = SSOSessionManager.getHandle();
		UserSsoSession session = sso.getSsoSession(user);
		sso.update(user, session);
	}

	/*
	 * Methode werkt de lokale sessie tijd bij.
	 */
	private void changeTGTSessionTime(String decodedcredentials)
		throws ASelectStorageException
	{
		Hashtable tgtBeforeUpdate = (Hashtable) _oTGTManager.get(decodedcredentials);
		_oTGTManager.update(decodedcredentials, tgtBeforeUpdate);
	}

	/*
	 * Change the update time of the sp
	 */
	private void changeUpdateTimeSp(String user, String serviceProviderUrl, String credentials)
		throws ASelectException
	{
		String _sMethod = "changeUpdateTimeSp";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "change update time = " + user);
		ServiceProvider toChangeSp = null;
		long now = new Date().getTime();
		SSOSessionManager sso = SSOSessionManager.getHandle();
		UserSsoSession session = sso.getSsoSession(user);
		List<ServiceProvider> lijst = session.getServiceProviders();
		for (ServiceProvider sp : lijst) {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "ServiceProvider = " + serviceProviderUrl);
			if (sp.getServiceProviderUrl().equals(serviceProviderUrl)) {
				toChangeSp = sp;
			}
		}
		if (toChangeSp != null) {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Time SP update before = "
					+ toChangeSp.getLastSessionSync() + "(" + this.getReadableDate(toChangeSp.getLastSessionSync())
					+ ")");
			toChangeSp.setLastSessionSync(now);
			sso.update(user, session);
			
			// Bauke: Also update the TGT Timestamp
	        Hashtable htTGTContext = _oTGTManager.getTGT(credentials);
	        if (htTGTContext != null)
	            _oTGTManager.updateTGT(credentials, htTGTContext);
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Time SP update after = " +
					toChangeSp.getLastSessionSync() + " New TimeStamp="+_oTGTManager.getTimestamp(credentials));
		}
		else {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SP not found in list SP=(" + serviceProviderUrl + ")");
		}
	}

	/*
	 * Maakt een SAML Response en verstuurt deze naar de SP. boolean geeft aan
	 * of er permit of deny moet worden gestuurd.
	 */
	@SuppressWarnings("unchecked")
	private void sendSAMLResponse(HttpServletRequest request, HttpServletResponse response, String uid, boolean permit)
		throws ASelectException
	{
		String _sMethod = "sendSAMLResponse";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Send SAML response to SP");

		Response finalResponse = buildSAMLResponse(uid, permit);

		// Send response over SOAP
		SOAPManager soapManager = new SOAPManager();
		Envelope envelope = soapManager.buildSOAPMessage(finalResponse);
		Element envelopeElem = null;
		try {
			NodeHelper nodeHelper = new NodeHelper();
			envelopeElem = nodeHelper.marshallMessage(envelope);
		}
		catch (MessageEncodingException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "marshall message failed", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Send SAML response: "
				+ XMLHelper.prettyPrintXML(envelopeElem));
		response.setContentType("text/xml");
		try {
			PrintWriter writer = response.getWriter();
			writer.write(URLEncoder.encode(XMLHelper.nodeToString(envelopeElem), "UTF-8"));
			writer.close();
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "failed to send response to sp", e);
		}

	}

	/*
	 * De methode bouwt een response op de SAML AuthzDecisionQuery boolean geeft
	 * aan of er permit of deny moet worden gestuurd.
	 */
	@SuppressWarnings("unchecked")
	private Response buildSAMLResponse(String uid, boolean permit)
		throws ASelectException
	{
		String sMethod = "buildSAMLResponse";
		_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Build SAML Response for " + uid);

		// Build SAML Response
		XMLObjectBuilderFactory oBuilderFactory = Configuration.getBuilderFactory();
		SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) oBuilderFactory
				.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response resp = responseBuilder.buildObject();

		// Build Assertion
		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) oBuilderFactory
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		Assertion assertion = assertionBuilder.buildObject();

		// Build Subject and NameID
		SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) oBuilderFactory
				.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject subject = subjectBuilder.buildObject();
		SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) oBuilderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameId = nameIdBuilder.buildObject();
		nameId.setValue(uid);
		subject.setNameID(nameId);

		// Build Action
		SAMLObjectBuilder<Action> actionBuilder = (SAMLObjectBuilder<Action>) oBuilderFactory
				.getBuilder(Action.DEFAULT_ELEMENT_NAME);
		Action action = actionBuilder.buildObject();
		action.setAction(Action.HTTP_GET_ACTION);

		// add authzdecisionstatement too assertion
		SAMLObjectBuilder<AuthzDecisionStatement> statementBuilder = (SAMLObjectBuilder<AuthzDecisionStatement>) oBuilderFactory
				.getBuilder(AuthzDecisionStatement.DEFAULT_ELEMENT_NAME);
		AuthzDecisionStatement statement = statementBuilder.buildObject();
		if (permit) {
			statement.setDecision(DecisionTypeEnumeration.PERMIT);
		}
		else {
			statement.setDecision(DecisionTypeEnumeration.DENY);
		}

		List<Action> actions = statement.getActions();
		actions.add(action);

		// add subject and authzDecisionStatement too assertion
		assertion.setSubject(subject);
		List<AuthzDecisionStatement> authzDecisionStatements = assertion.getAuthzDecisionStatements();
		authzDecisionStatements.add(statement);
		assertion.setVersion(SAMLVersion.VERSION_20);
		assertion.setIssueInstant(new DateTime());
		try {
			assertion.setID(Utils.generateIdentifier(_systemLogger, MODULE));
		}
		catch (ASelectException ase) {
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, "failed to build SAML response", ase);
		}

		// Build Status with status code
		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) oBuilderFactory
				.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status status = statusBuilder.buildObject();
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) oBuilderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue(StatusCode.SUCCESS_URI);
		status.setStatusCode(statusCode);

		// Fill Response
		resp.setStatus(status);
		List<Assertion> assertions = resp.getAssertions();
		assertions.add(assertion);

		resp.setID(Utils.generateIdentifier(_systemLogger, MODULE));
		resp.setVersion(SAMLVersion.VERSION_20);
		resp.setIssueInstant(new DateTime());
		Response finalResponse = marshallResponse(resp);

		return finalResponse;
	}

	/*
	 * Deze methode vangt het SAML bericht op van de sp en haalt de benodigde
	 * gegevens uit het bericht. En geeft de gebruiker terug.
	 */
	private AuthzDecisionQuery handleSAMLRequest(String docReceived)
		throws ASelectException
	{

		String _sMethod = "handleSAMLRequest";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Process SAML message");
		AuthzDecisionQuery authzDecisionQuery = null;
		try {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Received update: " + docReceived);

			// Build XML Document
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(docReceived);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);

			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "docReceivedSOAP = " + docReceivedSoap);

			// Get AuthzDecision obj
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			NodeHelper nodeHelper = new NodeHelper();
			Node eltArtifactResolve = nodeHelper.getNode(elementReceivedSoap, AUTHZDECISIONQUERY);

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);
			authzDecisionQuery = (AuthzDecisionQuery) unmarshaller.unmarshall((Element) eltArtifactResolve);
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed too process SAML message", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return authzDecisionQuery;
	}

	/*
	 * Methode haalt de user id uit de SAML AuthzDecisionQuery
	 */
	private String getUserFromSAML(AuthzDecisionQuery authzDecisionQuery)
	{
		Subject subject = authzDecisionQuery.getSubject();
		NameID nameId = subject.getNameID();
		return nameId.getValue();
	}

	/*
	 * Methode haalt de SP uit de SAML AuthzDecisionQuery
	 */
	private String getServiceProviderFromSAML(AuthzDecisionQuery authzDecisionQuery)
	{
		Issuer issuer = authzDecisionQuery.getIssuer();
		return issuer.getValue();
	}

	private Document handleXACMLRequest(String xacmlMessage)
		throws ASelectException
	{
		String _sMethod = "handleSAMLRequest";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Handle XACML Request");
		Document xacmlMessge = null;
		try {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Received update: " + xacmlMessage);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(xacmlMessage);
			InputSource inputSource = new InputSource(stringReader);
			xacmlMessge = builder.parse(inputSource);
		}
		catch (ParserConfigurationException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		catch (SAXException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		catch (IOException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}

		return xacmlMessge;
	}

	/*
	 * Methode haalt de user id uit de XACML AuthzDecisionQuery
	 */
	private String getUserFromXAML(Document xacmlDocument)
	{
		Node node = xacmlDocument.getFirstChild();
		NodeHelper nodeHelper = new NodeHelper();
		Node SubjectNode = nodeHelper.getNode(node, "Subject");
		String uid = nodeHelper.getNode(SubjectNode, "AttributeValue").getTextContent();
		return uid;
	}

	/*
	 * Methode haalt de SP uit de XACML AuthzDecisionQuery
	 */
	private String getServiceProviderFromXACML(Document xacmlDocument)
	{
		Node node = xacmlDocument.getFirstChild();
		NodeHelper nodeHelper = new NodeHelper();
		Node SubjectNode = nodeHelper.getNode(node, "Subject");
		Node ResourceNode = SubjectNode.getNextSibling();
		String resource = nodeHelper.getNode(ResourceNode, "AttributeValue").getTextContent();
		return resource;
	}

	private void sendXACMLResponse(HttpServletRequest request, HttpServletResponse response, String uid, boolean permit)
	{
		String _sMethod = "sendXACMLResponse";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Send XACML response to SP");

		String finalResponse = buildXACMLResponse(uid, permit);
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Send XACML response: " + finalResponse);
		response.setContentType("text/xml");
		try {
			PrintWriter writer = response.getWriter();
			writer.write(finalResponse);
			writer.close();
		}
		catch (IOException io) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "IOException trying to send response to sp", io);
		}

	}

	/*
	 * De methode bouwt een response op de XACML AuthzDecisionQuery
	 */
	private String buildXACMLResponse(String uid, boolean permit)
	{
		String sMethod = "buildXACMLResponse";
		_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Build XAML Response for " + uid);

		String decision = null;
		String statusCode = null;
		if (permit) {
			decision = "Permit";
			statusCode = "urn:oasis:names:tc:xacml:1.0:status:ok";
		}
		else {
			decision = "Deny";
			statusCode = "urn:oasis:names:tc:xacml:1.0:status:ok";
		}

		String xacmlResponse = "<soap:Envelope xmlns:xsi=\" http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\" http://schemas.xmlsoap.org/soap/envelope/\">"
				+ "<soap:Body>"
				+ "<Response>"
				+ "<Result>"
				+ "<Decision>"
				+ decision
				+ "</Decision>"
				+ "<Status>"
				+ "<StatusCode Value=\""
				+ statusCode
				+ "\"/>"
				+ "</Status>"
				+ "</Result>"
				+ "</Response>"
				+ "</soap:Body>" + "</soap:Envelope>";
		return xacmlResponse;
	}

	public Response marshallResponse(Response response)
		throws ASelectException
	{
		String sMethod = "marshallResponse";
		MarshallerFactory factory = Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(response);
		try {
			Node node = marshaller.marshall(response);
			String msg = XMLHelper.prettyPrintXML(node);
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, msg);
		}
		catch (MarshallingException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return response;
	}

	public void destroy()
	{

	}

	private String getReadableDate(long timestamp)
	{
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(new Date(timestamp));
		StringBuffer temp = new StringBuffer();

		temp.append(calendar.get(Calendar.DAY_OF_MONTH));
		temp.append('.');
		temp.append(calendar.get(Calendar.MONTH) + 1);
		temp.append('.');
		temp.append(calendar.get(Calendar.YEAR));

		temp.append(' ');
		temp.append(calendar.get(Calendar.HOUR_OF_DAY));
		temp.append(':');
		temp.append(calendar.get(Calendar.MINUTE));
		temp.append(':');
		temp.append(calendar.get(Calendar.SECOND));

		return temp.toString();
	}

	private boolean determineMessageType(String request)
		throws ASelectException
	{
		String _sMethod = "determinteMessageType";
		boolean saml = true;
		try {
			// Build XML Document
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(request);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);

			// print document
			// Serialize the document
			OutputFormat format = new OutputFormat(docReceivedSoap);
			format.setLineWidth(65);
			format.setIndenting(true);
			format.setIndent(2);
			XMLSerializer serializer = new XMLSerializer(System.out, format);
			serializer.serialize(docReceivedSoap);

			// Get AuthzDecision obj

			Node node = docReceivedSoap.getFirstChild();
			NodeHelper nodeHelper = new NodeHelper();
			Node doesAuthzExist = nodeHelper.getNode(node, AUTHZDECISIONQUERY);
			if (doesAuthzExist == null) {
				saml = false;
			}
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to determinte message", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return saml;
	}

	private String readRequest(HttpServletRequest request)
		throws ASelectException
	{
		String _sMethod = "readRequest";
		String returnString = null;
		try {
			// Read SAML message
			ServletInputStream input = request.getInputStream();
			BufferedInputStream bis = new BufferedInputStream(input);
			char b = (char) bis.read();
			StringBuffer sb = new StringBuffer();
			while (bis.available() != 0) {
				sb.append(b);
				b = (char) bis.read();
			}
			returnString = sb.toString();
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed read request", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return returnString;
	}
}
