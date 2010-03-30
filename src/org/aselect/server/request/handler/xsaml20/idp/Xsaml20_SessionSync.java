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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.SoapManager;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.ServiceProvider;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.SubjectConfirmation;
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

public class Xsaml20_SessionSync extends Saml20_BaseHandler
{
	private TGTManager _oTGTManager = TGTManager.getHandle();
	private final static String MODULE = "Xsaml20_SessionSync";
	private static final String AUTHZDECISIONQUERY = "AuthzDecisionQuery";

	// private static final String CONTENT_TYPE = "text/xml; charset=utf-8";

	/**
	 * Init for Xsaml20_SessionSync. <br>
	 * 
	 * @param oServletConfig
	 *            The Servlet Config.
	 * @param oHandlerConfig
	 *            The Handler Config.
	 * @throws ASelectException
	 *             If initialisation fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";
		super.init(oServletConfig, oHandlerConfig);
	}

	/**
	 * Process Session Sync Request<br>
	 * .
	 * 
	 * @param request
	 *            The HttpServletRequest.
	 * @param response
	 *            The HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If initialisation fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String _sMethod = "process";
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "-- SS IDP RequestHandler --");

		if (request.getContentType().startsWith("text/xml")) {
			String docReceived = readHttpPostData(request);
			String sNameID = null;
			String sp = null;
			// String credentials = null;

			boolean samlMessage = determineMessageType(docReceived);
			if (samlMessage) {
				// Handle request to get uid
				AuthzDecisionQuery authzDecisionQuery = handleSAMLRequest(docReceived);
				sNameID = getNameIdFromSAML(authzDecisionQuery);
				sp = getServiceProviderFromSAML(authzDecisionQuery);
				_systemLogger.log(Level.INFO, MODULE, _sMethod, "SAML NameID === " + sNameID + " SAML sp ===" + sp);

				_systemLogger.log(Level.INFO, MODULE, _sMethod, "Signature verification=" + is_bVerifySignature());
				if (is_bVerifySignature()) {
					// Check signature. We get the public key from the metadata
					// Therefore we need a valid Issuer to lookup the entityID in the metadata
					// We get the metadataURL from aselect.xml so we consider this safe and authentic
					if (sp == null || "".equals(sp)) {
						_systemLogger.log(Level.SEVERE, MODULE, _sMethod,
								"For signature verification the received message must have an Issuer");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
					PublicKey pkey = metadataManager.getSigningKeyFromMetadata(sp);
					if (pkey == null || "".equals(pkey)) {
						_systemLogger.log(Level.SEVERE, MODULE, _sMethod, "No public valid key in metadata");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					if (checkSignature(authzDecisionQuery, pkey)) {
						_systemLogger.log(Level.INFO, MODULE, _sMethod, "Message was signed OK");
					}
					else {
						_systemLogger.log(Level.SEVERE, MODULE, _sMethod, "Message was NOT signed OK");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
				}
				// check validity interval of authzDecisionQuery
				if (is_bVerifyInterval()) {
					Iterator itr = authzDecisionQuery.getSubject().getSubjectConfirmations().iterator();
					while (itr.hasNext()) { // SAML2 tells us there is at least one SubjectConfirmation
						// we wan't them all to be valid
						SubjectConfirmation sc = (SubjectConfirmation) itr.next();
						if (!SamlTools.checkValidityInterval(sc.getSubjectConfirmationData())) {
							_systemLogger.log(Level.SEVERE, MODULE, _sMethod,
									"One of the SubjectConfirmationData intervals was NOT valid");
							throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
						}
					}
				}
			}
			else {
				// Handle XACML Request
				Document xacmlDocument = handleXACMLRequest(docReceived);
				sNameID = getNameIdFromXAML(xacmlDocument);
				sp = getServiceProviderFromXACML(xacmlDocument);
				_systemLogger.log(Level.INFO, MODULE, _sMethod, "XACML NameID === " + sNameID + " XACML sp ===" + sp);
			}

			// credentials = sNameID;
			try {
				if (sNameID != null && sp != null) {
					// Update update time for sp
					this.changeUpdateTimeSp(sp, sNameID);
				}
				else {
					_systemLogger.log(Level.INFO, MODULE, _sMethod, "NameID or SP not available, SP=" + sp
							+ " credentials=" + sNameID + ")");
					throw new ASelectException("Not permitted"); // send refusal (handled by catch clause below)
				}
				if (samlMessage) {
					this.sendSAMLResponse(request, response, sNameID, true);
				}
				else {
					this.sendXACMLResponse(request, response, sNameID, true);
				}
			}
			catch (ASelectException as) {
				if (samlMessage) {
					this.sendSAMLResponse(request, response, sNameID, false);
				}
				else {
					this.sendXACMLResponse(request, response, sNameID, false);
				}
				_systemLogger.log(Level.WARNING, MODULE, _sMethod, "Session Sync failed", as);
			}
		}
		return null;
	}

	/*
	 * Methode haalt de credentials van de user op
	 */
	/*
	 * private String getCredentials(String user) { String credentials = null; SSOSessionManager sso; try { sso =
	 * SSOSessionManager.getHandle(); } catch (ASelectException e) { return null; } UserSsoSession session =
	 * sso.getSsoSession(user); if (session == null) return null; credentials = session.getTgtId(); return credentials;
	 * }
	 */

	/*
	 * Methode update het session obj van de user
	 */
	/*
	 * private void updateSSOSession(String user) throws ASelectException { SSOSessionManager sso =
	 * SSOSessionManager.getHandle(); UserSsoSession session = sso.getSsoSession(user); sso.update(user, session); }
	 */

	/*
	 * Methode werkt de lokale sessie tijd bij.
	 */
	/*
	 * private void changeTGTSessionTime(String decodedcredentials) throws ASelectStorageException { HashMap
	 * tgtBeforeUpdate = (HashMap) _oTGTManager.get(decodedcredentials); _oTGTManager.update(decodedcredentials,
	 * tgtBeforeUpdate); }
	 */

	/*
	 * Change the update time of the sp
	 */
	/**
	 * Change update time sp.
	 * 
	 * @param serviceProviderUrl
	 *            the service provider url
	 * @param tgtId
	 *            the tgt id
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void changeUpdateTimeSp(String serviceProviderUrl, String tgtId)
		throws ASelectException
	{
		String _sMethod = "changeUpdateTimeSp";
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "TGT=" + tgtId);

		HashMap htTGTContext = _oTGTManager.getTGT(tgtId);
		if (htTGTContext == null) {
			_systemLogger.log(Level.INFO, MODULE, _sMethod, "TGT not found SP=(" + serviceProviderUrl + ")");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_EXPIRED);
			// was: return; (Bauke: 20080829)
		}

		ServiceProvider spToBeChanged = null;
		long now = new Date().getTime();
		// SSOSessionManager sso = SSOSessionManager.getHandle();
		UserSsoSession ssoSession = (UserSsoSession) htTGTContext.get("sso_session"); // sso.getSsoSession(user);
		if (ssoSession == null) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "Missing sso_session data in TGT");
			return;
		}

		List<ServiceProvider> spList = ssoSession.getServiceProviders();
		for (ServiceProvider sp : spList) {
			_systemLogger.log(Level.INFO, MODULE, _sMethod, "ServiceProvider = " + serviceProviderUrl);
			if (sp.getServiceProviderUrl().equals(serviceProviderUrl)) {
				spToBeChanged = sp;
			}
		}
		if (spToBeChanged != null) {
			_systemLogger.log(Level.INFO, MODULE, _sMethod, "Time SP update before = "
					+ spToBeChanged.getLastSessionSync() + "(" + getReadableDate(spToBeChanged.getLastSessionSync())
					+ ")");
			spToBeChanged.setLastSessionSync(now);
			// sso.update(user, session);

			// Replace the ServiceProvider data and update the TGT timestamp in the process
			ssoSession.removeServiceProvider(spToBeChanged.getServiceProviderUrl());
			ssoSession.addServiceProvider(spToBeChanged);
			htTGTContext.put("sso_session", ssoSession);

			// Bauke: Also update the TGT Timestamp
			// HashMap htTGTContext = _oTGTManager.getTGT(credentials);
			// if (htTGTContext != null)
			_oTGTManager.updateTGT(tgtId, htTGTContext);
			_systemLogger.log(Level.INFO, MODULE, _sMethod, "Time SP update after = "
					+ spToBeChanged.getLastSessionSync() + "(" + getReadableDate(spToBeChanged.getLastSessionSync())
					+ ")" + " New TGT TimeStamp=" + _oTGTManager.getTimestamp(tgtId) + "("
					+ getReadableDate(_oTGTManager.getTimestamp(tgtId)) + ")");
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "SP not found in list SP=(" + serviceProviderUrl + ")");
		}
	}

	/*
	 * Maakt een SAML Response en verstuurt deze naar de SP. boolean geeft aan of er permit of deny moet worden
	 * gestuurd.
	 */
	/**
	 * Send saml response.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @param uid
	 *            the uid
	 * @param permit
	 *            the permit
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
	private void sendSAMLResponse(HttpServletRequest request, HttpServletResponse response, String uid, boolean permit)
		throws ASelectException
	{
		String _sMethod = "sendSAMLResponse";
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "Send SAML response to SP");

		Response finalResponse = buildSAMLResponse(uid, permit);

		// always sign the Response
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "Sign the finalResponse >======");
		finalResponse = (Response) sign(finalResponse);
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "Signed the finalResponse ======<");

		// Send response using SOAP
		SoapManager soapManager = new SoapManager();
		Envelope envelope = soapManager.buildSOAPMessage(finalResponse);
		Element envelopeElem = null;
		try {
			envelopeElem = SamlTools.marshallMessage(envelope);
			_systemLogger.log(Level.INFO, MODULE, _sMethod, "Send SAML response:\n"
					+ XMLHelper.nodeToString(envelopeElem));
			// XMLHelper.prettyPrintXML(envelopeElem));
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "marshall message failed", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		try { // Bauke 20081112: used same code for all Soap messages
			// Remy: 20081113: Move this code to HandlerTools for uniformity
			SamlTools.sendSOAPResponse(response, XMLHelper.nodeToString(envelopeElem));
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to send response", e);
		}
	}

	/*
	 * De methode bouwt een response op de SAML AuthzDecisionQuery boolean geeft aan of er permit of deny moet worden
	 * gestuurd.
	 */
	/**
	 * Builds the saml response.
	 * 
	 * @param uid
	 *            the uid
	 * @param permit
	 *            the permit
	 * @return the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
	private Response buildSAMLResponse(String uid, boolean permit)
		throws ASelectException
	{
		String sMethod = "buildSAMLResponse";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Build SAML Response for " + uid);

		// Build SAML Response
		XMLObjectBuilderFactory oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
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
		// assertion.setIssueInstant(new DateTime()); // RH 20080606, o
		DateTime tStamp = new DateTime();
		assertion.setIssueInstant(tStamp);
		// Set interval conditions
		assertion = (Assertion) SamlTools.setValidityInterval(assertion, tStamp, getMaxNotBefore(),
				getMaxNotOnOrAfter());

		try {
			assertion.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
		}
		catch (ASelectException ase) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "failed to build SAML response", ase);
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

		resp.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
		resp.setVersion(SAMLVersion.VERSION_20);
		resp.setIssueInstant(new DateTime());
		return marshallResponse(resp);
	}

	/*
	 * Deze methode vangt het SAML bericht op van de sp en haalt de benodigde gegevens uit het bericht. En geeft de
	 * gebruiker terug.
	 */
	/**
	 * Handle saml request.
	 * 
	 * @param docReceived
	 *            the doc received
	 * @return the authz decision query
	 * @throws ASelectException
	 *             the a select exception
	 */
	private AuthzDecisionQuery handleSAMLRequest(String docReceived)
		throws ASelectException
	{
		String _sMethod = "handleSAMLRequest";
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "Process SAML message:\n" + docReceived);
		AuthzDecisionQuery authzDecisionQuery = null;
		try {
			// Build XML Document
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(docReceived);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			_systemLogger.log(Level.INFO, MODULE, _sMethod, "docReceivedSOAP = " + docReceivedSoap);

			// Get AuthzDecision obj
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			Node eltAuthzDecision = SamlTools.getNode(elementReceivedSoap, AUTHZDECISIONQUERY);

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltAuthzDecision);
			authzDecisionQuery = (AuthzDecisionQuery) unmarshaller.unmarshall((Element) eltAuthzDecision);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed too process SAML message", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return authzDecisionQuery;
	}

	/*
	 * Methode haalt de user id uit de SAML AuthzDecisionQuery
	 */
	/**
	 * Gets the name id from saml.
	 * 
	 * @param authzDecisionQuery
	 *            the authz decision query
	 * @return the name id from saml
	 */
	private String getNameIdFromSAML(AuthzDecisionQuery authzDecisionQuery)
	{
		Subject subject = authzDecisionQuery.getSubject();
		NameID nameId = subject.getNameID();
		return nameId.getValue();
	}

	/*
	 * Methode haalt de SP uit de SAML AuthzDecisionQuery
	 */
	/**
	 * Gets the service provider from saml.
	 * 
	 * @param authzDecisionQuery
	 *            the authz decision query
	 * @return the service provider from saml
	 */
	private String getServiceProviderFromSAML(AuthzDecisionQuery authzDecisionQuery)
	{
		Issuer issuer = authzDecisionQuery.getIssuer();
		return issuer.getValue();
	}

	/**
	 * Handle xacml request.
	 * 
	 * @param xacmlMessage
	 *            the xacml message
	 * @return the document
	 * @throws ASelectException
	 *             the a select exception
	 */
	private Document handleXACMLRequest(String xacmlMessage)
		throws ASelectException
	{
		String _sMethod = "handleXACMLRequest";
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "Handle XACML Request");
		Document xacmlMessge = null;
		try {
			_systemLogger.log(Level.INFO, MODULE, _sMethod, "Received update: " + xacmlMessage);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(xacmlMessage);
			InputSource inputSource = new InputSource(stringReader);
			xacmlMessge = builder.parse(inputSource);
		}
		catch (ParserConfigurationException e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		catch (SAXException e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}
		return xacmlMessge;
	}

	/*
	 * Methode haalt de user id uit de XACML AuthzDecisionQuery
	 */
	/**
	 * Gets the name id from xaml.
	 * 
	 * @param xacmlDocument
	 *            the xacml document
	 * @return the name id from xaml
	 */
	private String getNameIdFromXAML(Document xacmlDocument)
	{
		Node node = xacmlDocument.getFirstChild();
		Node SubjectNode = SamlTools.getNode(node, "Subject");
		String uid = SamlTools.getNode(SubjectNode, "AttributeValue").getTextContent();
		return uid;
	}

	/*
	 * Methode haalt de SP uit de XACML AuthzDecisionQuery
	 */
	/**
	 * Gets the service provider from xacml.
	 * 
	 * @param xacmlDocument
	 *            the xacml document
	 * @return the service provider from xacml
	 */
	private String getServiceProviderFromXACML(Document xacmlDocument)
	{
		Node node = xacmlDocument.getFirstChild();
		Node SubjectNode = SamlTools.getNode(node, "Subject");
		Node ResourceNode = SubjectNode.getNextSibling();
		return SamlTools.getNode(ResourceNode, "AttributeValue").getTextContent();
	}

	/**
	 * Send xacml response.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @param uid
	 *            the uid
	 * @param permit
	 *            the permit
	 */
	private void sendXACMLResponse(HttpServletRequest request, HttpServletResponse response, String uid, boolean permit)
	{
		String _sMethod = "sendXACMLResponse";
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "Send XACML response to SP");

		String finalResponse = buildXACMLResponse(uid, permit);
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "Send XACML response: " + finalResponse);
		response.setContentType("text/xml");
		try {
			PrintWriter writer = response.getWriter();
			writer.write(finalResponse);
			writer.close();
		}
		catch (IOException io) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "IOException trying to send response to sp", io);
		}
	}

	/*
	 * De methode bouwt een response op de XACML AuthzDecisionQuery
	 */
	/**
	 * Builds the xacml response.
	 * 
	 * @param uid
	 *            the uid
	 * @param permit
	 *            the permit
	 * @return the string
	 */
	private String buildXACMLResponse(String uid, boolean permit)
	{
		String sMethod = "buildXACMLResponse";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Build XAML Response for " + uid);

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

	/**
	 * Marshall response.
	 * 
	 * @param response
	 *            the response
	 * @return the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	public Response marshallResponse(Response response)
		throws ASelectException
	{
		String sMethod = "marshallResponse";
		MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(response);
		try {
			Node node = marshaller.marshall(response);
			String msg = XMLHelper.prettyPrintXML(node);
			_systemLogger.log(Level.INFO, MODULE, sMethod, msg);
		}
		catch (MarshallingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return response;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	@Override
	public void destroy()
	{
	}

	/**
	 * Determine message type.
	 * 
	 * @param request
	 *            the request
	 * @return true, if successful
	 * @throws ASelectException
	 *             the a select exception
	 */
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
			Node doesAuthzExist = SamlTools.getNode(node, AUTHZDECISIONQUERY);
			if (doesAuthzExist == null) {
				saml = false;
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to determinte message", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return saml;
	}
}
