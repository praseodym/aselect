package org.aselect.server.request.handler.saml20.common;

import java.io.StringReader;
import java.net.URLDecoder;
import java.util.*;
import java.util.logging.Level;

import javax.xml.parsers.*;

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
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
import org.opensaml.saml2.core.Subject;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

// Can only be used by an SP
public class SessionSyncRequestSender
{
	private TGTManager _oTGTManager = TGTManager.getHandle();
	protected ASelectConfigManager _configManager;
	private static final String Response = "Response";
	private final String _AuthzDecisionStatement = "AuthzDecisionStatement";

	private String _sRedirectUrl;
	private String _sFederationUrl;
	private long _lUpdateInterval;
	private String _sSamlMessageType;

	private ASelectSystemLogger _oSystemLogger;
	private String MODULE = "SessionSyncRequestSender";

	public SessionSyncRequestSender(ASelectSystemLogger systemLogger, String redirectUrl,
			long updateInterval, String samlMessageType, String federationUrl) {
		_oSystemLogger = systemLogger;
		_sRedirectUrl = redirectUrl;
		_lUpdateInterval = updateInterval;
		_sSamlMessageType = samlMessageType;
		_sFederationUrl = federationUrl;
	}

	//
	// Retrieve the Session Sync parameters from the "ss_request_handler" section
	//
	static public Hashtable getSessionSyncParameters(ASelectSystemLogger mySystemLogger)
		throws ASelectException
	{
		String MODULE = "SessionSyncRequestSender";
		String sMethod = "getSessionSyncParameters";
		ASelectConfigManager myConfigManager = ASelectConfigManager.getHandle();
		Hashtable htResult = new Hashtable();
		try {
			Object oRequestsSection = myConfigManager.getSection(null, "requests");
			Object oHandlersSection = myConfigManager.getSection(oRequestsSection, "handlers");

			Object oHandler = myConfigManager.getSection(oHandlersSection, "handler");
			for ( ; oHandler != null; ) {
				try {
					String sId = myConfigManager.getParam(oHandler, "id");
					if (sId.equals("ss_request_handler")) {
						try {
							String federationUrl = myConfigManager.getParam(oHandler, "federation_url");
							htResult.put("federation_url", federationUrl);
						}
						catch (ASelectConfigException e) {
							mySystemLogger.log(Level.WARNING, MODULE, sMethod,
									"No config item 'federation_url' found in 'handler' section", e);
							throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
						}
						try {
							String _sUpdateInterval = myConfigManager.getParam(oHandler, "update_interval");
							Long updateInterval = Long.parseLong(_sUpdateInterval);
							updateInterval = updateInterval * 1000;
							mySystemLogger.log(Level.INFO, MODULE, sMethod, "Update interval on SP = "
									+ updateInterval);
							htResult.put("update_interval", updateInterval);
						}
						catch (ASelectConfigException e) {
							mySystemLogger.log(Level.WARNING, MODULE, sMethod,
									"No config item 'updateinterval' found in 'handler' section", e);
							throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
						}

						try {
							String samlMessageType = myConfigManager.getParam(oHandler, "message_type");
							htResult.put("message_type", samlMessageType);
						}
						catch (ASelectConfigException e) {
							mySystemLogger.log(Level.WARNING, MODULE, sMethod,
									"No config item 'message_type' found in 'handler' section", e);
							throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
						}
					}
				}
				catch (ASelectConfigException e) {
					mySystemLogger.log(Level.CONFIG, MODULE, sMethod, "No valid 'id' config item found", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				oHandler = myConfigManager.getNextSection(oHandler);
			}
		}
		catch (ASelectConfigException e) {
			mySystemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'handler' found in 'aselect' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		return htResult;
	}

	// Bauke: rewritten
	// Returns: ERROR_ASELECT_SUCCESS or error code upon failure
	//
	public String synchronizeSession(String argCredentials, boolean credsAreCoded, boolean upgradeTgt)
	{
		String _sMethod = "synchronizeSession";
		String errorCode = Errors.ERROR_ASELECT_SUCCESS;
		String credentials;

		if (credsAreCoded) {
			credentials = this.decodeCredentials(argCredentials);
			if (credentials == null) {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Can not decode credentials");
				return Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID;
			}
		}
		else credentials = argCredentials;
		
		Hashtable htTGTContext = _oTGTManager.getTGT(credentials);
		if (htTGTContext == null) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Unknown TGT");
			return Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT;
		}
		
		if (upgradeTgt) {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Upgrade TICKET context=" + htTGTContext);
			_oTGTManager.updateTGT(credentials, htTGTContext);
		}

		Long now = new Date().getTime();
		Long lastSync = Long.parseLong((String)htTGTContext.get("sessionsynctime"));
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "update_interval="+_lUpdateInterval+
				" LastSync="+(lastSync-now)+" Left="+(lastSync+_lUpdateInterval-now));
		
		if (now >= lastSync + _lUpdateInterval) {
			// Session Sync needed
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SP - Session Sync, type="+_sSamlMessageType+" now="+now);
			String sNameID = (String)htTGTContext.get("name_id");
			if (sNameID != null) {
				boolean success = false;
				try {
					if (_sSamlMessageType.equals("xacml"))
						success = sendXACMLMessageToFederation(sNameID, credentials);
					else
						success = sendSAMLUpdateToFederation(sNameID, credentials);
				}
				catch(ASelectException e) {
					return Errors.ERROR_ASELECT_INTERNAL_ERROR;
				}
				
				if (!success) {  // don't continue
					_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to send update to federation");
					return Errors.ERROR_ASELECT_INTERNAL_ERROR;
				}
			}
			else {
				errorCode = Errors.ERROR_ASELECT_SERVER_INVALID_SESSION;
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "No user found with credentials="+credentials);
				return errorCode;
			}
			
			// If successful, update the ticket granting ticket (timestamp will be set to "now")
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Update TGT timestamp="+now);
			htTGTContext.put("sessionsynctime", Long.toString(now));
			// Setting the value below prevents the Timestamp update
			htTGTContext.put("updatetimestamp", "no");
			_oTGTManager.updateTGT(credentials, htTGTContext);
		}
		else {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SP - No SessionSync yet");
		}
		return errorCode;
	}

	/*
	 * Methode kijkt wanneer de laatste update naar de federatie idp is
	 * gestuurd. Is dit langer dan 5 minuten geleden dan is de return value
	 * true. Als er een update korter dan 5 min. geleden is verstuurd dan is de
	 * return value false.
	 * 
	 * Always updates the tgt timestamp.
	 */
/*	private boolean needToSendUpdate(String credentials, long updateInterval)
		throws ASelectStorageException
	{
		String _sMethod = "needToSendUpdate";
		boolean update = false;

		// get timestamp and update time
		Long timestamp = this.getTimeStamp(credentials);
		Long now = new Date().getTime();
		Long timeLow = now - updateInterval;

		// Do we need to send update?
		if (timestamp >= timeLow && timestamp <= now) {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "time between " + timeLow + " timeLow("
					+ this.getReadableDate(timeLow) + ")" + " and " + now + " now(" + this.getReadableDate(now)
					+ ")" + " = TGT (" + timestamp + ")" + "(" + this.getReadableDate(timestamp) + ")");
			update = false;
		}
		else {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "time NOT between " + timeLow + " timeLow("
					+ this.getReadableDate(timeLow) + ")" + " and " + now + " now(" + this.getReadableDate(now)
					+ ")" + "= TGT (" + timestamp + ")" + "(" + this.getReadableDate(timestamp) + ")");
			changeSessionTime(credentials);
			update = true;
		}
		return update;
	}
*/
	/*
	 * Methode werkt de lokale sessie tijd bij.
	 */
/*	private void changeSessionTime(String credentials)
	{
		String _sMethod = "changeSessionTime";
		try {
			if (_oTGTManager.containsKey(credentials)) {
				Hashtable tgtBeforeUpdate = (Hashtable) _oTGTManager.get(credentials);
				tgtBeforeUpdate.put("sessionsynctime", new Date().getTime());
				_oTGTManager.update(credentials, tgtBeforeUpdate);
				//Hashtable tgtAfterUpdate = (Hashtable) _oTGTManager.get(decodedcredentials);
			}
			else {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "There is no TGT with key " + credentials);
			}
		}
		catch (ASelectStorageException asse) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "SP (" + _sRedirectUrl
					+ ")- failed too change the session time", asse);
			asse.printStackTrace();
		}
	}
*/
	/*
	 * Methode bouwt een SAML message. En verstuurt deze naar de federatie.
	 * 
	 */
	@SuppressWarnings("unchecked")
	private boolean sendSAMLUpdateToFederation(String sNameID, String credentials)
		throws ASelectException
	{
		String _sMethod = "sendSAMLUpdateToFederation";

		// Build AuthzDecisionQuery SAML
		XMLObjectBuilderFactory oBuilderFactory = Configuration.getBuilderFactory();
		SAMLObjectBuilder<AuthzDecisionQuery> authzBuilder = (SAMLObjectBuilder<AuthzDecisionQuery>) oBuilderFactory
				.getBuilder(AuthzDecisionQuery.DEFAULT_ELEMENT_NAME);
		AuthzDecisionQuery authz = authzBuilder.buildObject();

		// Build Subject
		SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) oBuilderFactory
				.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject subject = subjectBuilder.buildObject();

		// Build NameID
		SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) oBuilderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameId = nameIdBuilder.buildObject();
		nameId.setValue(sNameID);
		subject.setNameID(nameId);

		// Build Action
		SAMLObjectBuilder<Action> actionBuilder = (SAMLObjectBuilder<Action>) oBuilderFactory
				.getBuilder(Action.DEFAULT_ELEMENT_NAME);
		Action action = actionBuilder.buildObject();
		action.setAction(Action.HTTP_GET_ACTION);

		List<Action> actions = authz.getActions();
		actions.add(action);

		// Build Issuer
		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) oBuilderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = issuerBuilder.buildObject();
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "sp url is ===== " + _sRedirectUrl);
		issuer.setValue(_sRedirectUrl);

		// Fill Authz obj
		authz.setVersion(SAMLVersion.VERSION_20);
		authz.setSubject(subject);
		authz.setID(org.aselect.server.request.handler.saml20.common.Utils.generateIdentifier(_oSystemLogger, MODULE));
		authz.setIssueInstant(new DateTime());
		authz.setResource(_sFederationUrl);
		authz.setIssuer(issuer);

		SAMLObject saml = authz;
		SOAPManager soapmanager = new SOAPManager();

		// Build the SOAP message
		Envelope envelope = soapmanager.buildSOAPMessage(saml);
		Element envelopeElem = null;
		try {
			envelopeElem = new NodeHelper().marshallMessage(envelope);
		}
		catch (MessageEncodingException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "MessageEncodingException!", e);
			e.printStackTrace();
		}
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Writing SOAP message to response:\n"
				+ XMLHelper.prettyPrintXML(envelopeElem));
		return sendMessageToFederation(XMLHelper.nodeToString(envelopeElem), "", credentials);
	}

	/*
	 * Methode decode de meegeven credentials.
	 */
	private String decodeCredentials(String credentials)
	{
		String _sMethod = "decodeCredentials";
		String decodedCredentials = null;
		try {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Credentials are " + credentials);
			byte[] TgtBlobBytes = CryptoEngine.getHandle().decryptTGT(credentials);
			decodedCredentials = Utils.toHexString(TgtBlobBytes);
		}
		catch (ASelectException as) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "fails to decrypt credentials", as);
			as.printStackTrace();
		}
		return decodedCredentials;
	}

	/*
	 * Methode haalt de timestamp van de tgt op aan de hand van de meegegeven
	 * credentials.
	 */
/*	private long getTimeStamp(String credentials)
		throws ASelectStorageException
	{
		String _sMethod = "getTimeStamp";
		Hashtable htTGT = null;
		Long setTime = 0L;
		// get time from tgt manager
		if (_oTGTManager.containsKey(credentials)) {
			htTGT = (Hashtable) _oTGTManager.get(credentials);
			setTime = (Long) htTGT.get("lastsync");
			if (setTime == null) {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "CIO - lastsync was not set!");
				setTime = _oTGTManager.getTimestamp(credentials);
			}
			long expireTime = _oTGTManager.getExpirationTime(credentials);
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Timestamp = " + setTime + "("
					+ this.getReadableDate(setTime) + ")");
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Expire Time = " + expireTime + "("
					+ this.getReadableDate(expireTime) + ")");
		}
		else {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "There is no TGT with key " + credentials);
		}
		return setTime;
	}
*/
	/*
	 * Methode haalt aan de hand van de credentials de betreffende uid op.
	 */
/*	private String getUser(String credentials)
	{
		String _sMethod = "getUser";
		String user = null;
		try {
			// get time from tgt manager
			String decodedCredentials = decodeCredentials(credentials);
			if (_oTGTManager.containsKey(decodedCredentials)) {
				Hashtable hash = (Hashtable) _oTGTManager.get(decodedCredentials);
				user = (String) hash.get("uid");
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "User = " + user);
			}
		}
		catch (ASelectStorageException asse) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "fails to get user from TGT manager", asse);
		}
		return user;
	}
*/
	public void destroy()
	{

	}

	/*
	 * Build a XACML message En verstuur deze naar de federatie.
	 */
	private boolean sendXACMLMessageToFederation(String sNameID, String credentials)
	{
		String action = "GET";
		String var1 = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
		String var2 = "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name";
		String var6 = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
		String var7 = "http://www.w3.org/2001/XMLSchema#anyURI";
		String var8 = "urn:oasis:names:tc:xacml:1.0:action:action-id";
		String var9 = "http://www.w3.org/2001/XMLSchema#string";

		String xacmlRequest = "<soap:Envelope xmlns:xsi=\" http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\" http://schemas.xmlsoap.org/soap/envelope/\">"
				+ "<soap:Body>"
				+ "<Request>"
				+ "<Subject>"
				+ "<Attribute AttributeId=\""
				+ var1
				+ "\""
				+ " DataType=\""
				+ var2
				+ "\">"
				+ "<AttributeValue>"
				+ sNameID
				+ "</AttributeValue>"
				+ "</Attribute>"
				+ "</Subject>"
				+ "<Resource>"
				+ "<Attribute AttributeId=\""
				+ var6
				+ "\""
				+ " DataType=\""
				+ var7
				+ "\">"
				+ "<AttributeValue>"
				+ _sRedirectUrl
				+ "</AttributeValue>"
				+ "</Attribute>"
				+ "</Resource>"
				+ "<Action>"
				+ "<Attribute AttributeId=\""
				+ var8
				+ "\""
				+ " DataType=\""
				+ var9
				+ "\">"
				+ "<AttributeValue>"
				+ action
				+ "</AttributeValue>"
				+ "</Attribute>"
				+ "</Action>"
				+ "</Request>"
				+ "</soap:Body>" + "</soap:Envelope>";
		return sendMessageToFederation(xacmlRequest, sNameID, credentials);
	}

	// Bauke:
	// Return is true when Message was sent successful
	//
	private boolean sendMessageToFederation(String message, String sNameID, String credentials)
	{
		String _sMethod = "sendMessageToFederation";
		SOAPManager soapmanager = new SOAPManager();
		TGTManager tgtmanager = TGTManager.getHandle();
		String sResponse = "";
		boolean tgtKilled = false;
		boolean saml = false;
		
		try {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Send message="+message+" for user="+sNameID);
			// Send/Receive the SOAP message
			sResponse = URLDecoder.decode(soapmanager.sendSOAP(message, _sFederationUrl), "UTF-8");

			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Received response from IDP: " + sResponse);
			try {
				saml = determineMessageType(sResponse);
			}
			catch(ASelectException e) {
				// Bad or no response from partner
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Kill tgt for user=" + sNameID);
				tgtmanager.remove(credentials);
				return false;  // Bauke: no need to continue
			}
			if (saml) {
				tgtKilled = handleSAMLResponse(sResponse);
				if (tgtKilled == true) {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Response is correct no need to kill tgt "
							+ sResponse);
					return true;
				}
				else {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Response contains deny (IDP has not processed update correct)");
					String uidSaml = getUserFromSAMLResponse(sResponse);
					//killTgt(uidSaml);
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Kill tgt for user=" + uidSaml);
					tgtmanager.remove(credentials);
					return false;
				}
			}
			else {
				tgtKilled = handleXACMLResponse(sResponse);
				if (tgtKilled == true) {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Response is correct no need to kill tgt "
							+ sResponse);
					return true;
				}
				else {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Response contains deny (IDP has not processed update correct)");
					//killTgt(user);
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Kill tgt for user=" + sNameID);
					tgtmanager.remove(credentials);
					return false;
				}
			}
		}
		catch (Exception ex) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to send message to federation", ex);
		}
		return false;
	}

	/*
	 * Deze methode vangt het SAML bericht op van de IDP en haalt de benodigde
	 * gegevens uit het bericht.
	 */
	private boolean handleSAMLResponse(String sMessage)
	{

		String _sMethod = "handleSAMLResponse";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Process SAML message");
		Response response = null;
		try {
			// Build XML Document
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(sMessage);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedResponse = builder.parse(inputSource);

			// Get AuthzDecision obj
			Element elementReceivedSoap = docReceivedResponse.getDocumentElement();
			Node eltArtifactResolve = new NodeHelper().getNode(elementReceivedSoap, Response);

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);
			response = (Response) unmarshaller.unmarshall((Element) eltArtifactResolve);
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to process SAML message", e);
			e.printStackTrace();
		}
		boolean updateWasSucces = true;
		List lijst = response.getAssertions();
		if (lijst.size() == 1) {
			Assertion assertion = (Assertion) lijst.get(0);
			List authzLijst = assertion.getAuthzDecisionStatements();
			if (authzLijst.size() == 1) {
				AuthzDecisionStatement authz = (AuthzDecisionStatement) authzLijst.get(0);
				DecisionTypeEnumeration decision = authz.getDecision();
				if (decision.toString().equals("Deny")) {
					updateWasSucces = false;
				}
			}
		}
		return updateWasSucces;
	}

	/*
	 * Deze methode vangt het SAML bericht op van de IDP en haalt de benodigde
	 * gegevens uit het bericht.
	 */
	private boolean handleXACMLResponse(String sMessage)
	{

		String _sMethod = "handleXACMLResponse";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Process XACML message");
		Document docReceivedResponse = null;
		try {
			// Build XML Document
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(sMessage);
			InputSource inputSource = new InputSource(stringReader);
			docReceivedResponse = builder.parse(inputSource);
		}
		catch (Exception ex) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to build Document", ex);
		}

		Node node = docReceivedResponse.getFirstChild();
		String decision = new NodeHelper().getNode(node, "Decision").getTextContent();

		boolean updateWasSucces = true;
		if (decision.equals("Deny")) {
			updateWasSucces = false;
		}
		return updateWasSucces;
	}

	private boolean determineMessageType(String request)
	throws ASelectException
	{
		String _sMethod = "determineMessageType";
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
			Node doesAuthzExist = new NodeHelper().getNode(node, _AuthzDecisionStatement);
			if (doesAuthzExist == null) {
				saml = false;
			}
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to determine message", e);
			throw new ASelectException("Cannot determine message type");
		}
		return saml;
	}

	/*
	 * Methode killt de tgt aan de hand van een deny response.
	 */
/*	private void killTgt(String uid)
		throws ASelectStorageException
	{
		String _sMethod = "killTgt";
		TGTManager tgtmanager = TGTManager.getHandle();
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Kill tgt for user: " + uid);
		tgtmanager.remove(UserToTgtMapper.getTgtId(uid));
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Does sp contain uid?: "
				+ tgtmanager.containsKey(UserToTgtMapper.getTgtId(uid)));
	}*/

	/*
	 * Deze methode vangt het SAML bericht op van de IDP en haalt de benodigde
	 * gegevens uit het bericht.
	 */
	private String getUserFromSAMLResponse(String sMessage)
	{

		String _sMethod = "getUserFromSAMLResponse";
		String uid = null;
		Response response = null;
		try {
			// Build XML Document
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(sMessage);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedResponse = builder.parse(inputSource);

			// Get AuthzDecision obj
			Element elementReceivedSoap = docReceivedResponse.getDocumentElement();
			Node eltArtifactResolve = new NodeHelper().getNode(elementReceivedSoap, Response);

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);
			response = (Response) unmarshaller.unmarshall((Element) eltArtifactResolve);
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed too process SAML message", e);
			e.printStackTrace();
		}

		List lijst = response.getAssertions();
		if (lijst.size() == 1) {
			Assertion assertion = (Assertion) lijst.get(0);
			Subject subject = assertion.getSubject();
			NameID nameid = subject.getNameID();
			uid = nameid.getValue();
		}
		return uid;
	}
}
