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
package org.aselect.server.request.handler.xsaml20.sp;

import java.io.StringReader;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.server.request.handler.xsaml20.SoapManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.*;
import org.xml.sax.InputSource;

/**
 * SAML2.0 AssertionConsumer for A-Select (Service Provider side). <br>
 * <br>
 * <b>Description:</b><br>
 * The SAML2.0 AssertionConsumer for the A-Select Server (Service Provider side).<br/>
 * HTTP GET containing the following items in the querystring<br/>
 * <ul>
 * <li><b>SAMLart</b> - The SAML2.0 artifact</li>
 * </ul>
 * The SAML2.0 artifact is resolved by the requesters ArtifactResolver. The resolved artifact contains a SAML2.0
 * Response which is futher handled by this A-Select server. <br>
 * 
 * @author Atos Origin
 */
// public class Xsaml20_AssertionConsumer extends ProtoRequestHandler // RH, 20080602, o
public class Xsaml20_AssertionConsumer extends Saml20_BaseHandler // RH, 20080602, n
{
	private final static String MODULE = "Xsaml20_AssertionConsumer";
	private XMLObjectBuilderFactory _oBuilderFactory;
	private ASelectAuthenticationLogger _authenticationLogger;
	protected TGTManager _tgtManager;
	private String _sMyServerId;
	private String _sFederationUrl;
	private String _sRedirectUrl; // We use as Issuer in the send SAML message
	private boolean signingRequired = false; // OLD opensaml20 library	// true; // NEW opensaml20 library
	// TODO see when signing is actually required
	// get from aselect.xml <applications require_signing="false | true">
	private boolean localityAddressRequired = false; // Do we need to verify localityAddress in the AuthnStatement

	/**
	 * Initializes the request handler by reading the following configuration: <br/>
	 * <br/>
	 * 
	 * <pre>
	 * &lt;handler&gt;
	 * &lt;server_url&gt;[server_url]&lt;/server_url&gt;
	 * &lt;/handler&gt;
	 * </pre>
	 * <ul>
	 * <li><b>server_url</b> - The url of the IDP A-Select Server</li>
	 * </ul>
	 * <br>
	 * .
	 * 
	 * @param oServletConfig
	 *            the o servlet config
	 * @param oHandlerConfig
	 *            the o handler config
	 * @throws ASelectException
	 *             the a select exception
	 */
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		super.init(oServletConfig, oHandlerConfig);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		_oBuilderFactory = Configuration.getBuilderFactory();

		_sMyServerId = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);
		_sFederationUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "federation_url", false); // 20091207: // true);
		_sRedirectUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true); // We use as
		// Issuer in the send SAML message

		String sLocalityAddressRequired = ASelectConfigManager.getSimpleParam(oHandlerConfig,
				"locality_address_required", false);
		// if (sVerifySignature != null && sVerifySignature.equalsIgnoreCase("false")) {
		// _bVerifySignature = false;
		if ("true".equalsIgnoreCase(sLocalityAddressRequired)) {
			setLocalityAddressRequired(true);
		}

		_tgtManager = TGTManager.getHandle();
		_authenticationLogger = ASelectAuthenticationLogger.getHandle();

	}

	/**
	 * Assertion consumer. <br>
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             on failure
	 */
	//
	// Example configuration:
	// <handler id="saml20_assertionconsumer"
	// class="org.aselect.server.request.handler.xsaml20.Xsaml20_AssertionConsumer"
	// target="/saml20_assertion.*" >
	// </handler>
	//
	@SuppressWarnings("unchecked")
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";

		String sReceivedArtifact = request.getParameter("SAMLart");
		if (sReceivedArtifact == null || "".equals(sReceivedArtifact)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No artifact found in the message.");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		String sRelayState = request.getParameter("RelayState");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Received artifact: " + sReceivedArtifact + " RelayState="
				+ sRelayState);
		String sFederationUrl = _sFederationUrl; // default, remove later on
		if (sRelayState.startsWith("idp=")) {
			sFederationUrl = sRelayState.substring(4);
		}
		if (sFederationUrl == null || sFederationUrl.equals("")) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No idp value found in RelayState (or in <federation_url> config)");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		try {
			// use metadata
			MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
			String sASelectServerUrl = metadataManager.getLocation(sFederationUrl,
					ArtifactResolutionService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_SOAP11_BINDING_URI);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Artifact Resolution at " + sASelectServerUrl);

			if (sASelectServerUrl == null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Artifact NOT found");
				throw new ASelectException(Errors.ERROR_ASELECT_NOT_FOUND);
			}

			SAMLObjectBuilder<Artifact> artifactBuilder = (SAMLObjectBuilder<Artifact>) _oBuilderFactory
					.getBuilder(Artifact.DEFAULT_ELEMENT_NAME);
			Artifact artifact = artifactBuilder.buildObject();
			artifact.setArtifact(sReceivedArtifact);

			SAMLObjectBuilder<ArtifactResolve> artifactResolveBuilder = (SAMLObjectBuilder<ArtifactResolve>) _oBuilderFactory
					.getBuilder(ArtifactResolve.DEFAULT_ELEMENT_NAME);
			ArtifactResolve artifactResolve = artifactResolveBuilder.buildObject();

			// RH, 20081107, use SamlTools
			artifactResolve.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
			artifactResolve.setVersion(SAMLVersion.VERSION_20);
			artifactResolve.setIssueInstant(new DateTime());

			// We decided that the other side could retrieve public key from metadata
			// by looking up the issuer as an entityID in the metadata
			// So we MUST supply an Issuer (which otherwise would be optional (by SAML standards))
			SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) _oBuilderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
			assertionIssuer.setFormat(NameIDType.ENTITY);
			assertionIssuer.setValue(_sRedirectUrl);
			artifactResolve.setIssuer(assertionIssuer);
			artifactResolve.setArtifact(artifact);

			// Do some logging for testing
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the artifactResolve >======");
			artifactResolve = (ArtifactResolve)sign(artifactResolve);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the artifactResolve ======<");

			// Build the SOAP message
			SoapManager soapManager = new SoapManager();
			Envelope envelope = soapManager.buildSOAPMessage(artifactResolve);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Marshall");
			Element envelopeElem = SamlTools.marshallMessage(envelope);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Writing SOAP message:\n"
					+ XMLHelper.nodeToString(envelopeElem));
			// XMLHelper.prettyPrintXML(envelopeElem));

			// Send/Receive the SOAP message
			String sSamlResponse = soapManager.sendSOAP(XMLHelper.nodeToString(envelopeElem), sASelectServerUrl);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received response: " + sSamlResponse);

			byte[] sSamlResponseAsBytes = sSamlResponse.getBytes();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received response length: " + sSamlResponseAsBytes.length);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			// dbFactory.setExpandEntityReferences(false);
			// dbFactory.setIgnoringComments(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(sSamlResponse);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();

			// Remove all SOAP elements
			Node eltArtifactResponse = SamlTools.getNode(elementReceivedSoap, "ArtifactResponse");

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResponse);

			ArtifactResponse artifactResponse = (ArtifactResponse) unmarshaller
					.unmarshall((Element) eltArtifactResponse);

			String artifactResponseIssuer = (artifactResponse.getIssuer() == null || // avoid null pointers
					artifactResponse.getIssuer().getValue() == null || "".equals(artifactResponse.getIssuer()
					.getValue())) ? sASelectServerUrl : // if not in message, use sASelectServerUrl value retrieved from metadata
					artifactResponse.getIssuer().getValue(); // else value from message

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do artifactResponse signature verification="+is_bVerifySignature());
			if (is_bVerifySignature()) {
				// signature of artifactResponse here
				// check signature of artifactResolve here
				// We get the public key from the metadata
				// Therefore we need a valid Issuer to lookup the entityID in the metadata
				// We get the metadataURL from aselect.xml so we consider this safe and authentic
				if (artifactResponseIssuer == null || "".equals(artifactResponseIssuer)) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod,
							"For signature verification the received message must have an Issuer");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				PublicKey pkey = metadataManager.getSigningKeyFromMetadata(artifactResponseIssuer);
				if (pkey == null || "".equals(pkey)) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No valid public key in metadata");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}

				// if (checkSignature(artifactResponse, pkey )) { // We don't need the indirection anymore
				if (SamlTools.checkSignature(artifactResponse, pkey)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "artifactResponse was signed OK");
				}
				else {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "artifactResponse was NOT signed OK");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
			}

			Object samlResponseObject = artifactResponse.getMessage();

			// The object can either a Response (SSO case) or a StatusResponseType (SLO case)
			if (samlResponseObject instanceof Response) {
				// SSO
				Response samlResponse = (Response) samlResponseObject;
				// _systemLogger.log(Level.INFO, MODULE, sMethod,
				// "Received: \n"+XMLHelper.prettyPrintXML(samlResponse.getDOM()));
				// Detect if this is a successful or an error Response
				String sStatusCode = samlResponse.getStatus().getStatusCode().getValue();
				String sRemoteRid = samlResponse.getID();
				String sLocalRid = samlResponse.getInResponseTo();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "RemoteRid=" + sRemoteRid + " LocalRid=" + sLocalRid);
				if (sStatusCode.equals(StatusCode.SUCCESS_URI)) {
					_systemLogger
							.log(Level.INFO, MODULE, sMethod, "Response was successful " + samlResponse.toString());
					Assertion samlAssertion = samlResponse.getAssertions().get(0);
					String sOrganization = samlAssertion.getIssuer().getValue();
					String sNameID = samlAssertion.getSubject().getNameID().getValue();
					// Now check for time interval validation
					// We only check first object from the list
					// First the assertion itself
					if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(samlAssertion)) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Assertion time interval was NOT valid");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					// then the AuthnStatement
					if (is_bVerifyInterval()
							&& !SamlTools.checkValidityInterval(samlAssertion.getAuthnStatements().get(0))) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "AuthnStatement time interval was NOT valid");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					// check subjectlocalityaddress
					if (isLocalityAddressRequired()
							&& !SamlTools.checkLocalityAddress(samlAssertion.getAuthnStatements().get(0), request
									.getRemoteAddr())) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod,
								"AuthnStatement subjectlocalityaddress was NOT valid");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					String sAuthnContextClassRefURI = samlAssertion.getAuthnStatements().get(0).getAuthnContext()
							.getAuthnContextClassRef().getAuthnContextClassRef();
					String sAuthSpLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(sAuthnContextClassRefURI,
							_systemLogger, MODULE);

					HashMap htRemoteAttributes = new HashMap();
					htRemoteAttributes.put("name_id", sNameID);
					// This is the quickest way to get "name_id" into the Context

					// Retrieve the embedded attributes
					List<AttributeStatement> lAttrStatList = samlAssertion.getAttributeStatements();
					Iterator<AttributeStatement> iASList = lAttrStatList.iterator();
					while (iASList.hasNext()) {
						AttributeStatement sAttr = iASList.next();
						List<Attribute> lAttr = sAttr.getAttributes();
						Iterator<Attribute> iAttr = lAttr.iterator();
						while (iAttr.hasNext()) {
							Attribute attr = iAttr.next();
							String sAttrName = attr.getName();
							XSStringImpl xsString = (XSStringImpl) attr.getOrderedChildren().get(0);
							String sAttrValue = xsString.getValue();
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Name=" + sAttrName + " Value=" + sAttrValue);
							htRemoteAttributes.put(sAttrName, sAttrValue);
						}
					}
					_systemLogger.log(Level.INFO, MODULE, sMethod, "NameID=" + sNameID + " remote_rid=" + sRemoteRid
							+ " local_rid=" + sLocalRid + " authsp_level=" + sAuthSpLevel + " organization/authsp="
							+ sOrganization);

					// htRemoteAttributes.put("attributes", HandlerTools.serializeAttributes(htAttributes));
					htRemoteAttributes.put("remote_rid", sRemoteRid);
					htRemoteAttributes.put("local_rid", sLocalRid);

					htRemoteAttributes.put("authsp_level", sAuthSpLevel);
					htRemoteAttributes.put("organization", sOrganization);
					htRemoteAttributes.put("authsp", sOrganization);

					// Bauke, 20081204: If we want to send the IdP token as an attribute
					// to the application, we would need the following code:
					/*
					 * String sAssertion = XMLHelper.nodeToString(samlAssertion.getDOM());
					 * _systemLogger.log(Level.INFO, MODULE, sMethod, "sAssertion="+sAssertion);
					 * BASE64Encoder b64Enc = new BASE64Encoder();
					 * sAssertion = b64Enc.encode(sAssertion.getBytes("UTF-8"));
					 * htRemoteAttributes.put("saml_remote_token", sAssertion);
					 */
					// End of IdP token

					_systemLogger.log(Level.INFO, MODULE, sMethod, "htRemoteAttributes=" + htRemoteAttributes);
					handleSSOResponse(htRemoteAttributes, request, response);
				}
				else {
					// SLO
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Response was not successful: " + sStatusCode);
					HashMap htRemoteAttributes = new HashMap();
					htRemoteAttributes.put("remote_rid", sRemoteRid);
					htRemoteAttributes.put("local_rid", sLocalRid);
					String sStatusMessage = samlResponse.getStatus().getStatusMessage().getMessage();
					htRemoteAttributes.put("result_code", sStatusMessage);
					// Expect these codes: Errors.ERROR_ASELECT_SERVER_CANCEL,
					// Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;

					_systemLogger.log(Level.INFO, MODULE, sMethod, "htRemoteAttributes=" + htRemoteAttributes);

					// Choose your response (3rd is implemented below)
					// 1. handleSSOResponse(htRemoteAttributes, request, response); // Lets application display error
					// 2. throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED); // Standard server
					// error
					// 3. Show error page:
					HashMap htSessionContext = _oSessionManager.getSessionContext(sLocalRid);
					if (htSessionContext == null) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Unknown session in response from cross aselect server");
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					response.setContentType("text/html");
					showErrorPage(sStatusMessage, htSessionContext, response.getWriter());
				}
			}
			else {
				_systemLogger.log(Level.WARNING, "Unexpected SAMLObject type: " + samlResponseObject.getClass());
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	public void destroy()
	{
		String sMethod = "destroy()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "<--");
	}

	/**
	 * Handle sso response.
	 * 
	 * @param htRemoteAttributes
	 *            the ht remote attributes
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleSSOResponse(HashMap htRemoteAttributes, HttpServletRequest servletRequest,
			HttpServletResponse servletResponse)
		throws ASelectException
	{
		String sMethod = "handleSSOResponse";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "<--");

		try {
			String sRemoteRid = null;
			String sLocalRid = null;
			HashMap htSessionContext;
			HashMap htServiceRequest = createServiceRequest(servletRequest);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htServiceRequest=" + htServiceRequest);

			sRemoteRid = (String) htRemoteAttributes.get("remote_rid");
			sLocalRid = (String) htRemoteAttributes.get("local_rid");
			if ((sRemoteRid == null) || (sLocalRid == null)) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Invalid parameters");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			htSessionContext = _oSessionManager.getSessionContext(sLocalRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Unknown session in response from cross aselect server");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// for authentication logging
			String sRemoteOrg = (String) htSessionContext.get("remote_organization");
			String sOrg = (String) htRemoteAttributes.get("organization");
			if (sRemoteOrg != null && sOrg != null && !sRemoteOrg.equals(sOrg))
				sRemoteOrg = sOrg + "@" + sRemoteOrg;

			String sResultCode = (String) htRemoteAttributes.get("result_code");
			String sUID = (String) htRemoteAttributes.get("uid");
			if (sResultCode != null) {
				if (sResultCode.equals(Errors.ERROR_ASELECT_SERVER_CANCEL)
						|| sResultCode.equals(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cancel");
					_authenticationLogger.log(new Object[] {
						"Cross", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
						htSessionContext.get("app_id"), "denied", sResultCode
					});
					// Issue 'CANCEL' TGT
					TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
					tgtIssuer.issueErrorTGT(sLocalRid, sResultCode, servletResponse);
				}
				else { // remote server returned error
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error");
					_authenticationLogger.log(new Object[] {
						"Cross", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
						htSessionContext.get("app_id"), "denied", sResultCode
					});
					throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
				}
			}
			else { // No result_code set, log successful authentication
				_authenticationLogger.log(new Object[] {
					"Cross", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
					htSessionContext.get("app_id"), "granted"
				});

				// Issue a cross TGT since we do not know the AuthSP
				// and we might have received remote attributes.
				TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
				String sOldTGT = (String) htServiceRequest.get("aselect_credentials_tgt");
				// Will also redirect the user
				oTGTIssuer.issueTGT(sLocalRid, null, htRemoteAttributes, servletResponse, sOldTGT);
				// 20090909: oTGTIssuer.issueCrossTGT(sLocalRid, null, htRemoteAttributes, servletResponse, sOldTGT);
			}
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * This function converts a <code>servletRequest</code> to a <code>HashMap</code> by extracting the parameters from
	 * the <code>servletRequest</code> and inserting them into a <code>HashMap</code>. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            Contains request parameters
	 * @return HashMap containing request parameters.
	 */
	@SuppressWarnings("unchecked")
	private HashMap createServiceRequest(HttpServletRequest servletRequest)
	{
		// Extract parameters into htServiceRequest
		HashMap htServiceRequest = null;
		if (servletRequest.getMethod().equalsIgnoreCase("GET")) {
			htServiceRequest = Utils.convertCGIMessage(servletRequest.getQueryString());
		}
		else {
			htServiceRequest = new HashMap();
			String sParameter, sValue;
			Enumeration eParameters = servletRequest.getParameterNames();
			while (eParameters.hasMoreElements()) {
				sParameter = (String) eParameters.nextElement();
				sValue = servletRequest.getParameter(sParameter);
				if (sValue != null) {
					htServiceRequest.put(sParameter, sValue);
				}
			}
		}

		htServiceRequest.put("my_url", servletRequest.getRequestURL().toString());
		// Bauke 20081217: client_ip and user_agent should already be set
		// htServiceRequest.put("client_ip", servletRequest.getRemoteAddr());
		// String sAgent = servletRequest.getHeader("User-Agent");
		// if (sAgent != null) htServiceRequest.put("user_agent", sAgent);
		HashMap htCredentials = getASelectCredentials(servletRequest);
		if (htCredentials != null) {
			htServiceRequest.put("aselect_credentials_tgt", htCredentials.get("aselect_credentials_tgt"));
			htServiceRequest.put("aselect_credentials_uid", htCredentials.get("aselect_credentials_uid"));
			htServiceRequest.put("aselect_credentials_server_id", _sMyServerId);
		}

		return htServiceRequest;
	}

	/**
	 * Retrieve A-Select credentials. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Reads the A-Select credentials from a Cookie and put them into a <code>HashMap</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>servletRequest != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param servletRequest
	 *            The Request which should contain the Cookie.
	 * @return The A-Select credentials in a <code>HashMap</code>.
	 */
	@SuppressWarnings("unchecked")
	protected HashMap getASelectCredentials(HttpServletRequest servletRequest)
	{
		// This method overrides the default from ProtoRequestHandler.java
		String sMethod = "getASelectCredentials";
		HashMap htCredentials = new HashMap();

		// Check for credentials that might be present
		// Bauke 20080618, we only store the tgt value from now on
		String sTgt = HandlerTools.getCookieValue(servletRequest, "aselect_credentials", _systemLogger);
		if (sTgt == null)
			return null;

		HashMap htTGTContext = _tgtManager.getTGT(sTgt);
		if (htTGTContext == null)
			return null;

		String sUserId = (String) htTGTContext.get("uid");
		if (sUserId != null)
			htCredentials.put("aselect_credentials_uid", sUserId);
		htCredentials.put("aselect_credentials_tgt", sTgt);
		htCredentials.put("aselect_credentials_server_id", _sMyServerId); // Bauke 200806128 was: sServerId);
		return htCredentials;
	}

	/**
	 * Checks if is signing required.
	 * 
	 * @return true, if is signing required
	 */
	public synchronized boolean isSigningRequired()
	{
		return signingRequired;
	}

	/**
	 * Sets the signing required.
	 * 
	 * @param signingRequired
	 *            the new signing required
	 */
	public synchronized void setSigningRequired(boolean signingRequired)
	{
		this.signingRequired = signingRequired;
	}

	/**
	 * Checks if is locality address required.
	 * 
	 * @return true, if is locality address required
	 */
	public synchronized boolean isLocalityAddressRequired()
	{
		return localityAddressRequired;
	}

	/**
	 * Sets the locality address required.
	 * 
	 * @param localityAddressRequired
	 *            the new locality address required
	 */
	public synchronized void setLocalityAddressRequired(boolean localityAddressRequired)
	{
		this.localityAddressRequired = localityAddressRequired;
	}
}
