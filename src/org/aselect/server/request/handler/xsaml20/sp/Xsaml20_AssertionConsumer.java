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
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectAuthProofLogger;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectEntrustmentLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.server.request.handler.xsaml20.SoapManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Base64Codec;
import org.aselect.system.utils.Utils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
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
 */
public class Xsaml20_AssertionConsumer extends Saml20_BaseHandler
{
	private final static String MODULE = "Xsaml20_AssertionConsumer";
	private XMLObjectBuilderFactory _oBuilderFactory;
	private ASelectAuthenticationLogger _authenticationLogger;
	protected TGTManager _tgtManager;
	private String _sMyServerId;
	private String _sFederationUrl;
	private String _sRedirectUrl; // We use as Issuer in the send SAML message
	//private String _sRequestIssuer; // But it can be set explicitly
	private boolean signingRequired = false;
	// Get from aselect.xml <applications require_signing="false | true">
	private boolean localityAddressRequired = false; // Do we need to verify localityAddress in the AuthnStatement
	
	private boolean includeSessionindexes = false;
//	 should the SessionIndex(es) be included in the saml request, to be included the must be present in the tgt 
//		and therefore previously been received in the assertion
//	 if null value is not specified in aselect.xml

	private boolean useBackchannelClientcertificate = false;

	// 20120712, Bauke: Store TGT in class variable to save on reads
	protected HashMap _htTGTContext = null;

	private boolean verifyArtifactResponseSignature = false;

	private boolean useNameIDAsAuthID = false;

	private boolean carryAuthProof = false;
	private boolean logAuthProof = false;
	
	//
	// Example configuration:
	// <handler id="saml20_assertionconsumer"
	// class="org.aselect.server.request.handler.xsaml20.Xsaml20_AssertionConsumer"
	// target="/saml20_assertion.*" >
	// </handler>
	//
	/**
	 * Initializes the request handler by reading the configuration.
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
		String sMethod = "init";

		super.init(oServletConfig, oHandlerConfig);

		_oBuilderFactory = Configuration.getBuilderFactory();
		_sMyServerId = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);
		_sFederationUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "federation_url", false);
		// Issuer in the send SAML message
		_sRedirectUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);
		// 20100315: Specific issuer (eHerkenning) different from redirect_url
		// 20100429: removed: _sRequestIssuer = ASelectConfigManager.getSimpleParam(oHandlerConfig, "issuer", false);

		String sLocalityAddressRequired = ASelectConfigManager.getSimpleParam(oHandlerConfig, "locality_address_required", false);
		if ("true".equalsIgnoreCase(sLocalityAddressRequired)) {
			setLocalityAddressRequired(true);
		}
		// RH, 20120201, sn
		String sIncludeSessionindexes = ASelectConfigManager.getSimpleParam(oHandlerConfig, "include_sessionindexes", false);
		if ("true".equalsIgnoreCase(sIncludeSessionindexes)) {
			setIncludeSessionindexes(true);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "include_sessionindexes: " + isIncludeSessionindexes());
		// RH, 20120201, en

		// RH, 20120322, sn
		String sUseBackChannelClientCertificate = ASelectConfigManager.getSimpleParam(oHandlerConfig, "use_backchannelclientcertificate", false);
//		if ("true".equalsIgnoreCase(sIncludeSessionindexes)) {		// RH, 20130923, o
		if ("true".equalsIgnoreCase(sUseBackChannelClientCertificate)) {		// RH, 20130923, n
			setUseBackchannelClientcertificate(true);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "use_backchannelclientcertificate: " + isUseBackchannelClientcertificate());
		// RH, 20120322, en

		// RH, 20121205, sn
		String sVerifyArtifactresponseSignature = ASelectConfigManager.getSimpleParam(oHandlerConfig, "verify_artifactresponsesignature", false);
		if ("true".equalsIgnoreCase(sVerifyArtifactresponseSignature)) {
			setVerifyArtifactResponseSignature(true);
		}
		// RH, 20121205, en

		// RH, 20130923, sn
		String sUseNameIDAsAuthID = ASelectConfigManager.getSimpleParam(oHandlerConfig, "use_nameidasauthid", false);
		if ("true".equalsIgnoreCase(sUseNameIDAsAuthID)) {
			setUseNameIDAsAuthID(true);
		}
		// RH, 20130923, en
		
		// Because carrying and/or logging the quite large auth_proof may have some impact on resources we can enable/disable
		// RH, 20140327, sn
		String sCarryAuthProof = ASelectConfigManager.getSimpleParam(oHandlerConfig, "carry_auth_proof", false);
		if ("true".equalsIgnoreCase(sCarryAuthProof)) {
			setCarryAuthProof(true);
		}
		// RH, 20140327, en

		// RH, 20140327, sn
		String sLogAuthProof = ASelectConfigManager.getSimpleParam(oHandlerConfig, "log_auth_proof", false);
		if ("true".equalsIgnoreCase(sLogAuthProof)) {
			setLogAuthProof(true);
		}
		// RH, 20140327, en
		
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
	@SuppressWarnings("unchecked")
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process";
		boolean checkAssertionSigning = false;
		Object samlResponseObject = null;
		String auth_proof = null;

		try {
			String sReceivedArtifact = request.getParameter("SAMLart");
			String sReceivedResponse = request.getParameter("SAMLResponse");
			String sRelayState = request.getParameter("RelayState");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received artifact: " + sReceivedArtifact + " RelayState="+sRelayState);
			if ( !(sReceivedArtifact == null || "".equals(sReceivedArtifact)) ) {
				String sFederationUrl = _sFederationUrl; // default, remove later on, can be null
				if (sRelayState.startsWith("idp=")) {
					sFederationUrl = sRelayState.substring(4);
				}
				else {  // Could be Base64 encoded
					sRelayState = new String(Base64Codec.decode(sRelayState));
					_systemLogger.log(Level.INFO, MODULE, sMethod, "RelayState="+sRelayState);
					sFederationUrl = Utils.getParameterValueFromUrl(sRelayState, "idp");
				}
				if (!Utils.hasValue(sFederationUrl)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No idp value found in RelayState (or in <federation_url> config)");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
		
				_systemLogger.log(Level.INFO, MODULE, sMethod, "FederationUrl="+sFederationUrl);
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
	
				artifactResolve.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
				artifactResolve.setVersion(SAMLVersion.VERSION_20);
				artifactResolve.setIssueInstant(new DateTime());
	
				// We decided that the other side could retrieve public key from metadata
				// by looking up the issuer as an entityID in the metadata
				// So we MUST supply an Issuer (which otherwise would be optional (by SAML standards))
				SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) _oBuilderFactory
						.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
				Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
				
				// 20100312, Bauke: eHerkenning, no assertion issuer format:
				// assertionIssuer.setFormat(NameIDType.ENTITY);
				// 20100311, Bauke: added for eHerkenning: Specific issuer id, independent of the Url
				PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sFederationUrl);
				String specialSettings = (partnerData == null)? null: partnerData.getSpecialSettings();
				if (partnerData != null && partnerData.getLocalIssuer() != null)
					assertionIssuer.setValue(partnerData.getLocalIssuer());
				else
					assertionIssuer.setValue(_sRedirectUrl);
				artifactResolve.setIssuer(assertionIssuer);
				artifactResolve.setArtifact(artifact);
	
				// Do some logging for testing
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the artifactResolve >======");
				boolean useSha256 = (specialSettings != null && specialSettings.contains("sha256"));
				artifactResolve = (ArtifactResolve)SamlTools.signSamlObject(artifactResolve, useSha256? "sha256": "sha1");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the artifactResolve ======<");
	
				// Build the SOAP message
				SoapManager soapManager  = null;
				if (isUseBackchannelClientcertificate()) {
					soapManager = new SoapManager(getSslSocketFactory());
				} else {
					soapManager = new SoapManager();
				}
				Envelope envelope = soapManager.buildSOAPMessage(artifactResolve);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Marshall");
				Element envelopeElem = SamlTools.marshallMessage(envelope);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Writing SOAP message:\n"+ XMLHelper.nodeToString(envelopeElem));
				// XMLHelper.prettyPrintXML(envelopeElem));
	
				// ------------ Send/Receive the SOAP message
				String sSamlResponse = soapManager.sendSOAP(XMLHelper.nodeToString(envelopeElem), sASelectServerUrl);  // x_AssertionConsumer_x
				//byte[] sSamlResponseAsBytes = sSamlResponse.getBytes();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Received response: "+sSamlResponse+" length=" + sSamlResponse.length());
				
				// save original, but, for (internal) transport, encode base64 
				auth_proof = new String(org.apache.commons.codec.binary.Base64.encodeBase64(sSamlResponse.getBytes("UTF-8")));
				
				DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
				dbFactory.setNamespaceAware(true);
				// dbFactory.setExpandEntityReferences(false);
				// dbFactory.setIgnoringComments(true);
				DocumentBuilder builder = dbFactory.newDocumentBuilder();
	
				StringReader stringReader = new StringReader(sSamlResponse);
				InputSource inputSource = new InputSource(stringReader);
				Document docReceivedSoap = builder.parse(inputSource);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "parsed="+docReceivedSoap.toString());
				Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "getdoc="+elementReceivedSoap.toString());
	
				// Remove all SOAP elements
				Node eltArtifactResponse = SamlTools.getNode(elementReceivedSoap, "ArtifactResponse");
	
				// Unmarshall to the SAMLmessage
				UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
				Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResponse);
				ArtifactResponse artifactResponse = (ArtifactResponse) unmarshaller.unmarshall((Element) eltArtifactResponse);
	
				Issuer issuer = artifactResponse.getIssuer();
				String sIssuer = (issuer == null)? null: issuer.getValue();
				// If issuer is not present in the response, use sASelectServerUrl value retrieved from metadata
				// else use value from the response
				String artifactResponseIssuer = (sIssuer == null || "".equals(sIssuer))? sASelectServerUrl: sIssuer;
	
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Do artifactResponse signature verification="+is_bVerifySignature());
//				if (is_bVerifySignature()) {	// RH, 20121205, o
				if (is_bVerifySignature() || isVerifyArtifactResponseSignature()) {	// RH, 20121205, n
					// Check signature of artifactResolve here
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
	
					if (SamlTools.checkSignature(artifactResponse, pkey)) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "artifactResponse was signed OK");
					}
					else {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "artifactResponse was NOT signed OK");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
				}
				samlResponseObject = artifactResponse.getMessage();
			}	
			else if ( !(sReceivedResponse == null || "".equals(sReceivedResponse)) ) {
				// Handle http-post, can be unsolicited POST as well
				// Could be Base64 encoded
				// RelayState should contain intended application resource URL
				sRelayState = new String(Base64Codec.decode(sRelayState));
				
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Received Response: " + sReceivedResponse);	//	RH, 20130924, n
//				sReceivedResponse = new String(Base64Codec.decode(sReceivedResponse));	//	RH, 20130924, o
				auth_proof = sReceivedResponse;	// save original

				sReceivedResponse = new String(org.apache.commons.codec.binary.Base64.decodeBase64(sReceivedResponse.getBytes("UTF-8")));	//	RH, 20130924, n
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Received Response after base64 decoding: " + sReceivedResponse + " RelayState="+sRelayState);	//	RH, 20130924, n
				DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
				dbFactory.setNamespaceAware(true);
				// dbFactory.setExpandEntityReferences(false);
				// dbFactory.setIgnoringComments(true);
				DocumentBuilder builder = dbFactory.newDocumentBuilder();
	
				StringReader stringReader = new StringReader(sReceivedResponse);
				InputSource inputSource = new InputSource(stringReader);
				Document docReceived = builder.parse(inputSource);
				Node eltSAMLResponse = SamlTools.getNode(docReceived, "Response");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found node Response: " + eltSAMLResponse +((eltSAMLResponse==null)? " NULL": " ok"));
	
				// Unmarshall to the SAMLmessage
				UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
				Unmarshaller unmarshaller = factory.getUnmarshaller((Element)eltSAMLResponse);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Unmarshaller"+((unmarshaller==null)? " NULL": " ok"));
				samlResponseObject = (Response)unmarshaller.unmarshall((Element)eltSAMLResponse);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Unmarshalling done, VerifySignature="+is_bVerifySignature());

				// 20120308: Bauke added signature checking
				//   saml-profiles-2.0-os: The <Assertion> element(s) in the <Response> MUST be signed,
				//   if the HTTP POST binding is used, and MAY be signed if the HTTPArtifact binding is used.
				if (is_bVerifySignature())
					checkAssertionSigning = true;
				
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No Artifact and no Response found in the message.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			///////
			// The object can either a Response (SSO case) or a StatusResponseType (SLO case)
			///////////////////////////////////////////////////////////////////////////
			if (samlResponseObject instanceof Response) {
				// SSO
				Response samlResponse = (Response) samlResponseObject;
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Processing 'Response'");  // +XMLHelper.prettyPrintXML(samlResponse.getDOM()));

				
				// RH, 20121205, sn
				MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Do Response signature verification="+isVerifyResponseSignature());
				if (isVerifyResponseSignature()) {
					Issuer issuer = samlResponse.getIssuer();
					String sIssuer = (issuer == null)? null: issuer.getValue();
					// If issuer is not present in the response, use sASelectServerUrl value retrieved from metadata
					// else use value from the response
//					String responseIssuer = (sIssuer == null || "".equals(sIssuer))? sASelectServerUrl: sIssuer;
					String responseIssuer = (sIssuer == null || "".equals(sIssuer))? null: sIssuer;	// There must be an issuer for now
					// Check signature of artifactResolve here
					// We get the public key from the metadata
					// Therefore we need a valid Issuer to lookup the entityID in the metadata
					// We get the metadataURL from aselect.xml so we consider this safe and authentic
					if (responseIssuer == null || "".equals(responseIssuer)) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod,
								"For signature verification the received response must have an Issuer");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					
					PublicKey pkey = metadataManager.getSigningKeyFromMetadata(responseIssuer);
					if (pkey == null || "".equals(pkey)) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No valid public key in metadata");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
	
					if (SamlTools.checkSignature(samlResponse, pkey)) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Response was signed OK");
					}
					else {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Response was NOT signed OK");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
				}
				// RH, 20121205, en
				
				// Detect if this is a successful or an error Response		
				String sStatusCode = samlResponse.getStatus().getStatusCode().getValue();
				String sRemoteRid = samlResponse.getID();
				
				// 20100531, Bauke: Remove added timestamp to get our local RID
				String sLocalRid = samlResponse.getInResponseTo();
				int len = sLocalRid.length();
				if (len > 9)
					sLocalRid = sLocalRid.substring(0, len-9);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "RemoteRid=" + sRemoteRid +
								" LocalRid=" + sLocalRid + " StatusCode=" + sStatusCode);
				_htSessionContext = _oSessionManager.getSessionContext(sLocalRid);
				if (_htSessionContext == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Unknown session in response from cross aselect server");
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				
				if (sStatusCode.equals(StatusCode.SUCCESS_URI)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Response was successful " + samlResponse.toString());
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Number of Assertions found:  " +  samlResponse.getAssertions().size());
					Assertion samlAssertion = samlResponse.getAssertions().get(0);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Assertion ID:" +samlAssertion.getID());
					String sAssertIssuer = samlAssertion.getIssuer().getValue();
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Issuer:" +sAssertIssuer+" checkAssertionSigning="+checkAssertionSigning);
					
					// 20120308: Bauke added signature checking
//					if (checkAssertionSigning) {	// RH, 20121205, o
					if (checkAssertionSigning || isVerifyAssertionSignature()) {	// RH, 20121205, n
						// Check signature of artifactResolve here. We get the public key from the metadata
						// Therefore we need a valid Issuer to lookup the entityID in the metadata
						// We get the metadataURL from aselect.xml so we consider this safe and authentic
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Verify assertion signature, issuer="+sAssertIssuer);
						if (!Utils.hasValue(sAssertIssuer)) {
							_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No Issuer present in Assertion");
							throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
						}
						
//						MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();	// RH, 20121205, n
						PublicKey pkey = metadataManager.getSigningKeyFromMetadata(sAssertIssuer);
						if (pkey == null || "".equals(pkey)) {
							_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No valid public key in metadata");
							throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
						}
						if (!SamlTools.checkSignature(samlAssertion, pkey)) {
							_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Assertion was NOT signed OK");
							throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
						}
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Assertion was signed OK");
					}
					// 20120308
					
					String sNameID = samlAssertion.getSubject().getNameID().getValue();
					_systemLogger.log(Level.INFO, MODULE, sMethod, "NameID:" + sNameID);
					String sNameIDQualifier = samlAssertion.getSubject().getNameID().getNameQualifier();
					_systemLogger.log(Level.INFO, MODULE, sMethod, "NameIDQualifier:" + sNameIDQualifier);

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
							&& !SamlTools.checkLocalityAddress(samlAssertion.getAuthnStatements().get(0), request.getRemoteAddr())) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "AuthnStatement subjectlocalityaddress was NOT valid");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					
					// Get the (option) sessionindex from remote
					String sSessionindex = samlAssertion.getAuthnStatements().get(0).getSessionIndex();
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Sessionindex:" + sSessionindex);
					
					AuthnContext oAuthnContext = samlAssertion.getAuthnStatements().get(0).getAuthnContext();
					List<AuthenticatingAuthority> authAuthorities = oAuthnContext.getAuthenticatingAuthorities();
					String sAuthnAuthority = null;
					if (authAuthorities != null && authAuthorities.size() > 0)
						sAuthnAuthority = (String)authAuthorities.get(0).getURI();
					String sAuthnContextClassRefURI = oAuthnContext.getAuthnContextClassRef().getAuthnContextClassRef();
					_systemLogger.log(Level.INFO, MODULE, sMethod, "AuthnContextClassRefURI:" +sAuthnContextClassRefURI);;
					/////////////////////////	digid4	///////////////////////////////////////////
					/// Digid4 still has to decide how to provide a "face2face" declaration 
					//	String sAuthnContextDeclRefIssueMethod = samlAssertion.getAuthnStatements().get(0).getAuthnContext().
					/////////////////////////	digid4	///////////////////////////////////////////
					String sSelectedLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(sAuthnContextClassRefURI, _systemLogger);
					
					// Check returned security level
					Integer intAppLevel = (Integer) _htSessionContext.get("level");
					if (Integer.parseInt(sSelectedLevel) < intAppLevel) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Security level returned ("+
										sSelectedLevel+") must be at least: "+intAppLevel);
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}

					// Retrieve the embedded attributes
					HashMap hmSamlAttributes = new HashMap();
					String sEncodedAttributes = null;
					List<AttributeStatement> lAttrStatList = samlAssertion.getAttributeStatements();
					Iterator<AttributeStatement> iASList = lAttrStatList.iterator();
					while (iASList.hasNext()) {
						AttributeStatement sAttr = iASList.next();
						List<Attribute> lAttr = sAttr.getAttributes();
						Iterator<Attribute> iAttr = lAttr.iterator();
						while (iAttr.hasNext()) {
							Attribute attr = iAttr.next();
							String sAttrName = attr.getName();
							
							String sAttrValue = null;// RH, 20120124, sn
							List <XMLObject> aValues = attr.getAttributeValues();
							if ( aValues != null && aValues.size() == 1 ) {	// For now we only allow single valued simple type xs:string attributes
	                            XMLObject xmlObj = aValues.get(0);
//								XSStringImpl xsString = (XSStringImpl) attr.getOrderedChildren().get(0);// RH, 20120124, so
//								String sAttrValue = xsString.getValue();// RH, 20120124, o
//								sAttrValue = xsString.getValue();// RH, 20120124, eo
								sAttrValue = xmlObj.getDOM().getFirstChild().getTextContent();
								_systemLogger.log(Level.INFO, MODULE, sMethod, "Name=" + sAttrName + " Value=" + sAttrValue);
							}
							else {
								_systemLogger.log(Level.INFO, MODULE, sMethod, "Only single valued attributes allowed, skipped attribute Name=" + sAttrName);
							}	// RH, 20120124, en
							if ("attributes".equals(sAttrName))
								sEncodedAttributes = sAttrValue;
							else
								hmSamlAttributes.put(sAttrName, sAttrValue);
						}
					}
					
					// Since the "attributes" Attribute is used for gathering, add the Saml Attributes to it
					HashMap<String, String> hmAttributes;
					if (sEncodedAttributes != null) {
						hmAttributes = org.aselect.server.utils.Utils.deserializeAttributes(sEncodedAttributes);
					}
					else {
						hmAttributes = new HashMap<String, String>();
					}
					// Add the serialized attributes and a few specials
					hmSamlAttributes.putAll(hmAttributes);
					hmSamlAttributes.put("name_id", sNameID);  // "sel_level" was already set by the IdP
					if (sAuthnAuthority != null)
						hmSamlAttributes.put("authority", sAuthnAuthority);

					// eHerkenning addition: OrgID = KvKnummer+Vestigingsnummer
					// If EntityConcernedID = 00000003123456780000 and EntityConcernedSubID = ...0001,
					// then orgid = 1234567800000001
//					String sEntityId = (String)hmSamlAttributes.get("urn:nl:eherkenning:0.8def:EntityConcernedID");
					// RH, 20110523, add support for other versions of eHerk
					String sEntityId = null;

					Pattern p = Pattern.compile("urn:nl:eherkenning:(.*):EntityConcernedID");

					Set<String> keys = hmSamlAttributes.keySet();
					Iterator keyIter = keys.iterator();
					String eHerkversion = null;
					while (keyIter.hasNext()) {
						Matcher m = p.matcher((String)keyIter.next());
						if (m.find())  {
							sEntityId = (String)hmSamlAttributes.get(m.group());
							eHerkversion = m.group(1);
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Found sEntityId=" + sEntityId + " eHerkversion=" + eHerkversion);
							break;	// just take the first we find
						}
					}
						
					if (sEntityId != null) {
						int idx = sEntityId.length()-12;  // last 12 characters
						if (idx > 0) sEntityId = sEntityId.substring(idx);
						
//						String sEntitySubId = (String)hmSamlAttributes.get("urn:nl:eherkenning:0.8def:EntityConcernedSubID");
						String sEntitySubId = (String)hmSamlAttributes.get("urn:nl:eherkenning:" + eHerkversion + ":EntityConcernedSubID");
						if (sEntitySubId != null) {
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Found sEntitySubId=" + sEntitySubId);							
							idx = sEntitySubId.length()-12;  // last 12 characters to be on the safe side
							if (idx > 0) sEntitySubId = sEntitySubId.substring(idx);
							sEntityId = sEntitySubId;
						}
						else {  // ditch the last 4 zeroes
							idx = sEntityId.length()-4;
							if (idx > 0)
								sEntityId = sEntityId.substring(0, idx);
						}
						hmSamlAttributes.put("orgid", sEntityId);
					}
					
					// eHerkenning: AuthID = Unique Persistent Identifier
					if ( isUseNameIDAsAuthID() ) {		// RH, 20130923, sn
						hmSamlAttributes.put("authid", sNameID);
					} else {	// RH, 20130923, en
					// Use the fifth word from sAuthnAuthority (split using :) and add sNameID
						if (sNameIDQualifier != null) {
							String sAuthID = "", sAuthSubID = "";
							String[] tokens = sNameIDQualifier.split(":");
							if (tokens.length > 4)
								sAuthID = tokens[4];
	
	//						if (tokens.length > 5)
	//							sAuthSubID = tokens[5];
							// Test  new layout of eherkenning
							// Maybe do something with pattern search here
							if (tokens.length > 6)
								sAuthSubID = tokens[6];
							
							sAuthID += "_"+sAuthSubID+"_"+sNameID;  // add separator
							hmSamlAttributes.put("authid", sAuthID);
						}
					}	// RH, 20130923, n
					
					if ( isCarryAuthProof() ) { // Put the original authentication proof in hmSamlAttributes
						hmSamlAttributes.put("auth_proof", auth_proof); // original response, still base64 encoded
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "auth_proof=" + auth_proof);
					}
					// And serialize them back to where they came from
					sEncodedAttributes = org.aselect.server.utils.Utils.serializeAttributes(hmSamlAttributes);
					hmSamlAttributes.put("attributes", sEncodedAttributes);
					
					// This is the quickest way to get "name_id" into the Context
					hmSamlAttributes.put("name_id", sNameID);  // also as plain attribute
					
					///////////// Digid4	//////////////////////////////
					// must be made configurable and parameterized, still looking for some reference to identify the service (maybe issuer) 
					String[] splittedNameId = sNameID.split(":");
					if ( splittedNameId.length == 2 && splittedNameId[0].toUpperCase().startsWith("S") && splittedNameId[0].length() == 9 )	{		// for now this identifies as digid4
						hmSamlAttributes.put("uid", splittedNameId[1]);
						// add special attributes for digid4
						if ( "S00000000".equalsIgnoreCase(splittedNameId[0]) ) {
							hmSamlAttributes.put("bsn", splittedNameId[1]);
							
						} else if ( "S00000001".equalsIgnoreCase(splittedNameId[0]) ) {
							hmSamlAttributes.put("sofi", splittedNameId[1]);
							
						} else if ( "S00000002".equalsIgnoreCase(splittedNameId[0]) ) {
							hmSamlAttributes.put("anummer", splittedNameId[1]);

						} else if ( "S00000100".equalsIgnoreCase(splittedNameId[0]) ) {
							hmSamlAttributes.put("oeb", splittedNameId[1]);
						}
					}
					/////////////////////////////////////////////////////
					
					// 20100422, Bauke: no uid, then use NameID
					String sUid = (String)hmSamlAttributes.get("uid");
					if (sUid == null || sUid.equals(""))
						hmSamlAttributes.put("uid", sNameID);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "NameID=" + sNameID + " remote_rid=" + sRemoteRid
							+ " local_rid=" + sLocalRid + " sel_level=" + sSelectedLevel + " organization/authsp="
							+ sAssertIssuer);

					// htRemoteAttributes.put("attributes", HandlerTools.serializeAttributes(htAttributes));
					hmSamlAttributes.put("remote_rid", sRemoteRid);
					hmSamlAttributes.put("local_rid", sLocalRid);

					hmSamlAttributes.put("sel_level", sSelectedLevel);
					hmSamlAttributes.put("authsp_level", sSelectedLevel);  // default value, issueTGT will correct this
					hmSamlAttributes.put("organization", sAssertIssuer);
					hmSamlAttributes.put("authsp", sAssertIssuer);
					
					// RH, 20120201, sn
					// also save the provided session if present, saml2 specs say there might be more than one session to track
					if (  isIncludeSessionindexes() && sSessionindex != null && sSessionindex.length() > 0 ) {
						Vector sessionindexes = new Vector<String>();
						sessionindexes.add(sSessionindex);
						hmSamlAttributes.put("remote_sessionlist", sessionindexes);
					}
					// RH, 20120201, en

					// Bauke, 20081204: If we want to send the IdP token as an attribute
					// to the application, we will need the following code:
					/*
					 * String sAssertion = XMLHelper.nodeToString(samlAssertion.getDOM());
					 * _systemLogger.log(Level.INFO, MODULE, sMethod, "sAssertion="+sAssertion);
					 * BASE64Encoder b64Enc = new BASE64Encoder();
					 * sAssertion = b64Enc.encode(sAssertion.getBytes("UTF-8"));
					 * htRemoteAttributes.put("saml_remote_token", sAssertion);
					 */
					// End of IdP token

					_systemLogger.log(Level.INFO, MODULE, sMethod, "htRemoteAttributes=" + hmSamlAttributes);
					handleSSOResponse(_htSessionContext, hmSamlAttributes, request, response);
				}
				else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Response was not successful: " + sStatusCode);
					// Handle various error conditions here
					String sErrorCode = Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;	// default
					String sErrorSubCode = null;
					if ( samlResponse.getStatus().getStatusCode().getStatusCode() != null) {	// Get the subcode
						sErrorSubCode = SamlTools.mapStatus(samlResponse.getStatus().getStatusCode().getStatusCode().getValue());
						_systemLogger.log(Level.FINER, MODULE, sMethod, "ErrorSubcode: " + sErrorSubCode);
					}
					StatusMessage statMsg = samlResponse.getStatus().getStatusMessage();
					if (statMsg != null) {
						sErrorCode = statMsg.getMessage();
						_systemLogger.log(Level.FINER, MODULE, sMethod, "StatusMessage found: " + sErrorCode);
					} else {
						if (sErrorSubCode != null && !"".equals(sErrorSubCode)) {
							sErrorCode = sErrorSubCode;
						}
					}
					_systemLogger.log(Level.INFO, MODULE, sMethod, "ErrorCode=" + sErrorCode);
					//else if (samlResponse.getStatus().getStatusCode().getStatusCode().getValue().equals(StatusCode.AUTHN_FAILED_URI))
					//	sErrorCode = Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
					// Expect these codes: Errors.ERROR_ASELECT_SERVER_CANCEL,
					// Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;

					//HashMap htRemoteAttributes = new HashMap();
					//htRemoteAttributes.put("remote_rid", sRemoteRid);
					//htRemoteAttributes.put("local_rid", sLocalRid);
					//htRemoteAttributes.put("result_code", sErrorCode);

					// Choose your response (3rd is implemented below)
					// 1. handleSSOResponse(htRemoteAttributes, request, response); // Lets application display error
					// 2. throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED); // Standard server error
					// 3. Show error page:
					response.setContentType("text/html");
					showErrorPage(sErrorCode, _htSessionContext, response.getWriter(), request);
				}
			}
			else {  // SLO
				_systemLogger.log(Level.WARNING, "Unexpected SAMLObject type: " + samlResponseObject.getClass());
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			// 20130821, Bauke: save friendly name after session is gone
			if (_htSessionContext != null) {
				String sStatus = (String)_htSessionContext.get("status");
				String sAppId = (String)_htSessionContext.get("app_id");
				if ("del".equals(sStatus) && Utils.hasValue(sAppId)) {
					String sUF = ApplicationManager.getHandle().getFriendlyName(sAppId);
					HandlerTools.setEncryptedCookie(response, "requestor_friendly_name", sUF, _configManager.getCookieDomain(), -1/*age*/, _systemLogger);
				}
			}
			_oSessionManager.finalSessionProcessing(_htSessionContext, true/*really do it*/);
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	public void destroy()
	{
		String sMethod = "destroy";
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
	private void handleSSOResponse(HashMap htSessionContext, HashMap htRemoteAttributes,
						HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "handleSSOResponse";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "<--");

		try {
			// 20120712, Bauke: Stores TGT in class variable to save on reads:
			HashMap htServiceRequest = createServiceRequest(servletRequest);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htServiceRequest=" + htServiceRequest);

			String sLocalRid = (String) htRemoteAttributes.get("local_rid");
			if (sLocalRid == null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Missing remote attribute: 'local_rid'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// for authentication logging
			String sRemoteOrg = (String) htSessionContext.get("remote_organization");
			String sOrg = (String) htRemoteAttributes.get("organization");
			if (sRemoteOrg != null && sOrg != null && !sRemoteOrg.equals(sOrg))
				sRemoteOrg = sOrg + "@" + sRemoteOrg;

			String sResultCode = (String) htRemoteAttributes.get("result_code");
			String sUID = (String) htRemoteAttributes.get("uid");
			String sFederationId = (String) htSessionContext.get("federation_url");
			if (sResultCode != null) {
				if (sResultCode.equals(Errors.ERROR_ASELECT_SERVER_CANCEL)
						|| sResultCode.equals(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cancel");
					_authenticationLogger.log(new Object[] {
						"Saml", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
						htSessionContext.get("app_id"), "denied", sFederationId, sResultCode
					});
					// Issue 'CANCEL' TGT
					TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
					tgtIssuer.issueErrorTGTandRedirect(sLocalRid, htSessionContext, sResultCode, servletResponse);
				}
				else { // remote server returned error
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error");
					_authenticationLogger.log(new Object[] {
						"Saml", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
						htSessionContext.get("app_id"), "denied", sFederationId, sResultCode
					});
					throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
				}
			}
			else { // No result_code set, log successful authentication
				_authenticationLogger.log(new Object[] {
					"Saml", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
					htSessionContext.get("app_id"), "granted", sFederationId
				});
				if ( isLogAuthProof() ) {	// Log auth_proof here if enabled
					ASelectAuthProofLogger.getHandle().log( sUID, (String) htRemoteAttributes.get("client_ip"), (String)htSessionContext.get("app_id"), (String)null, (String)htRemoteAttributes.get("auth_proof") );
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "auth_proof logged after successful authentication=" + 
//							htRemoteAttributes.get("auth_proof"));
				}
				
				HandlerTools.setRequestorFriendlyCookie(servletResponse, htSessionContext, _systemLogger);  // 20130825

				// Issue a cross TGT since we do not know the AuthSP
				// and we might have received remote attributes.
				TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
				String sOldTGT = (String) htServiceRequest.get("aselect_credentials_tgt");
				// Will also redirect the user, this call can update/delete the session in the local cache
				// Final session updates will be done by finalSessionProcessing()
				oTGTIssuer.issueTGTandRedirect(sLocalRid, htSessionContext, null, htRemoteAttributes, servletRequest, servletResponse, sOldTGT, true);
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
			htServiceRequest = Utils.convertCGIMessage(servletRequest.getQueryString(), false);
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
	 * Retrieve A-Select credentials. Reads TGT in _htTGTContext.<br>
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

		// 20120712, Bauke: Store TGT in class variable to save on reads
		_htTGTContext = _tgtManager.getTGT(sTgt);
		if (_htTGTContext == null)
			return null;

		String sUserId = (String) _htTGTContext.get("uid");
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

	/**
	 * @return the includeSessionindexes
	 */
	public synchronized boolean isIncludeSessionindexes()
	{
		return includeSessionindexes;
	}

	/**
	 * @param includeSessionindexes the includeSessionindexes to set
	 */
	public synchronized void setIncludeSessionindexes(boolean includeSessionindexes)
	{
		this.includeSessionindexes = includeSessionindexes;
	}

	/**
	 * @return the useBackchannelClientcertificate
	 */
	public boolean isUseBackchannelClientcertificate()
	{
		return useBackchannelClientcertificate;
	}

	/**
	 * @param useBackchannelClientcertificate the useBackchannelClientcertificate to set
	 */
	public void setUseBackchannelClientcertificate(boolean useBackchannelClientcertificate)
	{
		this.useBackchannelClientcertificate = useBackchannelClientcertificate;
	}

	public synchronized boolean isVerifyArtifactResponseSignature()
	{
		return verifyArtifactResponseSignature;
	}

	public synchronized void setVerifyArtifactResponseSignature(boolean verifyArtifactResponseSignature)
	{
		this.verifyArtifactResponseSignature = verifyArtifactResponseSignature;
	}

	public synchronized boolean isUseNameIDAsAuthID()
	{
		return useNameIDAsAuthID;
	}

	public synchronized void setUseNameIDAsAuthID(boolean useNameIDAsAuthID)
	{
		this.useNameIDAsAuthID = useNameIDAsAuthID;
	}

	public boolean isCarryAuthProof() {
		return carryAuthProof;
	}

	public void setCarryAuthProof(boolean carryAuthProof) {
		this.carryAuthProof = carryAuthProof;
	}

	public boolean isLogAuthProof() {
		return logAuthProof;
	}

	public void setLogAuthProof(boolean logAuthProof) {
		this.logAuthProof = logAuthProof;
	}
}
