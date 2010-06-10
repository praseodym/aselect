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

import java.io.StringReader;
import java.security.PublicKey;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SoapManager;
import org.aselect.server.request.handler.xsaml20.Saml20_ArtifactManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

//
// <handler id="saml20_artifactresolver"
//    class="org.aselect.server.request.handler.xsaml20.Xsaml20_ArtifactResolver"
//    target="/saml20_artifact.*">
// </handler>
//
/**
 * SAML2.0 ArtifactResolver for A-Select (Identity Provider side). <br>
 * <br>
 * <b>Description:</b><br>
 * The SAML2.0 ArtifactResolver for the A-Select Server (Identity Provider side).<br/>
 * SOAP message containing a SAML ArtifactResolve.<br/>
 * <br/>
 * The Response message coupled to the artifact is returned as a SOAP message with a SAML ArtifactResponse. <br>
 * 
 * @author Atos Origin
 */
public class Xsaml20_ArtifactResolver extends Saml20_BaseHandler
{
	// TODO This is NOT a good default
	// We have a problem if the SAML message send from the SP has no Issuer element
	// How do we find the public key?
	// If we take the public key from the KeyInfo (if it is present;-)
	// then we still have to establish the trust to this SP
	private final static String MODULE = "Xsaml20_ArtifactResolver";
	private XMLObjectBuilderFactory _oBuilderFactory;
	private String _sEntityId;
	private static final String CONTENT_TYPE = "text/xml; charset=utf-8";
	private boolean signingRequired = false; // OLD opensaml20 library

	// true; // NEW opensaml20 library
	// TODO see when signing is actually required
	// get from aselect.xml <applications require_signing="false | true">

	/**
	 * Init for class SAML20ArtifactResolver. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig.
	 * @param oHandlerConfig
	 *            Object.
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
	throws ASelectException
	{
		String sMethod = "init";

		super.init(oServletConfig, oHandlerConfig);
		_oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		_sEntityId = _configManager.getRedirectURL();
	}

	/**
	 * Resolve Artifact. <br>
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If resolving off artifact fails.
	 */
	@SuppressWarnings("unchecked")
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process";
		_systemLogger.log(Level.INFO, MODULE, sMethod, request.getContentType());

		try {
			MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();

			String sReceivedSoap = Tools.stream2string(request.getInputStream());
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received Soap:\n" + sReceivedSoap);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(sReceivedSoap);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			// _systemLogger.log(Level.INFO, MODULE, sMethod, "SOAP message:\n"
			// + XMLHelper.prettyPrintXML(elementReceivedSoap));

			// Remove all SOAP elements
			Node eltArtifactResolve = getNode(elementReceivedSoap, "ArtifactResolve");

			// _systemLogger.log(Level.INFO, MODULE, sMethod, "ArtifactResolve:\n"
			// + XMLHelper.nodeToString(eltArtifactResolve));

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);

			ArtifactResolve artifactResolve = (ArtifactResolve) unmarshaller.unmarshall((Element) eltArtifactResolve);
			String sReceivedArtifact = artifactResolve.getArtifact().getArtifact();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received artifact: " + sReceivedArtifact);

			String artifactResolveIssuer = (artifactResolve.getIssuer() == null || // avoid nullpointers
					artifactResolve.getIssuer().getValue() == null || "".equals(artifactResolve.getIssuer().getValue())) ? null
					: artifactResolve.getIssuer().getValue(); // else value from message
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do artifactResolve signature verification="
					+ is_bVerifySignature());
			if (is_bVerifySignature()) {
				// check signature of artifactResolve here
				// We get the public key from the metadata
				// Therefore we need a valid Issuer to lookup the entityID in the metadata
				// We get the metadataURL from aselect.xml so we consider this safe and authentic
				if (artifactResolveIssuer == null || "".equals(artifactResolveIssuer)) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod,
							"For signature verification the received message must have an Issuer");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				PublicKey pkey = metadataManager.getSigningKeyFromMetadata(artifactResolveIssuer);
				if (pkey == null || "".equals(pkey)) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No public valid key in metadata");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				if (checkSignature(artifactResolve, pkey)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "artifactResolve was signed OK");
				}
				else {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "artifactResolve was NOT signed OK");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
			}
			String sInResponseTo = artifactResolve.getID(); // Is required in SAMLsyntax

			// 20090409, Bauke: If back-channel communication is used Destination is optional
			// If we ever want to set it, look for the Recipient attribute contained
			// in the subject confirmation
			// (tgt:"sp_assert_url" equals the location where the artifact was sent to).
			// The issuer (artifactResolve.getIssuer()) cannot be used for this purpose!
			//
			String sDestination = null;

			ArtifactResponse artifactResponse = null;
			if (sReceivedArtifact == null || "".equals(sReceivedArtifact)) {
				String sStatusCode = StatusCode.INVALID_ATTR_NAME_VALUE_URI;
				String sStatusMessage = "No 'artifact' found in element 'ArtifactResolve' of SAMLMessage.";
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sStatusMessage);
				artifactResponse = errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
			}
			else {
				Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
				Response samlResponse = (Response) artifactManager.getArtifactFromStorage(sReceivedArtifact);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "samlResponse retrieved from storage:\n"
						+ XMLHelper.nodeToString(samlResponse.getDOM()));

				// We will not allow to use the artifact again
				artifactManager.remove(sReceivedArtifact); // RH, 20081113, n

				SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) _oBuilderFactory
						.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
				StatusCode statusCode = statusCodeBuilder.buildObject();
				statusCode.setValue(StatusCode.SUCCESS_URI);

				SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) _oBuilderFactory
						.getBuilder(Status.DEFAULT_ELEMENT_NAME);
				Status status = statusBuilder.buildObject();
				status.setStatusCode(statusCode);

				SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) _oBuilderFactory
						.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
				Issuer issuer = issuerBuilder.buildObject();
				issuer.setFormat(NameIDType.ENTITY);
				issuer.setValue(_sEntityId);

				SAMLObjectBuilder<ArtifactResponse> artifactResponseBuilder = (SAMLObjectBuilder<ArtifactResponse>) _oBuilderFactory
						.getBuilder(ArtifactResponse.DEFAULT_ELEMENT_NAME);
				artifactResponse = artifactResponseBuilder.buildObject();

				// nvl_patch, Novell: add xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
				artifactResponse.addNamespace(new Namespace(SAMLConstants.SAML20_NS, "saml"));

				artifactResponse.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
				artifactResponse.setInResponseTo(sInResponseTo);
				artifactResponse.setVersion(SAMLVersion.VERSION_20);
				artifactResponse.setIssueInstant(new DateTime());
				if (sDestination != null)
					artifactResponse.setDestination(sDestination);
				artifactResponse.setStatus(status);
				artifactResponse.setIssuer(issuer);
				artifactResponse.setMessage(samlResponse);
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the artifactResponse >======");
			artifactResponse = (ArtifactResponse) SamlTools.signSamlObject(artifactResponse);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the artifactResponse ======<");
			Envelope envelope = new SoapManager().buildSOAPMessage(artifactResponse);
			Element envelopeElem = SamlTools.marshallMessage(envelope);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Writing SOAP message:\n"
					+ XMLHelper.nodeToString(envelopeElem));
			// XMLHelper.prettyPrintXML(envelopeElem));

			// Bauke: added, it's considered polite to tell the other side what we are sending
			SamlTools.sendSOAPResponse(response, XMLHelper.nodeToString(envelopeElem));
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return null;
	}

	/**
	 * Gets the node.
	 * 
	 * @param node
	 *            the node
	 * @param sSearch
	 *            the s search
	 * @return the node
	 */
	private Node getNode(Node node, String sSearch)
	{
		Node nResult = null;
		NodeList nodeList = node.getChildNodes();
		for (int i = 0; i < nodeList.getLength() && nResult == null; i++) {
			if (sSearch.equals(nodeList.item(i).getLocalName()))
				nResult = nodeList.item(i);
			else
				nResult = getNode(nodeList.item(i), sSearch);
		}
		return nResult;
	}

	/**
	 * /** Contructs an errorResponse:
	 * 
	 * <pre>
	 * &lt;ArtifactResponse
	 * ID=&quot;RTXXcU5moVW3OZcvnxVoc&quot;
	 * InResponseTo=&quot;&quot;
	 * Version=&quot;2.0&quot;
	 * IssueInstant=&quot;2007-08-13T11:29:11Z&quot;
	 * Destination=&quot;&quot;&gt;
	 * &lt;Status&gt;
	 * &lt;StatusCode
	 * Value=&quot;urn:oasis:names:tc:SAML:2.0:status:Requester&quot;&gt;
	 * &lt;StatusCode
	 * Value=&quot;urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue&quot;/&gt;
	 * &lt;/StatusCode&gt;
	 * &lt;StatusMessage&gt;No ProviderName attribute found in element AuthnRequest of SAML message&lt;/StatusMessage&gt;
	 * &lt;/Status&gt;
	 * &lt;/ArtifactResponse&gt;
	 * </pre>
	 * 
	 * @param sInResponseTo
	 *            the s in response to
	 * @param sDestination
	 *            the s destination
	 * @param sSecLevelstatusCode
	 *            the s sec levelstatus code
	 * @param sStatusMessage
	 *            the s status message
	 * @return the artifact response
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
	private ArtifactResponse errorResponse(String sInResponseTo, String sDestination, String sSecLevelstatusCode,
			String sStatusMessage)
		throws ASelectException
	{
		String sMethod = "errorResponse()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) _oBuilderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode secLevelStatusCode = statusCodeBuilder.buildObject();
		secLevelStatusCode.setValue(sSecLevelstatusCode);

		StatusCode topLevelstatusCode = statusCodeBuilder.buildObject();
		topLevelstatusCode.setValue(StatusCode.REQUESTER_URI);
		topLevelstatusCode.setStatusCode(secLevelStatusCode);

		SAMLObjectBuilder<StatusMessage> statusMessagebuilder = (SAMLObjectBuilder<StatusMessage>) _oBuilderFactory
				.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
		StatusMessage statusMessage = statusMessagebuilder.buildObject();
		statusMessage.setMessage(sStatusMessage);

		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) _oBuilderFactory
				.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status status = statusBuilder.buildObject();
		status.setStatusCode(topLevelstatusCode);
		status.setStatusMessage(statusMessage);

		SAMLObjectBuilder<ArtifactResponse> artifactResponseBuilder = (SAMLObjectBuilder<ArtifactResponse>) _oBuilderFactory
				.getBuilder(ArtifactResponse.DEFAULT_ELEMENT_NAME);
		ArtifactResponse artifactResponse = artifactResponseBuilder.buildObject();

		artifactResponse.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
		artifactResponse.setInResponseTo(sInResponseTo);
		artifactResponse.setVersion(SAMLVersion.VERSION_20);
		artifactResponse.setIssueInstant(new DateTime());
		if (sDestination != null)
			artifactResponse.setDestination(sDestination);
		artifactResponse.setMessage(status);
		return null;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	@Override
	public void destroy()
	{
		String sMethod = "destroy()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");
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
}
