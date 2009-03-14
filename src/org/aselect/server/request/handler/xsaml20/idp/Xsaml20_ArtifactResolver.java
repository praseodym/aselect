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
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.ws.soap.soap11.Envelope;
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
 * The SAML2.0 ArtifactResolver for the A-Select Server (Identity Provider
 * side).<br/> SOAP message containing a SAML ArtifactResolve.<br/> <br/> The
 * Response message coupled to the artifact is returned as a SOAP message with a
 * SAML ArtifactResponse. <br>
 * 
 * @author Atos Origin
 */
//public class Xsaml20_ArtifactResolver extends ProtoRequestHandler  // RH, 20080602, o
public class Xsaml20_ArtifactResolver extends Saml20_BaseHandler  // RH, 20080602, n
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
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		super.init(oServletConfig, oHandlerConfig);

		// RH, 20080602, so, is done by Saml20_BaseHandler now        
//		try {
//			DefaultBootstrap.bootstrap();
			// RH, 20080602, eo, is done by Saml20_BaseHandler now        

			_oBuilderFactory = Configuration.getBuilderFactory();
			// RH, 20080602, so, is done by Saml20_BaseHandler now        

//		}
//		catch (ConfigurationException e) {
//			_systemLogger
//					.log(Level.WARNING, MODULE, sMethod, "There is a problem initializing the OpenSAML library", e);
//			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
//		}
		// RH, 20080602, eo, is done by Saml20_BaseHandler now        

		_sEntityId = _configManager.getRedirectURL();
	}

	/**
	 * Resolve Artifact. <br>
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @throws ASelectException
	 *             If resolving off artifact fails.
	 */
	@SuppressWarnings("unchecked")
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, request.getContentType());

		try {
			MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
//			ServletInputStream input = request.getInputStream();
//			BufferedInputStream bis = new BufferedInputStream(input);
//			ByteArrayOutputStream bos = new ByteArrayOutputStream();  // RH, 20080714, n

			/*
			int xRead = 0;
			byte[] ba = new byte[512];
			DataInputStream isInput = null;
			isInput = new DataInputStream(request.getInputStream());
			while ((xRead = isInput.read(ba)) != -1) {
				// append to stringbuffer
				//sb.append(new String(ba, 0, xRead)); // RH, 20080714, o
				bos.write(ba, 0, xRead); // RH, 20080714, n
				// clear the buffer
				Arrays.fill(ba, (byte) 0);
				
			} 
			 */
			/*
			char b = (char) bis.read();
			StringBuffer sb = new StringBuffer();
			sb.append(b);
			while (bis.available() != 0) {
				b = (char) bis.read();
				sb.append(b);
			}
			String sReceivedSoap = sb.toString();
			*/
			String sReceivedSoap = Tools.stream2string(request.getInputStream()); // RH, 20080715, n
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received Soap:\n" + sReceivedSoap);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(sReceivedSoap);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			//_systemLogger.log(Level.INFO, MODULE, sMethod, "SOAP message:\n"
			//		+ XMLHelper.prettyPrintXML(elementReceivedSoap));

			// Remove all SOAP elements
			Node eltArtifactResolve = getNode(elementReceivedSoap, "ArtifactResolve");

			//_systemLogger.log(Level.INFO, MODULE, sMethod, "ArtifactResolve:\n"
			//		+ XMLHelper.nodeToString(eltArtifactResolve));

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);

			ArtifactResolve artifactResolve = (ArtifactResolve) unmarshaller.unmarshall((Element) eltArtifactResolve);
			String sReceivedArtifact = artifactResolve.getArtifact().getArtifact();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received artifact: " + sReceivedArtifact);

			String artifactResolveIssuer = ( artifactResolve.getIssuer() == null || 						// avoid nullpointers
					artifactResolve.getIssuer().getValue() == null ||
					"".equals(artifactResolve.getIssuer().getValue()) ) ? null :
						artifactResolve.getIssuer().getValue();	// else value from message
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do artifactResolve signature verification=" + is_bVerifySignature());
			if (is_bVerifySignature()) {
				// check signature of artifactResolve here
				// We get the public key from the metadata
				// Therefore we need a valid Issuer to lookup the entityID in the metadata
				// We get the metadataURL from aselect.xml so we consider this safe and authentic
				if (artifactResolveIssuer == null || "".equals(artifactResolveIssuer)) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "For signature verification the received message must have an Issuer");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				PublicKey pkey = metadataManager.getSigningKey(artifactResolveIssuer);
				if (pkey == null || "".equals(pkey)) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No public valid key in metadata");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				if (checkSignature(artifactResolve, pkey )) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "artifactResolve was signed OK");
				} else {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "artifactResolve was NOT signed OK");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
			}

			
			String sInResponseTo = artifactResolve.getID(); // Is required in SAMLsyntax
			// String sDestination = request.getRequestURL().toString();
			String sDestination = "Destination unknown";
			// RH, 20080602, sn
			// resolveIssuer is not used any further
//			Issuer resolveIssuer = artifactResolve.getIssuer();
//			if (resolveIssuer != null) {
//				sDestination = resolveIssuer.getValue();
//			}
			// RH, 20080602, en

			ArtifactResponse artifactResponse = null;
			if (sReceivedArtifact == null || "".equals(sReceivedArtifact)) {
				String sStatusCode = StatusCode.INVALID_ATTR_NAME_VALUE_URI;
				String sStatusMessage = "No 'artifact' found in element 'ArtifactResolve' of SAMLMessage.";
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sStatusMessage);
				artifactResponse = errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
			}
			else {
				Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
//				StatusResponseType samlResponse = (StatusResponseType) artifactManager
//				.getArtifactFromStorage(sReceivedArtifact);
				Response samlResponse = (Response) artifactManager.getArtifactFromStorage(sReceivedArtifact);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "samlResponse retrieved from storage:\n" + XMLHelper.nodeToString(samlResponse.getDOM()));

				// We will not allow to use the artifact again
				artifactManager.remove(sReceivedArtifact);	// RH, 20081113, n

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
				artifactResponse.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
				artifactResponse.setInResponseTo(sInResponseTo);
				artifactResponse.setVersion(SAMLVersion.VERSION_20);
				artifactResponse.setIssueInstant(new DateTime());
				artifactResponse.setDestination(sDestination);
				artifactResponse.setStatus(status);
				artifactResponse.setIssuer(issuer);
				artifactResponse.setMessage(samlResponse);
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the artifactResponse >======" );
//			artifactResponse = (ArtifactResponse)sign(artifactResponse);
			artifactResponse = (ArtifactResponse)SamlTools.sign(artifactResponse);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the artifactResponse ======<" );
			Envelope envelope = new SoapManager().buildSOAPMessage(artifactResponse);
			Element envelopeElem = SamlTools.marshallMessage(envelope);
			//_systemLogger.log(Level.INFO, MODULE, sMethod, "Writing SOAP message to response:\n"
			//		+ XMLHelper.prettyPrintXML(envelopeElem));

			// Bauke: added, it's considered polite to tell the other side what we are sending
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "Send: ContentType: "+CONTENT_TYPE);
			// Remy: 20081113: Move this code to HandlerTools for uniformity
			SamlTools.sendSOAPResponse(response, XMLHelper.nodeToString(envelopeElem));
			// RH, 20081113, so
//			response.setContentType(CONTENT_TYPE);			
//			ServletOutputStream sos = response.getOutputStream();
//			sos.print(XMLHelper.nodeToString(envelopeElem));
//			sos.println("\r\n\r\n");
//			sos.close();
			// RH, 20081113, eo
			

		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return null;
	}

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
	 *             &lt;ArtifactResponse 
	 *                ID=&quot;RTXXcU5moVW3OZcvnxVoc&quot; 
	 *                InResponseTo=&quot;&quot;
	 *                Version=&quot;2.0&quot;
	 *                IssueInstant=&quot;2007-08-13T11:29:11Z&quot;
	 *                Destination=&quot;&quot;&gt;
	 *                &lt;Status&gt;
	 *                    &lt;StatusCode
	 *                        Value=&quot;urn:oasis:names:tc:SAML:2.0:status:Requester&quot;&gt;
	 *                        &lt;StatusCode
	 *                            Value=&quot;urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue&quot;/&gt;
	 *                    &lt;/StatusCode&gt;             
	 *                    &lt;StatusMessage&gt;No ProviderName attribute found in element AuthnRequest of SAML message&lt;/StatusMessage&gt;
	 *                &lt;/Status&gt;
	 *             &lt;/ArtifactResponse&gt;
	 * </pre>
	 * 
	 * @param sInResponseTo
	 * @param sDestination
	 * @param sSecLevelstatusCode
	 * @param sStatusMessage
	 * @return
	 * @throws ASelectException
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
		artifactResponse.setDestination(sDestination);
		artifactResponse.setMessage(status);
		return null;
	}

	public void destroy()
	{
		String sMethod = "destroy()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");
	}

	public synchronized boolean isSigningRequired() {
		return signingRequired;
	}

	public synchronized void setSigningRequired(boolean signingRequired) {
		this.signingRequired = signingRequired;
	}
}
