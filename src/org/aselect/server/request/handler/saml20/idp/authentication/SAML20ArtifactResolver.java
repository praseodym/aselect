package org.aselect.server.request.handler.saml20.idp.authentication;

import java.io.BufferedInputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml20.common.NodeHelper;
import org.aselect.server.request.handler.saml20.common.SOAPManager;
import org.aselect.server.request.handler.saml20.common.Utils;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

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
public class SAML20ArtifactResolver extends AbstractRequestHandler
{
	private final static String MODULE = "SAML20ArtifactResolver";

	private XMLObjectBuilderFactory _oBuilderFactory;

	private String _sEntityId;

	private static final String CONTENT_TYPE = "text/xml; charset=utf-8";

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

		try {
			DefaultBootstrap.bootstrap();
			_oBuilderFactory = Configuration.getBuilderFactory();
		}
		catch (ConfigurationException e) {
			_systemLogger
					.log(Level.WARNING, MODULE, sMethod, "There is a problem initializing the OpenSAML library", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
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
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============# "+request.getContentType());

		try {
			ServletInputStream input = request.getInputStream();
			BufferedInputStream bis = new BufferedInputStream(input);
			char b = (char) bis.read();
			StringBuffer sb = new StringBuffer();
			sb.append(b);
			while (bis.available() != 0) {
				/* >>OUA-7 */
				b = (char) bis.read();
				sb.append(b);
				/* OUA-7<< */
			}
			String sReceivedSoap = sb.toString();
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

			String sInResponseTo = artifactResolve.getID(); // Is required
			// in SAMLsyntax
			// String sDestination = request.getRequestURL().toString();
			String sDestination = "Destination unknown";
			Issuer resolveIssuer = artifactResolve.getIssuer();
			if (resolveIssuer != null) {
				sDestination = resolveIssuer.getValue();
			}

			ArtifactResponse artifactResponse = null;
			if (sReceivedArtifact == null || "".equals(sReceivedArtifact)) {
				String sStatusCode = StatusCode.INVALID_ATTR_NAME_VALUE_URI;
				String sStatusMessage = "No 'artifact' found in element 'ArtifactResolve' of SAMLMessage.";
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sStatusMessage);
				artifactResponse = errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
			}

			if (artifactResponse == null) {
				SAML20ArtifactManager artifactManager = SAML20ArtifactManagerLocator.getArtifactManager();
				StatusResponseType samlResponse = (StatusResponseType) artifactManager
						.getArtifactFromStorage(sReceivedArtifact);

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
				artifactResponse.setID(Utils.generateIdentifier(_systemLogger, MODULE));
				artifactResponse.setInResponseTo(sInResponseTo);
				artifactResponse.setVersion(SAMLVersion.VERSION_20);
				artifactResponse.setIssueInstant(new DateTime());
				artifactResponse.setDestination(sDestination);
				artifactResponse.setStatus(status);
				artifactResponse.setIssuer(issuer);
				artifactResponse.setMessage(samlResponse);
			}

			Envelope envelope = new SOAPManager().buildSOAPMessage(artifactResponse);
			NodeHelper nodeHelper = new NodeHelper();
			Element envelopeElem = nodeHelper.marshallMessage(envelope);
			//_systemLogger.log(Level.INFO, MODULE, sMethod, "Writing SOAP message to response:\n"
			//		+ XMLHelper.prettyPrintXML(envelopeElem));

			// Bauke: added, it's polite to tell the other side what we are sending
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Send: ContentType: "+CONTENT_TYPE);
			response.setContentType(CONTENT_TYPE);
			
			PrintWriter pwOut = response.getWriter();
			pwOut.write(XMLHelper.nodeToString(envelopeElem));

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

		artifactResponse.setID(Utils.generateIdentifier(_systemLogger, MODULE));
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

}
