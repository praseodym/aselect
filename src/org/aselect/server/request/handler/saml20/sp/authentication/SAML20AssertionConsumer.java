package org.aselect.server.request.handler.saml20.sp.authentication;

import java.io.StringReader;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml20.common.NodeHelper;
import org.aselect.server.request.handler.saml20.common.SOAPManager;
import org.aselect.server.request.handler.saml20.sp.metadata.MetaDataManagerSP;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.tgt.saml20.SpTGTIssuer;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Utils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

/**
 * SAML2.0 AssertionConsumer for A-Select (Service Provider side). <br>
 * <br>
 * <b>Description:</b><br>
 * The SAML2.0 AssertionConsumer for the A-Select Server (Service Provider
 * side).<br/> HTTP GET containing the following items in the querystring<br/>
 * <ul>
 * <li><b>SAMLart</b> - The SAML2.0 artifact</li>
 * </ul>
 * The SAML2.0 artifact is resolved by the requesters ArtifactResolver. The
 * resolved artifact contains a SAML2.0 Response which is futher handled by this
 * A-Select server. <br>
 * 
 * @author Atos Origin
 */
public class SAML20AssertionConsumer extends AbstractRequestHandler
{
	private final static String MODULE = "SAML20AssertionConsumer";

	private XMLObjectBuilderFactory _oBuilderFactory;

	private ASelectAuthenticationLogger _authenticationLogger;

	protected TGTManager _tgtManager;

	private String _sMyServerId;

	private String _sFederationUrl;

	/**
	 * Initializes the request handler by reading the following configuration:
	 * <br/><br/>
	 * 
	 * <pre>
	 *                       &lt;handler&gt;
	 *                         &lt;server_url&gt;[server_url]&lt;/server_url&gt;
	 *                       &lt;/handler&gt;
	 * </pre>
	 * 
	 * <ul>
	 * <li><b>server_url</b> - The url of the IDP A-Select Server</li>
	 * </ul>
	 * <br>
	 * <br>
	 * 
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig,
	 *      java.lang.Object)
	 */
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		super.init(oServletConfig, oHandlerConfig);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		try {
			DefaultBootstrap.bootstrap();
			_oBuilderFactory = Configuration.getBuilderFactory();
		}
		catch (ConfigurationException e) {
			_systemLogger
					.log(Level.WARNING, MODULE, sMethod, "There is a problem initializing the OpenSAML library", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		Object oASelect = null;
		try {
			oASelect = _configManager.getSection(null, "aselect");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'aselect' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		try {
			_sMyServerId = _configManager.getParam(oASelect, "server_id");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'server_id' found in 'aselect' section",
					e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		try {
			_sFederationUrl = _configManager.getParam(oASelect, "federation_url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'federation_url' found in 'aselect' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
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
	 * @throws ASelectException
	 *             If ??? fails.
	 */
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
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Received artifact: " + sReceivedArtifact);

		try {
			// use metadata
			MetaDataManagerSP metadataManager = MetaDataManagerSP.getHandle();
			String sASelectServerUrl = metadataManager.getLocation(_sFederationUrl,
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
			SecureRandomIdentifierGenerator idGenerator = null;
			try {
				idGenerator = new SecureRandomIdentifierGenerator();
			}
			catch (NoSuchAlgorithmException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "The SHA1PRNG algorithm is not supported by the JVM",
						e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			artifactResolve.setID(idGenerator.generateIdentifier());
			artifactResolve.setVersion(SAMLVersion.VERSION_20);
			artifactResolve.setIssueInstant(new DateTime());
			artifactResolve.setArtifact(artifact);

			// Build the SOAP message
			SOAPManager soapManager = new SOAPManager();
			Envelope envelope = soapManager.buildSOAPMessage(artifactResolve);
			NodeHelper nodeHelper = new NodeHelper();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Marshall");
			Element envelopeElem = nodeHelper.marshallMessage(envelope);
			//_systemLogger.log(Level.INFO, MODULE, sMethod, "Writing SOAP message to response:\n"
			//		+ XMLHelper.prettyPrintXML(envelopeElem));

			// Send/Receive the SOAP message
			String sSamlResponse = soapManager.sendSOAP(XMLHelper.nodeToString(envelopeElem), sASelectServerUrl);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received response: " + sSamlResponse);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(sSamlResponse);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			//_systemLogger.log(Level.INFO, MODULE, sMethod, "SOAP message:\n"
			//		+ XMLHelper.prettyPrintXML(elementReceivedSoap));

			// Remove all SOAP elements
			Node eltArtifactResponse = nodeHelper.getNode(elementReceivedSoap, "ArtifactResponse");

			//_systemLogger.log(Level.INFO, MODULE, sMethod, "ArtifactResponse:\n"
			//		+ XMLHelper.nodeToString(eltArtifactResponse));

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResponse);

			ArtifactResponse artifactResponse = (ArtifactResponse) unmarshaller
					.unmarshall((Element) eltArtifactResponse);

			Object samlResponseObject = artifactResponse.getMessage();
			// object kan een Response zijn of een StatusResponseType in het
			// geval van resp. SSO of SLO
			if (samlResponseObject instanceof Response) {
				// SSO
				Response samlResponse = (Response) samlResponseObject;
				//_systemLogger.log(Level.INFO, MODULE, sMethod, "Received: \n"
				//		+ XMLHelper.prettyPrintXML(samlResponse.getDOM()));
				// Detect if this is a successful or an error Response
				if (samlResponse.getStatus().getStatusCode().getValue().equals(StatusCode.SUCCESS_URI)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Response was successful");
					String sOrganization = samlResponse.getAssertions().get(0).getIssuer().getValue();
					String sUid = samlResponse.getAssertions().get(0).getSubject().getNameID().getValue();
					String sRemoteRid = samlResponse.getID();
					String sLocalRid = samlResponse.getInResponseTo();
					String sAuthnContextClassRefURI = samlResponse.getAssertions().get(0).getAuthnStatements().get(0)
							.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef();
					String sAuthSpLevel = org.aselect.server.request.handler.saml20.common.Utils
							.convertAuthnContextClassRefURIToLevel(sAuthnContextClassRefURI, _systemLogger, MODULE);

					Hashtable htRemoteAttributes = new Hashtable();
					htRemoteAttributes.put("organization", sOrganization);
					htRemoteAttributes.put("uid", sUid);
					htRemoteAttributes.put("remote_rid", sRemoteRid);
					htRemoteAttributes.put("local_rid", sLocalRid);

					htRemoteAttributes.put("authsp_level", sAuthSpLevel);
					htRemoteAttributes.put("authsp", sOrganization);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "htRemoteAttributes="+htRemoteAttributes);

					handleSSOResponse(htRemoteAttributes, request, response);
				}
				else
				// not successful
				{
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Response was not successful");
					throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
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

	public void destroy()
	{
		String sMethod = "destroy()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");
	}

	private void handleSSOResponse(Hashtable htRemoteAttributes, HttpServletRequest servletRequest,
			HttpServletResponse servletResponse)
		throws ASelectException
	{
		String sMethod = "handleSSOResponse()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		try {
			String sRemoteRid = null;
			String sLocalRid = null;
			// String sCredentials = null;
			Hashtable htSessionContext;

			Hashtable htServiceRequest = createServiceRequest(servletRequest);

			// check parameters
			sRemoteRid = (String) htRemoteAttributes.get("remote_rid");
			sLocalRid = (String) htRemoteAttributes.get("local_rid");
			// sCredentials = (String)
			// htServiceRequest.get("aselect_credentials");

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

			String sRemoteOrg = (String) htSessionContext.get("remote_organization");

			// for authentication logging
			String sOrg = (String) htRemoteAttributes.get("organization");
			if (!sRemoteOrg.equals(sOrg))
				sRemoteOrg = sOrg + "@" + sRemoteOrg;

			String sResultCode = (String) htRemoteAttributes.get("result_code");
			String sUID = (String) htRemoteAttributes.get("uid");
			if (sResultCode != null) {
				if (sResultCode.equals(Errors.ERROR_ASELECT_SERVER_CANCEL)) {
					_authenticationLogger.log(new Object[] {
						"Cross", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
						htSessionContext.get("app_id"), "denied", sResultCode
					});
					// Issue 'CANCEL' TGT
					SpTGTIssuer tgtIssuer = new SpTGTIssuer(_sMyServerId);
					tgtIssuer.issueErrorTGT(sLocalRid, sResultCode, servletResponse);
				}
				else {
					// remote server returned error
					_authenticationLogger.log(new Object[] {
						"Cross", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
						htSessionContext.get("app_id"), "denied", sResultCode
					});

					throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
				}
			}
			else {
				// Log succesful authentication
				_authenticationLogger.log(new Object[] {
					"Cross", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
					htSessionContext.get("app_id"), "granted"
				});

				// Issue a cross TGT since we do not know the AuthSP
				// and we might have received remote attributes.
				SpTGTIssuer oTGTIssuer = new SpTGTIssuer(_sMyServerId);
				String sOldTGT = (String) htServiceRequest.get("aselect_credentials_tgt");
				oTGTIssuer.issueCrossTGT(sLocalRid, null, htRemoteAttributes, servletResponse, sOldTGT);
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
	 * This function converts a <code>servletRequest</code> to a
	 * <code>Hashtable</code> by extracting the parameters from the
	 * <code>servletRequest</code> and inserting them into a
	 * <code>Hashtable</code>. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            Contains request parameters
	 * @return Hashtable containing request parameters.
	 */
	@SuppressWarnings("unchecked")
	private Hashtable createServiceRequest(HttpServletRequest servletRequest)
	{
		// Extract parameters into htServiceRequest
		Hashtable htServiceRequest = null;
		if (servletRequest.getMethod().equalsIgnoreCase("GET")) {
			htServiceRequest = Utils.convertCGIMessage(servletRequest.getQueryString());
		}
		else {
			htServiceRequest = new Hashtable();
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
		htServiceRequest.put("client_ip", servletRequest.getRemoteAddr());
		Hashtable htCredentials = getASelectCredentials(servletRequest);
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
	 * Reads the A-Select credentials from a Cookie and put them into a
	 * <code>Hashtable</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>servletRequest != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param servletRequest
	 *            The Request which should contain the Cookie.
	 * @return The A-Select credentials in a <code>Hashtable</code>.
	 */
	@SuppressWarnings("unchecked")
	protected Hashtable getASelectCredentials(HttpServletRequest servletRequest)
	{
		String sMethod = "getASelectCredentials";
		Hashtable htCredentials = new Hashtable();

		// check for credentials that might be present
		Cookie[] aCookies = servletRequest.getCookies();

		if (aCookies == null) {
			return null;
		}

		String sCredentialsCookie = null;

		for (int i = 0; i < aCookies.length; i++) {
			if (aCookies[i].getName().equals(SpTGTIssuer.COOKIE_NAME)) {
				sCredentialsCookie = aCookies[i].getValue();
				// remove '"' surrounding cookie if applicable
				int iLength = sCredentialsCookie.length();
				if (sCredentialsCookie.charAt(0) == '"' && sCredentialsCookie.charAt(iLength - 1) == '"') {
					sCredentialsCookie = sCredentialsCookie.substring(1, iLength - 1);
				}
			}
		}
		if (sCredentialsCookie == null) {
			return null;
		}

		Hashtable sCredentialsParams = Utils.convertCGIMessage(sCredentialsCookie);
		if (sCredentialsParams == null) {
			return null;
		}
		String sTgt = (String) sCredentialsParams.get("tgt");
		String sUserId = (String) sCredentialsParams.get("uid");
		String sServerId = (String) sCredentialsParams.get("a-select-server");
		if ((sTgt == null) || (sUserId == null) || (sServerId == null)) {
			return null;
		}
		if (!sServerId.equals(_sMyServerId)) {
			return null;
		}
		Hashtable htTGTContext = null;
		try {
			if (_tgtManager.containsKey(sTgt)) {
				htTGTContext = _tgtManager.getTGT(sTgt);
			}
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage());
		}
		if (htTGTContext == null) {
			return null;
		}
		if (!sUserId.equals(htTGTContext.get("uid"))) {
			return null;
		}

		htCredentials.put("aselect_credentials_tgt", sTgt);
		htCredentials.put("aselect_credentials_uid", sUserId);
		htCredentials.put("aselect_credentials_server_id", sServerId);
		return htCredentials;
	}

}
