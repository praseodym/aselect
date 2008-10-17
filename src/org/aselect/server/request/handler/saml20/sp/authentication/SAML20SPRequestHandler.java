package org.aselect.server.request.handler.saml20.sp.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml20.common.Utils;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Node;

/**
 * SAML2.0 interface for A-Select (Service Provider side). <br>
 * <br>
 * <b>Description:</b><br>
 * The SAML2.0 interface for the A-Select Server (Service Provider side).<br/>
 * HTTP GET containing the following items in the querystring<br/>
 * <ul>
 * <li><b>interrupt</b> - The trigger for this handler</li>
 * <li><b>rid</b> - The request identifier of the A-Select server (Service
 * Provider side)</li>
 * </ul>
 * <br>
 * 
 * @author Atos Origin
 * 
 */
public class SAML20SPRequestHandler extends AbstractRequestHandler
{
	private final static String MODULE = "SAML20SPRequestHandler";

	private String _sAppId; // The value of <server_id> in the <aselect>

	// section

	private String _sFederationUrl;

	private HashMap<String, String> levelMap;

	/**
	 * Initializes the request handler by reading the following
	 * configuration: <br/><br/>
	 * 
	 * <pre>
	 *                       &lt;aselect&gt;
	 *                         &lt;server_id&gt;[_sAppId]&lt;/server_id&gt;
	 *                       &lt;/aselect&gt;
	 *                       
	 *                       &lt;handler&gt;
	 *                         &lt;server_url&gt;[_sASelectServerUrl]&lt;/server_url&gt;
	 *                       &lt;/handler&gt;
	 * </pre>
	 * 
	 * <ul>
	 * <li><b>server_id</b> - The id of <b>this</b> (SP) A-Select Server</li>
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
			_sAppId = _configManager.getParam(oASelect, "server_id");
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
		levelMap = new HashMap<String, String>();
		Object oAuthnContextClassRef = null;
		try {
			oAuthnContextClassRef = _configManager.getSection(oHandlerConfig, "AuthnContextClassRef");
			String sLevel = _configManager.getParam(oAuthnContextClassRef, "level");
			String sAuthnContextClassRef = _configManager.getParam(oAuthnContextClassRef, "AuthnContextClassRef");
			levelMap.put(sLevel, sAuthnContextClassRef);

			oAuthnContextClassRef = _configManager.getNextSection(oAuthnContextClassRef);
			while (oAuthnContextClassRef != null) {
				sLevel = _configManager.getParam(oAuthnContextClassRef, "level");
				sAuthnContextClassRef = _configManager.getParam(oAuthnContextClassRef, "AuthnContextClassRef");
				levelMap.put(sLevel, sAuthnContextClassRef);
				oAuthnContextClassRef = _configManager.getNextSection(oAuthnContextClassRef);
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'AuthnContextClassRef' found in handler section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

	}

	/**
	 * Processes the following request:<br/>
	 * <code>?request=interrupt&rid=[rid]</code><br/> <br/><br/> During
	 * processing a SAML2.0 message is constructed: <br/><br/>
	 * 
	 * <pre>
	 *                        &lt;sp:AuthnRequest
	 *                           xmlns:sp=&quot;urn:oasis:names:tc:SAML:2.0:protocol&quot;
	 *                           AssertionConsumerServiceURL=&quot;{sAppUrl}&quot;
	 *                           Destination=&quot;{sASelectServerUrl}&quot;
	 *                           ID=&quot;{sRid}&quot;
	 *                           IssueInstant=&quot;2007-08-13T11:29:11Z&quot;
	 *                           ProviderName=&quot;{sAppId}&quot;
	 *                           Version=&quot;2.0&quot;&gt;
	 *                           &lt;saml:Issuer xmlns:saml=&quot;urn:oasis:names:tc:SAML:2.0:assertion&quot;&gt;
	 *                               http://localhost:8080/aselect_sp/server&lt;/saml:Issuer&gt;
	 *                        &lt;/sp:AuthnRequest&gt;
	 * </pre>
	 * 
	 * During processing, the following steps are runned through:
	 * <ul>
	 * <li>checking validity of the request parameters</li>
	 * <li>creates a SAML AutnRequest message</li>
	 * <li>redirects the user to the A-Select Server</li>
	 * </ul>
	 * <br>
	 * <br>
	 * 
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#process(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@SuppressWarnings("unchecked")
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		String sRid; // The rid from this server
		sRid = request.getParameter("rid");
		// >>>>#OUA-23
		if (sRid == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing RID parameter");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		// <<<<#OUA-23
		String sAppId; // The Id from this application/server
		sAppId = _sAppId;
		String sAppUrl; // The url from this application/server
		sAppUrl = request.getRequestURL().toString();
		String sASelectServerUrl; // The url for the requested A-Select Server
		sASelectServerUrl = _sFederationUrl;

		CrossASelectManager oCrossASelectManager = CrossASelectManager.getHandle();
		// Gets from organization key/value = id/friendforced_ly_name
		Hashtable htRemoteServers = oCrossASelectManager.getRemoteServers();
		Enumeration enRemoteOrganizationIds = htRemoteServers.keys();
		String sRemoteOrganization = (String) enRemoteOrganizationIds.nextElement();

		Hashtable htSessionContext = _oSessionManager.getSessionContext(sRid);
		_systemLogger.log(Level.WARNING, MODULE, sMethod, "SessionContext " + htSessionContext);

		// >>>>#OUA-23
		if (htSessionContext == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid RID: " + sRid);
			PrintWriter pwOut;
			try {
				pwOut = response.getWriter();
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "IO Exception", e);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
			}
			showErrorPage(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST, pwOut);
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
			return null;
		}
		// <<<<#OUA-23
		htSessionContext.put("remote_organization", sRemoteOrganization);
		_oSessionManager.updateSession(sRid, htSessionContext);

		String sApplicationId = (String) htSessionContext.get("app_id");
		String sApplicationLevel = getApplicationLevel(sApplicationId);
		String sAuthnContextClassRefURI = levelMap.get(sApplicationLevel);
		if (sAuthnContextClassRefURI == null) {
			// this level was not configured. Log it and inform the user
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Application Level " + sApplicationLevel
					+ " is not configured for this Service Provider.");
			PrintWriter pwOut;
			try {
				pwOut = response.getWriter();
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "IO Exception", e);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
			}
			showErrorPage(Errors.ERROR_ASELECT_SERVER_INVALID_APP_LEVEL, pwOut);
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
			return null;
		}
		try {
			XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

			SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
					.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();

			authnContextClassRef.setAuthnContextClassRef(sAuthnContextClassRefURI);

			SAMLObjectBuilder<RequestedAuthnContext> requestedAuthnContextBuilder = (SAMLObjectBuilder<RequestedAuthnContext>) builderFactory
					.getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
			RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
			requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
			requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

			SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer issuer = issuerBuilder.buildObject();
			issuer.setValue(sAppUrl);

			SAMLObjectBuilder<AuthnRequest> authnRequestbuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
					.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
			AuthnRequest authnRequest = authnRequestbuilder.buildObject();
			authnRequest.setAssertionConsumerServiceURL(sAppUrl);
			authnRequest.setDestination(sASelectServerUrl);
			authnRequest.setID(sRid);
			authnRequest.setIssueInstant(new DateTime());
			authnRequest.setProviderName(sAppId);
			authnRequest.setVersion(SAMLVersion.VERSION_20);
			authnRequest.setIssuer(issuer);
			authnRequest.setRequestedAuthnContext(requestedAuthnContext);

			SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
					.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
			Endpoint samlEndpoint = endpointBuilder.buildObject();
			samlEndpoint.setLocation(sASelectServerUrl);
			samlEndpoint.setResponseLocation(sAppUrl);

//			HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response); // RH 20080529, o
			HttpServletResponseAdapter outTransport = SamlTools.createHttpServletResponseAdapter(response, sASelectServerUrl); // RH 20080529, n

			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setOutboundMessageTransport(outTransport);
			messageContext.setOutboundSAMLMessage(authnRequest);
			messageContext.setPeerEntityEndpoint(samlEndpoint);
			messageContext.setRelayState("relay");

			BasicX509Credential credential = new BasicX509Credential();
			PrivateKey key = _configManager.getDefaultPrivateKey();
			credential.setPrivateKey(key);
			messageContext.setOutboundSAMLMessageSigningCredential(credential);

			MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(messageContext.getOutboundSAMLMessage());
			Node nodeMessageContext = marshaller.marshall(messageContext.getOutboundSAMLMessage());
			_systemLogger.log(Level.INFO, MODULE, sMethod, "MessageContext:\n"
					+ XMLHelper.prettyPrintXML(nodeMessageContext));

			HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
			encoder.encode(messageContext);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Ready");
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return null;
	}

	private String getApplicationLevel(String sApplicationId)
		throws ASelectException
	{
		String sMethod = "getApplicationLevel()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");
		Object oApplications = null;
		try {
			oApplications = _configManager.getSection(null, "applications");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'applications' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		Object oApplication = null;
		try {
			oApplication = _configManager.getSection(oApplications, "application");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'application' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		String sApplicationLevel = null;
		while (oApplication != null) {
			if (_configManager.getParam(oApplication, "id").equals(sApplicationId)) {
				sApplicationLevel = _configManager.getParam(oApplication, "level");
				if (sApplicationLevel == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config attribute 'level' found");
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}
				return sApplicationLevel;
			}
			oApplication = _configManager.getNextSection(oApplication);
		}
		return null;
	}

	public void destroy()
	{
		String sMethod = "destroy()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");
	}

	/**
	 * Shows the main A-Select Error page with the approprate errors. <br>
	 * <br>
	 * 
	 * @param sErrorCode
	 * @param htServiceRequest
	 * @param pwOut
	 */
	protected void showErrorPage(String sErrorCode, PrintWriter pwOut)
	{
		String sMethod = "showErrorPage()";
		try {
			String sErrorForm = _configManager.getForm("error");
			sErrorForm = org.aselect.system.utils.Utils.replaceString(sErrorForm, "[error]", sErrorCode);
			sErrorForm = org.aselect.system.utils.Utils.replaceString(sErrorForm, "[error_message]", _configManager
					.getErrorMessage(sErrorCode));

			Hashtable htSession = null;
			sErrorForm = _configManager.updateTemplate(sErrorForm, htSession);

			pwOut.println(sErrorForm);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not show error page with error: " + sErrorCode, e);
		}
	}
}
