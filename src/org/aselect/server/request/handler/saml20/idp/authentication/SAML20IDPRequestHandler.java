package org.aselect.server.request.handler.saml20.idp.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml20.common.LogoutRequestSender;
import org.aselect.server.request.handler.saml20.common.LogoutResponseSender;
import org.aselect.server.request.handler.saml20.common.SessionKeys;
import org.aselect.server.request.handler.saml20.common.SignatureUtil;
import org.aselect.server.request.handler.saml20.common.Utils;
import org.aselect.server.request.handler.saml20.idp.metadata.MetaDataManagerIDP;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.tgt.saml20.TGTIssuer;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.communication.client.soap11.SOAP11Communicator;
import org.aselect.system.communication.client.soap12.SOAP12Communicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.util.XMLHelper;

/**
 * SAML2.0 interface for A-Select (Identify Provider side). <br>
 * <br>
 * <b>Description:</b><br>
 * The SAML2.0 interface for the A-Select Server (Identity Provider side).<br/>
 * HTTP GET containing the following items in the querystring<br/>
 * <ul>
 * <li><b>SAMLRequest</b> - The SAML2.0 request (encoded)</li>
 * </ul>
 * <br>
 * 
 * @author Atos Origin
 */
public class SAML20IDPRequestHandler extends AbstractRequestHandler
{
	private final String AUTHNREQUEST = "AuthnRequest";

	private final String LOGOUTREQUEST = "LogoutRequest";

	private final static String MODULE = "SAML20IDPRequestHandler";

	private IClientCommunicator _oClientCommunicator;

	private String _sAppId; // The value of <server_id> in the <aselect> section

	private String _sAppOrg; // The value of <organization> in the <aselect> section

	private String _sASelectServerUrl; // The value of <server_url> in the <aselect> section

	private RequestHandlerFactory _oRequestHandlerFactory;

	private XMLObjectBuilderFactory _oBuilderFactory;

	private boolean _bVerifySignature = true;

	private int _iRedirectLogoutTimeout = 30;

	private boolean _bTryRedirectLogoutFirst = true;

	/**
	 * Initializes the request handler by reading the following configuration:
	 * <br/><br/>
	 * 
	 * <pre>
	 *                   &lt;aselect&gt;
	 *                     &lt;server_id&gt;[_sAppId]&lt;/server_id&gt;
	 *                     &lt;organization&gt;[_sAppOrg]&lt;/organization&gt;
	 *                   &lt;/aselect&gt;
	 *                                                                 
	 *                   &lt;handler&gt;
	 *                     &lt;server_id&gt;[_sASelectServerId]&lt;/server_id&gt;
	 *                     &lt;server_url&gt;[_sASelectServerUrl]&lt;/server_url&gt;
	 *                     &lt;clientcommunicator&gt;[_oClientCommunicator]&lt;/clientcommunicator&gt;
	 *                   &lt;/handler&gt;
	 * </pre>
	 * 
	 * <ul>
	 * <li><b>_sAppId</b> - The id of <b>this</b> (IDP) A-Select Server</li>
	 * <li><b>_sAppOrg</b> - The organization of <b>this</b> (IDP) A-Select
	 * Server</li>
	 * <li><b>_sASelectServerId</b> - The id of the IDP A-Select Server</li>
	 * <li><b>_sASelectServerUrl</b> - The url of the IDP A-Select Server</li>
	 * <li><b>_oClientCommunicator</b> - The ClientCommunicator</li>
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

		try {
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException e) {
			_systemLogger
					.log(Level.WARNING, MODULE, sMethod, "There is a problem initializing the OpenSAML library", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		_oBuilderFactory = Configuration.getBuilderFactory();

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
			_sAppOrg = _configManager.getParam(oASelect, "organization");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not retrieve 'organization' config parameter in 'aselect' config section", e);
			throw e;
		}

		_oRequestHandlerFactory = RequestHandlerFactory.getHandle();
		_oRequestHandlerFactory.init(_sAppId, _sAppOrg);

		try {
			_sASelectServerUrl = _configManager.getParam(oASelect, "redirect_url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_url' found in 'aselect' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		try {
			_bTryRedirectLogoutFirst = new Boolean(_configManager.getParam(oHandlerConfig, "try_redirect_logout_first"))
					.booleanValue();
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'try_redirect_logout_first' found in 'handler' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		try {
			_iRedirectLogoutTimeout = new Integer(_configManager.getParam(oHandlerConfig, "redirect_logout_timeout"))
					.intValue();
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_logout_timeout' found in 'handler' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		String sClientCommunicator = null;
		try {
			sClientCommunicator = _configManager.getParam(oHandlerConfig, "clientcommunicator");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'clientcommunicator' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		if (sClientCommunicator == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'clientcommunicator' found");
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}

		if (sClientCommunicator.equalsIgnoreCase("soap11")) {
			_oClientCommunicator = new SOAP11Communicator("ASelect", _systemLogger);
		}
		else if (sClientCommunicator.equalsIgnoreCase("soap12")) {
			_oClientCommunicator = new SOAP12Communicator("ASelect", _systemLogger);
		}
		else if (sClientCommunicator.equalsIgnoreCase("raw")) {
			_oClientCommunicator = new RawCommunicator(_systemLogger);
		}
		String sVerifySignature = null;
		try {
			sVerifySignature = _configManager.getParam(oHandlerConfig, "verify_signature");
		}
		catch (Exception e) {
			if (sVerifySignature != null) {
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		if (sVerifySignature != null && sVerifySignature.equalsIgnoreCase("false")) {
			_bVerifySignature = false;
		}
	}

	/**
	 * Dispatches the incoming request:
	 * <ul>
	 * <li>If the requestQuery contains the parameter "SAMLRequest" then
	 * handleSAMLRequest is invoked.</li>
	 * <li>If the requestQuery contains the parameter "aselect_credentials"
	 * then handleCredentialsRequest is invoked.</li>
	 * </ul>
	 * 
	 * @param request -
	 *            HttpServletRequest
	 * @param response -
	 *            HttpServletResponse
	 * @return RequestState
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#process(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== RequestQuery: " + request.getQueryString());

/*TEST:		SLOTimer timer = SLOTimer.getHandle(_systemLogger);
		SLOTimerTask task = new SLOTimerTask("950000516", "1234567890", "79714", _sASelectServerUrl);
		long now = new Date().getTime();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Schedule timer +" + _iRedirectLogoutTimeout * 500);
		timer.schedule(task, new Date(now + _iRedirectLogoutTimeout * 1000));
		//timer.cancel();
*/
		if (request.getParameter("SAMLRequest") != null) {
			handleSAMLRequest(request, response);
		}
		else if (request.getParameter("aselect_credentials") != null) {
			handleCredentialsRequest(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + request.getQueryString()
					+ " is not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		return null;
	}

	private void handleSAMLRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
		throws ASelectException
	{
		String sMethod = "handleSAMLRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		try {
			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(httpRequest));

			HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
			decoder.decode(messageContext);

			SignableSAMLObject samlMessage = (SignableSAMLObject) messageContext.getInboundSAMLMessage();
			_systemLogger.log(Level.INFO, MODULE, sMethod, XMLHelper.prettyPrintXML(samlMessage.getDOM()));

			String elementName = samlMessage.getElementQName().getLocalPart();

			// The SAMLRequest must be signed, if not the message can't be trusted
			// and a responsemessage is send to the browser
			if (!SignatureUtil.isSigned(httpRequest)) {
				String errorMessage = "SAML message must be signed.";
				_systemLogger.log(Level.INFO, MODULE, sMethod, errorMessage);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
				PrintWriter pwOut = httpResponse.getWriter();
				pwOut.write(errorMessage);
				return;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML message IS signed.");

			// The signing must be correct, if not the message can't be trusted
			// and a responsemessage is send to the browser

			// First we must detect which public key must be used
			// The alias of the publickey is equal to the appId and the
			// appId is retrieved by the Issuer, which is the server_url
			Issuer issuer;
			if (elementName.equals(AUTHNREQUEST)) {
				AuthnRequest authnRequest = (AuthnRequest) samlMessage;
				issuer = authnRequest.getIssuer();
			}
			else if (elementName.equals(LOGOUTREQUEST)) {
				LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
				issuer = logoutRequest.getIssuer();
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage: "
						+ XMLHelper.prettyPrintXML(samlMessage.getDOM()) + " is not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			String sEntityId = issuer.getValue();
			MetaDataManagerIDP metadataManager = MetaDataManagerIDP.getHandle();
			PublicKey publicKey = metadataManager.getSigningKey(sEntityId);
			if (publicKey == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "PublicKey for entityId: " + sEntityId
						+ " not found.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Found PublicKey for entityId: " + sEntityId);

			if (_bVerifySignature) {
				if (!SignatureUtil.verifySignature(publicKey, httpRequest)) {
					String errorMessage = "Signing of SAML message is not correct.";
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					PrintWriter pwOut = httpResponse.getWriter();
					pwOut.write(errorMessage);
					return;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Signature is correct.");
			}
			else {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No verification on Signature.");
			}

			if (elementName.equals(AUTHNREQUEST)) {
				handleAuthnRequest(httpRequest, httpResponse, samlMessage);
			}
			else if (elementName.equals(LOGOUTREQUEST)) {
				handleLogoutRequest(httpRequest, httpResponse, samlMessage);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage: "
						+ XMLHelper.prettyPrintXML(samlMessage.getDOM()) + " is not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * @param request
	 * @param response
	 * @param decoder
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	private void handleAuthnRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			SignableSAMLObject samlMessage)
		throws ASelectException
	{
		String sMethod = "handleAuthnRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		try {
			AuthnRequest authnRequest = (AuthnRequest) samlMessage;
			Response errorResponse = validateAuthnRequest(authnRequest, httpRequest);

			// if there's an errorResponse
			if (errorResponse != null) {
				sendArtifact(errorResponse, authnRequest, httpResponse);
				return;
			}

			// Now the message is OK
			// String sAppId = authnRequest.getProviderName();
			String sAppId = authnRequest.getIssuer().getValue();
			String sAssertionConsumerServiceURL = getAssertionConsumerServiceURL(samlMessage);
			if (sAssertionConsumerServiceURL == null) {
				String errorMessage = "No AssertionConsumerServiceURL found.";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
				PrintWriter pwOut = httpResponse.getWriter();
				pwOut.write(errorMessage);
				return;
			}
			String sSPRid = authnRequest.getID();

			String sASelectServerId = _sAppId;
			String sASelectServerUrl = _sASelectServerUrl;

			_systemLogger.log(Level.INFO, MODULE, sMethod, "SPRid = " + sSPRid);

			Hashtable htRequest = new Hashtable();
			htRequest.put("request", "authenticate");
			htRequest.put("app_id", sAppId);
			htRequest.put("app_url", sAssertionConsumerServiceURL);
			htRequest.put("a-select-server", sASelectServerId);

			Hashtable htResponse = null;

			try {
				htResponse = _oClientCommunicator.sendMessage(htRequest, _sASelectServerUrl);
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not send authentication request to: "
						+ _sASelectServerUrl);
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}

			sASelectServerUrl = (String) htResponse.get("as_url");
			String sIDPRid = (String) htResponse.get("rid");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Supplied rid=" + sIDPRid);

			// The new session
			Hashtable htSession = _oSessionManager.getSessionContext(sIDPRid);

			// htSession.put(SessionKeys.ORGANIZATION, _sAppOrg); TODO Is al
			// in de sessie aanwezig, en kan dus weg 16-10-07 HW
			// htSession.put(SessionKeys.APP_ID, sAppId); TODO Is al in de
			// sessie aanwezig, en kan dus weg 16-10-07 HW
			htSession.put("sp_rid", sSPRid);
			// htSession.put(SessionKeys.AS_URL, sASelectServerUrl); TODO
			// Volgens mij gebruiken we dit niet, en kan dus weg 16-10-07 HW
			htSession.put("sp_assert_url", sAssertionConsumerServiceURL);
			// Is needed for the SAMLArtifact
			htSession.put("server_url", _sASelectServerUrl);
			
			String sIssuer = authnRequest.getIssuer().getValue();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Issuer="+sIssuer);
			htSession.put("sp_issuer", sIssuer);

			// Het betrouwbaarheidsniveau wordt hier in de sessiecontext gestopt
			RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();
			String sBetrouwbaarheidsNiveau = Utils.getBetrouwbaarheidsNiveau(requestedAuthnContext);
			if (sBetrouwbaarheidsNiveau.equals(Utils.BN_NOT_FOUND)) {
				// Er zit een betrouwbaarheidsniveau in het bericht maar het
				// komt niet overeen met de configuratie
				String sInResponseTo = authnRequest.getID();
				String sSecLevelstatusCode = StatusCode.NO_AUTHN_CONTEXT_URI;
				String sStatusMessage = "The requested AuthnContext doesn't match with the configuration!";

				errorResponse = errorResponse(sInResponseTo, sAssertionConsumerServiceURL, sSecLevelstatusCode,
						sStatusMessage);
				sendArtifact(errorResponse, authnRequest, httpResponse);
				return;
			}
			org.opensaml.saml2.core.Subject mySubj = authnRequest.getSubject();
			if (mySubj != null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Subject.BaseID="+mySubj.getBaseID()+
						" Subject.NameID="+mySubj.getNameID());
			}

			htSession.put("requested_betrouwbaarheidsniveau", sBetrouwbaarheidsNiveau);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htSession=" + htSession);
			_oSessionManager.updateSession(sIDPRid, htSession);

			// redirect with A-Select request=login1
			StringBuffer sbURL = new StringBuffer(sASelectServerUrl);
			sbURL.append("&rid=");
			sbURL.append(sIDPRid);
			sbURL.append("&a-select-server=");
			sbURL.append(sASelectServerId);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + sbURL.toString());
			httpResponse.sendRedirect(sbURL.toString());
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * The incoming AuthnRequest is something like:
	 * 
	 * <pre>
	 *         &lt;sp:AuthnRequest 
	 *         xmlns:sp=&quot;urn:oasis:names:tc:SAML:2.0:protocol&quot;
	 *         AssertionConsumerServiceURL=&quot;https://localhost:8780/SP-A&quot;
	 *         Destination=&quot;https://localhost:8880/IDP-F&quot; 
	 *         ForceAuthn=&quot;false&quot;
	 *         ID=&quot;RTXXcU5moVW3OZcvnxVoc&quot; 
	 *         IsPassive=&quot;false&quot;
	 *         IssueInstant=&quot;2007-08-13T11:29:11Z&quot;
	 *         ProtocolBinding=&quot;urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact&quot;
	 *         ProviderName=&quot;SP 1&quot; 
	 *         Version=&quot;2.0&quot;&gt;
	 *         &lt;sa:Issuer 
	 *         xmlns:sa=&quot;urn:oasis:names:tc:SAML:2.0:assertion&quot;
	 *         Format=&quot;urn:oasis:names:tc:SAML:2.0:nameid-format:entity&quot;&gt;
	 *         https://localhost:8780/sp.xml
	 *         &lt;/sa:Issuer&gt;
	 *         &lt;sp:NameIDPolicy 
	 *         AllowCreate=&quot;true&quot;
	 *         Format=&quot;urn:oasis:names:tc:SAML:2.0:nameid-format:persistent&quot;&gt;
	 *         &lt;/sp:NameIDPolicy&gt;
	 *         &lt;/sp:AuthnRequest&gt;
	 * </pre>
	 * 
	 * The following attributes and elements are required (from a business
	 * perspective) and are checked on presence: <br>
	 * <br>
	 * <ul>
	 * <li>ProviderName</li>
	 * </ul>
	 * The following constraints come from the SAML Protocol: <br>
	 * <br>
	 * <ul>
	 * <li>If attribute Destination is present it MUST be checked that the URI
	 * reference identifies <br>
	 * the location at which the message was received.</li>
	 * <br>
	 * <br>
	 * 
	 * @param authnRequest
	 * @throws ASelectException
	 */
	private Response validateAuthnRequest(AuthnRequest authnRequest, HttpServletRequest httpRequest)
		throws ASelectException
	{
		String sMethod = "validateAuthnRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		Response errorResponse = null;
		String sInResponseTo = authnRequest.getID(); // Is required in SAMLsyntax
		String sDestination = authnRequest.getAssertionConsumerServiceURL();
		if (sDestination == null) {
			sDestination = "UnkownDestination";
		}
		String sStatusCode = "";
		String sStatusMessage = "";
		/*
		 * if (authnRequest.getProviderName() == null) { sStatusCode =
		 * StatusCode.INVALID_ATTR_NAME_VALUE_URI; sStatusMessage = "No
		 * 'ProviderName' attribute found in element AuthnRequest of SAML
		 * message"; _systemLogger.log(Level.WARNING, MODULE, sMethod,
		 * sStatusMessage); return errorResponse(sInResponseTo, sDestination,
		 * sStatusCode, sStatusMessage); }
		 */
		if (authnRequest.getDestination() != null) {
			if (!httpRequest.getRequestURL().toString().equals(authnRequest.getDestination())) {
				sStatusCode = StatusCode.REQUEST_DENIED_URI;
				sStatusMessage = "The 'Destination' attribute found in element AuthnRequest of SAML message" +
						" doesn't match 'RequestURL'";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage +
						" Destination="+authnRequest.getDestination()+" RequestUrl="+httpRequest.getRequestURL());
				return errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, sMethod + " succesfull");

		return errorResponse;
	}

	/**
	 * Contructs an errorResponse:
	 * 
	 * <pre>
	 *         &lt;Response 
	 *         ID=&quot;RTXXcU5moVW3OZcvnxVoc&quot; 
	 *         InResponseTo=&quot;&quot;
	 *         Version=&quot;2.0&quot;
	 *         IssueInstant=&quot;2007-08-13T11:29:11Z&quot;
	 *         Destination=&quot;&quot;&gt;
	 *         &lt;Status&gt;
	 *         &lt;StatusCode
	 *         Value=&quot;urn:oasis:names:tc:SAML:2.0:status:Requester&quot;&gt;
	 *         &lt;StatusCode
	 *         Value=&quot;urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue&quot;/&gt;
	 *         &lt;/StatusCode&gt;             
	 *         &lt;StatusMessage&gt;No ProviderName attribute found in element AuthnRequest of SAML message&lt;/StatusMessage&gt;
	 *         &lt;/Status&gt;
	 *         &lt;/Response&gt;
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
	private Response errorResponse(String sInResponseTo, String sDestination, String sSecLevelstatusCode,
			String sStatusMessage)
		throws ASelectException
	{
		String sMethod = "errorResponse()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

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

		SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) _oBuilderFactory
				.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response response = responseBuilder.buildObject();
		SecureRandomIdentifierGenerator idGenerator = null;
		try {
			idGenerator = new SecureRandomIdentifierGenerator();
		}
		catch (NoSuchAlgorithmException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The SHA1PRNG algorithm is not supported by the JVM", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		response.setID(idGenerator.generateIdentifier());
		response.setInResponseTo(sInResponseTo);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssueInstant(new DateTime());
		response.setDestination(sDestination);
		response.setStatus(status);

		return response;
	}

	private void handleCredentialsRequest(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "handleCredentialsRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		try {
			// Check if the parameter "local_rid" is in the request
			// If not, enrich the request with the IdDPRid:
			// local_rid=[IDPRid] and resend
			// TODO Is dit nodig en is er hier aan de IDPRid te komen
			if (request.getParameter("local_rid") == null) {
				String sLocalRid = "TEST";
				StringBuffer url = request.getRequestURL();
				url.append(request.getQueryString());
				url.append("&local_rid=" + sLocalRid);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + url);
				response.sendRedirect(url.toString());
			}

			// create the appropriate handler
			IRequestHandler iHandler = _oRequestHandlerFactory.createRequestHandler(request, response);
			iHandler.processRequest();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Ready");
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * send a LogoutRequests to one of the other involved SPs TO: De
	 * federatie-idp vernietigd de lokale serversessie en clientcookie. De
	 * federatie-idp verwijderd de PIP-sessie en kijkt in eigen sessietabel voor
	 * overige bestaande sessie. Federatie-idp stuurt gebruiker naar de
	 * logoutservice van de eerstvolgende SP samen met een SAML-logoutrequest.
	 * This other SP will respond with an artifact, which will be resolved in
	 * the idp artifactResolver. There it will look for even more SPs and
	 * initiate communication with them. If there are no more other SPs a logout
	 * response will be sent to the original initiating SP
	 */
	private void handleLogoutRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			SignableSAMLObject samlMessage)
		throws ASelectException
	{
		String sMethod = "handleLogoutRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		try {
			LogoutRequest logoutRequest = (LogoutRequest) samlMessage;

			_systemLogger.log(Level.INFO, MODULE, sMethod, "received SAMLRequest: \n"
					+ XMLHelper.prettyPrintXML(logoutRequest.getDOM()));

			Response errorResponse = validateLogoutRequest(logoutRequest, httpRequest);

			// if there's an errorResponse
			if (errorResponse != null) {
				// TODO De juiste foutboodschap bepalen
				String errorMessage = "Something wrong in SAML communication";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
				PrintWriter pwOut = httpResponse.getWriter();
				pwOut.write(errorMessage);
				return;
			}

			// Now the message is OK
			String uid = logoutRequest.getNameID().getValue();

			// retrieve the sso session for this user
			SSOSessionManager ssoSessionManager = SSOSessionManager.getHandle();
			UserSsoSession ssoSession = ssoSessionManager.getSsoSession(uid);

			// Remove initiating SP
			String initiatingSP = logoutRequest.getIssuer().getValue();
			ssoSession.removeServiceProvider(initiatingSP);
			// Store the initiating SP as initiatingSP for future reference
			ssoSession.setLogoutInitiator(initiatingSP);
			// overwrite the session (needed for database storage)
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Removed initiatingSP="+initiatingSP+
					" new session="+ssoSession);
			ssoSessionManager.putSsoSession(ssoSession);

			// Remove the TGT, extract ID from session
			TGTManager tgtManager = TGTManager.getHandle();
			String tgtId = ssoSession.getTgtId();

			if (tgtManager.containsKey(tgtId)) {
				tgtManager.remove(tgtId);
			}

			// Overwrite the IdP client cookie
			Cookie cookie = new Cookie(TGTIssuer.COOKIE_NAME, "");
			cookie.setMaxAge(0);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Delete Cookie " + TGTIssuer.COOKIE_NAME);
			httpResponse.addCookie(cookie);

			// voor iedere SP die aan de user is gelinkt: stuur een logoutRequest
			List<ServiceProvider> serviceProviders = ssoSession.getServiceProviders();
			for (ServiceProvider sp : serviceProviders) {
				if (_bTryRedirectLogoutFirst) {
					// if there is another SP involved we redirect the user
					// there. we start a timertask for this request. Which
					// will start synchronized logout if the 'normal' way
					// with redirects is not working correctly (for instance
					// when a service provider does not respond properly to
					// our logoutrequest). We already remove the current
					// spUrl from the list, because if it does not respond
					// to the normal way of logging out, it will probably
					// not respond to backchannel logout either.

					String serviceProvider = sp.getServiceProviderUrl();
					ssoSession.removeServiceProvider(serviceProvider);
					// overwrite the session (needed for database storage)
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Remove SP="+serviceProvider+" session="+ssoSession);
					ssoSessionManager.putSsoSession(ssoSession);

					// determine ResponseLocation from metadata
					MetaDataManagerIDP metadataManager = MetaDataManagerIDP.getHandle();
					String url = metadataManager.getLocation(serviceProvider,
							SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);

					// schedule the task in the configured time
					_systemLogger.log(Level.INFO, MODULE, sMethod, "TIMER");
					SLOTimer timer = SLOTimer.getHandle(_systemLogger);
					SLOTimerTask task = new SLOTimerTask(uid, logoutRequest.getID(), tgtId, _sASelectServerUrl);
					long now = new Date().getTime();
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Schedule timer +" + _iRedirectLogoutTimeout * 1000);
					timer.schedule(task, new Date(now + _iRedirectLogoutTimeout * 1000));
					LogoutRequestSender sender = new LogoutRequestSender();
					sender.sendLogoutRequest(url, _sASelectServerUrl, uid, httpRequest, httpResponse,
							"federation initiated redirect logout");
					// we only need 1, and if we got 1 we can't send a logoutresponse from here:
					return;
				}
				else {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "TIMER");
					SLOTimer timer = SLOTimer.getHandle(_systemLogger);
					SLOTimerTask task = new SLOTimerTask(uid, logoutRequest.getID(), tgtId, _sASelectServerUrl);
					// schedule it for now. No need to wait
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Schedule timer now");
					timer.schedule(task, new Date());
					return;
				}
			}

			// als er geen 'andere SPs' zijn moeten we een logoutResponse
			// terugsturen naar initiating SP
			ssoSessionManager.delSsoSession(uid);
			// we sturen een artifact, dus haal de location op uit metadata
			MetaDataManagerIDP metadataManager = MetaDataManagerIDP.getHandle();

			String logoutResponseLocation = metadataManager.getResponseLocation(initiatingSP,
					SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
			if (logoutResponseLocation == null) {
				logoutResponseLocation = metadataManager.getLocation(initiatingSP,
						SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
			}

			String statusCode = StatusCode.SUCCESS_URI;
			LogoutResponseSender sender = new LogoutResponseSender();
			sender.sendLogoutResponse(logoutResponseLocation, _sASelectServerUrl, statusCode, logoutRequest.getID(),
					httpRequest, httpResponse);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	// TODO kijken waar allemaal op gevalideerd kan/moet worden
	private Response validateLogoutRequest(LogoutRequest logoutRequest, HttpServletRequest httpRequest)
		throws ASelectException
	{
		String sMethod = "validateLogoutRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		Response errorResponse = null;
		String sInResponseTo = logoutRequest.getID(); // Is required in
		// SAMLsyntax
		String sDestination = logoutRequest.getDestination();
		String sStatusCode = "";
		String sStatusMessage = "";
		if (sDestination == null) {
			sDestination = "UnkownDestination";
			sStatusCode = StatusCode.INVALID_ATTR_NAME_VALUE_URI;
			sStatusMessage = "The 'Destination' attribute found in element LogoutRequest of SAML message was null";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage);
			return errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, sMethod + " succesful");

		return errorResponse;
	}

	public void destroy()
	{
		String sMethod = "destroy()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
	}

	private void sendArtifact(Response errorResponse, AuthnRequest authnRequest, HttpServletResponse httpResponse)
		throws IOException, ASelectException
	{
		String sMethod = "sendArtifact()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		String sId = errorResponse.getID();

		SAML20ArtifactManager artifactManager = SAML20ArtifactManagerLocator.getArtifactManager();
		String sArtifact = artifactManager.buildArtifact(errorResponse, _sASelectServerUrl, sId);

		// If the AssertionConsumerServiceURL is missing, redirecting the
		// artifact is senseless
		// So in this case send a message to the browser
		String sAssertionConsumerServiceURL = getAssertionConsumerServiceURL(authnRequest);
		if (sAssertionConsumerServiceURL != null) {
			artifactManager.sendArtifact(sArtifact, errorResponse, sAssertionConsumerServiceURL, httpResponse);
		}
		else {
			String errorMessage = "Something wrong in SAML communication";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
			PrintWriter pwOut = httpResponse.getWriter();
			pwOut.write(errorMessage);
		}
	}

	private String getAssertionConsumerServiceURL(SignableSAMLObject samlMessage)
	{
		String sMethod = "getAssertionConsumerServiceURL()";
		String elementName = samlMessage.getElementQName().getLocalPart();
		Issuer issuer = null;
		if (elementName.equals(AUTHNREQUEST)) {
			AuthnRequest authnRequest = (AuthnRequest) samlMessage;
			issuer = authnRequest.getIssuer();
		}
		else if (elementName.equals(LOGOUTREQUEST)) {
			LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
			issuer = logoutRequest.getIssuer();
		}
		String sAssertionConsumerServiceURL = null;
		String sEntityId = issuer.getValue();
		String sElementName = AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME;
		String sBindingName = SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
		try {
			MetaDataManagerIDP metadataManager = MetaDataManagerIDP.getHandle();
			sAssertionConsumerServiceURL = metadataManager.getLocation(sEntityId, sElementName, sBindingName);
		}
		catch (ASelectException e) {
			// Getting it from metadata is not succeeded so see if it is in
			// the message
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage());
		}
		if (sAssertionConsumerServiceURL == null) {
			if (elementName.equals(AUTHNREQUEST)) {
				AuthnRequest authnRequest = (AuthnRequest) samlMessage;
				sAssertionConsumerServiceURL = authnRequest.getAssertionConsumerServiceURL();
			}
		}
		return sAssertionConsumerServiceURL;
	}
}
