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
package org.aselect.server.request.handler.xsaml20;

import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.idp.MetaDataManagerIdp;
import org.aselect.server.request.handler.xsaml20.idp.SLOTimer;
import org.aselect.server.request.handler.xsaml20.idp.SLOTimerTask;
import org.aselect.server.request.handler.xsaml20.idp.UserSsoSession;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.communication.client.soap11.SOAP11Communicator;
import org.aselect.system.communication.client.soap12.SOAP12Communicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.Audit;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.Configuration;
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
// Example configuration
// <handler id="saml20_sso"
// class="org.aselect.server.request.handler.xsaml20.Xsaml20_SSO"
// target="/saml20_sso.*" >
// </handler>
//
public abstract class Saml20_BrowserHandler extends Saml20_BaseHandler
{
	private final static String MODULE = "Saml20_BrowserHandler";

	public IClientCommunicator _oClientCommunicator;
	public String _sMyServerId; // The value of <server_id> in the <aselect> section
	public String _sAppOrg; // The value of <organization> in the <aselect> section
	public String _sASelectServerUrl; // The value of <server_url> in the <aselect> section
	private XMLObjectBuilderFactory _oBuilderFactory;

	// private boolean _bVerifySignature = true; // RH, 20080602, o, is done by Saml20_BaseHandler now
	// Must be overridden:
	/**
	 * Retrieve issuer.
	 * 
	 * @param elementName
	 *            the element name
	 * @param samlMessage
	 *            the saml message
	 * @return the issuer
	 */
	abstract protected Issuer retrieveIssuer(String elementName, SignableSAMLObject samlMessage);

	// Override please
	/**
	 * Handle specific saml20 request.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @param samlMessage
	 *            the saml message
	 * @throws ASelectException
	 *             the a select exception
	 */
	abstract protected void handleSpecificSaml20Request(HttpServletRequest httpRequest,
			HttpServletResponse httpResponse, SignableSAMLObject samlMessage)
		throws ASelectException;

	/**
	 * Initializes the request handler by reading the following configuration: <br/>
	 * <br/>
	 * 
	 * <pre>
	 * &lt;aselect&gt;
	 * &lt;server_id&gt;[_sMyServerId]&lt;/server_id&gt;
	 * &lt;organization&gt;[_sAppOrg]&lt;/organization&gt;
	 * &lt;/aselect&gt;
	 * 
	 * &lt;handler&gt;
	 * &lt;server_id&gt;[_sASelectServerId]&lt;/server_id&gt;
	 * &lt;server_url&gt;[_sASelectServerUrl]&lt;/server_url&gt;
	 * &lt;clientcommunicator&gt;[_oClientCommunicator]&lt;/clientcommunicator&gt;
	 * &lt;/handler&gt;
	 * </pre>
	 * <ul>
	 * <li><b>_sMyServerId</b> - The id of <b>this</b> (IDP) A-Select Server</li>
	 * <li><b>_sAppOrg</b> - The organization of <b>this</b> (IDP) A-Select Server</li>
	 * <li><b>_sASelectServerId</b> - The id of the IDP A-Select Server</li>
	 * <li><b>_sASelectServerUrl</b> - The url of the IDP A-Select Server</li>
	 * <li><b>_oClientCommunicator</b> - The ClientCommunicator</li>
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
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		try {
			super.init(oServletConfig, oHandlerConfig);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "SSO");
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
			_sMyServerId = _configManager.getParam(oASelect, "server_id");
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

		try {
			_sASelectServerUrl = _configManager.getParam(oASelect, "redirect_url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_url' found in 'aselect' section", e);
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
	}

	/**
	 * Process.
	 * 
	 * @param request
	 *            - HttpServletRequest
	 * @param response
	 *            - HttpServletResponse
	 * @return RequestState
	 * @throws ASelectException
	 *             the a select exception
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		String sPathInfo = request.getPathInfo();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== Path=" + sPathInfo + " RequestQuery: "
				+ request.getQueryString());

		if (request.getParameter("SAMLRequest") != null || request.getParameter("SAMLResponse") != null) {
			handleSAMLMessage(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + request.getQueryString()
					+ " is not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		return new RequestState(null);
	}

	// Entry point for incoming SAML requests
	/**
	 * Handle saml message.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void handleSAMLMessage(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
		throws ASelectException
	{
		String sMethod = "handleSAMLMessage";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">> SAMLMessage received");

		try {
			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(httpRequest));

			Saml20_RedirectDecoder decoder = new Saml20_RedirectDecoder();
			decoder.decode(messageContext);

			SignableSAMLObject samlMessage = (SignableSAMLObject) messageContext.getInboundSAMLMessage();
			_systemLogger.log(Level.INFO, MODULE, sMethod, XMLHelper.prettyPrintXML(samlMessage.getDOM()));

			// Check the signature. First we must detect which public key must be used
			// The alias of the public key is equal to the appId and the
			// appId is retrieved by the Issuer, which is the server_url
			String elementName = samlMessage.getElementQName().getLocalPart();
			Issuer issuer = retrieveIssuer(elementName, samlMessage);
			if (issuer == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage was not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			String sEntityId = issuer.getValue();
			if (!is_bVerifySignature()) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No signature verification needed");
			}
			else { // The SAMLRequest must be signed
				if (!SamlTools.isSigned(httpRequest)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAML message must be signed.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML message IS signed.");

				MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
				PublicKey publicKey = metadataManager.getSigningKeyFromMetadata(sEntityId);
				if (publicKey == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "PublicKey for entityId: " + sEntityId
							+ " not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found PublicKey for entityId: " + sEntityId);
				// TODO this uses SAML11, should be SAML20:
				if (!SamlTools.verifySignature(publicKey, httpRequest)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAML message signature is not correct.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Signature OK");
			}

			// Set appropriate headers Pragma and Cache-Control
			httpResponse.setHeader("Pragma", "no-cache");
			httpResponse.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
			handleSpecificSaml20Request(httpRequest, httpResponse, samlMessage);
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">> SAMLMessage handled");
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
	 * &lt;sp:AuthnRequest
	 * xmlns:sp=&quot;urn:oasis:names:tc:SAML:2.0:protocol&quot;
	 * AssertionConsumerServiceURL=&quot;https://localhost:8780/SP-A&quot;
	 * Destination=&quot;https://localhost:8880/IDP-F&quot;
	 * ForceAuthn=&quot;false&quot;
	 * ID=&quot;RTXXcU5moVW3OZcvnxVoc&quot;
	 * IsPassive=&quot;false&quot;
	 * IssueInstant=&quot;2007-08-13T11:29:11Z&quot;
	 * ProtocolBinding=&quot;urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact&quot;
	 * ProviderName=&quot;SP 1&quot;
	 * Version=&quot;2.0&quot;&gt;
	 * &lt;sa:Issuer
	 * xmlns:sa=&quot;urn:oasis:names:tc:SAML:2.0:assertion&quot;
	 * Format=&quot;urn:oasis:names:tc:SAML:2.0:nameid-format:entity&quot;&gt;
	 * https://localhost:8780/sp.xml
	 * &lt;/sa:Issuer&gt;
	 * &lt;sp:NameIDPolicy
	 * AllowCreate=&quot;true&quot;
	 * Format=&quot;urn:oasis:names:tc:SAML:2.0:nameid-format:persistent&quot;&gt;
	 * &lt;/sp:NameIDPolicy&gt;
	 * &lt;/sp:AuthnRequest&gt;
	 * </pre>
	 * 
	 * The following attributes and elements are required (from a business perspective) and are checked on presence: <br>
	 * <br>
	 * <ul>
	 * <li>ProviderName</li>
	 * </ul>
	 * The following constraints come from the SAML Protocol: <br>
	 * <br>
	 * <ul>
	 * <li>If attribute Destination is present it MUST be checked that the URI reference identifies <br>
	 * the location at which the message was received.</li> <br>
	 * <br>
	 * 
	 * @param authnRequest
	 *            the authn request
	 * @param httpRequest
	 *            the http request
	 * @return the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected Response validateAuthnRequest(AuthnRequest authnRequest, HttpServletRequest httpRequest)
		throws ASelectException
	{
		String sMethod = "validateAuthnRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		Response errorResponse = null;
		String sInResponseTo = authnRequest.getID(); // Is required in SAMLsyntax
		String sDestination = authnRequest.getAssertionConsumerServiceURL();
		if (sDestination == null) {
			sDestination = "UnknownDestination";
		}
		String sStatusCode = "";
		String sStatusMessage = "";

		/*
		 * Bauke 20080623: this check is already done by the opensaml library: if (authnRequest.getDestination() !=
		 * null) { if (!httpRequest.getRequestURL().toString().equals(authnRequest.getDestination())) { sStatusCode =
		 * StatusCode.REQUEST_DENIED_URI; sStatusMessage =
		 * "The 'Destination' attribute found in element AuthnRequest doesn't match 'RequestURL'";
		 * _systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage +
		 * " Destination="+authnRequest.getDestination()+" RequestUrl="+httpRequest.getRequestURL()); return
		 * errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage); } }
		 */
		// Check validity interval here
		if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(authnRequest)) {
			sStatusCode = StatusCode.REQUEST_DENIED_URI;
			sStatusMessage = "The time interval in element AuthnRequest is not valid";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage + " Destination="
					+ authnRequest.getDestination() + " RequestUrl=" + httpRequest.getRequestURL());
			return errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
		}

		_systemLogger.log(Level.INFO, MODULE, sMethod, sMethod + " successful");
		return errorResponse;
	}

	/**
	 * Contructs an errorResponse:
	 * 
	 * <pre>
	 * &lt;Response
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
	 * &lt;/Response&gt;
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
	 * @return the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
	protected Response errorResponse(String sInResponseTo, String sDestination, String sSecLevelstatusCode,
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
		response.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
		response.setInResponseTo(sInResponseTo);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssueInstant(new DateTime());
		response.setDestination(sDestination);
		response.setStatus(status);
		return response;
	}

	//
	// Get the next SP session from the TgT and send it a Logout request
	// Always save the TgT, caller may have changed it already.
	//
	/**
	 * Logout next session sp.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @param logoutRequest
	 *            the logout request
	 * @param initiatingSP
	 *            the initiating sp
	 * @param initiatingID
	 *            the initiating id
	 * @param tryRedirectLogoutFirst
	 *            the try redirect logout first
	 * @param redirectLogoutTimeout
	 *            the redirect logout timeout
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param responseIssuer
	 *            the response issuer
	 * @throws ASelectException
	 *             the a select exception
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 */
	protected void logoutNextSessionSP(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			LogoutRequest logoutRequest, String initiatingSP, String initiatingID, boolean tryRedirectLogoutFirst,
			int redirectLogoutTimeout, HashMap htTGTContext, Issuer responseIssuer)
		throws ASelectException, ASelectStorageException
	{
		String sMethod = "logoutNextSessionSP";
		String sRelayState = null;
		TGTManager tgtManager = TGTManager.getHandle();

		String sNameID = logoutRequest.getNameID().getValue();
		if (htTGTContext == null) { // caller did not get the TGT yet
			htTGTContext = tgtManager.getTGT(sNameID);
		}

		// TODO: if one or more sessionindexes are mentioned in the logout request
		// only logout the ones mentioned!!
		// List SessionIndexes = logoutRequest.getSessionIndexes();
		if (htTGTContext != null) {
			UserSsoSession sso = (UserSsoSession) htTGTContext.get("sso_session");
			List<ServiceProvider> spList = sso.getServiceProviders();

			if (initiatingSP != null) // store in the Tgt-session
				sso.setLogoutInitiator(initiatingSP);
			else
				// retrieve from the session
				initiatingSP = sso.getLogoutInitiator();

			if (initiatingID != null)
				sso.setLogoutInitiatingID(initiatingID);
			else
				initiatingID = sso.getLogoutInitiatingID();
			// initiatingSP & initiatingID are known now

			// Remove SP from the session
			// Only do this when the slo_http_response comes in!
			if (responseIssuer != null) { // It's an HTTP response
				sso.removeServiceProvider(responseIssuer.getValue());
				htTGTContext.put("sso_session", sso);
			}
			// Write the TgT (caller may also have changed it!)
			tgtManager.updateTGT(sNameID, htTGTContext);
			sRelayState = (String) htTGTContext.get("RelayState");

			// Send a LogoutRequest to another SP
			for (ServiceProvider sp : spList) {
				String serviceProvider = sp.getServiceProviderUrl();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "initiatingSP=" + initiatingSP + " initiatingID="
						+ initiatingID + " thisSP=" + serviceProvider + " session=" + sso);

				if (initiatingSP != null && serviceProvider.equals(initiatingSP)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "SKIP " + initiatingSP);
					continue;
				}

				if (tryRedirectLogoutFirst) {
					// If there is another SP involved we redirect the user there.
					// We also start a timertask for this request. Which will start synchronized
					// logout if the 'normal' way with redirects is not working correctly
					// (for instance when a service provider does not respond properly to
					// our logoutrequest).
					// 20091010, Bauke: Session is removed when http_response comes in (not beforehand).

					// 20091011, Bauke: needs to be scheduled only once
					if (responseIssuer == null) { // It's an HTTP request from the initiating SP
						// Schedule the task at the configured time
						_systemLogger.log(Level.INFO, MODULE, sMethod, "TIMER logout (as backup)");
						SLOTimer timer = SLOTimer.getHandle(_systemLogger);
						// Store the session with the remaining SP's in it
						SLOTimerTask task = new SLOTimerTask(sNameID, logoutRequest.getID(), sso, _sASelectServerUrl);
						long now = new Date().getTime();
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Schedule timer +" + redirectLogoutTimeout
								* 1000);
						timer.schedule(task, new Date(now + redirectLogoutTimeout * 1000));
					}

					// Determine ResponseLocation from metadata
					MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
					String url = metadataManager.getLocation(serviceProvider,
							SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);

					_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect logout for SP=" + serviceProvider);
					LogoutRequestSender sender = new LogoutRequestSender();
					_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">> Sending logoutrequest to: " + url);
					// Will come back at this same handler
					sender.sendLogoutRequest(httpRequest, httpResponse, sNameID, url, _sASelectServerUrl, sNameID,
							"urn:oasis:names:tc:SAML:2.0:logout:user", null);
					return;
					// stop further execution, we'll be back here to handle the rest
				}
				else {
					// This will logout all SP's
					_systemLogger.log(Level.INFO, MODULE, sMethod, "TIMER logout for SP=" + serviceProvider);
					SLOTimer timer = SLOTimer.getHandle(_systemLogger);
					SLOTimerTask task = new SLOTimerTask(sNameID, logoutRequest.getID(), sso, _sASelectServerUrl);
					// schedule it for now. No need to wait
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Schedule timer now");
					timer.schedule(task, new Date());
					// Continue with the rest
				}
			}
			// No SP's left (except the initiating SP)
			_systemLogger.log(Level.INFO, MODULE, sMethod, "No SP's left");
			String sSendIdPLogout = (String) htTGTContext.get("SendIdPLogout");
			String sAuthspType = (String) htTGTContext.get("authsp_type");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "No SP's left. SendIdPLogout=" + sSendIdPLogout
					+ " authsp_type=" + sAuthspType);
			// For Saml20, will also send word to the IdP
			if (sAuthspType != null && sAuthspType.equals("saml20") && sSendIdPLogout == null) {
				htTGTContext.put("SendIdPLogout", "true");
				tgtManager.updateTGT(sNameID, htTGTContext);
				// Should also come back to this handler, but an IdP will send to the slo_http_response handler!
				sendLogoutToIdP(httpRequest, httpResponse, sNameID, htTGTContext, _sASelectServerUrl, null/* sLogoutReturnUrl */);
				// _sASelectServerUrl+"/saml20_sp_slo_http_request");
				// The sp_slo_htt_response handler must take care of TgT destruction
				// and responding to the caller
				return;
			}
			// No saml20 IdP, the TgT goes down the drain
			tgtManager.remove(sNameID);
		}

		// And answer the initiating SP by sending a LogoutResponse
		// Get location from metadata, try ResponseLocation first, then Location
		MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
		String logoutResponseLocation = metadataManager.getResponseLocation(initiatingSP,
				SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		if (logoutResponseLocation == null) {
			// try getLocation as well
			logoutResponseLocation = metadataManager.getLocation(initiatingSP,
					SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		}
		if (logoutResponseLocation == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No logout ResponseLocation in metadata for "
					+ initiatingSP);
			throw new ASelectException(Errors.ERROR_ASELECT_PARSE_ERROR);
		}

		// 20090604, Bauke passed RelayState to sendLogoutResponse
		// if (sRelayState != null) {
		// String sStart = (logoutResponseLocation.contains("?"))? "&": "?";
		// logoutResponseLocation += sStart+"RelayState="+sRelayState;
		// }
		String statusCode = StatusCode.SUCCESS_URI;
		LogoutResponseSender sender = new LogoutResponseSender();
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">> Sending logoutresponse to: " + logoutResponseLocation);
		sender.sendLogoutResponse(logoutResponseLocation, _sASelectServerUrl, statusCode, initiatingID, sRelayState,
				httpRequest, httpResponse);
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	@Override
	public void destroy()
	{
		String sMethod = "destroy()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
	}
}
