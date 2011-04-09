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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.server.request.handler.xsaml20.Saml20_ArtifactManager;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.Audit;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDecl;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.SubjectLocality;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLConstants;
import org.opensaml.xml.util.XMLHelper;

// Example configuration
// <handler id="saml20_sso"
//    class="org.aselect.server.request.handler.xsaml20.idp.Xsaml20_SSO"
//    target="/saml20_sso.*" >
// </handler>
//
public class Xsaml20_SSO extends Saml20_BrowserHandler
{
	private final static String MODULE = "Xsaml20_SSO";
	private final static String RETURN_SUFFIX = "_return";
	private final String AUTHNREQUEST = "AuthnRequest";
	private String _sPostTemplate = null;

	// Communication for processReturn()
	private String _sAppId = null;
	private String _sAddedPatching = null;
	private String _sReqSigning = null;
	private String _sAddKeyName = null;
	private String _sAddCertificate = null;
	boolean _bSignAssertion = false;  // must be retrieved from the metadata
	
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
		
		try {
			set_sPostTemplate(_configManager.getParam(oHandlerConfig, "post_template"));
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'post_template' found", e);
		}
	}
	
	
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler#retrieveIssuer(java.lang.String, org.opensaml.common.SignableSAMLObject)
	 */
	public Issuer retrieveIssuer(String elementName, SignableSAMLObject samlMessage)
	{
		if (elementName.equals(AUTHNREQUEST)) {
			AuthnRequest authnRequest = (AuthnRequest) samlMessage;
			return authnRequest.getIssuer();
		}
		return null;
	}

	/**
	 * Overrides the default.
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
		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== Path=" + sPathInfo + " RequestQuery: "	+ request.getQueryString());
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request received === Path=" + sPathInfo+
				" Locale="+request.getLocale().getLanguage()+" Method="+request.getMethod());

		if (sPathInfo.endsWith(RETURN_SUFFIX)) {
			processReturn(request, response);
		}
		// 20100331, Bauke: added HTTP POST support
		else if (request.getParameter("SAMLRequest") != null || "POST".equals(request.getMethod())) {
			handleSAMLMessage(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + request.getQueryString()
					+ " is not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request handled ");
		return new RequestState(null);
	}
	
	/**
	 * Tell caller the XML type we want recognized
	 * Overrides the abstract method called in handleSAMLMessage().
	 * 
	 * @return
	 *		the XML type
	 */
	protected String retrieveXmlType()
	{
		return AUTHNREQUEST;
	}
	
	/**
	 * Handle specific saml20 request.
	 * Overrides the abstract method called in handleSAMLMessage().
	 * 
	 * @param httpRequest
	 *            the HTTP request
	 * @param httpResponse
	 *            the HTTP response
	 * @param samlMessage
	 *            the saml message to be handled
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	protected void handleSpecificSaml20Request(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			SignableSAMLObject samlMessage, String sRelayState)
	throws ASelectException
	{
		String sMethod = "handleSpecificSaml20Request " + Thread.currentThread().getId();
		AuthnRequest authnRequest = (AuthnRequest) samlMessage;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "PathInfo="+httpRequest.getPathInfo());

		try {
			Response errorResponse = validateAuthnRequest(authnRequest, httpRequest.getRequestURL().toString());
			if (errorResponse != null) {
				_systemLogger.log(Audit.SEVERE, MODULE, sMethod, "validateAuthnRequest failed");
				sendErrorArtifact(errorResponse, authnRequest, httpResponse, sRelayState);
				return;
			}
			// The message is OK
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> SAML AuthnRequest received");
			String sAppId = authnRequest.getIssuer().getValue(); // authnRequest.getProviderName();
			String sSPRid = authnRequest.getID();
			String sIssuer = authnRequest.getIssuer().getValue();
			
			//  RH, 20101101, get the requested binding, can be null
			String sReqBinding = authnRequest.getProtocolBinding();
			boolean bForcedAuthn = authnRequest.isForceAuthn();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Requested binding="+sReqBinding+" ForceAuthn = " + bForcedAuthn);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "==== SPRid=" + sSPRid + " RelayState=" + sRelayState);

			// 20110323, Bauke: retrieve binding from metadata if requested binding is not present
			HashMap<String, String> hmBinding = new HashMap<String, String>();
			String sAssertionConsumerServiceURL = getAssertionConsumerServiceURL(samlMessage, hmBinding);
			if (sAssertionConsumerServiceURL == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "AssertionConsumerServiceURL not found");
				throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST);
			}

			// Start an authenticate request, we've done signature checking already, so do not ask to do it again
			// Also performAuthenticateRequest is an internal call, so who wants signing
			// 20110407, Bauke: check sig set to false
			_systemLogger.log(Level.INFO, MODULE, sMethod, "performAuthenticateRequest AppId=" + sAppId);
			HashMap htResponse = performAuthenticateRequest(_sASelectServerUrl, httpRequest.getPathInfo(),
					RETURN_SUFFIX, sAppId, false /* check sig */, _oClientCommunicator);

			String sASelectServerUrl = (String) htResponse.get("as_url");
			String sIDPRid = (String) htResponse.get("rid");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Supplied rid=" + sIDPRid + " response=" + htResponse);

			// The new sessionhttpRequest
			HashMap htSession = _oSessionManager.getSessionContext(sIDPRid);
			if (sRelayState != null) {
				htSession.put("RelayState", sRelayState);
				
			// Look for "aselect_specials" in the RelayState (is base64 encode if present)
			/*	if (!sRelayState.contains("idp=")) {  // it's base64 encoded
					sRelayState = new String(Base64Codec.decode(sRelayState));
					String sSpecials = Utils.getParameterValueFromUrl(sRelayState, "aselect_specials");
					if (sSpecials != null) {
						// allows to pass the specials on to the next IdP in the chain
						htSession.put("aselect_specials", sSpecials);
					}
				} */
			}
			htSession.put("sp_rid", sSPRid);
			htSession.put("sp_issuer", sIssuer);
			htSession.put("sp_assert_url", sAssertionConsumerServiceURL);
			htSession.put("forced_uid", "saml20_user");
			// RH, 20101101, Save requested binding for when we return from authSP
			// 20110323, Bauke: if no requested binding, take binding from metadata
			htSession.put("sp_reqbinding", hmBinding.get("binding"));  // 20110323: sReqBinding);

			// RH, 20081117, strictly speaking forced_logon != forced_authenticate
			// 20090613, Bauke: 'forced_login' is used as API parameter (a String value)
			// 'forced_authenticate' is used in the Session (a Boolean value),
			// the meaning of both is identical
			if (bForcedAuthn) {
				htSession.put("forced_authenticate", new Boolean(bForcedAuthn));
				_systemLogger.log(Level.INFO, MODULE, sMethod, "'forced_authenticate' in htSession set to: "
						+ bForcedAuthn);
			}

			// The betrouwbaarheidsniveau is stored in the session context
			RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();
//			String sBetrouwbaarheidsNiveau = SecurityLevel.getSecurityLevel(requestedAuthnContext, _systemLogger);			// RH, 20101216, o
			// RH, 20101216, sn
			HashMap<String, String> secLevels =  ApplicationManager.getHandle().getSecLevels(sAppId);
			String sBetrouwbaarheidsNiveau = SecurityLevel.getSecurityLevel(requestedAuthnContext, _systemLogger, secLevels);
			// RH, 20101216, en

			if (sBetrouwbaarheidsNiveau.equals(SecurityLevel.BN_NOT_FOUND)) {
				// We've got a security level but is not known
				String sStatusMessage = "The requested AuthnContext isn't present in the configuration";
				errorResponse = errorResponse(sSPRid, sAssertionConsumerServiceURL, StatusCode.NO_AUTHN_CONTEXT_URI,
						sStatusMessage);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage);
				sendErrorArtifact(errorResponse, authnRequest, httpResponse, sRelayState);
				return;
			}
			// debug
			/*
			 * org.opensaml.saml2.core.Subject mySubj = authnRequest.getSubject();
			 * if (mySubj != null) {
			 *		_systemLogger.log(Level.INFO, MODULE, sMethod, "Subject.BaseID="+mySubj.getBaseID()+
			 * 				" Subject.NameID="+mySubj.getNameID());
			 * }
			 */

			// 20090110, Bauke changed requested_betrouwbaarheidsniveau to required_level
			htSession.put("required_level", sBetrouwbaarheidsNiveau);
			htSession.put("level", Integer.parseInt(sBetrouwbaarheidsNiveau)); // 20090111, Bauke added, NOTE: it's an Integer
			_oSessionManager.updateSession(sIDPRid, htSession);

			// redirect with A-Select request=login1
			StringBuffer sbURL = new StringBuffer(sASelectServerUrl);
			sbURL.append("&rid=").append(sIDPRid);
			sbURL.append("&a-select-server=").append(_sASelectServerID);
			if (bForcedAuthn)
				sbURL.append("&forced_logon=").append(bForcedAuthn);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + sbURL.toString());
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Challenge for credentials, redirect to:"
					+ sbURL.toString());
			httpResponse.sendRedirect(sbURL.toString());
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, XMLHelper.prettyPrintXML(samlMessage.getDOM()));
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> SAML AuthnRequest handled");
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
	protected Response validateAuthnRequest(AuthnRequest authnRequest, String sRequestUrl)
		throws ASelectException
	{
		String sMethod = "validateAuthnRequest";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "RequestUrl=" + sRequestUrl);

		Response errorResponse = null;
		String sInResponseTo = authnRequest.getID(); // Is required in SAMLsyntax
		String sDestination = authnRequest.getAssertionConsumerServiceURL();
		if (sDestination == null) {
			sDestination = "UnknownDestination";
		}
		String sStatusCode = "";
		String sStatusMessage = "";

		/*
		 * The opensaml library already checks that
		 * the 'Destination' attribute from the AuthnRequest matches 'RequestURL'
		 */
		// Check validity interval here
		if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(authnRequest)) {
			sStatusCode = StatusCode.REQUEST_DENIED_URI;
			sStatusMessage = "The time interval in element AuthnRequest is not valid";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage + " Destination="
					+ authnRequest.getDestination() + " RequestUrl=" + sRequestUrl);
			return errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
		}

		_systemLogger.log(Level.INFO, MODULE, sMethod, sMethod + " successful");
		return errorResponse;
	}

	/**
	 * Gets the assertion consumer service url.
	 * 
	 * @param samlMessage
	 *            the saml message
	 * @param hmBinding
	 *            the hashmap to receive the binding
	 * @return the assertion consumer service url
	 * @throws ASelectException
	 *             the a select exception
	 */
	private String getAssertionConsumerServiceURL(SignableSAMLObject samlMessage, HashMap<String, String> hmBinding)
	throws ASelectException
	{
		String sMethod = "getAssertionConsumerServiceURL " + Thread.currentThread().getId();

		String sAssertionConsumerServiceURL = null;
		String sElementName = AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME;
		String elementName = samlMessage.getElementQName().getLocalPart();

		// IDP MUST honor requested sAssertionConsumerServiceURL from AUTHNREQUEST first
		String sBindingName = null;
		if (AUTHNREQUEST.equals(elementName)) {
			AuthnRequest authnRequest = (AuthnRequest) samlMessage;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Get Location from AuthnRequest 1");
			sAssertionConsumerServiceURL = authnRequest.getAssertionConsumerServiceURL();
			sBindingName = authnRequest.getProtocolBinding();
		}

		if (sAssertionConsumerServiceURL == null) {	// We didn't find it in the authnrequest
			
			Issuer issuer = retrieveIssuer(elementName, samlMessage);
			if (issuer == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "SAMLMessage: " + elementName + " was not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			String sEntityId = issuer.getValue();
	
			// get from metadata
			MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
			
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Looking for EntityId="+sEntityId + " sElementName="+sElementName+
					" sBindingName="+sBindingName + " in:"+metadataManager.getMetadataURL(sEntityId));
			
			try {
				// if sBindingName was null, binding was not present in the Auhtentication request
				sAssertionConsumerServiceURL = metadataManager.getLocationAndBinding(sEntityId, sElementName,
						sBindingName, "Location", hmBinding);
			}
			catch (ASelectException e) {
				// Metadata retrieval failed so get it from the message
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get location: " + e.getMessage());
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Meta done ACurl="+sAssertionConsumerServiceURL+" hmBinding="+hmBinding);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Return " + sAssertionConsumerServiceURL+" binding="+hmBinding);
		return sAssertionConsumerServiceURL;
	}

	/**
	 * Error response, send error artifact.
	 * 
	 * @param errorResponse
	 *            the error response
	 * @param authnRequest
	 *            the authn request
	 * @param httpResponse
	 *            the http response
	 * @param sRelayState
	 *            the s relay state
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void sendErrorArtifact(Response errorResponse, AuthnRequest authnRequest, HttpServletResponse httpResponse,
			String sRelayState)
		throws IOException, ASelectException
	{
		String sMethod = "sendErrorArtifact()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		String sId = errorResponse.getID();

		Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
		String sArtifact = artifactManager.buildArtifact(errorResponse, _sASelectServerUrl, sId);

		// If the AssertionConsumerServiceURL is missing, redirecting the artifact is senseless
		// So in this case send a message to the browser
		String sAssertionConsumerServiceURL = getAssertionConsumerServiceURL(authnRequest, null);
		if (sAssertionConsumerServiceURL != null) {
			artifactManager.sendArtifact(sArtifact, errorResponse, sAssertionConsumerServiceURL, httpResponse,
					sRelayState, null);
		}
		else {
			String errorMessage = "Something wrong in SAML communication";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
			PrintWriter pwOut = httpResponse.getWriter();
			pwOut.write(errorMessage);
		}
	}

	// We're returning from the AuthSP
	// RequestQuery: aselect_credentials=7HxCWBudn...W8bAU3OY&rid=4B9FF1406696C0C8&a-select-server=umcn_aselect_server1
	/**
	 * Process return.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void processReturn(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
		throws ASelectException
	{
		String sMethod = "processReturn()";
		HashMap htTGTContext = null;
		HashMap htSessionContext = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Handle return from the AuthSP");

		try {
			// We have to return to the calling SP using a SAML Artifact
			// RH, 20101101, or maybe another binding
			// If a TgT is present the session has been deleted
			String sRid = (String) httpRequest.getParameter("rid");
			String sTgt = (String) httpRequest.getParameter("aselect_credentials");
			if (sTgt != null && !sTgt.equals("")) {
				sTgt = decryptCredentials(sTgt);
				htTGTContext = getContextFromTgt(sTgt, false); // Don't check expiration
			}
			else {
				htSessionContext = _oSessionManager.getSessionContext(sRid);
			}

			// One of them must be available
			if (htTGTContext == null && htSessionContext == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod,
						"Neither TGT context nor Session context are available");
				throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
			}

			String sAssertUrl = null;
			if (htTGTContext != null)
				sAssertUrl = (String) htTGTContext.get("sp_assert_url");
			if (sAssertUrl == null && htSessionContext != null)
				sAssertUrl = (String) htSessionContext.get("sp_assert_url");
			if (sAssertUrl == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Return url \"sp_assert_url\" is missing");
				throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
			}

			// 20090603, Bauke: Only take RelayState from the session (not from TgT)
			// If RelayState was given, it must be available in the Session Context.
			String sRelayState = null;
			if (htSessionContext != null)
				sRelayState = (String) htSessionContext.get("RelayState");
			else
				sRelayState = (String) htTGTContext.get("RelayState");

			// RH, 2011101, retrieve the requested binding
			String sReqBInding = null;
			if (htTGTContext  != null)
				sReqBInding = (String) htTGTContext.get("sp_reqbinding");
			if (sReqBInding == null && htSessionContext != null )
				sReqBInding = (String) htSessionContext.get("sp_reqbinding");
			if (sReqBInding == null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Requested binding \"sp_reqbinding\" is missing, using default" );
			}
			
			//String sIssuer = (String)htTGTContext.get("sp_issuer");
			//MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
			//String sWantAssertionsSigned = metadataManager.getAttributeFromMetadata(sIssuer, "WantAssertionsSigned");
			//_bSignAssertion = "true".equals(sWantAssertionsSigned); // Siam always sets this to true

			// And off you go!
			retrieveLocalSettings(htSessionContext, htTGTContext);  // results are placed in this object
			
			if (Saml20_Metadata.singleSignOnServiceBindingConstantPOST.equals(sReqBInding)) {
				_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Redirecting with post to: " + sAssertUrl);
				sendSAMLResponsePOST(sAssertUrl, sRid, htSessionContext, sTgt, htTGTContext, httpResponse, sRelayState);
			}
			else {	// use artifact as default (for backward compatibility) 
				_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Redirecting with artifact to: " + sAssertUrl);
				sendSAMLArtifactRedirect(sAssertUrl, sRid, htSessionContext, sTgt, htTGTContext, httpResponse, sRelayState);
			}
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Return from  AuthSP handled");

			// Cleanup for a forced_authenticate session
			Boolean bForcedAuthn = (Boolean) htTGTContext.get("forced_authenticate");
			if (bForcedAuthn == null)
				bForcedAuthn = false;
			if (bForcedAuthn && htTGTContext != null) {
				TGTManager tgtManager = TGTManager.getHandle();
				tgtManager.remove(sTgt);
			}
			if (bForcedAuthn && htSessionContext != null) {
				SessionManager sessionManager = SessionManager.getHandle();
				sessionManager.killSession(sRid);
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
	 * Send saml artifact error redirect.
	 * If htTGTContext is null we have to create an error <Response>, send no Assertion, just <Status>
	 * 
	 * @param sAppUrl
	 *            the s app url
	 * @param sRid
	 *            the s rid
	 * @param htSessionContext
	 *            the ht session context
	 * @param sTgt
	 *            the s tgt
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param oHttpServletResponse
	 *            the o http servlet response
	 * @param sRelayState
	 *            the s relay state
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
	private void sendSAMLArtifactRedirect(String sAppUrl, String sRid, HashMap htSessionContext, String sTgt,
			HashMap htTGTContext, HttpServletResponse oHttpServletResponse, String sRelayState)
	throws ASelectException
	{
		String sMethod = "sendSAMLArtifactRedirect";
//		boolean isSuccessResponse = (htTGTContext != null);
//		Assertion assertion = null;
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
//		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
//		String addedPatching = _configManager.getAddedPatching();
//
//			DateTime tStamp = new DateTime(); // We will use one timestamp
//
//			XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
//			XMLObjectBuilder stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);
//
//			String sSPRid = null;
//			if (htSessionContext != null)
//				sSPRid = (String) htSessionContext.get("sp_rid");
//
//			if (htTGTContext != null) {
//
//				sSPRid = (String) htTGTContext.get("sp_rid");
//				String sSelectedLevel = (String) htTGTContext.get("sel_level");
//				if (sSelectedLevel == null) sSelectedLevel = (String) htTGTContext.get("authsp_level");
//				if (sSelectedLevel == null) sSelectedLevel = (String) htTGTContext.get("betrouwbaarheidsniveau");  // To be removed
//				String sUid = (String) htTGTContext.get("uid");
//				String sCtxRid = (String) htTGTContext.get("rid");
//				String sSubjectLocalityAddress = (String) htTGTContext.get("client_ip");
//				String sAssertionID = SamlTools.generateIdentifier(_systemLogger, MODULE);
//				_systemLogger.log(Level.INFO, MODULE, sMethod, "CHECK ctxRid=" + sCtxRid + " rid=" + sRid
//						+ " client_ip=" + sSubjectLocalityAddress);
//
//				// ---- Attributes
//				// Create an attribute statement builder
//				QName qName = AttributeStatement.DEFAULT_ELEMENT_NAME;
//				_systemLogger.log(Level.INFO, MODULE, sMethod, "AttributeStatement qName="+qName);
//				SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder =
//					(SAMLObjectBuilder<AttributeStatement>) builderFactory.getBuilder(qName);
//				AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
//
//				// Create an attribute builder
//				qName = Attribute.DEFAULT_ELEMENT_NAME;
//				_systemLogger.log(Level.INFO, MODULE, sMethod, "Attribute qName="+qName);
//				SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory.getBuilder(qName);
//
//				// Gather attributes, including the attributes from the ticket context
//				HashMap htAttributes = getAttributesFromTgtAndGatherer(htTGTContext);
//				String sAllAttributes = org.aselect.server.utils.Utils.serializeAttributes(htAttributes);
//
//				// 20090910, Bauke: new mechanism to pass the attributes
//				HashMap htAllAttributes = new HashMap();
//				htAllAttributes.put("attributes", sAllAttributes);
//				htAllAttributes.put("uid", sUid);
//				htAllAttributes.put("betrouwbaarheidsniveau", sSelectedLevel);
//
//				Set keys = htAllAttributes.keySet();
//				for (Object s : keys) {
//					String sKey = (String)s;
//					Object oValue = htAllAttributes.get(sKey);
//
//					if (!(oValue instanceof String))
//						continue;
//					String sValue = (String)oValue;
//
//					Attribute theAttribute = attributeBuilder.buildObject();
//					theAttribute.setName(sKey);
//					XSString theAttributeValue = null;
//					boolean bNvlAttrName = addedPatching.contains("nvl_attrname");
//					if (bNvlAttrName) {
//						// add namespaces to the attribute
//						_systemLogger.log(Level.INFO, MODULE, sMethod, "nvl_attrname");
//						boolean bXS = addedPatching.contains("nvl_attr_namexsd");
//						Namespace namespace = new Namespace(XMLConstants.XSD_NS, (bXS)? "xsd": XMLConstants.XSD_PREFIX);
//						theAttribute.addNamespace(namespace);
//						namespace = new Namespace(XMLConstants.XSI_NS, XMLConstants.XSI_PREFIX);
//						theAttribute.addNamespace(namespace);
//						theAttribute.setNameFormat(Attribute.BASIC);  // URI_REFERENCE);  // BASIC);
//						_systemLogger.log(Level.INFO, MODULE, sMethod, "Novell Attribute="+theAttribute);
//					}
//					theAttributeValue = (XSString)stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
//					theAttributeValue.setValue(sValue);
//					
//					theAttribute.getAttributeValues().add(theAttributeValue);
//					attributeStatement.getAttributes().add(theAttribute); // add this attribute
//				}
//
//				/*
//				 * // 200909, Bauke: replaced by the attribute gatherer solution
//				 * Attribute attributeAuthspLevel = attributeBuilder.buildObject();
//				 * attributeAuthspLevel.setName("betrouwbaarheidsniveau");
//				 * XSString attributeAuthspLevelValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
//				 * attributeAuthspLevelValue.setValue(sAuthspLevel);
//				 * attributeAuthspLevel.getAttributeValues().add(attributeAuthspLevelValue);
//				 * attributeStatement.getAttributes().add(attributeAuthspLevel); // add this attribute Attribute
//				 * attributeUid = attributeBuilder.buildObject();
//				 * attributeUid.setName("uid");
//				 * XSString attributeUidValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
//				 * attributeUidValue.setValue(sUid);
//				 * attributeUid.getAttributeValues().add(attributeUidValue);
//				 * attributeStatement.getAttributes().add(attributeUid);
//				 */
//
//				// ---- AuthenticationContext
//				SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
//						.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
//				AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
//				String sAutnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sSelectedLevel, _systemLogger);
//				authnContextClassRef.setAuthnContextClassRef(sAutnContextClassRefURI);
//
//				SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory
//						.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
//				AuthnContext authnContext = authnContextBuilder.buildObject();
//				authnContext.setAuthnContextClassRef(authnContextClassRef);
//
//				SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory
//						.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
//				AuthnStatement authnStatement = authnStatementBuilder.buildObject();
//				authnStatement.setAuthnInstant(new DateTime());
//				// Sun doesn't like this:
//				// authnStatement.setSessionIndex((String) htTGTContext.get("sp_issuer"));
//				String sSessionIndex = sAssertionID.replaceAll("_", "");
//				authnStatement.setSessionIndex(sSessionIndex);
//				// Always try to set the locality address, except when null or empty
//				if (sSubjectLocalityAddress != null && !"".equals(sSubjectLocalityAddress)) {
//					SAMLObjectBuilder<SubjectLocality> subjectLocalityBuilder = (SAMLObjectBuilder<SubjectLocality>) builderFactory
//							.getBuilder(SubjectLocality.DEFAULT_ELEMENT_NAME);
//					SubjectLocality locality = subjectLocalityBuilder.buildObject();
//					locality.setAddress(sSubjectLocalityAddress);
//					authnStatement.setSubjectLocality(locality);
//					// We could also set DNSName in locality, but for now, that's not requested
//				}
//
//				authnStatement.setAuthnContext(authnContext);
//				SAMLObjectBuilder<Audience> audienceBuilder = (SAMLObjectBuilder<Audience>) builderFactory
//						.getBuilder(Audience.DEFAULT_ELEMENT_NAME);
//				Audience audience = audienceBuilder.buildObject();
//				audience.setAudienceURI((String) htTGTContext.get("sp_issuer")); // 20081109 added
//
//				SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory
//						.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
//				AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
//				audienceRestriction.getAudiences().add(audience);
//
//				SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
//						.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
//				SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
//				subjectConfirmationData = (SubjectConfirmationData) SamlTools.setValidityInterval(
//						subjectConfirmationData, tStamp, null, getMaxNotOnOrAfter());
//				subjectConfirmationData.setRecipient((String) htTGTContext.get("sp_assert_url"));
//
//				// Bauke: added for OpenSSO 20080329
//				subjectConfirmationData.setInResponseTo(sSPRid);
//
//				SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory
//						.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
//				SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
//				subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);  // "urn:oasis:names:tc:SAML:2.0:cm:bearer"
//				subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
//
//				SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) builderFactory
//						.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
//				NameID nameID = nameIDBuilder.buildObject();
//				
//				// 20100525, flag added for Novell, they need PERSISTENT
//				boolean bNvlPersist = addedPatching.contains("nvl_persist");
//				if (bNvlPersist) _systemLogger.log(Level.INFO, MODULE, sMethod, "nvl_persist");
//				nameID.setFormat((bNvlPersist)? NameIDType.PERSISTENT: NameIDType.TRANSIENT); // was PERSISTENT originally
//				
//				// nvl_patch, Novell: added
//				if (addedPatching.contains("nvl_patch")) {
//					nameID.setNameQualifier(_sASelectServerUrl);  // NameQualifier
//					nameID.setSPNameQualifier((String) htTGTContext.get("sp_issuer"));  // SPNameQualifier
//				}
//				
//				// 20090602, Bauke Saml-core-2.0, section 2.2.2: SHOULD be omitted:
//				// nameID.setNameQualifier(_sASelectServerUrl);
//				nameID.setValue((bNvlPersist)? sUid: sTgt);  // 20100811: depends on NameIDType
//				_systemLogger.log(Level.INFO, MODULE, sMethod, "nameID=" + Utils.firstPartOf(nameID.getValue(), 30));
//
//				SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
//						.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
//				Subject subject = subjectBuilder.buildObject();
//				subject.setNameID(nameID);
//				subject.getSubjectConfirmations().add(subjectConfirmation);
//
//				SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
//						.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
//				Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
//				assertionIssuer.setFormat(NameIDType.ENTITY);
//				assertionIssuer.setValue(_sASelectServerUrl);
//
//				SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
//						.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
//				assertion = assertionBuilder.buildObject();
//
//				assertion.setID(sAssertionID);
//				assertion.setIssueInstant(tStamp);
//				// Set interval conditions
//				assertion = (Assertion) SamlTools.setValidityInterval(assertion, tStamp, getMaxNotBefore(), getMaxNotOnOrAfter());
//				// and then AudienceRestrictions
//				assertion = (Assertion) SamlTools.setAudienceRestrictions(assertion, audienceRestriction);
//
//				assertion.setVersion(SAMLVersion.VERSION_20);
//				assertion.setIssuer(assertionIssuer);
//				assertion.setSubject(subject);
//				assertion.getAuthnStatements().add(authnStatement);
//				assertion.getAttributeStatements().add(attributeStatement);
//			}
//
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "Set StatusCode");
//			SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
//					.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
//			StatusCode statusCode = statusCodeBuilder.buildObject();
//			statusCode.setValue((htTGTContext == null) ? StatusCode.AUTHN_FAILED_URI : StatusCode.SUCCESS_URI);
//
//			SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
//					.getBuilder(Status.DEFAULT_ELEMENT_NAME);
//			Status status = statusBuilder.buildObject();
//			status.setStatusCode(statusCode);
//			if (htTGTContext == null) {
//				String sResultCode = (String) htSessionContext.get("result_code");
//				SAMLObjectBuilder<StatusMessage> statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) builderFactory
//						.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
//				StatusMessage msg = statusMessageBuilder.buildObject();
//				msg.setMessage((sResultCode != null) ? sResultCode : "unspecified error");
//				status.setStatusMessage(msg);
//			}
//
//			SAMLObjectBuilder<Issuer> responseIssuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
//					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
//			Issuer responseIssuer = responseIssuerBuilder.buildObject();
//			responseIssuer.setFormat(NameIDType.ENTITY);
//			responseIssuer.setValue(_sASelectServerUrl);
//
//			SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory
//					.getBuilder(Response.DEFAULT_ELEMENT_NAME);
//			Response response = responseBuilder.buildObject();
//
//			response.setInResponseTo(sSPRid);
//
//			// nvl_patch, Novell: add xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
//			response.addNamespace(new Namespace(SAMLConstants.SAML20_NS, "saml"));
//			
//			response.setID("_" + sRid); // 20090512, Bauke: must be NCNAME format
//			response.setIssueInstant(tStamp);
//
//			response.setVersion(SAMLVersion.VERSION_20);
//			response.setStatus(status);
//			response.setIssuer(responseIssuer);
//			if (isSuccessResponse) {
//				response.getAssertions().add(assertion);
//			}

		Response response = buildSpecificSAMLResponse(sRid, htSessionContext, sTgt, htTGTContext);
			
		Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "buildArtifact serverUrl=" + _sASelectServerUrl + " rid=" + sRid);
		String sArtifact = artifactManager.buildArtifact(response, _sASelectServerUrl, sRid);
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "sendArtifact " + sArtifact);
			artifactManager.sendArtifact(sArtifact, response, sAppUrl, oHttpServletResponse, sRelayState, _sAddedPatching);
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Redirect to : '" + sAppUrl + "' failed", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}


	/**
	 * Send SAMLResponse POST redirect.
	 * 
	 * @param sAppUrl
	 *            the s app url
	 * @param sRid
	 *            the s rid
	 * @param htSessionContext
	 *            the ht session context
	 * @param sTgt
	 *            the s tgt
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param oHttpServletResponse
	 *            the o http servlet response
	 * @param sRelayState
	 *            the s relay state
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
	private void sendSAMLResponsePOST(String sAppUrl, String sRid, HashMap htSessionContext, String sTgt,
			HashMap htTGTContext, HttpServletResponse oHttpServletResponse, String sRelayState)
	throws ASelectException
	{
		String sMethod = "sendSAMLResponsePOST";
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Response signing >======");
		Response response = buildSpecificSAMLResponse(sRid, htSessionContext, sTgt, htTGTContext);
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Response signing=" + _bSignAssertion+" sha="+ _sReqSigning);
		if (_bSignAssertion) {
			// only the assertion was signed
			try {
				// don't forget to marshall the response when no signing will be done here
				org.opensaml.xml.Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
			}
			catch (MarshallingException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Cannot marshall object", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
		}
		else {  // No assertion signing, sign the complete response
			response = (Response)SamlTools.signSamlObject(response, _sReqSigning, 
							"true".equals(_sAddKeyName), "true".equals(_sAddCertificate));
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Response signing ======<"+response);
		
		String sResponse = XMLHelper.nodeToString(response.getDOM());
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Response=" + sResponse);
		try {
			byte[] bBase64Assertion = sResponse.getBytes("UTF-8");
			BASE64Encoder b64enc = new BASE64Encoder();
			sResponse = b64enc.encode(bBase64Assertion);
		}
		catch (UnsupportedEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		String sp_assert_url = null;
		if (htTGTContext  != null)
			sp_assert_url = (String) htTGTContext.get("sp_assert_url");
		if (sp_assert_url == null && htSessionContext != null )
			sp_assert_url = (String) htSessionContext.get("sp_assert_url");
		if (sp_assert_url== null) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No assertion consumer url provided");
			throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);	
		}

		// Handle RelayState
		try {
			byte[] bBase64RelayState = sAppUrl.getBytes("UTF-8");
			BASE64Encoder b64enc = new BASE64Encoder();
			sAppUrl = b64enc.encode(bBase64RelayState);
		}
		catch (UnsupportedEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		if ("".equals(sRelayState))
			sRelayState = sAppUrl;	// By convention we load RelayState with appURL

		String sInputs = buildHtmlInput("RelayState", sRelayState);
		String sLang = null;
		if (htTGTContext  != null)
			sLang = (String) htTGTContext.get("language");
		if (sLang == null && htSessionContext != null )
			sLang = (String) htSessionContext.get("language");
		if (sLang != null)
			sInputs += buildHtmlInput("language",sLang);
		
		// Keep logging short:
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Template="+get_sPostTemplate()+" sInputs="+sInputs+" ...");
		sInputs += buildHtmlInput("SAMLResponse", sResponse);  //Tools.htmlEncode(nodeMessageContext.getTextContent()));

		// Let's POST the token
		if (get_sPostTemplate() != null) {
			String sSelectForm = _configManager.loadHTMLTemplate(null, get_sPostTemplate(), _sUserLanguage, _sUserCountry);
			handlePostForm(sSelectForm, sp_assert_url, sInputs, oHttpServletResponse);
		}
		else {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No POST template found");
			throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}	
	}


	/**
	 * Retrieve several settings for session and/or context
	 * 
	 * @param htSessionContext
	 * 			the session context
	 * @param htTGTContext
	 * 			the ticket
	 */
	private void retrieveLocalSettings(HashMap htSessionContext, HashMap htTGTContext)
	{
		String sMethod = "retrieveLocalSettings";
		
		// RH, 20101207, sn
		if (htTGTContext  != null)
			_sAppId = (String) htTGTContext.get("app_id");
		if (_sAppId == null && htSessionContext != null )
			_sAppId = (String) htSessionContext.get("app_id");
		if (_sAppId == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve app_id from context" );
		}

		if (_sAppId != null) {	// application level overrules handler level configuration
			_sAddedPatching = ApplicationManager.getHandle().getAddedPatching(_sAppId);
		}
		// RH, 20101207, en
		if (_sAddedPatching == null) {	// backward compatibility, get it from handler configuration
			_sAddedPatching = _configManager.getAddedPatching();
		}
		_bSignAssertion = _sAddedPatching.contains("sign_assertion");  // this is an application attribute
		
		// RH, 2011101, retrieve the requested signing
		if (htTGTContext  != null)
			_sReqSigning = (String) htTGTContext.get("sp_reqsigning");
		if (_sReqSigning == null && htSessionContext != null )
			_sReqSigning = (String) htSessionContext.get("sp_reqsigning");
		if (_sReqSigning == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Requested signing \"sp_reqsigning\" is missing, using default" );
		}
		
		if (!"sha256".equals(_sReqSigning))  // we only support sha256 and sha1
			_sReqSigning = "sha1";

		// RH, 2011116, retrieve whether addkeyname requested
		if (htTGTContext  != null)
			_sAddKeyName = (String) htTGTContext.get("sp_addkeyname");
		if (_sAddKeyName == null && htSessionContext != null )
			_sAddKeyName = (String) htSessionContext.get("sp_addkeyname");
		if (_sAddKeyName == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Requested signing \"sp_addkeyname\" is missing, using default" );
		}

		// RH, 2011116, retrieve whether addcertificate requested
		if (htTGTContext  != null)
			_sAddCertificate = (String) htTGTContext.get("sp_addcertificate");
		if (_sAddCertificate == null && htSessionContext != null )
			_sAddCertificate = (String) htSessionContext.get("sp_addcertificate");
		if (_sAddCertificate == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Requested signing \"sp_addcertificate\" is missing, using default" );
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "SignAssertion="+_bSignAssertion+" ReqSigning="+_sReqSigning);
	}
	
	/**
	 * Build a SAML response and return it.
	 * 
	 * @param sRid
	 *            the s rid
	 * @param htSessionContext
	 *            the ht session context
	 * @param sTgt
	 *            the s tgt
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param oHttpServletResponse
	 *            the o http servlet response
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
	private Response buildSpecificSAMLResponse(String sRid, HashMap htSessionContext, String sTgt, HashMap htTGTContext)
	throws ASelectException
	{
		String sMethod = "buildSpecificSAMLResponse";
		boolean isSuccessResponse = (htTGTContext != null);
		Assertion assertion = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		DateTime tStamp = new DateTime(); // We will use one timestamp

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XMLObjectBuilder stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);

		String sSPRid = null;
		if (htSessionContext != null)
			sSPRid = (String) htSessionContext.get("sp_rid");

		if (htTGTContext != null) {

			sSPRid = (String) htTGTContext.get("sp_rid");
			String sSelectedLevel = (String) htTGTContext.get("sel_level");
			if (sSelectedLevel == null) sSelectedLevel = (String) htTGTContext.get("authsp_level");
			if (sSelectedLevel == null) sSelectedLevel = (String) htTGTContext.get("betrouwbaarheidsniveau");  // To be removed
			String sUid = (String) htTGTContext.get("uid");
			String sCtxRid = (String) htTGTContext.get("rid");
			String sSubjectLocalityAddress = (String) htTGTContext.get("client_ip");
			String sAssertionID = SamlTools.generateIdentifier(_systemLogger, MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "CHECK ctxRid=" + sCtxRid + " rid=" + sRid
					+ " client_ip=" + sSubjectLocalityAddress);

			// ---- Attributes
			// Create an attribute statement builder
			QName qName = AttributeStatement.DEFAULT_ELEMENT_NAME;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "AttributeStatement qName="+qName);
			SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder =
				(SAMLObjectBuilder<AttributeStatement>) builderFactory.getBuilder(qName);
			AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

			// Create an attribute builder
			qName = Attribute.DEFAULT_ELEMENT_NAME;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Attribute qName="+qName+" AppId="+_sAppId);
			SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory.getBuilder(qName);

			// Gather attributes, including the attributes from the ticket context
			HashMap htAttributes = getAttributesFromTgtAndGatherer(htTGTContext);
			String sAllAttributes = org.aselect.server.utils.Utils.serializeAttributes(htAttributes);

			// 20090910, Bauke: new mechanism to pass the attributes
			HashMap htAllAttributes = new HashMap();
			htAllAttributes.put("attributes", sAllAttributes);
			htAllAttributes.put("uid", sUid);
			htAllAttributes.put("betrouwbaarheidsniveau", sSelectedLevel);

			// 20101229, Bauke: add configurable fixed value attributes
			if (_sAppId != null) {
				HashMap<String,String> additionalAttributes = ApplicationManager.getHandle().getAdditionalAttributes(_sAppId);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "AddAttr="+additionalAttributes);
				if (additionalAttributes != null) {
					Set<String> keys = additionalAttributes.keySet();
					for (String sKey : keys) {
						String sValue = additionalAttributes.get(sKey);
						_systemLogger.log(Level.FINE, MODULE, sMethod, "Attr "+sKey+"="+sValue);
						htAllAttributes.put(sKey, sValue);
					}
				}
			}
			
			Set keys = htAllAttributes.keySet();
			for (Object s : keys) {
				String sKey = (String)s;
				Object oValue = htAllAttributes.get(sKey);

				if (!(oValue instanceof String))
					continue;
				String sValue = (String)oValue;

				Attribute theAttribute = attributeBuilder.buildObject();
				theAttribute.setName(sKey);
				XSString theAttributeValue = null;
				boolean bNvlAttrName = _sAddedPatching.contains("nvl_attrname");
				if (bNvlAttrName) {
					// add namespaces to the attribute
					_systemLogger.log(Level.INFO, MODULE, sMethod, "nvl_attrname");
					boolean bXS = _sAddedPatching.contains("nvl_attr_namexsd");
					Namespace namespace = new Namespace(XMLConstants.XSD_NS, (bXS)? "xsd": XMLConstants.XSD_PREFIX);
					theAttribute.addNamespace(namespace);
					namespace = new Namespace(XMLConstants.XSI_NS, XMLConstants.XSI_PREFIX);
					theAttribute.addNamespace(namespace);
					theAttribute.setNameFormat(Attribute.BASIC);  // URI_REFERENCE);  // BASIC);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Novell Attribute="+theAttribute);
				}
				theAttributeValue = (XSString)stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
				theAttributeValue.setValue(sValue);
				
				theAttribute.getAttributeValues().add(theAttributeValue);
				attributeStatement.getAttributes().add(theAttribute); // add this attribute
			}
			// CONSIDER maybe also add htAttributes as individual saml attributes
			
			// ---- AuthenticationContext
			SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
					.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
			
			// RH, 20101214, sn
			String sAutnContextClassRefURI = null;
			HashMap<String, String> secLevels =  ApplicationManager.getHandle().getSecLevels(_sAppId);
			if (secLevels != null) {
				sAutnContextClassRefURI = secLevels.get(sSelectedLevel);
			}
			if (sAutnContextClassRefURI == null) {	// for backward compatability
				sAutnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sSelectedLevel, _systemLogger);
			}				
			// RH, 20101214, en
			authnContextClassRef.setAuthnContextClassRef(sAutnContextClassRefURI);

			SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory
					.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
			AuthnContext authnContext = authnContextBuilder.buildObject();
			authnContext.setAuthnContextClassRef(authnContextClassRef);

			// RH, 20101217, sn
			if ( ApplicationManager.getHandle().getAuthnContextDeclValue(_sAppId) != null ) {
				if (AuthnContextDecl.DEFAULT_ELEMENT_LOCAL_NAME.equals(ApplicationManager.getHandle().getAuthnContextDeclType(_sAppId)) ) {
					SAMLObjectBuilder<AuthnContextDecl> authnContextDeclBuilderBuilder = (SAMLObjectBuilder<AuthnContextDecl>) builderFactory
					.getBuilder(AuthnContextDecl.DEFAULT_ELEMENT_NAME);
					AuthnContextDecl authnContextDecl = authnContextDeclBuilderBuilder.buildObject();
					authnContextDecl.setTextContent(ApplicationManager.getHandle().getAuthnContextDeclValue(_sAppId));
					authnContext.setAuthnContextDecl(authnContextDecl);
				} else {
					SAMLObjectBuilder<AuthnContextDeclRef> authnContextDeclBuilderBuilder = (SAMLObjectBuilder<AuthnContextDeclRef>) builderFactory
					.getBuilder(AuthnContextDeclRef.DEFAULT_ELEMENT_NAME);
					AuthnContextDeclRef authnContextDeclRef = authnContextDeclBuilderBuilder.buildObject();
					authnContextDeclRef.setAuthnContextDeclRef(ApplicationManager.getHandle().getAuthnContextDeclValue(_sAppId));
					authnContext.setAuthnContextDeclRef(authnContextDeclRef);
				}
			}
			// RH, 20101217, sn
			
			SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory
					.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
			AuthnStatement authnStatement = authnStatementBuilder.buildObject();
			// use same time reference for all
			// authnStatement.setAuthnInstant(new DateTime()); // RH, 20101116, o
			authnStatement.setAuthnInstant(tStamp); // RH, 20101116, n
			
			// Sun doesn't like this:
			// authnStatement.setSessionIndex((String) htTGTContext.get("sp_issuer"));
			String sSessionIndex = sAssertionID.replaceAll("_", "");
			authnStatement.setSessionIndex(sSessionIndex);
			// Always try to set the locality address, except when null or empty
			if (sSubjectLocalityAddress != null && !"".equals(sSubjectLocalityAddress)) {
				SAMLObjectBuilder<SubjectLocality> subjectLocalityBuilder = (SAMLObjectBuilder<SubjectLocality>) builderFactory
						.getBuilder(SubjectLocality.DEFAULT_ELEMENT_NAME);
				SubjectLocality locality = subjectLocalityBuilder.buildObject();
				locality.setAddress(sSubjectLocalityAddress);
				authnStatement.setSubjectLocality(locality);
				// We could also set DNSName in locality, but for now, that's not requested
			}

			authnStatement.setAuthnContext(authnContext);
			SAMLObjectBuilder<Audience> audienceBuilder = (SAMLObjectBuilder<Audience>) builderFactory
					.getBuilder(Audience.DEFAULT_ELEMENT_NAME);
			Audience audience = audienceBuilder.buildObject();
			
//				audience.setAudienceURI((String) htTGTContext.get("sp_issuer")); // 20081109 added
			String sAudience = (String) htTGTContext.get("sp_audience");
			audience.setAudienceURI( (sAudience != null) ? sAudience : (String) htTGTContext.get("sp_issuer")); // 20101116, RH,  for backward compatibility

			SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory
					.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
			AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
			audienceRestriction.getAudiences().add(audience);

			SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
					.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
			SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
			subjectConfirmationData = (SubjectConfirmationData) SamlTools.setValidityInterval(
					subjectConfirmationData, tStamp, null, getMaxNotOnOrAfter());
			subjectConfirmationData.setRecipient((String) htTGTContext.get("sp_assert_url"));

			// Bauke: added for OpenSSO 20080329
			subjectConfirmationData.setInResponseTo(sSPRid);

			SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory
					.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
			SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
			subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);  // "urn:oasis:names:tc:SAML:2.0:cm:bearer"
			subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

			SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) builderFactory
					.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
			NameID nameID = nameIDBuilder.buildObject();
			
			// 20100525, flag added for Novell, they need PERSISTENT
			boolean bNvlPersist = _sAddedPatching.contains("nvl_persist");
			if (bNvlPersist) _systemLogger.log(Level.INFO, MODULE, sMethod, "nvl_persist");
			nameID.setFormat((bNvlPersist)? NameIDType.PERSISTENT: NameIDType.TRANSIENT); // was PERSISTENT originally
			
			// nvl_patch, Novell: added
			if (_sAddedPatching.contains("nvl_patch")) {
				nameID.setNameQualifier(_sASelectServerUrl);  // NameQualifier
				nameID.setSPNameQualifier((String) htTGTContext.get("sp_issuer"));  // SPNameQualifier
			}
			
			// 20090602, Bauke Saml-core-2.0, section 2.2.2: SHOULD be omitted:
			// nameID.setNameQualifier(_sASelectServerUrl);
			nameID.setValue((bNvlPersist)? sUid: sTgt);  // 20100811: depends on NameIDType
			_systemLogger.log(Level.INFO, MODULE, sMethod, "nameID=" + Utils.firstPartOf(nameID.getValue(), 30));

			SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
					.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
			Subject subject = subjectBuilder.buildObject();
			subject.setNameID(nameID);
			subject.getSubjectConfirmations().add(subjectConfirmation);

			SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
			assertionIssuer.setFormat(NameIDType.ENTITY);
			assertionIssuer.setValue(_sASelectServerUrl);

			SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
					.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
			assertion = assertionBuilder.buildObject();

			assertion.setID(sAssertionID);
			assertion.setIssueInstant(tStamp);
			// Set interval conditions
			assertion = (Assertion) SamlTools.setValidityInterval(assertion, tStamp, getMaxNotBefore(), getMaxNotOnOrAfter());
			// and then AudienceRestrictions
			assertion = (Assertion) SamlTools.setAudienceRestrictions(assertion, audienceRestriction);

			assertion.setVersion(SAMLVersion.VERSION_20);
			assertion.setIssuer(assertionIssuer);
			assertion.setSubject(subject);
			assertion.getAuthnStatements().add(authnStatement);
			assertion.getAttributeStatements().add(attributeStatement);

			// 20110406, Bauke: added option to only sign the assertion
			if (_bSignAssertion) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign Assertion");
				assertion = (Assertion)SamlTools.signSamlObject(assertion, _sReqSigning,
						"true".equals(_sAddKeyName), "true".equals(_sAddCertificate));
			}
		}

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Set StatusCode");
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue((htTGTContext == null) ? StatusCode.AUTHN_FAILED_URI : StatusCode.SUCCESS_URI);

		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
				.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status status = statusBuilder.buildObject();
		status.setStatusCode(statusCode);
		if (htTGTContext == null) {
			String sResultCode = (String) htSessionContext.get("result_code");
			SAMLObjectBuilder<StatusMessage> statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) builderFactory
					.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
			StatusMessage msg = statusMessageBuilder.buildObject();
			msg.setMessage((sResultCode != null) ? sResultCode : "unspecified error");
			status.setStatusMessage(msg);
		}

		SAMLObjectBuilder<Issuer> responseIssuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer responseIssuer = responseIssuerBuilder.buildObject();
		responseIssuer.setFormat(NameIDType.ENTITY);
		responseIssuer.setValue(_sASelectServerUrl);

		SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory
				.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response response = responseBuilder.buildObject();

		response.setInResponseTo(sSPRid);

		// nvl_patch, Novell: add xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		response.addNamespace(new Namespace(SAMLConstants.SAML20_NS, "saml"));
		
		response.setID("_" + sRid); // 20090512, Bauke: must be NCNAME format
		response.setIssueInstant(tStamp);

		response.setVersion(SAMLVersion.VERSION_20);
		response.setStatus(status);
		response.setIssuer(responseIssuer);
		if (isSuccessResponse) {
			response.getAssertions().add(assertion);
		}
		return response;
	}

	public synchronized String get_sPostTemplate()
	{
		return _sPostTemplate;
	}
	public synchronized void set_sPostTemplate(String sPostTemplate)
	{
		_sPostTemplate = sPostTemplate;
	}
}