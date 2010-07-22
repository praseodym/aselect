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

import java.io.PrintWriter;

import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.Saml20_RedirectEncoder;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Node;

public class Xsaml20_ISTS extends Saml20_BaseHandler
{
	private final static String MODULE = "Xsaml20_ISTS";
	protected final String singleSignOnServiceBindingConstantREDIRECT = SAMLConstants.SAML2_REDIRECT_BINDING_URI;

	private String _sServerId = null; // <server_id> in <aselect>
//	private HashMap<String, String> levelMap;
	
	private String _sAssertionConsumerUrl = null;
//	private String _sSpecialSettings = null;
//	private String _sRequestIssuer = null;
	private String _sPostTemplate = null;
	private String _sHttpMethod = "GET";

	// Example configuration
	//
	// <handler id="saml20_ists"
	// class="org.aselect.server.request.handler.xsaml20.Xsaml20_ISTS"
	// target="/saml20_ists.*">
	//
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		try {
			super.init(oServletConfig, oConfig);
		}
		catch (ASelectException e) { // pass to caller
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
//		_sSpecialSettings = ASelectConfigManager.getSimpleParam(oConfig, "special_settings", false);
//		_sRequestIssuer = ASelectConfigManager.getSimpleParam(oConfig, "issuer", false);
//		if (_sSpecialSettings == null)
//			_sSpecialSettings = "";
		_sServerId = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);

		_sHttpMethod = ASelectConfigManager.getSimpleParam(oConfig, "http_method", false);
		if (_sHttpMethod != null && _sHttpMethod.equalsIgnoreCase("POST"))
			_sHttpMethod = "POST";
		else
			_sHttpMethod = "GET";
		
		if (_sHttpMethod.equals("POST"))
			_sPostTemplate = readTemplateFromConfig(oConfig, "post_template");

		/* 20100429 replaced by IdP parameters
		levelMap = new HashMap<String, String>();
		Object oSecurity = null;
		try {
			oSecurity = _configManager.getSection(oConfig, "security");
			String sLevel = _configManager.getParam(oSecurity, "level");
			String sUri = _configManager.getParam(oSecurity, "uri");
			levelMap.put(sLevel, sUri);

			oSecurity = _configManager.getNextSection(oSecurity);
			while (oSecurity != null) {
				sLevel = _configManager.getParam(oSecurity, "level");
				sUri = _configManager.getParam(oSecurity, "uri");
				levelMap.put(sLevel, sUri);
				oSecurity = _configManager.getNextSection(oSecurity);
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid config item 'uri' found in handler section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}*/
		
		// Get Assertion Consumer data from config
		try {
			Object oRequest = _configManager.getSection(null, "requests");
			Object oHandlers = _configManager.getSection(oRequest, "handlers");
			Object oHandler = _configManager.getSection(oHandlers, "handler");
			Object oASelect = _configManager.getSection(null, "aselect");
			String sRedirectUrl = _configManager.getParam(oASelect, "redirect_url");

			for ( ; oHandler != null; oHandler = _configManager.getNextSection(oHandler)) {
				String sId = _configManager.getParam(oHandler, "id");
				if (sId != null && !sId.equals("saml20_assertionconsumer"))
					continue;
				String sTarget = _configManager.getParam(oHandler, "target");
				if (sTarget != null) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + " target=" + sTarget);
					sTarget = sTarget.replace("\\", "");
					sTarget = sTarget.replace(".*", "");
					_sAssertionConsumerUrl = sRedirectUrl + sTarget;
				}
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config next section 'handler' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}
	
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.IRequestHandler#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@SuppressWarnings("unchecked")
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process()";
		String sRid;
		String sFederationUrl = null;
		String sMyUrl = _sServerUrl; // extractAselectServerUrl(request);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "MyUrl=" + sMyUrl + " Request=" + request);

		try {
			sRid = request.getParameter("rid");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing RID parameter");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Find the associated session context
			HashMap htSessionContext = _oSessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found for RID: " + sRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// 20091028, Bauke, let the user choose which IdP to use
			sFederationUrl = request.getParameter("federation_url");
			int cnt = MetaDataManagerSp.getHandle().getIdpCount();
			if (cnt == 1) {
				sFederationUrl = MetaDataManagerSp.getHandle().getDefaultIdP(); // there can only be one
			}
			if (sFederationUrl == null || sFederationUrl.equals("")) {
				// No Federation URL choice made yet
				String sSelectForm = _configManager.loadHTMLTemplate(null, "idpselect", _sUserLanguage, _sUserCountry);
				sSelectForm = Utils.replaceString(sSelectForm, "[rid]", sRid);
				sSelectForm = Utils.replaceString(sSelectForm, "[aselect_url]", sMyUrl + "/saml20_ists");
				sSelectForm = _configManager.updateTemplate(sSelectForm, htSessionContext);
				response.setContentType("text/html");
				PrintWriter pwOut = response.getWriter();
				pwOut.println(sSelectForm);
				pwOut.close();
				return new RequestState(null);
			}

			// 20090811, Bauke: save type of Authsp to store in the TGT later on
			// This is needed to prevent session sync when we're not saml20
			htSessionContext.put("authsp_type", "saml20");
			htSessionContext.put("federation_url", sFederationUrl);
			_oSessionManager.updateSession(sRid, htSessionContext);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Get MetaData Url=" + sFederationUrl);
			MetaDataManagerSp metadataMgr = MetaDataManagerSp.getHandle();
			// We currently have the Redirect Binding only
			String sDestination = metadataMgr.getLocation(sFederationUrl,
					SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME, singleSignOnServiceBindingConstantREDIRECT);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Using Location retrieved from IDP=" + sDestination);

			String sApplicationId = (String) htSessionContext.get("app_id");
			String sApplicationLevel = getApplicationLevel(sApplicationId);
			String sAuthnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sApplicationLevel, _systemLogger);
			// 20100428, Bauke: old: String sAuthnContextClassRefURI = levelMap.get(sApplicationLevel);
			if (sAuthnContextClassRefURI == null) {
				// this level was not configured. Log it and inform the user
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Application Level " + sApplicationLevel
						+ " is not configured");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_APP_LEVEL);
			}
			
			// Send SAML request to the IDP
			XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

			SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
					.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();

			authnContextClassRef.setAuthnContextClassRef(sAuthnContextClassRefURI);

			SAMLObjectBuilder<RequestedAuthnContext> requestedAuthnContextBuilder = (SAMLObjectBuilder<RequestedAuthnContext>) builderFactory
					.getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
			RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
			requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
			
			// 20100311, Bauke: added for eHerkenning
			PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sFederationUrl);
			String specialSettings = (partnerData == null)? null: partnerData.getSpecialSettings();
			if (specialSettings != null && specialSettings.contains("minimum"))
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
			else
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
			
			SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer issuer = issuerBuilder.buildObject();
			// 20100311, Bauke: Alternate Issuer, added for eHerkenning
			if (partnerData != null && partnerData.getLocalIssuer() != null)
				issuer.setValue(partnerData.getLocalIssuer());
			else
				issuer.setValue(sMyUrl);

			// AuthRequest
			SAMLObjectBuilder<AuthnRequest> authnRequestbuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
					.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
			AuthnRequest authnRequest = authnRequestbuilder.buildObject();
			
			// 20100311, Bauke: added for eHerkenning
			// The assertion consumer url must be set to the value in the Metadata:
			authnRequest.setAssertionConsumerServiceURL(_sAssertionConsumerUrl);
			authnRequest.setProtocolBinding(Saml20_Metadata.assertionConsumerServiceBindingConstantARTIFACT);
			authnRequest.setAttributeConsumingServiceIndex(2);

			authnRequest.setDestination(sDestination);
			DateTime tStamp = new DateTime();
			// Set interval conditions
			authnRequest = (AuthnRequest) SamlTools.setValidityInterval(authnRequest, tStamp, getMaxNotBefore(), getMaxNotOnOrAfter());

			// 20100531, Bauke, use Rid but add part of the timestamp to make the ID unique
			// The AssertionConsumer will strip it off to regain our Rid value
			String timePostFix = String.format("%02d%02d%02d%03d", tStamp.getHourOfDay(), tStamp.getMinuteOfHour(), tStamp.getSecondOfMinute(), tStamp.getMillisOfSecond());
			authnRequest.setID(sRid+timePostFix);

			authnRequest.setProviderName(_sServerId);
			authnRequest.setVersion(SAMLVersion.VERSION_20);
			authnRequest.setIssuer(issuer);
			authnRequest.setIssueInstant(new DateTime());  // 20100712
			authnRequest.setRequestedAuthnContext(requestedAuthnContext);

			// Check if we have to set the ForceAuthn attribute
			// 20090613, Bauke: use forced_authenticate (not forced_logon)!
			Boolean bForcedAuthn = (Boolean) htSessionContext.get("forced_authenticate");
			if (bForcedAuthn == null)
				bForcedAuthn = false;
			// 20100311, Bauke: "force" special_setting added for eHerkenning
			if (bForcedAuthn || (specialSettings != null && specialSettings.contains("force"))) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting the ForceAuthn attribute");
				authnRequest.setForceAuthn(true);
			}
			
			//
			// We have the AuthnRequest, now get it to the other side
			//
			boolean useSha256 = (specialSettings != null && specialSettings.contains("sha256"));
			if (_sHttpMethod.equals("GET")) {
				// No use signing the AuthnRequest, it's even forbidden according to the Saml specs
				// Brent Putman quote: The Redirect-DEFLATE binding encoder strips off the protocol message's ds:Signature element (if even present)
				// before the marshalling and signing operations. Per the spec, it's not allowed to carry the signature that way.
				SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
						.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
				Endpoint samlEndpoint = endpointBuilder.buildObject();
				samlEndpoint.setLocation(sDestination);
				samlEndpoint.setResponseLocation(sMyUrl);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "EndPoint="+samlEndpoint+"Destination="+sDestination);
				
				//HttpServletResponseAdapter outTransport = SamlTools.createHttpServletResponseAdapter(response, sDestination);
				HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response,
							(sDestination == null)? false: sDestination.toLowerCase().startsWith("https"));
				
				// RH, 20081113, set appropriate headers
				outTransport.setHeader("Pragma", "no-cache");
				outTransport.setHeader("Cache-Control", "no-cache, no-store");
	
				BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
				messageContext.setOutboundMessageTransport(outTransport);
				messageContext.setOutboundSAMLMessage(authnRequest);
				messageContext.setPeerEntityEndpoint(samlEndpoint);
	
				BasicX509Credential credential = new BasicX509Credential();
				PrivateKey key = _configManager.getDefaultPrivateKey();
				credential.setPrivateKey(key);
				messageContext.setOutboundSAMLMessageSigningCredential(credential);
	
				// 20091028, Bauke: use RelayState to transport rid to my AssertionConsumer
				messageContext.setRelayState("idp=" + sFederationUrl);
	
				MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
				Marshaller marshaller = marshallerFactory.getMarshaller(messageContext.getOutboundSAMLMessage());
				Node nodeMessageContext = marshaller.marshall(messageContext.getOutboundSAMLMessage());
				_systemLogger.log(Level.INFO, MODULE, sMethod, "OutboundSAMLMessage:\n"+XMLHelper.prettyPrintXML(nodeMessageContext));
				
				if (useSha256) {
					Saml20_RedirectEncoder encoder = new Saml20_RedirectEncoder();
					encoder.encode(messageContext);  // does a sendRedirect()
				}
				else {
					// HTTPRedirectDeflateEncoder: SAML 2.0 HTTP Redirect encoder using the DEFLATE encoding method.
					// This encoder only supports DEFLATE compression and DSA-SHA1 and RSA-SHA1 signatures.
					HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
					encoder.encode(messageContext);  // does a sendRedirect()
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Ready "+messageContext);
			}
			else {  // POST
				// 20100331, Bauke: added support for HTTP POST
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the authnRequest >======"+authnRequest);
				authnRequest = (AuthnRequest)SamlTools.signSamlObject(authnRequest, useSha256? "sha256": "sha1");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the authnRequest ======<"+authnRequest);

				String sAssertion = XMLHelper.nodeToString(authnRequest.getDOM());
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Assertion=" + sAssertion);
				try {
					byte[] bBase64Assertion = sAssertion.getBytes("UTF-8");
					BASE64Encoder b64enc = new BASE64Encoder();
					sAssertion = b64enc.encode(bBase64Assertion);
				}
				catch (UnsupportedEncodingException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}

				// Let's POST the token
				String sInputs = buildHtmlInput("RelayState", "idp=" + sFederationUrl);
				sInputs += buildHtmlInput("SAMLResponse", sAssertion);  //Tools.htmlEncode(nodeMessageContext.getTextContent()));
				
				// 20100317, Bauke: pass language to IdP (does not work in the GET version)
				String sLang = (String)htSessionContext.get("language");
				if (sLang != null)
					sInputs += buildHtmlInput("language",sLang);
	
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Inputs=" + sInputs);
				handlePostForm(_sPostTemplate, sDestination, sInputs, response);
			}
		}
		catch (ASelectException e) { // pass unchanged to the caller
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return new RequestState(null);
	}

	/**
	 * Gets the application level.
	 * 
	 * @param sApplicationId
	 *            the s application id
	 * @return the application level
	 * @throws ASelectException
	 *             the a select exception
	 */
	private String getApplicationLevel(String sApplicationId)
		throws ASelectException
	{
		String sMethod = "getApplicationLevel()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Id=" + sApplicationId);

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
}
