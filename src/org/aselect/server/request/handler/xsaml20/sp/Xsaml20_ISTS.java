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
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.Saml20_RedirectEncoder;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Base64Codec;
import org.aselect.system.utils.Tools;
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
	protected final String singleSignOnServiceBindingConstantHTTPPOST = SAMLConstants.SAML2_POST_BINDING_URI;
	
	private String _sServerId = null; // <server_id> in <aselect>
	
	private String _sAssertionConsumerUrl = null;
	private String _sPostTemplate = null;
	private String _sHttpMethod = "GET";
	private String _sIdpResourceGroup = null;
	private String _sFallbackUrl = null;
	private String _sRedirectSyncTime = null;
	private boolean bIdpSelectForm = false;

	// Example configuration
	//
	// <handler id="saml20_ists" target="/saml20_ists.*"
	// class="org.aselect.server.request.handler.xsaml20.Xsaml20_ISTS">
	//
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";
		Object sam = null;
		Object agent = null;
		Object idpSection = null;
	
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

		_sServerId = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);

		_sHttpMethod = ASelectConfigManager.getSimpleParam(oConfig, "http_method", false);
		if (_sHttpMethod != null && _sHttpMethod.equalsIgnoreCase("POST"))
			_sHttpMethod = "POST";
		else
			_sHttpMethod = "GET";
		
		if (_sHttpMethod.equals("POST"))
			_sPostTemplate = readTemplateFromConfig(oConfig, "post_template");

		String sUseIdpSelectForm = ASelectConfigManager.getSimpleParam(oConfig, "use_idp_select", false);
		if (sUseIdpSelectForm != null && sUseIdpSelectForm.equals("true"))
			bIdpSelectForm = true;

		_sIdpResourceGroup = ASelectConfigManager.getSimpleParam(oConfig, "resourcegroup", false);
		if (_sIdpResourceGroup == null)
			_sIdpResourceGroup = "federation-idp";  // backward compatibility
		_systemLogger.log(Level.INFO, MODULE, sMethod, "IDP resourcegroup="+_sIdpResourceGroup);

		_sFallbackUrl = ASelectConfigManager.getSimpleParam(oConfig, "fallback_url", false);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "fallback_url="+_sFallbackUrl);
		
		// Find the resourcegroup
		sam = _configManager.getSection(null, "sam");
		agent = _configManager.getSection(sam, "agent");
		try {
			Object metaResourcegroup = _configManager.getSection(agent, "resourcegroup", "id=" + _sIdpResourceGroup);
			idpSection = _configManager.getSection(metaResourcegroup, "resource");
		}		
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No resourcegroup: "+_sIdpResourceGroup+" configured");
		}
		
		// And pass it's resources to the metadata manager
		MetaDataManagerSp metadataMgr = MetaDataManagerSp.getHandle();  // will create the MetaDataManager object
		while (idpSection != null) {
			metadataMgr.processResourceSection(idpSection);
			idpSection = _configManager.getNextSection(idpSection);
		}
		metadataMgr.logIdPs();
		
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
				// The Assertion Consumer
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
	public RequestState process(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "process";
		String sRid;
		String sFederationUrl = null;
		PrintWriter pwOut = null;

		String sMyUrl = _sServerUrl; // extractAselectServerUrl(request);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "MyUrl=" + sMyUrl + " MyId="+getID()+ " path=" + servletRequest.getPathInfo());

		try {
			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

			sRid = servletRequest.getParameter("rid");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing RID parameter");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Find the associated session context
			_htSessionContext = _oSessionManager.getSessionContext(sRid);
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found for RID: " + sRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			// Session present
			Tools.resumeSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102, can change the session
			// 20091028, Bauke, let the user choose which IdP to use
			// 20110308, Bauke: changed, user chooses when "use_idp_select" is "true"
			//     otherwise this handler uses it's own resource group to get a resource and sets "federation_url"
			//     to the id of that resource
			sFederationUrl = servletRequest.getParameter("federation_url");
			
			//int cnt = MetaDataManagerSp.getHandle().getIdpCount();
			//if (cnt == 1) {
			//	sFederationUrl = MetaDataManagerSp.getHandle().getDefaultIdP(); // there can only be one
			//}
			if (bIdpSelectForm && (!Utils.hasValue(sFederationUrl))) {
				// No Federation URL choice made yet, allow the user to choose
				String sIdpSelectForm = Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(), null/*subdir*/,
						"idpselect", _sUserLanguage, _configManager.getOrgFriendlyName(), Version.getVersion());
				sIdpSelectForm = Utils.replaceString(sIdpSelectForm, "[rid]", sRid);
				// Not backward compatible! [aselect_url] used to be server_url/handler_id,
				// they're separated now to allow use of [aselect_url] in the traditional way too!
				sIdpSelectForm = Utils.replaceString(sIdpSelectForm, "[handler_url]", sMyUrl + "/" + getID());
				sIdpSelectForm = Utils.replaceString(sIdpSelectForm, "[aselect_url]", sMyUrl); // 20110310 + "/" + getID());
				sIdpSelectForm = Utils.replaceString(sIdpSelectForm, "[handler_id]", getID());
				sIdpSelectForm = Utils.replaceString(sIdpSelectForm, "[a-select-server]", _sServerId);  // 20110310
				//sSelectForm = Utils.replaceString(sSelectForm, "[language]", sLanguage);
				sIdpSelectForm = _configManager.updateTemplate(sIdpSelectForm, _htSessionContext, servletRequest);  // 20130822, Bauke: added to show requestor_friendly_name
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Template updated, [handler_url]="+sMyUrl + "/" + getID());

				_htSessionContext.put("user_state", "state_idpselect");			
				_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120403, Bauke: was updateSession
				Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102 can update the session
				pwOut.println(sIdpSelectForm);
				return new RequestState(null);
			}
			// federation_url was set or bIdpSelectForm is false
			_systemLogger.log(Level.FINER, MODULE, sMethod, "federation_url="+sFederationUrl);
			_htSessionContext.put("user_state", "state_toidp");  // at least remove state_select
			_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120403, Bauke: was updateSession

			// 20110308, Bauke: new mechanism to get to the IdP using the SAM agent (allows redundant resources)
			// User choice was made, or "federation_url" was set programmatically
			ASelectSAMAgent samAgent = ASelectSAMAgent.getHandle();
			SAMResource samResource = null;
			try {
				samResource = samAgent.getActiveResource(_sIdpResourceGroup);
			}
			catch (ASelectSAMException ex) {  // no active resource
				// if a fallback is present: REDIRECT to the authsp
				if (Utils.hasValue(_sFallbackUrl)) {
					// Don't come back here:
					_htSessionContext.remove("forced_authsp");
					// 20110331, Bauke: We leave forced_uid in place!
					// If we do, control can easily be transferred to e.g. DigiD
					//htSessionContext.remove("forced_uid");
					_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120403, Bauke: added

					String sRedirectUrl = _sFallbackUrl;
					//sRedirectUrl = "[aselect_url]?request=direct_login1&rid=[rid]&authsp=Ldap&a-select-server=[a-select-server]";
					sRedirectUrl = Utils.replaceString(sRedirectUrl, "[aselect_url]", sMyUrl);
					sRedirectUrl = Utils.replaceString(sRedirectUrl, "[a-select-server]", _sServerId);
					sRedirectUrl = Utils.replaceString(sRedirectUrl, "[rid]", sRid);
					//sRedirectUrl = Utils.replaceString(sRedirectUrl, "[language]", sLanguage);
					_systemLogger.log(Level.FINER, MODULE, sMethod, "Fallback REDIRECT to: " + sRedirectUrl);
					
					Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102 can change the session
					//_oSessionManager.updateSession(sRid, _htSessionContext);  // 20120403, Bauke: removed
					servletResponse.sendRedirect(sRedirectUrl);
					return new RequestState(null);
				}
				else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No active resource available");
					throw new ASelectSAMException(Errors.ERROR_ASELECT_SAM_UNAVALABLE);
				}
			}
			// The result is a single resource from our own resourcegroup
			sFederationUrl = samResource.getId();
			_systemLogger.log(Level.FINER, MODULE, sMethod, "IdP resource id="+sFederationUrl);

			// 20090811, Bauke: save type of Authsp to store in the TGT later on
			// This is needed to prevent session sync when we're not saml20
			_htSessionContext.put("authsp_type", "saml20");
			_htSessionContext.put("federation_url", sFederationUrl);
			_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120403, Bauke: was updateSession

			_systemLogger.log(Level.FINER, MODULE, sMethod, "Get MetaData FederationUrl=" + sFederationUrl);
			MetaDataManagerSp metadataMgr = MetaDataManagerSp.getHandle();
			// RM_57_01
			// RM_57_02
			// We now support the Redirect and POST Binding
			String sDestination = null;
			if ("POST".equalsIgnoreCase(_sHttpMethod)) {
				sDestination = metadataMgr.getLocation(sFederationUrl,
						SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME, singleSignOnServiceBindingConstantHTTPPOST);
			} else {
				sDestination = metadataMgr.getLocation(sFederationUrl,
						SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME, singleSignOnServiceBindingConstantREDIRECT);
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Location retrieved=" + sDestination);
			if ("".equals(sDestination))
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);

			String sApplicationId = (String)_htSessionContext.get("app_id");
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
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Partnerdata: "+partnerData);
			String specialSettings = (partnerData == null)? null: partnerData.getSpecialSettings();
			if (specialSettings != null && specialSettings.contains("minimum"))
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
			else
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
			
			// 20120706, Bauke: save in session, must be transferred to TGT and used for Digid4 session_sync mechanism
			String sst = partnerData.getRedirectSyncTime();
			if (Utils.hasValue(sst)) {
				_htSessionContext.put("redirect_sync_time", sst);
				_htSessionContext.put("redirect_ists_url", sMyUrl + "/" + getID());
				_htSessionContext.put("redirect_post_form", partnerData.getRedirectPostForm());
				_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);
			}
			
			SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer issuer = issuerBuilder.buildObject();
			// 20100311, Bauke: Alternate Issuer, added for eHerkenning
			if (partnerData != null && partnerData.getLocalIssuer() != null)
				issuer.setValue(partnerData.getLocalIssuer());
			else
				issuer.setValue(sMyUrl);

			// AuthnRequest
			SAMLObjectBuilder<AuthnRequest> authnRequestbuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
					.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
			AuthnRequest authnRequest = authnRequestbuilder.buildObject();

			// We should be able to set AssertionConsumerServiceIndex. This is according to saml specs mutually exclusive with
			// ProtocolBinding and AssertionConsumerServiceURL
			
			if (partnerData !=null)
				_systemLogger.log(Level.FINER, MODULE, sMethod, "acsi="+partnerData.getAssertionConsumerServiceindex());
			
			if  (partnerData != null && partnerData.getAssertionConsumerServiceindex() != null) {
				authnRequest.setAssertionConsumerServiceIndex(Integer.parseInt(partnerData.getAssertionConsumerServiceindex() ));
			}
			else {	 // mutually exclusive
				// 20100311, Bauke: added for eHerkenning
				// The assertion consumer url must be set to the value in the Metadata:
				// 20101112, RH, added support for POST binding
				if (specialSettings != null && specialSettings.toUpperCase().contains("POST"))
					authnRequest.setProtocolBinding(Saml20_Metadata.singleSignOnServiceBindingConstantPOST);
				else	// backward compatibility, defaults to ARTIFACT
					authnRequest.setProtocolBinding(Saml20_Metadata.assertionConsumerServiceBindingConstantARTIFACT);
	
				// We should be able to not set setAssertionConsumerServiceURL and let IDP get it from metadata
				// But not sure if all idp's will handle that well
				if (partnerData != null && partnerData.getDestination() != null) {
					if (!"".equals(partnerData.getDestination().trim())) {	// if empty, let the idp look for the AssertionConsumerServiceURL in metadata 
						authnRequest.setAssertionConsumerServiceURL(partnerData.getDestination());
					}
				}
				else {	// backward compatibility, default to _sAssertionConsumerUrl
					authnRequest.setAssertionConsumerServiceURL(_sAssertionConsumerUrl);
				}
			}
			
			// RH, 20140505, sn
			String sForcedAttrConServInd = ApplicationManager.getHandle().getForcedAttrConsServIndex(sApplicationId);
			if ( sForcedAttrConServInd != null ) {
				authnRequest.setAttributeConsumingServiceIndex(Integer.parseInt(sForcedAttrConServInd));
			} else {
				// RH, 20140505, en

				if  (partnerData != null && partnerData.getAttributeConsumerServiceindex() != null) {
					authnRequest.setAttributeConsumingServiceIndex(Integer.parseInt(partnerData.getAttributeConsumerServiceindex() ));
				} else {	// be backwards compatible
					authnRequest.setAttributeConsumingServiceIndex(2);
				}

			}// RH, 20140505, n
			
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
			Boolean bForcedAuthn = (Boolean)_htSessionContext.get("forced_authenticate");
			if (bForcedAuthn == null)
				bForcedAuthn = false;
			// 20100311, Bauke: "force" special_setting added for eHerkenning
			if (bForcedAuthn || (specialSettings != null && specialSettings.contains("force"))) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting the ForceAuthn attribute");
				authnRequest.setForceAuthn(true);
			}

			// 20140924, RH: "force_passive" special_setting (only for testing yet)
			// If needed in production must have its own element/attribuut in config
			Boolean bForcedPassive = (Boolean)_htSessionContext.get("forced_passive");
			if (bForcedPassive || (specialSettings != null && specialSettings.contains("passive"))) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting the IsPassive attribute");
				authnRequest.setIsPassive(true);
			}

			
			// Handle testdata
			if (partnerData.getTestdata4partner() != null) {
				String timeOffset = partnerData.getTestdata4partner().getIssueInstant();
				if (timeOffset != null) {
//					if (timeOffset.startsWith("-")) {
//						authnRequest.setIssueInstant(new DateTime().minus(1000*Long.parseLong(timeOffset)));
//					} else {
						authnRequest.setIssueInstant(new DateTime().plus(1000*Long.parseLong(timeOffset)));
//					}
					// RM_57_03
				}
				if (partnerData.getTestdata4partner().getIssuer() != null) {
					authnRequest.getIssuer().setValue(partnerData.getTestdata4partner().getIssuer());
				}
				if (partnerData.getTestdata4partner().getAuthnContextClassRefURI() != null) {
					// There should be one so take first
					authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).setAuthnContextClassRef(partnerData.getTestdata4partner().getAuthnContextClassRefURI());
				}
				if (partnerData.getTestdata4partner().getAuthnContextComparisonTypeEnumeration() != null) {
					if ("minimum".equalsIgnoreCase( partnerData.getTestdata4partner().getAuthnContextComparisonTypeEnumeration()) ) 
						requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
					else if ("exact".equalsIgnoreCase( partnerData.getTestdata4partner().getAuthnContextComparisonTypeEnumeration()) ) 
						requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
						else if ("better".equalsIgnoreCase( partnerData.getTestdata4partner().getAuthnContextComparisonTypeEnumeration()) ) 
							requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
							else if ("maximum".equalsIgnoreCase( partnerData.getTestdata4partner().getAuthnContextComparisonTypeEnumeration()) ) 
								requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
				}
				if ( partnerData.getTestdata4partner() .getForceAuthn() != null) {
					authnRequest.setForceAuthn(Boolean.parseBoolean(partnerData.getTestdata4partner() .getForceAuthn()));
				}
				if (partnerData.getTestdata4partner() .getProviderName() != null) {
					authnRequest.setProviderName(partnerData.getTestdata4partner() .getProviderName());
					
				}
				if (partnerData.getTestdata4partner() .getAssertionConsumerServiceIndex() != null) {
					// RM_57_04
					authnRequest.setAssertionConsumerServiceIndex(Integer.parseInt(partnerData.getTestdata4partner() .getAssertionConsumerServiceIndex()));
				}
				if (partnerData.getTestdata4partner() .getAssertionConsumerServiceURL() != null) {
					authnRequest.setAssertionConsumerServiceURL(partnerData.getTestdata4partner() .getAssertionConsumerServiceURL());
				}
				if (partnerData.getTestdata4partner() .getDestination() != null) {
					authnRequest.setDestination(partnerData.getTestdata4partner() .getDestination());
				}
				
			}
			
			
			// 20100908, Bauke: Look for aselect_specials!
			// In app_url or in the caller's RelayState (if we're an IdP)
			String sSpecials = null;
			if (specialSettings != null && specialSettings.contains("relay_specials")) {
				sSpecials = Utils.getAselectSpecials(_htSessionContext, false/*leave base64*/, _systemLogger);
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "<special_settings>="+specialSettings+" aselect_specials="+sSpecials);
			
			// Create the new RelayState
			String sRelayState = "idp=" + sFederationUrl;
			if (specialSettings != null && specialSettings.contains("relay_specials")) {	
				if (Utils.hasValue(sSpecials))
					sRelayState += "&aselect_specials="+sSpecials;
				sRelayState = Base64Codec.encode(sRelayState.getBytes());
				_systemLogger.log(Level.FINER, MODULE, sMethod, "RelayState="+sRelayState);
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
				_systemLogger.log(Level.FINER, MODULE, sMethod, "GET EndPoint="+samlEndpoint+" Destination="+sDestination);
				
				//HttpServletResponseAdapter outTransport = SamlTools.createHttpServletResponseAdapter(response, sDestination);
				HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(servletResponse,
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
				messageContext.setRelayState(sRelayState);
	
				MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
				Marshaller marshaller = marshallerFactory.getMarshaller(messageContext.getOutboundSAMLMessage());
				Node nodeMessageContext = marshaller.marshall(messageContext.getOutboundSAMLMessage());
				_systemLogger.log(Level.FINER, MODULE, sMethod, "RelayState="+sRelayState+" OutboundSAMLMessage:\n"+XMLHelper.prettyPrintXML(nodeMessageContext));
				
				if (useSha256) {
					Saml20_RedirectEncoder encoder = new Saml20_RedirectEncoder();  // is a HTTPRedirectDeflateEncoder
					encoder.encode(messageContext);  // does a sendRedirect()
				}
				else {
					// HTTPRedirectDeflateEncoder: SAML 2.0 HTTP Redirect encoder using the DEFLATE encoding method.
					// This encoder only supports DEFLATE compression and DSA-SHA1 and RSA-SHA1 signatures.
					HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
					encoder.encode(messageContext);  // does a sendRedirect()
				}
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Ready "+messageContext);
			}
			else {  // POST
				// 20100331, Bauke: added support for HTTP POST
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Sign the authnRequest >======"+authnRequest);
				authnRequest = (AuthnRequest)SamlTools.signSamlObject(authnRequest, useSha256? "sha256": "sha1", 
							"true".equalsIgnoreCase(partnerData.getAddkeyname()), "true".equalsIgnoreCase(partnerData.getAddcertificate()) );
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Signed the authnRequest ======<"+authnRequest);

				String sAssertion = XMLHelper.nodeToString(authnRequest.getDOM());
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Assertion=" + sAssertion);
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
				String sInputs = buildHtmlInput("RelayState", sRelayState);
//				sInputs += buildHtmlInput("SAMLResponse", sAssertion);  //Tools.htmlEncode(nodeMessageContext.getTextContent()));
				// RH, 20101104, this should be a SAMLRequest, we were just lucky the other side didn't bother   
				sInputs += buildHtmlInput("SAMLRequest", sAssertion);  //Tools.htmlEncode(nodeMessageContext.getTextContent()));
				
				// 20100317, Bauke: pass language to IdP (does not work in the GET version)
				String sLang = (String)_htSessionContext.get("language");
				if (sLang != null)
					sInputs += buildHtmlInput("language",sLang);
	
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Inputs=" + Utils.firstPartOf(sInputs,200));
				handlePostForm(_sPostTemplate, sDestination, sInputs, servletRequest, servletResponse);
			}
			Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102 can change the session
		}
		catch (ASelectException e) { // pass unchanged to the caller
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			if (pwOut != null)
				pwOut.close();
			
			// 20130821, Bauke: save friendly name after session is gone
			if (_htSessionContext != null) {
				String sStatus = (String)_htSessionContext.get("status");
				String sAppId = (String)_htSessionContext.get("app_id");
				if ("del".equals(sStatus) && Utils.hasValue(sAppId)) {
					String sUF = ApplicationManager.getHandle().getFriendlyName(sAppId);
					HandlerTools.setEncryptedCookie(servletResponse, "requestor_friendly_name", sUF, _configManager.getCookieDomain(), -1/*age*/, _systemLogger);
				}
			}
			_oSessionManager.finalSessionProcessing(_htSessionContext, true/*update session*/);
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
		String sMethod = "getApplicationLevel";
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
