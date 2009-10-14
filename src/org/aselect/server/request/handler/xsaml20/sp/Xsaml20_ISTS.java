package org.aselect.server.request.handler.xsaml20.sp;

import java.security.PrivateKey;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
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

	private String _sServerId; // <server_id> in <aselect>
	private String _sFederationUrl;
	private HashMap<String, String> levelMap;

	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init()";

		try {
	        super.init(oServletConfig, oConfig);
	    }
	    catch (ASelectException e) {  // pass to caller
	        throw e;
	    }
	    catch (Exception e) {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	    // TODO, remove this bootstrap, is done by Saml20_BaseHandler, RH, 20080721, n
		/*try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Saml Bootstrap");
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot initialize the OpenSAML library", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}*/

		_sServerId = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);
		_sFederationUrl = ASelectConfigManager.getSimpleParam(oConfig, "federation_url", true);

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
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'uri' found in handler section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}
	
	// Example configuration
	//
	// <handler id="saml20_ists"
    //    class="org.aselect.server.request.handler.xsaml20.Xsaml20_ISTS"
    //    target="/saml20_ists.*">
    // <federation_url>https://testsiam.extern.umcn.nl/aselectserver/server</federation_url>
	//    <security level="5" uri="urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified" />
	//    <security level="10" uri="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" />
	//    <security level="20" uri="urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract" />
	//    <security level="30" uri="urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI" />
	// </handler>
	//
	// "federation_url" contains a default value used when it's not given in the request
	//
	@SuppressWarnings("unchecked")
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
    throws ASelectException
    {
        String sMethod = "process()";
		String sRid;
		String sFederationUrl = null;
		String sMyUrl = _sServerUrl;  // extractAselectServerUrl(request);
        _systemLogger.log(Level.INFO, MODULE, sMethod, "MyUrl="+sMyUrl+" Request="+request);
        
        try {
	        sFederationUrl = request.getParameter("federation_url");
	        if (sFederationUrl == null || sFederationUrl.equals(""))
	        	sFederationUrl = _sFederationUrl;  // use the default
	        sRid = request.getParameter("rid");
	        if (sRid == null) {
	            _systemLogger.log(Level.WARNING,MODULE,sMethod, "Missing RID parameter");
	            throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
	        }

	        // Find the associated session context
	        HashMap htSessionContext = _oSessionManager.getSessionContext(sRid);
	        if (htSessionContext == null) {
	            _systemLogger.log(Level.WARNING,MODULE,sMethod, "No session found for RID: "+sRid);	            
	            throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
	        }
	        
	        // 20090811, Bauke: save type of Authsp to store in the TGT later on
	        // This is needed to prevent session sync when we're not saml20
	        htSessionContext.put("authsp_type", "saml20");
			_oSessionManager.updateSession(sRid, htSessionContext);
	        
			/* 20090113, Bauke TRY TO SKIP THIS CODE, "remote_organization" will not be set
			CrossASelectManager oCrossASelectManager = CrossASelectManager.getHandle();
			// Gets from organization key/value = id/friendforced_ly_name
			HashMap htRemoteServers = oCrossASelectManager.getRemoteServers();
			Enumeration enRemoteOrganizationIds = htRemoteServers.keys();
			String sRemoteOrganization = (String) enRemoteOrganizationIds.nextElement();

			htSessionContext.put("remote_organization", sRemoteOrganization);
			_oSessionManager.updateSession(sRid, htSessionContext);
			*/

	        _systemLogger.log(Level.INFO, MODULE, sMethod, "Get MetaData");
			MetaDataManagerSp metadataMgr = MetaDataManagerSp.getHandle();
			// TODO maybe allow for other BINDINGs
			String sDestination = metadataMgr.getLocation(sFederationUrl, SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME, singleSignOnServiceBindingConstantREDIRECT);
	        _systemLogger.log(Level.INFO, MODULE, sMethod, "Using Location retrieved from IDP="+sDestination);

	        String sApplicationId = (String) htSessionContext.get("app_id");
			String sApplicationLevel = getApplicationLevel(sApplicationId);
			String sAuthnContextClassRefURI = levelMap.get(sApplicationLevel);
			if (sAuthnContextClassRefURI == null) {
				// this level was not configured. Log it and inform the user
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Application Level " + sApplicationLevel + " is not configured");
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
			requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
	
			SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer issuer = issuerBuilder.buildObject();
			issuer.setValue(sMyUrl);
	
			// AuthRequest
			SAMLObjectBuilder<AuthnRequest> authnRequestbuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
					.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
			AuthnRequest authnRequest = authnRequestbuilder.buildObject();
			authnRequest.setAssertionConsumerServiceURL(sMyUrl);
			authnRequest.setDestination(sDestination);
			authnRequest.setID(sRid);
			DateTime tStamp = new DateTime();
			authnRequest.setIssueInstant(tStamp);
			// Set interval conditions
			authnRequest = (AuthnRequest)SamlTools.setValidityInterval(authnRequest, tStamp, getMaxNotBefore(), getMaxNotOnOrAfter());
			
			authnRequest.setProviderName(_sServerId);
			authnRequest.setVersion(SAMLVersion.VERSION_20);
			authnRequest.setIssuer(issuer);
			authnRequest.setRequestedAuthnContext(requestedAuthnContext);
			
			// Check if we have to set the ForceAuthn attribute
			// 20090613, Bauke: use forced_authenticate (not forced_logon)!
			Boolean bForcedAuthn = (Boolean)htSessionContext.get("forced_authenticate");
			if (bForcedAuthn == null) bForcedAuthn = false;
			//String sForcedLogin = (String) htSessionContext.get("forced_logon");
	        //if ("true".equalsIgnoreCase(sForcedLogin)) {
			if (bForcedAuthn) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting the ForceAuthn attribute");
	        	authnRequest.setForceAuthn(true);
	        }

			SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
					.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
			Endpoint samlEndpoint = endpointBuilder.buildObject();
			samlEndpoint.setLocation(sDestination);
			samlEndpoint.setResponseLocation(sMyUrl);
	
//			HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response); // RH 20080529, o
			HttpServletResponseAdapter outTransport = SamlTools.createHttpServletResponseAdapter(response, sDestination); // RH 20080529, n
			// RH, 20081113, set appropriate headers
			outTransport.setHeader("Pragma", "no-cache");
			outTransport.setHeader("Cache-Control", "no-cache, no-store");
			
			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setOutboundMessageTransport(outTransport);
			messageContext.setOutboundSAMLMessage(authnRequest);
			messageContext.setPeerEntityEndpoint(samlEndpoint);
			//messageContext.setRelayState("federation_url="+sFederationUrl);  // 20090526: we're not using RelayState here
	
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
        catch (ASelectException e) {  // pass unchanged to the caller
        	throw e;
        }
        catch (Exception e) {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
		return new RequestState(null);
	}
	
	private String getApplicationLevel(String sApplicationId)
	throws ASelectException
	{
		String sMethod = "getApplicationLevel()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Id="+sApplicationId);
		
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
