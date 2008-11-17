package org.aselect.server.request.handler.xsaml20.idp;

import java.util.logging.Level;

import org.apache.xerces.util.DOMUtil;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.AuthzService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.XMLSignatureBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.opensaml.xml.util.XMLHelper;

// Configuration example
//
// <handler id="saml20_idp_metadata"
//    class="org.aselect.server.request.handler.xsaml20.idp.Xsaml20_Metadata_handler"
//    target="/saml20_idp_metadata">
// </handler>
//
public class Xsaml20_Metadata_handler extends Saml20_Metadata
{
	private final static String MODULE = "idp.Xsaml20_Metadata_handler";

	protected void aselectReader() // Get handler specific data from configuration 
	throws ASelectException
	{
		String sMethod = "aselectReader()";
	
		Object oRequest = null;
		Object oHandlers = null;
		Object oHandler = null;
		super.aselectReader();
	
		setSingleSignOnServiceTarget(getRedirectURL()); // We use redirect_url (for now)
		try {
			oRequest = _configManager.getSection(null, "requests");
			oHandlers = _configManager.getSection(oRequest, "handlers");
			oHandler = _configManager.getSection(oHandlers, "handler");
	
			// Get targets for our handlers
			// NOTE: id's must match the configuration!
			for ( ; oHandler != null; oHandler = _configManager.getNextSection(oHandler)) {
				try {
					String sId = _configManager.getParam(oHandler, "id");
					if (!sId.startsWith("saml20_")) {
						continue;
					}
					String sTarget = _configManager.getParam(oHandler, "target");
					_systemLogger.log(Level.INFO, MODULE, sMethod, "id="+sId+" target="+sTarget);
					sTarget = sTarget.replace("\\", "");
					sTarget = sTarget.replace(".*", "");

					if (sId.equals("saml20_artifactresolver")) {
						setArtifactResolverTarget(sTarget);
					}
					else if (sId.equals("saml20_sso")) {
						setSingleSignOnServiceTarget(sTarget);
					}
					else if (sId.equals("saml20_idp_slo_http_request")) {
						setIdpSloHttpLocation(sTarget);
					}
					else if (sId.equals("saml20_idp_slo_http_response")) {
						setIdpSloHttpResponse(sTarget);
					}
					else if (sId.equals("saml20_idp_slo_soap_request")) {
						setIdpSloSoapLocation(sTarget);
					}
					else if (sId.equals("saml20_idp_slo_soap_response")) {
						setIdpSloSoapResponse(sTarget);
					}
					else if (sId.equals("saml20_idp_session_sync")) {
						setIdpSSSoapLocation(sTarget);
					}

				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config next section 'handler' found", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not find 'aselect' config section in config file",	e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	// entityID is redirect_url from aselect.xml
	// Create Metadata entries for IdP
	protected String createMetaDataXML() throws ASelectException
	{
		String sMethod = "createMetaDataXML()";
		String xmlMDRequest = null;
		
		DateTime tStamp = new DateTime();

/*
		// TODO, this should be done by a transformer (using xslt)
		String xmlMDRequest = "<?xml version=\"1.0\"?>"
				+ "<m:EntityDescriptor xmlns:m=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\""
				+ getEntityIdIdp() + "\">"
				+ "	<m:IDPSSODescriptor WantAuthnRequestsSigned=\"true\"  protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n";
		
		xmlMDRequest += "<m:KeyDescriptor use=\"signing\">" + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
				+ "<ds:X509Data>" + "<ds:X509Certificate>" + getSigningCertificate() + "</ds:X509Certificate>"
				+ "</ds:X509Data>" + "</ds:KeyInfo>" + "</m:KeyDescriptor>\n";
		
		if (getSingleSignOnServiceTarget() != null)
			xmlMDRequest += "<m:SingleSignOnService Binding=\"" + singleSignOnServiceBindingConstantREDIRECT + "\""
					+ " Location=\"" + getRedirectURL()+getSingleSignOnServiceTarget()
					+ "\">" + "</m:SingleSignOnService>\n";
		
		if (getArtifactResolverTarget() != null)
			xmlMDRequest += "<m:ArtifactResolutionService Binding=\"" + artifactResolutionServiceBindingConstantSOAP + "\"" 
					+ " Location=\"" + getRedirectURL()+getArtifactResolverTarget() + "\"" 
					+ " index=\"0\" isDefault=\"true\">" + "</m:ArtifactResolutionService>\n";
		
		if (getIdpSloHttpLocation() != null) {
			xmlMDRequest += "<m:SingleLogoutService Binding=\"" + singleLogoutServiceBindingConstantREDIRECT + "\""
							+ " Location=\"" + getRedirectURL()+getIdpSloHttpLocation();
			if (getIdpSloHttpResponse() != null)
				xmlMDRequest += "\" ResponseLocation=\"" + getRedirectURL()+getIdpSloHttpResponse();
			xmlMDRequest +=	"\"></m:SingleLogoutService>\n";
		}

		if (getIdpSloSoapLocation() != null) {				
			xmlMDRequest += "<m:SingleLogoutService Binding=\"" + singleLogoutServiceBindingConstantSOAP + "\""
					+ " Location=\"" + getRedirectURL()+getIdpSloSoapLocation();
			if (getIdpSloSoapResponse() != null)
				xmlMDRequest += "\" ResponseLocation=\"" + getRedirectURL()+getIdpSloSoapResponse();
			xmlMDRequest += "\">" + "</m:SingleLogoutService>\n";
		}
		
		xmlMDRequest += "</m:IDPSSODescriptor>" + "</m:EntityDescriptor>\n";
*/	
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Starting to build metadata");
		// Create the EntityDescriptor
		SAMLObjectBuilder<EntityDescriptor> entityDescriptorBuilder = (SAMLObjectBuilder<EntityDescriptor>) _oBuilderFactory
		.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		
		EntityDescriptor entityDescriptor = entityDescriptorBuilder.buildObject();
		entityDescriptor.setEntityID(getEntityIdIdp());
		entityDescriptor.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
		
		if (getValidUntil()!=null)
			entityDescriptor.setValidUntil(tStamp.plus(getValidUntil().longValue()));
		if (getCacheDuration()!=null)
			entityDescriptor.setCacheDuration(getCacheDuration());
		
/*		
		// Create the KeyDescriptor
		SAMLObjectBuilder<KeyDescriptor> keyDescriptorBuilder = (SAMLObjectBuilder<KeyDescriptor>) _oBuilderFactory
		.getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		KeyDescriptor keyDescriptor = keyDescriptorBuilder.buildObject();
		keyDescriptor.setUse(org.opensaml.xml.security.credential.UsageType.SIGNING);
		
		XMLSignatureBuilder<KeyInfo> keyInfoBuilder = (XMLSignatureBuilder<KeyInfo>) _oBuilderFactory
		.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
		KeyInfo keyInfo = keyInfoBuilder.buildObject();

		X509CertificateBuilder x509CertificateBuilder = (X509CertificateBuilder) _oBuilderFactory
		.getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME);
		X509Certificate x509Certificate = x509CertificateBuilder.buildObject();
		x509Certificate.setValue(getSigningCertificate());
		
		X509DataBuilder x509DataBuilder = (X509DataBuilder) _oBuilderFactory
		.getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
		X509Data x509Data = x509DataBuilder.buildObject();
		x509Data.getX509Certificates().add(x509Certificate);
		
		keyInfo.getX509Datas().add(x509Data);
		keyDescriptor.setKeyInfo(keyInfo);
*/
		
		// Create the IDPSSODescriptor
		SAMLObjectBuilder<IDPSSODescriptor> ssoDescriptorBuilder = (SAMLObjectBuilder<IDPSSODescriptor>) _oBuilderFactory
		.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
		IDPSSODescriptor ssoDescriptor = ssoDescriptorBuilder.buildObject();

		// Create the SingleSignOnService
		if (getSingleSignOnServiceTarget() != null) {
			SAMLObjectBuilder<SingleSignOnService> ssoServiceBuilder = (SAMLObjectBuilder<SingleSignOnService>) _oBuilderFactory
			.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);
			SingleSignOnService ssoService = ssoServiceBuilder.buildObject();
			ssoService.setBinding(singleSignOnServiceBindingConstantREDIRECT);
			ssoService.setLocation(getRedirectURL()+getSingleSignOnServiceTarget());
			ssoDescriptor.getSingleSignOnServices().add(ssoService);
		}

		// Create the ArtifactResolutionService
		if (getArtifactResolverTarget() != null) {
			SAMLObjectBuilder<ArtifactResolutionService> artResolutionSeviceBuilder = (SAMLObjectBuilder<ArtifactResolutionService>) _oBuilderFactory
			.getBuilder(ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
			ArtifactResolutionService artResolutionService = artResolutionSeviceBuilder.buildObject();
			artResolutionService.setBinding(artifactResolutionServiceBindingConstantSOAP);
			artResolutionService.setLocation(getRedirectURL()+getArtifactResolverTarget());
			artResolutionService.setIsDefault(true);
			artResolutionService.setIndex(0);
			ssoDescriptor.getArtifactResolutionServices().add(artResolutionService);
		}

		// Create the SingleLogoutService HTTP
		if (getIdpSloHttpLocation() != null) {
			SAMLObjectBuilder<SingleLogoutService> sloHttpServiceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
			.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
			SingleLogoutService sloHttpService = sloHttpServiceBuilder.buildObject();
			sloHttpService.setBinding(singleLogoutServiceBindingConstantREDIRECT);
			sloHttpService.setLocation(getRedirectURL()+getIdpSloHttpLocation());
			if (getIdpSloHttpResponse() != null)
				sloHttpService.setResponseLocation(getRedirectURL()+getIdpSloHttpResponse());

			ssoDescriptor.getSingleLogoutServices().add(sloHttpService);
		}

		// Create the SingleLogoutService SOAP
		if (getIdpSloSoapLocation() != null) {
			SAMLObjectBuilder<SingleLogoutService> sloSoaperviceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
			.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
			SingleLogoutService sloSoapService = sloSoaperviceBuilder.buildObject();
			sloSoapService.setBinding(singleLogoutServiceBindingConstantSOAP);
			sloSoapService.setLocation(getRedirectURL()+getIdpSloSoapLocation());
			if (getIdpSloSoapResponse() != null)
				sloSoapService.setResponseLocation(getRedirectURL()+getIdpSloSoapResponse());

			ssoDescriptor.getSingleLogoutServices().add(sloSoapService);
		}


		// Create the PDPDescriptor>
		SAMLObjectBuilder<PDPDescriptor> pdpDescriptorBuilder = (SAMLObjectBuilder<PDPDescriptor>) _oBuilderFactory
		.getBuilder(PDPDescriptor.DEFAULT_ELEMENT_NAME);
		PDPDescriptor pdpDescriptor = pdpDescriptorBuilder.buildObject();

		// Create the AuthDecisionQuery target
		if (getIdpSSSoapLocation() != null) {
			SAMLObjectBuilder<AuthzService> adqSoaperviceBuilder = (SAMLObjectBuilder<AuthzService>) _oBuilderFactory
			.getBuilder(AuthzService.DEFAULT_ELEMENT_NAME);
			AuthzService adqSoapService = adqSoaperviceBuilder.buildObject();
			adqSoapService.setBinding(authzServiceBindingConstantSOAP);
			adqSoapService.setLocation(getRedirectURL()+getIdpSSSoapLocation());
			pdpDescriptor.getAuthzServices().add(adqSoapService);
		}

		// Create final EntityDescriptor
		ssoDescriptor.setWantAuthnRequestsSigned(true);
//		ssoDescriptor.getKeyDescriptors().add(keyDescriptor);
		ssoDescriptor.getKeyDescriptors().add(createKeyDescriptor(getSigningCertificate()));
		ssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		entityDescriptor.getRoleDescriptors().add(ssoDescriptor);

		pdpDescriptor.getKeyDescriptors().add( createKeyDescriptor(getSigningCertificate()));
		pdpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		entityDescriptor.getRoleDescriptors().add(pdpDescriptor);

		entityDescriptor = (EntityDescriptor)SamlTools.sign(entityDescriptor);
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Just built the entityDescriptor");
		
		// Marshall to the Node
		MarshallerFactory factory = Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(entityDescriptor);
		Node node = null;
		try {
			node = marshaller.marshall(entityDescriptor);
			_systemLogger.log(Level.INFO, MODULE, sMethod, xmlMDRequest);
		}
		catch (MarshallingException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not marshall metadata",	e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Just marshalled into metadata node");

		xmlMDRequest = XMLHelper.nodeToString(node);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "xmlMDRequest: " + xmlMDRequest);
		return xmlMDRequest;
		
	}

	
	// Create the KeyDescriptor
	// TODO, this should probably be a utility in SAMLTools
	private KeyDescriptor createKeyDescriptor(String signingCertificate) {
		SAMLObjectBuilder<KeyDescriptor> keyDescriptorBuilder = (SAMLObjectBuilder<KeyDescriptor>) _oBuilderFactory
		.getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		KeyDescriptor keyDescriptor = keyDescriptorBuilder.buildObject();
		keyDescriptor.setUse(org.opensaml.xml.security.credential.UsageType.SIGNING);
		
		XMLSignatureBuilder<KeyInfo> keyInfoBuilder = (XMLSignatureBuilder<KeyInfo>) _oBuilderFactory
		.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
		KeyInfo keyInfo = keyInfoBuilder.buildObject();
	
		X509CertificateBuilder x509CertificateBuilder = (X509CertificateBuilder) _oBuilderFactory
		.getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME);
		X509Certificate x509Certificate = x509CertificateBuilder.buildObject();
		x509Certificate.setValue(signingCertificate);
		
		X509DataBuilder x509DataBuilder = (X509DataBuilder) _oBuilderFactory
		.getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
		X509Data x509Data = x509DataBuilder.buildObject();
		x509Data.getX509Certificates().add(x509Certificate);
		
		keyInfo.getX509Datas().add(x509Data);
		keyDescriptor.setKeyInfo(keyInfo);
		
		return keyDescriptor;
	}
}
