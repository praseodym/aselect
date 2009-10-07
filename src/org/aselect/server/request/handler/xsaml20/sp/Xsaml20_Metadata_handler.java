package org.aselect.server.request.handler.xsaml20.sp;

import java.util.logging.Level;

import javax.servlet.ServletConfig;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.idp.MetaDataManagerIdp;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.XMLSignatureBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Node;

// Configuration example
//
// <handler id="saml20_sp_metadata"
//    class="org.aselect.server.request.handler.xsaml20.sp.Xsaml20_Metadata_handler"
//    target="/saml20_sp_metadata">
// </handler>
//
public class Xsaml20_Metadata_handler extends Saml20_Metadata
{
	private final static String MODULE = "sp.Xsaml20_Metadata_handler";

	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";
		
		super.init(oServletConfig, oConfig);
		String sCheckCertificates = ASelectConfigManager.getSimpleParam(oConfig, "check_certificates", false);
		if (sCheckCertificates != null) {
			MetaDataManagerIdp.setCheckCertificates(sCheckCertificates);
		}
	}

	protected void aselectReader() // Get handler specific data from configuration 
	throws ASelectException
	{
		String sMethod = "aselectReader()";
	
		Object oRequest = null;
		Object oHandlers = null;
		Object oHandler = null;
	
		super.aselectReader();
	
		try {
			oRequest = _configManager.getSection(null, "requests");
			oHandlers = _configManager.getSection(oRequest, "handlers");
			oHandler = _configManager.getSection(oHandlers, "handler");
	
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

					if (sId.equals("saml20_assertionconsumer")) {
						setAssertionConsumerTarget(sTarget);
					}
					else if (sId.equals("saml20_sp_slo_http_request")) {
						setSpSloHttpLocation(sTarget);
					}
					else if (sId.equals("saml20_sp_slo_http_response")) {
						setSpSloHttpResponse(sTarget);
					}
					else if (sId.equals("saml20_sp_slo_soap_request")) {
						setSpSloSoapLocation(sTarget);
					}
					else if (sId.equals("saml20_sp_slo_soap_response")) {
						setSpSloSoapResponse(sTarget);
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
	// Create Metadata SP version
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
				+ "	<m:SPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
				+ "<m:KeyDescriptor use=\"signing\">" + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
				+ "<ds:X509Data>" + "<ds:X509Certificate>" + getSigningCertificate() + "</ds:X509Certificate>"
				+ "</ds:X509Data>" + "</ds:KeyInfo>" + "</m:KeyDescriptor>";

		if (getAssertionConsumerTarget() != null)
			xmlMDRequest += "<m:AssertionConsumerService Binding=\""
					+ assertionConsumerServiceBindingConstantARTIFACT + "\""
					+ " Location=\"" + getRedirectURL()+getAssertionConsumerTarget()
					+ "\"" + " index=\"0\" isDefault=\"true\">" + "</m:AssertionConsumerService>";
		
		if (getSpSloHttpLocation() != null) {
			xmlMDRequest += "<m:SingleLogoutService Binding=\"" + singleLogoutServiceBindingConstantREDIRECT + "\""
					+ " Location=\"" + getRedirectURL()+getSpSloHttpLocation();
			if (getSpSloHttpResponse() != null)
				xmlMDRequest += "\" ResponseLocation=\"" + getRedirectURL()+getSpSloHttpResponse();
			xmlMDRequest += "\">" + "</m:SingleLogoutService>";
		}
		
		if (getSpSloSoapLocation() != null) {				
			xmlMDRequest += "<m:SingleLogoutService Binding=\"" + singleLogoutServiceBindingConstantSOAP + "\""
					+ " Location=\"" + getRedirectURL()+getSpSloSoapLocation();
			if (getSpSloSoapResponse() != null)
				xmlMDRequest += "\" ResponseLocation=\"" + getRedirectURL()+getSpSloSoapResponse();
			xmlMDRequest += "\">" + "</m:SingleLogoutService>";
		}

		xmlMDRequest += "</m:SPSSODescriptor>" + "</m:EntityDescriptor>";
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

		// Create the SPSSODescriptor
		SAMLObjectBuilder<SPSSODescriptor> ssoDescriptorBuilder = (SAMLObjectBuilder<SPSSODescriptor>) _oBuilderFactory
		.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
		SPSSODescriptor ssoDescriptor = ssoDescriptorBuilder.buildObject();


		// Create the AssertionConsumerService 
		if (getAssertionConsumerTarget() != null) {
			SAMLObjectBuilder<AssertionConsumerService> assResolutionSeviceBuilder = (SAMLObjectBuilder<AssertionConsumerService>) _oBuilderFactory
			.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
			AssertionConsumerService assResolutionService = assResolutionSeviceBuilder.buildObject();
			assResolutionService.setBinding(assertionConsumerServiceBindingConstantARTIFACT);
			assResolutionService.setLocation(getRedirectURL()+getAssertionConsumerTarget());
			assResolutionService.setIsDefault(true);
			assResolutionService.setIndex(0);
			ssoDescriptor.getAssertionConsumerServices().add(assResolutionService);
		}

		// Create the SingleLogoutService HTTP
		if (getSpSloHttpLocation() != null) {
			SAMLObjectBuilder<SingleLogoutService> sloHttpServiceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
			.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
			SingleLogoutService sloHttpService = sloHttpServiceBuilder.buildObject();
			sloHttpService.setBinding(singleLogoutServiceBindingConstantREDIRECT);
			sloHttpService.setLocation(getRedirectURL()+getSpSloHttpLocation());
			if (getSpSloHttpResponse() != null)
				sloHttpService.setResponseLocation(getRedirectURL()+getSpSloHttpResponse());

			ssoDescriptor.getSingleLogoutServices().add(sloHttpService);
		}

		// Create the SingleLogoutService SOAP
		if (getSpSloSoapLocation() != null) {
			SAMLObjectBuilder<SingleLogoutService> sloSoaperviceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
			.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
			SingleLogoutService sloSoapService = sloSoaperviceBuilder.buildObject();
			sloSoapService.setBinding(singleLogoutServiceBindingConstantSOAP);
			sloSoapService.setLocation(getRedirectURL()+getSpSloSoapLocation());
			if (getSpSloSoapResponse() != null)
				sloSoapService.setResponseLocation(getRedirectURL()+getSpSloSoapResponse());

			ssoDescriptor.getSingleLogoutServices().add(sloSoapService);
		}

		// Create final EntityDescriptor
		ssoDescriptor.setWantAssertionsSigned(true);
		ssoDescriptor.getKeyDescriptors().add(keyDescriptor);
		ssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		entityDescriptor.getRoleDescriptors().add(ssoDescriptor);

		entityDescriptor = (EntityDescriptor)SamlTools.sign(entityDescriptor);

		// TODO create descriptor (PDPDescriptor?) for session sync here
		
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
}
