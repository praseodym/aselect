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

import java.util.logging.Level;

import javax.servlet.ServletConfig;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
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

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_Metadata#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init";

		super.init(oServletConfig, oConfig);
		String sCheckCertificates = ASelectConfigManager.getSimpleParam(oConfig, "check_certificates", false);
		if (sCheckCertificates != null) {
			AbstractMetaDataManager.setCheckCertificates(sCheckCertificates);
		}
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_Metadata#aselectReader()
	 */
	@Override
	protected void aselectReader()
		// Get handler specific data from configuration
		throws ASelectException
	{
		String sMethod = "aselectReader";

		super.aselectReader();

		try {
			Object oRequest = _configManager.getSection(null, "requests");
			Object oHandlers = _configManager.getSection(oRequest, "handlers");
			Object oHandler = _configManager.getSection(oHandlers, "handler");

			for (; oHandler != null; oHandler = _configManager.getNextSection(oHandler)) {
				try {
					String sId = _configManager.getParam(oHandler, "id");
					if (!sId.startsWith("saml20_")) {
						continue;
					}
					String sTarget = _configManager.getParam(oHandler, "target");
					_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + " target=" + sTarget);
					sTarget = sTarget.replace("\\", "");
					sTarget = sTarget.replace(".*", "");

					if (sId.equals("saml20_assertionconsumer")) {
						setAssertionConsumerTarget(sTarget);
					}
					else if (sId.equals("saml20_sp_slo_http_request")) {
						setSpSloHttpLocation(sTarget);
					}
					else if (sId.equals("saml20_sp_slo_soap_request")) {
						setSpSloSoapLocation(sTarget);
					}
					else if (sId.equals("saml20_sp_slo_http_response")) {
						setSpSloHttpResponse(sTarget);
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
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not find 'aselect' config section in config file",
					e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	// entityID is redirect_url from aselect.xml
	// Create Metadata SP version
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_Metadata#createMetaDataXML()
	 */
	@Override
	protected String createMetaDataXML()
		throws ASelectException
	{
		String sMethod = "createMetaDataXML";
		String xmlMDRequest = null;

		DateTime tStamp = new DateTime();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Starting to build metadata");
		// Create the EntityDescriptor
		SAMLObjectBuilder<EntityDescriptor> entityDescriptorBuilder = (SAMLObjectBuilder<EntityDescriptor>) _oBuilderFactory
				.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);

		EntityDescriptor entityDescriptor = entityDescriptorBuilder.buildObject();
		entityDescriptor.setEntityID(getEntityIdIdp());
		entityDescriptor.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));

		if (getValidUntil() != null)
			entityDescriptor.setValidUntil(tStamp.plus(getValidUntil().longValue()));
		if (getCacheDuration() != null)
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

		X509DataBuilder x509DataBuilder = (X509DataBuilder) _oBuilderFactory.getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
		X509Data x509Data = x509DataBuilder.buildObject();
		x509Data.getX509Certificates().add(x509Certificate);

		keyInfo.getX509Datas().add(x509Data);
		keyDescriptor.setKeyInfo(keyInfo);

		// Create the SPSSODescriptor
		SAMLObjectBuilder<SPSSODescriptor> ssoDescriptorBuilder = (SAMLObjectBuilder<SPSSODescriptor>) _oBuilderFactory
				.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
		SPSSODescriptor ssoDescriptor = ssoDescriptorBuilder.buildObject();

		// Create the AssertionConsumerService
		_systemLogger.log(Level.INFO, MODULE, sMethod, getAssertionConsumerTarget());
		if (getAssertionConsumerTarget() != null) {
			SAMLObjectBuilder<AssertionConsumerService> assResolutionSeviceBuilder = (SAMLObjectBuilder<AssertionConsumerService>) _oBuilderFactory
					.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
			AssertionConsumerService assResolutionService = assResolutionSeviceBuilder.buildObject();
			assResolutionService.setBinding(assertionConsumerServiceBindingConstantARTIFACT);
			assResolutionService.setLocation(getRedirectURL() + getAssertionConsumerTarget());
			assResolutionService.setIsDefault(true);
			assResolutionService.setIndex(0);
			ssoDescriptor.getAssertionConsumerServices().add(assResolutionService);
		}

		// Create the SingleLogoutService HTTP, creates Request and Response
		_systemLogger.log(Level.INFO, MODULE, sMethod, getSpSloHttpLocation());
		if (getSpSloHttpLocation() != null) {
			SAMLObjectBuilder<SingleLogoutService> sloHttpServiceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
					.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
			SingleLogoutService sloHttpService = sloHttpServiceBuilder.buildObject();
			sloHttpService.setBinding(singleLogoutServiceBindingConstantREDIRECT);
			sloHttpService.setLocation(getRedirectURL() + getSpSloHttpLocation());
			if (getSpSloHttpResponse() != null)
				sloHttpService.setResponseLocation(getRedirectURL() + getSpSloHttpResponse());

			ssoDescriptor.getSingleLogoutServices().add(sloHttpService);
		}

		// Create the SingleLogoutService SOAP, creates Request and Response
		_systemLogger.log(Level.INFO, MODULE, sMethod, getSpSloSoapLocation());
		if (getSpSloSoapLocation() != null) {
			SAMLObjectBuilder<SingleLogoutService> sloSoaperviceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
					.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
			SingleLogoutService sloSoapService = sloSoaperviceBuilder.buildObject();
			sloSoapService.setBinding(singleLogoutServiceBindingConstantSOAP);
			sloSoapService.setLocation(getRedirectURL() + getSpSloSoapLocation());
			if (getSpSloSoapResponse() != null)
				sloSoapService.setResponseLocation(getRedirectURL() + getSpSloSoapResponse());

			ssoDescriptor.getSingleLogoutServices().add(sloSoapService);
		}

		// Create final EntityDescriptor
		ssoDescriptor.setWantAssertionsSigned(true);
		ssoDescriptor.getKeyDescriptors().add(keyDescriptor);
		ssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		entityDescriptor.getRoleDescriptors().add(ssoDescriptor);

		entityDescriptor = (EntityDescriptor) SamlTools.sign(entityDescriptor);

		// The Session Sync descriptor (PDPDescriptor?) would go here
		_systemLogger.log(Level.INFO, MODULE, sMethod, "entityDescriptor done");

		// Marshall to the Node
		MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(entityDescriptor);
		Node node = null;
		try {
			node = marshaller.marshall(entityDescriptor);
		}
		catch (MarshallingException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not marshall metadata", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Marshalling done");
		xmlMDRequest = XMLHelper.nodeToString(node);

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "xmlMDRequest: " + xmlMDRequest);
		return xmlMDRequest;
	}
}
