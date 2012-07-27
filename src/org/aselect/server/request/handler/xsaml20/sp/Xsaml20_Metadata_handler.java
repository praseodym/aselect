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

import java.util.Enumeration;
import java.util.logging.Level;

import javax.servlet.ServletConfig;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.PartnerData.HandlerInfo;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.GivenName;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.Organization;
import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml2.metadata.OrganizationName;
import org.opensaml.saml2.metadata.OrganizationURL;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SurName;
import org.opensaml.saml2.metadata.TelephoneNumber;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
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

	// Get handler specific data from configuration
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_Metadata#aselectReader()
	 */
	@Override
	protected void aselectReader()
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

	/**
	* Create Metadata entries for SP
	 * @param the remoteID
	 * 		The remote identity for whom to create the metadata. If null a default metadata xml will be created
	 * 		with entityID is redirect_url from aselect.xml 
	 * @return the xml metadata string
	 * @throws ASelectException
	 *             the a select exception
	* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_Metadata#createMetaDataXML()
	 */
	@Override
//	protected String createMetaDataXML(String sLocalIssuer)
	protected String createMetaDataXML(String remoteID)
	throws ASelectException
	{
		String sMethod = "createMetaDataXML";
		String xmlMDRequest = null;
		DateTime tStamp = new DateTime();

		// RH, 20110113, sn
		boolean addkeyname = false;
		boolean addcertificate = false;
		boolean usesha256 = false;
		// RH, 20110113, en
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Starting to build metadata");
//		 RH, 20110111, sn
		PartnerData partnerData = null;
		String sLocalIssuer = null;
		if (remoteID != null) {
			// find "id" in the partner's section
			partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(remoteID);
		}
		if (partnerData != null)
			sLocalIssuer = partnerData.getLocalIssuer();

//		 RH, 20110111, en
		// RH, 20110113, sn
		_systemLogger.log(Level.INFO, MODULE, sMethod, "setting partnerdata");
		if (partnerData != null) {
			addkeyname = Boolean.parseBoolean(partnerData.getMetadata4partner().getAddkeyname());
			addcertificate = Boolean.parseBoolean(partnerData.getMetadata4partner().getAddcertificate());
			String specialsettings = partnerData.getMetadata4partner().getSpecialsettings();
			usesha256 = specialsettings != null && specialsettings.toLowerCase().contains("sha256");
		}
		
		// Create the EntityDescriptor
		SAMLObjectBuilder<EntityDescriptor> entityDescriptorBuilder = (SAMLObjectBuilder<EntityDescriptor>) _oBuilderFactory
				.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);

		EntityDescriptor entityDescriptor = entityDescriptorBuilder.buildObject();
		// EntityID can be overruled by the caller
		entityDescriptor.setEntityID((sLocalIssuer != null)? sLocalIssuer: getEntityIdIdp());
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
		
		if ( addkeyname ) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Add keyname to keyinfo");

			XMLSignatureBuilder<KeyName> keyNameBuilder = (XMLSignatureBuilder<KeyName>) _oBuilderFactory
			.getBuilder(KeyName.DEFAULT_ELEMENT_NAME);
			KeyName keyName = keyNameBuilder.buildObject();
			keyName.setValue( _configManager.getDefaultCertId());
			keyInfo.getKeyNames().add(keyName);
		}

		keyDescriptor.setKeyInfo(keyInfo);

		// Create the SPSSODescriptor
		SAMLObjectBuilder<SPSSODescriptor> ssoDescriptorBuilder = (SAMLObjectBuilder<SPSSODescriptor>) _oBuilderFactory
				.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
		SPSSODescriptor ssoDescriptor = ssoDescriptorBuilder.buildObject();

		// RH, 20110113, sn
		if (partnerData != null && partnerData.getMetadata4partner().getHandlers().size() > 0) {	// Get handlers to publish from partnerdata
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Using Parnerdata");

			Enumeration<HandlerInfo> eHandler = partnerData.getMetadata4partner().getHandlers().elements();
			while (eHandler.hasMoreElements()) {
				HandlerInfo hHandler = eHandler.nextElement();
				if (AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME.equalsIgnoreCase(hHandler.getType()) ) {
					// Create the AssertionConsumerService
					_systemLogger.log(Level.INFO, MODULE, sMethod, getAssertionConsumerTarget());
					if (getAssertionConsumerTarget() != null) {
						SAMLObjectBuilder<AssertionConsumerService> assResolutionSeviceBuilder = (SAMLObjectBuilder<AssertionConsumerService>) _oBuilderFactory
								.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
						AssertionConsumerService assResolutionService = assResolutionSeviceBuilder.buildObject();
						if (SAMLConstants.SAML2_POST_BINDING_URI.equals(hHandler.getBinding())) {
							assResolutionService.setBinding( SAMLConstants.SAML2_POST_BINDING_URI);
						} else {
							assResolutionService.setBinding(assertionConsumerServiceBindingConstantARTIFACT);
						}
						assResolutionService.setLocation(getRedirectURL() + getAssertionConsumerTarget());
						if (hHandler.getIsdefault() != null) {
							assResolutionService.setIsDefault( hHandler.getIsdefault().booleanValue() );
						}
						if (hHandler.getIndex() != null) {
							assResolutionService.setIndex(hHandler.getIndex().intValue());
						}
						ssoDescriptor.getAssertionConsumerServices().add(assResolutionService);
					}
				}
				
				if (SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME.equalsIgnoreCase(hHandler.getType()) ) {
					String sBInding = null;
					String sLocation = null;
					// RH, 20120703, n, For singlelogout service we allow to define alternate location, maybe in future also for other services
					String forcedLocation = hHandler.getLocation();	// returns null if not set
					
					if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(hHandler.getBinding())) {
						// Create the SingleLogoutService HTTP, creates Request and Response
						_systemLogger.log(Level.INFO, MODULE, sMethod, getSpSloHttpLocation());
						sBInding = SAMLConstants.SAML2_REDIRECT_BINDING_URI;
						sLocation = getSpSloHttpLocation();
					}	else if (SAMLConstants.SAML2_SOAP11_BINDING_URI.equals(hHandler.getBinding())) {
						// Create the SingleLogoutService SOAP, creates Request and Response
						_systemLogger.log(Level.INFO, MODULE, sMethod, getSpSloSoapLocation());
						sBInding = SAMLConstants.SAML2_SOAP11_BINDING_URI;
						sLocation = getSpSloSoapLocation();
					}
					if (sBInding != null && sLocation != null) {
						SAMLObjectBuilder<SingleLogoutService> sloHttpServiceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
								.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
						SingleLogoutService sloHttpService = sloHttpServiceBuilder.buildObject();
						sloHttpService.setBinding(sBInding);
						if (forcedLocation != null) {	// RH, 20120703, sn
							sloHttpService.setLocation(forcedLocation);							;
						} else 	// RH, 20120703, en
							sloHttpService.setLocation(getRedirectURL() + sLocation);
						
						if (hHandler.getResponselocation() != null) {
							sloHttpService.setResponseLocation(hHandler.getResponselocation());
						} else {
								sloHttpService.setResponseLocation(getRedirectURL() + sLocation);
						}
						ssoDescriptor.getSingleLogoutServices().add(sloHttpService);
					}
				}
			}
		} else {	// publish all handlers in config 			// RH, 20110113, en
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
	}		// end publish all handlers in config 
		
		// Publish Organization info
		if (partnerData != null && partnerData.getMetadata4partner().getMetaorgname() != null) {	// If Organization present name is mandatory, so check name
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting Organization info");

			SAMLObjectBuilder<Organization> organizationBuilder = (SAMLObjectBuilder<Organization>) _oBuilderFactory
			.getBuilder(Organization.DEFAULT_ELEMENT_NAME);
			Organization organization = organizationBuilder.buildObject();
			SAMLObjectBuilder<OrganizationName> organizationNameBuilder = (SAMLObjectBuilder<OrganizationName>) _oBuilderFactory
			.getBuilder(OrganizationName.DEFAULT_ELEMENT_NAME);
			OrganizationName organizationName = organizationNameBuilder.buildObject();
			organizationName.setName(new LocalizedString(partnerData.getMetadata4partner().getMetaorgname(), partnerData.getMetadata4partner().getMetaorgnamelang()));
			organization.getOrganizationNames().add(organizationName);

			
			if (partnerData.getMetadata4partner().getMetaorgdisplname() != null) {
				SAMLObjectBuilder<OrganizationDisplayName> organizationDisplayNameBuilder = (SAMLObjectBuilder<OrganizationDisplayName>) _oBuilderFactory
				.getBuilder(OrganizationDisplayName.DEFAULT_ELEMENT_NAME);
				OrganizationDisplayName organizationDisplayName = organizationDisplayNameBuilder.buildObject();
				organizationDisplayName.setName(new LocalizedString(partnerData.getMetadata4partner().getMetaorgdisplname(), partnerData.getMetadata4partner().getMetaorgdisplnamelang()));
				organization.getDisplayNames().add(organizationDisplayName);
			}

			if (partnerData.getMetadata4partner().getMetaorgurl() != null) {
				SAMLObjectBuilder<OrganizationURL> organizationURLBuilder = (SAMLObjectBuilder<OrganizationURL>) _oBuilderFactory
				.getBuilder(OrganizationURL.DEFAULT_ELEMENT_NAME);
				OrganizationURL organizationURL = organizationURLBuilder.buildObject();
				organizationURL.setURL(new LocalizedString(partnerData.getMetadata4partner().getMetaorgurl(), partnerData.getMetadata4partner().getMetaorgurllang()));
				organization.getURLs().add(organizationURL);
			}
		
			entityDescriptor.setOrganization(organization);
		}		// End Publish Organization info

		
		//	publish ContactPerson info
		if (partnerData != null && partnerData.getMetadata4partner().getMetacontacttype() != null) {	// If ContactPerson present  ContactType  is mandatory so check  ContactType
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting ContactPerson info");

			SAMLObjectBuilder<ContactPerson> contactBuilder = (SAMLObjectBuilder<ContactPerson>) _oBuilderFactory
			.getBuilder(ContactPerson.DEFAULT_ELEMENT_NAME);
			ContactPerson contact = contactBuilder.buildObject();

			if (ContactPersonTypeEnumeration.ADMINISTRATIVE.toString().equalsIgnoreCase(partnerData.getMetadata4partner().getMetacontacttype())) {
				contact.setType(ContactPersonTypeEnumeration.ADMINISTRATIVE);
			} else	if (ContactPersonTypeEnumeration.BILLING.toString().equalsIgnoreCase(partnerData.getMetadata4partner().getMetacontacttype())) {
				contact.setType(ContactPersonTypeEnumeration.BILLING);
			} else if (ContactPersonTypeEnumeration.SUPPORT.toString().equalsIgnoreCase(partnerData.getMetadata4partner().getMetacontacttype())) {
				contact.setType(ContactPersonTypeEnumeration.SUPPORT);
			} else 	if (ContactPersonTypeEnumeration.TECHNICAL.toString().equalsIgnoreCase(partnerData.getMetadata4partner().getMetacontacttype())) {
				contact.setType(ContactPersonTypeEnumeration.TECHNICAL);
			}	else {
				contact.setType(ContactPersonTypeEnumeration.OTHER);
			}

			if (partnerData.getMetadata4partner().getMetacontactname() != null) {
				SAMLObjectBuilder<GivenName> givenNameBuilder = (SAMLObjectBuilder<GivenName>) _oBuilderFactory
				.getBuilder(GivenName.DEFAULT_ELEMENT_NAME);
				GivenName givenName = givenNameBuilder.buildObject();
				givenName.setName(partnerData.getMetadata4partner().getMetacontactname());
				contact.setGivenName(givenName);
			}

			if (partnerData.getMetadata4partner().getMetacontactsurname() != null) {
				SAMLObjectBuilder<SurName> surNameBuilder = (SAMLObjectBuilder<SurName>) _oBuilderFactory
				.getBuilder(SurName.DEFAULT_ELEMENT_NAME);
				SurName surName = surNameBuilder.buildObject();
				surName.setName(partnerData.getMetadata4partner().getMetacontactsurname());
				contact.setSurName(surName);
			}

			if (partnerData.getMetadata4partner().getMetacontactemail() != null) {
				SAMLObjectBuilder<EmailAddress> emailBuilder = (SAMLObjectBuilder<EmailAddress>) _oBuilderFactory
				.getBuilder(EmailAddress.DEFAULT_ELEMENT_NAME);
				EmailAddress email = emailBuilder.buildObject();
				email.setAddress(partnerData.getMetadata4partner().getMetacontactemail());
				contact.getEmailAddresses().add(email);
			}
			
			if (partnerData.getMetadata4partner().getMetacontactephone() != null) {
				SAMLObjectBuilder<TelephoneNumber> phonelBuilder = (SAMLObjectBuilder<TelephoneNumber>) _oBuilderFactory
				.getBuilder(TelephoneNumber.DEFAULT_ELEMENT_NAME);
				TelephoneNumber phone = phonelBuilder.buildObject();
				phone.setNumber(partnerData.getMetadata4partner().getMetacontactephone());
				contact.getTelephoneNumbers().add(phone);
			}
		
			entityDescriptor.getContactPersons().add(contact);
		}		//	End publish ContactPerson info

		
		// Create final EntityDescriptor
		ssoDescriptor.setWantAssertionsSigned(true);
		ssoDescriptor.setAuthnRequestsSigned(true);	// RH, 20120727, n. Actually we always sign the request. Just never told so
		
		ssoDescriptor.getKeyDescriptors().add(keyDescriptor);
		ssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		entityDescriptor.getRoleDescriptors().add(ssoDescriptor);

//		entityDescriptor = (EntityDescriptor) SamlTools.signSamlObject(entityDescriptor);		// RH, 20110113, o
		// RH, 20110113, sn
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Signing entityDescriptor");
		entityDescriptor = (EntityDescriptor) SamlTools.signSamlObject(entityDescriptor,  usesha256 ? "sha256": "sha1",
						addkeyname, addcertificate);
		// RH, 20110113, en

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

		_systemLogger.log(Level.INFO, MODULE, sMethod, "xmlMDRequest: " + xmlMDRequest);
		return xmlMDRequest;
	}
}
