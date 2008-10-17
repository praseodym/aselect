package org.aselect.server.request.handler.saml20.common;

import java.io.File;
import java.io.PrintWriter;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.UsageType;
// import org.opensaml.xml.signature.KeyInfoHelper;  // RH 20080529, o
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public abstract class MetaDataManager
{
	protected String protocolSupportEnumeration = SAMLConstants.SAML20P_NS; // "urn:oasis:names:tc:SAML:2.0:protocol"
	protected ASelectConfigManager _configManager;
	protected SystemLogger _systemLogger;
	protected final String MODULE = "MetaDataManager";
	protected String myRole = "IDP";
	protected final String sFederationIdpKeyword = "federation-idp";

	// All descriptors
	protected HashMap<String, EntityDescriptor> entityDescriptors = new HashMap<String, EntityDescriptor>();
	protected HashMap<String, SSODescriptor> SSODescriptors = new HashMap<String, SSODescriptor>();
	protected Hashtable<String, String> metadataSPs = new Hashtable<String, String>();

	protected void init()
		throws ASelectException
	{
		_configManager = ASelectConfigManager.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
	}

	/**
	 * Read the List metaDataUrls, read the metadata.xml and put it to the
	 * metadataprovider.
	 * 
	 * @return metadataProvider
	 * @throws ASelectException
	 */
	protected void getMetaDataProviderfromList()
		throws ASelectException
	{
		String sMethod = "getMetaDataProviderfromList()";

		// Initialize the opensaml library
		try {
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException cfge) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize bootstrap", cfge);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, cfge);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Metadata SPs="+metadataSPs);
	}

	protected void fileSystemProvider(ChainingMetadataProvider myMetadataProvider, String sMethod, BasicParserPool ppMgr, String metadataURL)
	{
		File mdFile = new File(metadataURL);
		mdFile.toURI();
		FilesystemMetadataProvider fileProvider;
		try {
			fileProvider = new FilesystemMetadataProvider(mdFile);
			fileProvider.setParserPool(ppMgr);
			fileProvider.initialize();
			myMetadataProvider.addMetadataProvider(fileProvider);
		}
		catch (MetadataProviderException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not read metadata xml file, check the pathname within aselect xml file: " + metadataURL, e);
		}
	}

	protected void urlSystemProvider(ChainingMetadataProvider myMetadataProvider, String sMethod, BasicParserPool ppMgr, String metadataURL)
	{
		HTTPMetadataProvider urlProvider;
		try {
			urlProvider = new HTTPMetadataProvider(metadataURL, 1000 * 5);

			urlProvider.setParserPool(ppMgr);
			urlProvider.initialize();
			myMetadataProvider.addMetadataProvider(urlProvider);
		}
		catch (MetadataProviderException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not read metadata xml file, check the pathname within aselect xml file: " + metadataURL, e);
		}
	}

	// Bauke: added
	//
	// If a new SP is making contact with the IdP, we must be able to read it's metadata
	// Can be called any time, not necessarily at startup
	// Must be called before using SSODescriptors or entityDescriptors
	//
	protected void checkMetadataProvider(String entityId)
	{
		String sMethod = "checkMetadataProvider";
		String metadataURL = null;
		ChainingMetadataProvider myMetadataProvider = new ChainingMetadataProvider();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "1. SSODescriptors=" + SSODescriptors);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "2. entityDescriptors=" + entityDescriptors);
		if (entityId == null)
			return;
		if (SSODescriptors.containsKey(entityId)) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId=" + entityId + " present");
			return;
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId=" + entityId + " not present yet");
		
		metadataURL = metadataSPs.get((myRole.equals("SP"))? sFederationIdpKeyword: entityId);
		if (metadataURL == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity id: " + entityId + " is not Configured");
			return;
		}
		
		// Get parser pool manager
		BasicParserPool ppMgr = new BasicParserPool();
		ppMgr.setNamespaceAware(true);
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "reading metadataURL=" + metadataURL);
		if (metadataURL.toLowerCase().startsWith("http"))
			urlSystemProvider(myMetadataProvider, sMethod, ppMgr, metadataURL);
		else
			fileSystemProvider(myMetadataProvider, sMethod, ppMgr, metadataURL);
		
		// Result was stored in myMetadataProvider
		addMetadata(myMetadataProvider);
		// Will have added to SSODescriptors and entityDescriptors
	}

	// Bauke: added
	// Remove an entity from the metadata storage
	//
	public void handleMetadataProvider(PrintWriter out, String entityId, boolean sList)
	{
		String sMethod = "handleMetadataProvider";
		int remove = 2;

		if (sList) {
			Set SSOkeys = SSODescriptors.keySet();
			for (Object SSOkey : SSOkeys) {
				out.println("EntityId="+(String)SSOkey);
			}
			return;
		}
		// Remove entry from SSODescriptors and entityDescriptors
		if (!SSODescriptors.containsKey(entityId)) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SSODescriptors does not contain entityId=" + entityId);
			out.println("Entity "+entityId+" not found.");
			remove--;
		}
		else 
			SSODescriptors.remove(entityId);
		if (!entityDescriptors.containsKey(entityId)) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "entityDescriptors does not contain entityId=" + entityId);
			if (remove == 2) out.println("Entity "+entityId+" not found.");
			remove--;
		}
		else
			entityDescriptors.remove(entityId);
		if (remove != 0) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "removed entityId=" + entityId);
			out.println("Entity "+entityId+" removed.");
		}
	}

	/**
	 * Get issuer(entityID) and metadata file location from application Put this
	 * values in the hashMap SSODescriptors and entityDescriptors The key is the
	 * entityID and the value the Descriptors
	 * 
	 * @param application
	 * @throws ASelectException
	 */
	protected void addMetadata(ChainingMetadataProvider myMetadataProvider)
	{
		String sMethod = "addMetadata()";
		ArrayList<MetadataProvider> metadataProviderArray = new ArrayList<MetadataProvider>();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "getProviders");
		metadataProviderArray.addAll(myMetadataProvider.getProviders());

		for (MetadataProvider metadataEntityId : metadataProviderArray) {

			try {
				Element domDescriptor;
				EntityDescriptor entityDescriptorValue = null;
				XMLObject domdoc = metadataEntityId.getMetadata();

				BasicParserPool parser = new BasicParserPool();
				parser.setNamespaceAware(true);

				MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
				Marshaller marshaller = marshallerFactory.getMarshaller(domdoc);
				domDescriptor = marshaller.marshall(domdoc, parser.newDocument());

				String entityId = domDescriptor.getAttribute("entityID");

				// We will get and fill the HASHMAPs SSODescriptors and entityDescriptors
				entityDescriptorValue = metadataEntityId.getEntityDescriptor(entityId);

				if (entityDescriptorValue != null) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity Descriptor: " + entityDescriptorValue
							+ " for " + entityId);
					SSODescriptor descriptorValueIDP = entityDescriptorValue.getIDPSSODescriptor(protocolSupportEnumeration);
					SSODescriptor descriptorValueSP = entityDescriptorValue.getSPSSODescriptor(protocolSupportEnumeration);
					if (descriptorValueIDP != null) {
						SSODescriptors.put(entityId, descriptorValueIDP);
					}
					else if (descriptorValueSP != null) {
						SSODescriptors.put(entityId, descriptorValueSP);
					}

					entityDescriptors.put(entityId, entityDescriptorValue);
				}
			}
			catch (MarshallingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Marshalling failed with the following error: ", e);
			}
			catch (XMLParserException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Parser failed with the following error: ", e);
			}
			catch (MetadataProviderException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not read metadata xml file ", e);
			}
		}
	}

	/**
	 * @param entityId
	 * @param elementName
	 *                <BR>
	 *                SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *                SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *                ArtifactResolutionService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *                AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME
	 * @param bindingName
	 *                <BR>
	 *                SAMLConstants.SAML2_SOAP11_BINDING_URI <BR>
	 *                SAMLConstants.SAML2_REDIRECT_BINDING_URI <BR>
	 *                SAMLConstants.SAML2_POST_BINDING_URI <BR>
	 *                SAMLConstants.SAML2_ARTIFACT_BINDING_URI
	 * @return Location
	 * @throws ASelectException
	 */
	public String getLocation(String entityId, String elementName, String bindingName)
		throws ASelectException
	{

		String locationValue = getMDNodevalue(entityId, elementName, bindingName, "Location");

		return locationValue;

	}

	/**
	 * @param entityId
	 * @param elementName
	 *                <BR>
	 *                SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *                SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *                ArtifactResolutionService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *                AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME
	 * @param bindingName
	 *                <BR>
	 *                SAMLConstants.SAML2_SOAP11_BINDING_URI <BR>
	 *                SAMLConstants.SAML2_REDIRECT_BINDING_URI <BR>
	 *                SAMLConstants.SAML2_POST_BINDING_URI <BR>
	 *                SAMLConstants.SAML2_ARTIFACT_BINDING_URI
	 * @return ResponseLocation
	 * @throws ASelectException
	 */
	public String getResponseLocation(String entityId, String elementName, String bindingName)
		throws ASelectException
	{

		String locationValue = getMDNodevalue(entityId, elementName, bindingName, "ResponseLocation");

		return locationValue;

	}

	/**
	 * @param entityId
	 * @param elementName
	 * @param bindingName
	 * @param attrName
	 * @return location
	 * @throws ASelectException
	 */
	protected String getMDNodevalue(String entityId, String elementName, String bindingName, String attrName)
		throws ASelectException
	{
		String sMethod = "getMDNodevalue()";
		String location = null;

		if (entityId == null)
			return null;
		checkMetadataProvider(entityId);
		if (SSODescriptors.containsKey(entityId)) {

			SSODescriptor descriptor = SSODescriptors.get(entityId);

			BasicParserPool parser = new BasicParserPool();
			parser.setNamespaceAware(true);

			MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(descriptor);

			try {
				Element domDescriptor;
				domDescriptor = marshaller.marshall(descriptor, parser.newDocument());

				NodeList nodeList = domDescriptor.getChildNodes();
				for (int i = 0; i < nodeList.getLength(); i++) {
					Node childNode = nodeList.item(i);
					if (elementName.equals(childNode.getLocalName())) {
						NamedNodeMap nodeMap = childNode.getAttributes();
						String bindingMDValue = nodeMap.getNamedItem("Binding").getNodeValue();
						if (bindingMDValue.equals(bindingName)) {
							Node node = nodeMap.getNamedItem(attrName);
							if (node != null) {
								location = node.getNodeValue();
								_systemLogger.log(Level.INFO, MODULE, sMethod, "Found location for entityId: "
										+ entityId + " elementName: " + elementName + " bindingName: " + bindingName
										+ " attrName: " + attrName + " location value= " + location);
							}
							else {
								_systemLogger.log(Level.INFO, MODULE, sMethod, "Did not find location for entityId: "
										+ entityId + " elementName: " + elementName + " bindingName: " + bindingName
										+ " attrName: " + attrName + " location value= " + location);
							}
						}
					}
				}
			}
			catch (MarshallingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Marshalling failed with the following error: ", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);

			}
			catch (XMLParserException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Parser failed with the following error: ", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		return location;
	}

	/**
	 * 
	 * @param entityId
	 * @return PublicKey
	 */
	public PublicKey getSigningKey(String entityId)
	{
		String sMethod = "getSigningKey()";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId="+entityId);
		checkMetadataProvider(entityId);
		
		if (!SSODescriptors.containsKey(entityId)) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity id: " + entityId + " not in SSODescriptors");
			return null;
		}

		SSODescriptor descriptor = SSODescriptors.get(entityId);

		List<KeyDescriptor> keyDescriptors = descriptor.getKeyDescriptors();
		for (KeyDescriptor keydescriptor : keyDescriptors) {

			UsageType useType = keydescriptor.getUse();
			if (!useType.name().equalsIgnoreCase("SIGNING")) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Use type: " + useType + " != SIGNING");
				return null;
			}

			org.opensaml.xml.signature.KeyInfo keyinfo = keydescriptor.getKeyInfo();
			X509Data x509Data = keyinfo.getX509Datas().get(0);

			List<X509Certificate> certs = x509Data.getX509Certificates();

			if (!certs.isEmpty()) {
				X509Certificate cert = certs.get(0);

				try {
//					java.security.cert.X509Certificate javaCert = KeyInfoHelper.getCertificate(cert); // RH 20080529, o
					java.security.cert.X509Certificate javaCert = SamlTools.getCertificate(cert); // RH 20080529, n

					if (javaCert != null) {
						PublicKey publicKey = javaCert.getPublicKey();
						return publicKey;
					}
					else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Could not retrieve the public key from metadata for entity id : " + entityId);
					}
				}
				catch (CertificateException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata: ",
							e);
				}
			}
		}
		return null;
	}
}
