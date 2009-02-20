package org.aselect.server.request.handler.xsaml20;

import java.io.File;
import java.io.PrintWriter;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
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
// import org.opensaml.xml.signature.KeyInfoHelper; // RH 20080529, o
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public abstract class AbstractMetaDataManager
{
	protected final String MODULE = "MetaDataManagerIdp";
	protected final String sFederationIdpKeyword = "federation-idp";
	protected String protocolSupportEnumeration = SAMLConstants.SAML20P_NS; // "urn:oasis:names:tc:SAML:2.0:protocol"
	protected ASelectConfigManager _configManager;
	protected SystemLogger _systemLogger;
	protected String myRole = "IDP";

	// All descriptors
	//protected ConcurrentHashMap<String, EntityDescriptor> entityDescriptors = new ConcurrentHashMap<String, EntityDescriptor>();
	protected ConcurrentHashMap<String, SSODescriptor> SSODescriptors = new ConcurrentHashMap<String, SSODescriptor>();
	protected ConcurrentHashMap<String, String> metadataSPs = new ConcurrentHashMap<String, String>();

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
					"Could not read metadata, check your aselect.xml file: " + metadataURL, e);
		}
	}

	// Bauke: added
	//
	// If a new SP is making contact with the IdP, we must be able to read it's metadata
	// Can be called any time, not necessarily at startup
	// Must be called before using SSODescriptors
	//
	protected void checkMetadataProvider(String entityId)
	{
		String sMethod = "checkMetadataProvider";
		String metadataURL = null;
		ChainingMetadataProvider myMetadataProvider = new ChainingMetadataProvider();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "SSODescriptors=" + SSODescriptors); // +" entityDescriptors=" + entityDescriptors);
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
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "READ url=" + metadataURL);
		if (metadataURL.toLowerCase().startsWith("http"))
			urlSystemProvider(myMetadataProvider, sMethod, ppMgr, metadataURL);
		else
			fileSystemProvider(myMetadataProvider, sMethod, ppMgr, metadataURL);
		
		// Result was stored in myMetadataProvider
		addMetadata(myMetadataProvider);
		// Will have added to SSODescriptors
	}

	// Bauke: added
	// List all entries or Remove an entity from the metadata storage
	// Produces output on stdout!
	//
	public void handleMetadataProvider(PrintWriter out, String entityId, boolean sList)
	{
		String sMethod = "handleMetadataProvider";
		//int remove = 2;

		if (sList) {
			Set SSOkeys = SSODescriptors.keySet();
			for (Object SSOkey : SSOkeys) {
				out.println("EntityId="+(String)SSOkey);
			}
			return;
		}
		// Remove entry from SSODescriptors
		SSODescriptor descriptor = SSODescriptors.remove(entityId);
		if (descriptor==null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity "+entityId+" not found");
			out.println("Entity "+entityId+" not found");
		}
		
		/*if (!entityDescriptors.containsKey(entityId)) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity "+entityId+" not found.");
			remove--;
		}
		else
			entityDescriptors.remove(entityId);
		
		if (remove != 0) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity "+entityId+" removed.");
		}*/
	}

	/**
	 * Get issuer(entityID) and metadata file location from application Put these
	 * values in SSODescriptors. The key is the entityID and the value the Descriptors
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
				EntityDescriptor entityDescriptorValue = null;
				XMLObject domdoc = metadataEntityId.getMetadata();

				Element domDescriptor = marshallDescriptor(domdoc);
				String entityId = domDescriptor.getAttribute("entityID");

				// We will get and fill SSODescriptors
				entityDescriptorValue = metadataEntityId.getEntityDescriptor(entityId);

				if (entityDescriptorValue != null) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "New Entity Descriptor: " + entityDescriptorValue
							+ " for " + entityId);
					SSODescriptor descriptorValueIDP = entityDescriptorValue.getIDPSSODescriptor(protocolSupportEnumeration);
					SSODescriptor descriptorValueSP = entityDescriptorValue.getSPSSODescriptor(protocolSupportEnumeration);
					if (descriptorValueIDP != null) {
						SSODescriptors.put(entityId, descriptorValueIDP);
					}
					else if (descriptorValueSP != null) {
						SSODescriptors.put(entityId, descriptorValueSP);
					}
					//entityDescriptors.put(entityId, entityDescriptorValue);
				}
			}
			catch (MarshallingException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Marshalling failed with the following error: ", e);
			}
			catch (XMLParserException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Parser failed with the following error: ", e);
			}
			catch (MetadataProviderException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not read metadata xml file ", e);
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
		return getMDNodevalue(entityId, elementName, bindingName, "ResponseLocation");
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
		String sMethod = "getMDNodevalue "+Thread.currentThread().getId();
		String location = null;

		if (entityId == null)
			return null;
		checkMetadataProvider(entityId);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Meta checked for "+entityId);
		SSODescriptor descriptor = SSODescriptors.get(entityId);
		
		if (descriptor != null) {
			try {
				Element domDescriptor = marshallDescriptor(descriptor);
				NodeList nodeList = domDescriptor.getChildNodes();				
				
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Try "+nodeList.getLength()+" entries");
				for (int i = 0; i < nodeList.getLength(); i++) {
					Node childNode = nodeList.item(i);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Node "+childNode.getLocalName());
					if (elementName.equals(childNode.getLocalName())) {
						NamedNodeMap nodeMap = childNode.getAttributes();
						String bindingMDValue = nodeMap.getNamedItem("Binding").getNodeValue();
						if (bindingMDValue.equals(bindingName)) {
							Node node = nodeMap.getNamedItem(attrName);
							if (node != null) {
								location = node.getNodeValue();
								_systemLogger.log(Level.INFO, MODULE, sMethod, "Found location for entityId="
										+ entityId + " elementName=" + elementName + " bindingName=" + bindingName
										+ " attrName=" + attrName + " location=" + location);
							}
							else {
								_systemLogger.log(Level.INFO, MODULE, sMethod, "Did not find location for entityId="
										+ entityId + " elementName=" + elementName + " bindingName=" + bindingName
										+ " attrName=" + attrName + " locatione=" + location);
							}
						}
					}
				}
			}
			catch (MarshallingException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Marshalling failed with the following error: ", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);

			}
			catch (XMLParserException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Parser failed with the following error: ", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Return "+location);
		return location;
	}

	private synchronized Element marshallDescriptor(XMLObject descriptor)
	throws MarshallingException, XMLParserException
	{
		String sMethod = "marshallDescriptor";
		
		BasicParserPool parser = new BasicParserPool();
		parser.setNamespaceAware(true);
		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(descriptor);
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Marshall "+descriptor);
		Element domDescriptor = marshaller.marshall(descriptor, parser.newDocument());
		return domDescriptor;
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
		
		SSODescriptor descriptor = SSODescriptors.get(entityId);
		if (descriptor == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Entity id: " + entityId + " not in SSODescriptors");
			return null;
		}

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
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata: ", e);
				}
			}
		}
		return null;
	}
}
