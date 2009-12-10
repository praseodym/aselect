package org.aselect.server.request.handler.xsaml20;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.ArrayList;
import java.util.Enumeration;
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
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public abstract class AbstractMetaDataManager
{
	// RH, 20090616
	// Forward proxy can now be enabled by setting java system properties "http.proxyPort" en "http.proxyPort"
	private static final String HTTP_PROXY_PORT = "http.proxyPort";
	private static final String HTTP_PROXY_HOST = "http.proxyHost";
	private static final String DEFAULT_PROXY_PORT = "8080"; // RH, 20090615, n
	protected final String MODULE = "AbstractMetaDataManager";
	protected final String sFederationIdpKeyword = "federation-idp";
	protected String protocolSupportEnumeration = SAMLConstants.SAML20P_NS; // "urn:oasis:names:tc:SAML:2.0:protocol"
	protected ASelectConfigManager _configManager;
	protected SystemLogger _systemLogger;
	protected String myRole = "IDP";  // default

	// All descriptors
	//protected ConcurrentHashMap<String, EntityDescriptor> entityDescriptors = new ConcurrentHashMap<String, EntityDescriptor>();
	protected ConcurrentHashMap<String, SSODescriptor> SSODescriptors = new ConcurrentHashMap<String, SSODescriptor>();
	protected ConcurrentHashMap<String, String> metadataSPs = new ConcurrentHashMap<String, String>();
	protected ConcurrentHashMap<String, String> sessionSyncSPs = new ConcurrentHashMap<String, String>();
	protected ConcurrentHashMap<String, java.security.cert.X509Certificate>
				trustedIssuers = new ConcurrentHashMap<String, java.security.cert.X509Certificate>();

	private static String _sCheckCertificates = null;

	protected void init()
	throws ASelectException
	{
		_configManager = ASelectConfigManager.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
	}

	/**
	 */
	protected void initializeMetaDataHandling()
	throws ASelectException
	{
		String sMethod = "initializeMetaData";

		// Initialize the opensaml library
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Saml Bootstrap");
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException cfge) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize bootstrap", cfge);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, cfge);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Metadata SPs="+metadataSPs+" SessionSync SPs="+sessionSyncSPs);
	}

	protected void fileSystemProvider(ChainingMetadataProvider myMetadataProvider, String sMethod, BasicParserPool ppMgr, String metadataURL)
	throws ASelectException
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
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	protected void urlSystemProvider(ChainingMetadataProvider myMetadataProvider, String sMethod,
			BasicParserPool ppMgr, String metadataURL)
	throws ASelectException
	{
		HTTPMetadataProvider urlProvider;
		try {
			// RH, 20090615, sn
			// opensaml2 does not (yet) support usage of proxy
			// use the wrapper class ProxyHTTPMetadataProvider if the SYstemproperty is set
			String proxyHost = System.getProperty(HTTP_PROXY_HOST);
			if (proxyHost != null) {
				String sPort = System.getProperty(HTTP_PROXY_PORT);
				if (sPort == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No proxyPort defined, using default port");
					sPort = DEFAULT_PROXY_PORT;
				}
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Using proxy: " + proxyHost + " on port: " + sPort);
				int proxyPort = Integer.parseInt(sPort);
				urlProvider = new ProxyHTTPMetadataProvider(metadataURL, 1000 * 5, proxyHost, proxyPort);
			}
			else { // RH, 20090615, en
				urlProvider = new HTTPMetadataProvider(metadataURL, 1000 * 5);
			} // RH, 20090615, n

			urlProvider.setParserPool(ppMgr);
			urlProvider.initialize();
			myMetadataProvider.addMetadataProvider(urlProvider);
		}
		catch (MetadataProviderException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not read metadata, check your aselect.xml file: "
					+ metadataURL, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * If a new SP is making contact with the IdP, we must be able to read it's metadata
	 * Can be called any time, not necessarily at startup
	 * Must be called before using SSODescriptors
	 */
	// Bauke: added
	protected void checkMetadataProvider(String entityId)
	throws ASelectException
	{
		String sMethod = "checkMetadataProvider";
		String metadataURL = null;
		ChainingMetadataProvider myMetadataProvider = new ChainingMetadataProvider();

		_systemLogger.log(Level.FINE, MODULE, sMethod, "this="+this+" SSODescriptors=" + SSODescriptors); // +" entityDescriptors=" + entityDescriptors);
		if (trustedIssuers.isEmpty() && getCheckCertificates() != null) {
			// Load trusted ca's (SP) or trusted SP's (IdP) from trusted_issuers.keystore
			loadTrustedIssuers();
		}
		if (entityId == null)
			return;
		if (SSODescriptors.containsKey(entityId)) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId=" + entityId + " already in cache");
			return;
		}
		
		// Read the new metadata
		_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId=" + entityId + " not in cache yet");
		metadataURL = getMetadataURL(entityId);
//		metadataURL = metadataSPs.get((myRole.equals("SP"))? sFederationIdpKeyword: entityId);
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
		// Result has been stored in myMetadataProvider
		
		// Add to the SSODescriptor
		addMetadata(myMetadataProvider);
	}

	private void loadTrustedIssuers()
	throws ASelectException
	{
		String sMethod = "loadTrustedIssuers";
		
	    ASelectConfigManager _oASelectConfigManager = ASelectConfigManager.getHandle();
        StringBuffer sbKeystoreLocation = new StringBuffer(_oASelectConfigManager.getWorkingdir());	
		_systemLogger.log(Level.FINE, MODULE, sMethod, "WorkingDir="+sbKeystoreLocation);
        sbKeystoreLocation.append(File.separator).append("keystores").
        		append(File.separator).append("trusted_issuers.keystore").toString();
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Read "+sbKeystoreLocation+ " Prefix=ca_ Check="+getCheckCertificates());
		try {
			KeyStore ksASelect = KeyStore.getInstance("JKS");
			ksASelect.load(new FileInputStream(sbKeystoreLocation.toString()), null);
			
			Enumeration<String> enumAliases = ksASelect.aliases();
			while (enumAliases.hasMoreElements()) {
				String sAlias = enumAliases.nextElement().toLowerCase();
				java.security.cert.X509Certificate x509Cert = 
						(java.security.cert.X509Certificate) ksASelect.getCertificate(sAlias);
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Alias="+sAlias);
				if (checkCertificate("ca_", x509Cert))
					trustedIssuers.put(sAlias, x509Cert);
				else
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Alias="+sAlias+" not valid!");
			}
		}
		catch (NoSuchAlgorithmException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Algorithm exception, "+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (CertificateException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Certificate exception, "+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (FileNotFoundException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Keystore cannot be found, "+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Keystore cannot be read, "+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (KeyStoreException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Keystore exception: "+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		// Make size() > 0 so this method does not get called again
		if (trustedIssuers.size() == 0)
			trustedIssuers.put("loading_has_been_done", null);
	}

	// Bauke: added
	// List all entries or Remove an entity from the metadata storage
	// Produces output on stdout!
	// Can be called from the Operating System to cleanup the cache.
	//
	public void handleMetadataProvider(PrintWriter out, String entityId, boolean sList)
	{
		String sMethod = "handleMetadataProvider";

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
	}

	/**
	 * Get issuer(entityID) and metadata file location from application.
	 * Put these values in SSODescriptors.
	 * The key is the entityID and the value the Descriptors
	 * 
	 * @param application
	 * @throws ASelectException 
	 */
	protected void addMetadata(ChainingMetadataProvider myMetadataProvider)
	throws ASelectException
	{
		String sMethod = "addMetadata";
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
						if (!checkKeyDescriptor(descriptorValueIDP))
							throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
						SSODescriptors.put(entityId, descriptorValueIDP);
					}
					else if (descriptorValueSP != null) {
						if (!checkKeyDescriptor(descriptorValueSP))
							throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
						SSODescriptors.put(entityId, descriptorValueSP);
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
			catch (MetadataProviderException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not read metadata xml file ", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
	}
	
	/**
	 * Check validity  of a metadata certificate.
	 * Called when the metadata is read in.
	 * Dates must be valid, and the certificate must be trusted by a
	 * ca stored in the trusted_issuers keystore.
	 */
	// Bauke, 20091006: Added
	private boolean checkKeyDescriptor(SSODescriptor descriptor)
	{
		String sMethod = "checkKeyDescriptor";
		List<KeyDescriptor> keyDescriptors = descriptor.getKeyDescriptors();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Metadata Prefix= Check="+getCheckCertificates());
		for (KeyDescriptor keydescriptor : keyDescriptors) {
			UsageType useType = keydescriptor.getUse();
			if (!useType.name().equalsIgnoreCase("SIGNING")) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Use type: " + useType + " != SIGNING");
				continue;  // skip
			}

			org.opensaml.xml.signature.KeyInfo keyinfo = keydescriptor.getKeyInfo();
			X509Data x509Data = keyinfo.getX509Datas().get(0);

			List<X509Certificate> certs = x509Data.getX509Certificates();
			if (!certs.isEmpty()) {
				X509Certificate cert = certs.get(0);
				try {
					java.security.cert.X509Certificate javaCert = SamlTools.getCertificate(cert);
					if (javaCert != null) {
						if (checkCertificate("", javaCert)) {
							_systemLogger.log(Level.INFO, MODULE, sMethod, "OK "+javaCert.getSubjectX500Principal().getName()+" - Issuer="+javaCert.getIssuerX500Principal().getName());
							return true;
						}
						_systemLogger.log(Level.INFO, MODULE, sMethod, "NOT OK "+javaCert.getSubjectX500Principal().getName()+" - Issuer="+javaCert.getIssuerX500Principal().getName());
					}
				}
				catch (CertificateException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata: ", e);
					return false;
				}
			}
		}
		_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid signing certificate found");
		return false;
	}

	/**
	 * Check dates and/or issuer of the given certificate
	 * 
	 * @param prefix - can be "" or "ca_", the second version checks the ca-certificate as well
	 * @param javaCert - the certificate to be checked
	 * @return - is certificate ok?
	 */
	private boolean checkCertificate(String prefix, java.security.cert.X509Certificate javaCert)
	{
		String sMethod = "checkCertificate";
		String sCheckCerts = getCheckCertificates();

		//_systemLogger.log(Level.INFO, MODULE, sMethod, "Prefix="+prefix+" CheckCerts="+sCheckCerts);
		try {
			if (sCheckCerts != null && sCheckCerts.contains(prefix+"dates")) {
				javaCert.checkValidity();
				//_systemLogger.log(Level.INFO, MODULE, sMethod, "The certificate dates are valid");
			}
			if (sCheckCerts != null && sCheckCerts.contains(prefix+"issuer")) {
				boolean isTrusted = isCertificateTrusted(javaCert);
				if (!isTrusted)
					_systemLogger.log(Level.INFO, MODULE, sMethod, "The certificate issuer is not valid");
				return isTrusted;
			}
			// TODO: CRL checking?
			return true;
		}
		catch (CertificateExpiredException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The certificate has expired");
			return false;
		}
		catch (CertificateNotYetValidException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The certificate is not yet valid");
			return false;
		}
	}
	
	private boolean isCertificateTrusted(java.security.cert.X509Certificate clientCert)
	{
		String sMethod = "isCertificateTrusted";
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Check clientCert="+clientCert.getSubjectX500Principal().getName()+
							" - Issued by "+clientCert.getIssuerX500Principal().getName());
		Set<String> allIssuers = trustedIssuers.keySet();
		for (String ca : allIssuers) {
			java.security.cert.X509Certificate caCert = trustedIssuers.get(ca);
			if (caCert == null)  // skip dummy entry
				continue;
			if (caCert.getSubjectX500Principal().equals(clientCert.getIssuerX500Principal())) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Trusted by '"+ca+"': "+caCert.getSubjectX500Principal().getName());
				return true;
			}
		}
		return false;
	}

	/**
	 * Retrieve the signing key for the given entity id from the metadata cache.
	 * 
	 * @param entityId
	 * @return PublicKey, is null on errors.
	 */
	public PublicKey getSigningKeyFromMetadata(String entityId)
	{
		String sMethod = "getSigningKeyFromMetadata";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId="+entityId);
		try {
			checkMetadataProvider(entityId);
		}
		catch (ASelectException e) {
			return null;
		}
		
		SSODescriptor descriptor = SSODescriptors.get(entityId);
		if (descriptor == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Entity id: " + entityId + " not in SSODescriptors");
			return null;
		}

		List<KeyDescriptor> keyDescriptors = descriptor.getKeyDescriptors();
		for (KeyDescriptor keydescriptor : keyDescriptors) {
			UsageType useType = keydescriptor.getUse();
			if (!useType.name().equalsIgnoreCase("SIGNING")) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Use type: " + useType + " != SIGNING");
				return null;
			}

			org.opensaml.xml.signature.KeyInfo keyinfo = keydescriptor.getKeyInfo();
			X509Data x509Data = keyinfo.getX509Datas().get(0);

			List<X509Certificate> certs = x509Data.getX509Certificates();
			if (!certs.isEmpty()) {
				X509Certificate cert = certs.get(0);
				try {
					java.security.cert.X509Certificate javaCert = SamlTools.getCertificate(cert);
					if (javaCert != null) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Cert: "+javaCert.getSubjectX500Principal().getName()+
										" - Issuer="+javaCert.getIssuerX500Principal().getName());
						return javaCert.getPublicKey();
					}
					else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata for entity id : " + entityId);
					}
				}
				catch (CertificateException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata: ", e);
				}
			}
		}
		return null;
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

		_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId="+entityId+" elementName="+elementName+
				" binding="+bindingName+" attr="+attrName);
		if (entityId == null)
			return null;
		checkMetadataProvider(entityId);
		_systemLogger.log(Level.FINE, MODULE, sMethod, "Meta checked for "+entityId);
		SSODescriptor descriptor = SSODescriptors.get(entityId);
		
		if (descriptor != null) {
			try {
				Element domDescriptor = marshallDescriptor(descriptor);
				NodeList nodeList = domDescriptor.getChildNodes();				
				
				//_systemLogger.log(Level.FINE, MODULE, sMethod, "Try "+nodeList.getLength()+" entries");
				for (int i = 0; i < nodeList.getLength(); i++) {
					Node childNode = nodeList.item(i);
					//_systemLogger.log(Level.FINE, MODULE, sMethod, "Node "+childNode.getLocalName());
					if (elementName.equals(childNode.getLocalName())) {
						NamedNodeMap nodeMap = childNode.getAttributes();
						String bindingMDValue = nodeMap.getNamedItem("Binding").getNodeValue();
						//_systemLogger.log(Level.FINE, MODULE, sMethod, "Binding "+bindingMDValue);
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
		//_systemLogger.log(Level.INFO, MODULE, sMethod, XMLHelper.prettyPrintXML(descriptor.getDOM()));
		Element domDescriptor = marshaller.marshall(descriptor, parser.newDocument());
		return domDescriptor;
	}

	public static String getCheckCertificates()
	{
		return _sCheckCertificates;
	}

	public static void setCheckCertificates(String checkCertificates)
	{
		_sCheckCertificates = checkCertificates;
	}

	/**
	 * Retrieve the session sync URL for the given entity id.
	 * 
	 * @param entityId
	 * @return The session sync URL, or null on errors.
	 */
	public String getSessionSyncURL(String entityId)
	{
		String sMethod = "getSessionSyncURL";

		String sUrl = sessionSyncSPs.get(entityId);
		if (sUrl == null) {
			sUrl = sessionSyncSPs.get("metadata");  // old mechanism
		}
		if (sUrl == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity id: " + entityId + " not found (session sync)");
			return null;
		}
		return sUrl;
	}

	/**
	 * Retrieve the session sync URL for the given entity id.
	 * 
	 * @param entityId
	 * @return The session sync URL, or null on errors.
	 */
	public String getMetadataURL(String entityId)
	{
		String sMethod = "getMetadataURL";

		String sUrl = metadataSPs.get(entityId);
		if (sUrl == null) {
			sUrl = metadataSPs.get("metadata");  // old mechanism
		}
		if (sUrl == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity id: " + entityId + " not found (metadata)");
			return null;
		}
		return sUrl;
	}
	
	// Return the number of configured IdPs
	public int getIdpCount()
	{
		return metadataSPs.size();
	}
	
	public String getDefaultIdP()
	{
		// Get the first one, useful when there's only one (the default)
		Set keys = metadataSPs.keySet();
		for (Object s : keys) {
			String sIdP = (String)s;
			return (sIdP.equals("metadata"))? _configManager.getFederationUrl(): sIdP;
		}
		return null;
	}
}
