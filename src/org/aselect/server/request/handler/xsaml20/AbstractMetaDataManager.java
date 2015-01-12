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
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Utils;
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

/**
 * @author bauke
 *
 */
public abstract class AbstractMetaDataManager
{
	// RH, 20090616
	// Forward proxy can now be enabled by setting java system properties "http.proxyPort" en "http.proxyPort"
	private static final String HTTP_PROXY_PORT = "http.proxyPort";
	private static final String HTTP_PROXY_HOST = "http.proxyHost";
	private static final String DEFAULT_PROXY_PORT = "8080"; // RH, 20090615, n
	protected final String MODULE = "AbstractMetaDataManager";
	protected String protocolSupportEnumeration = SAMLConstants.SAML20P_NS; // "urn:oasis:names:tc:SAML:2.0:protocol"
	protected ASelectConfigManager _configManager;
	protected SystemLogger _systemLogger;

	// All descriptors
	protected ConcurrentHashMap<String, SSODescriptor> SSODescriptors = new ConcurrentHashMap<String, SSODescriptor>();
//	protected ConcurrentHashMap<String, String> metadataSPs = new ConcurrentHashMap<String, String>();
//	protected ConcurrentHashMap<String, String> sessionSyncSPs = new ConcurrentHashMap<String, String>();
	protected ConcurrentHashMap<String, java.security.cert.X509Certificate> trustedIssuers = new ConcurrentHashMap<String, java.security.cert.X509Certificate>();

	public ConcurrentHashMap<String, PartnerData> storeAllIdPData = new ConcurrentHashMap<String, PartnerData>();

	private static String _sCheckCertificates = null;
	
	/**
	 * Override to specify the classes role
	 * 
	 * @return - the role, either "SP" or "IDP"
	 */
	protected abstract String getMyRole();
	
	/**
	 * Initialization method
	 * 
	 * @throws ASelectException
	 */
	protected void init()
	throws ASelectException
	{
		_configManager = ASelectConfigManager.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
	}

	/**
	 * Initialize meta data handling.
	 * 
	 * @throws ASelectException
	 *             the a select exception
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
		_systemLogger.log(Level.INFO, MODULE, sMethod, "storeAllIdPData=" + storeAllIdPData);
	}

	/**
	 * File system provider.
	 * 
	 * @param myMetadataProvider
	 *            the my metadata provider
	 * @param sMethod
	 *            the s method
	 * @param ppMgr
	 *            the pp mgr
	 * @param metadataURL
	 *            the metadata url
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void fileSystemProvider(ChainingMetadataProvider myMetadataProvider, String sMethod,
			BasicParserPool ppMgr, String metadataURL)
	throws ASelectException
	{
		_systemLogger.log(Level.INFO, MODULE, sMethod, "fileSystemProvider url="+metadataURL);
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

	/**
	 * Url system provider.
	 * 
	 * @param myMetadataProvider
	 *            the my metadata provider
	 * @param sMethod
	 *            the s method
	 * @param ppMgr
	 *            the pp mgr
	 * @param metadataURL
	 *            the metadata url
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void urlSystemProvider(ChainingMetadataProvider myMetadataProvider, String sMethod,
			BasicParserPool ppMgr, String metadataURL)
	throws ASelectException
	{
		_systemLogger.log(Level.INFO, MODULE, sMethod, "urlSystemProvider url="+metadataURL);
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
	 * If a new partner (SP or IDP is making contact, we must be able to read it's metadata.
	 * Can be called any time, not necessarily at startup.
	 * Must be called before using SSODescriptors.
	 * 
	 * @param entityId
	 *            the entity id
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void ensureMetadataPresence(String entityId)
	throws ASelectException
	{
		String sMethod = "ensureMetadataPresence";
		String metadataURL = null;
		ChainingMetadataProvider myMetadataProvider = new ChainingMetadataProvider();

		_systemLogger.log(Level.FINE, MODULE, sMethod, "myRole="+getMyRole()+" entityId="+entityId+" SSODescriptors="+SSODescriptors);
		if (trustedIssuers.isEmpty() && getCheckCertificates() != null) {
			// Load trusted ca's (SP) or trusted SP's (IdP) from trusted_issuers.keystore
			loadTrustedIssuers();
		}
		if (entityId == null)
			return;
		if (SSODescriptors.containsKey(makeEntityKey(entityId, null))) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId=" + entityId + " already in cache");
			return;
		}

		// Read the new metadata
		_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId=" + entityId + " not in cache yet");
		metadataURL = getMetadataURL(entityId);
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

	/**
	 * Load trusted issuers.
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void loadTrustedIssuers()
	throws ASelectException
	{
		String sMethod = "loadTrustedIssuers";

		ASelectConfigManager _oASelectConfigManager = ASelectConfigManager.getHandle();
		StringBuffer sbKeystoreLocation = new StringBuffer(_oASelectConfigManager.getWorkingdir());
		_systemLogger.log(Level.FINE, MODULE, sMethod, "WorkingDir=" + sbKeystoreLocation);
		sbKeystoreLocation.append(File.separator).append("keystores").append(File.separator).append(
				"trusted_issuers.keystore").toString();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Load TrustedIssuers " + sbKeystoreLocation + " Prefix=ca_ Check="
				+ getCheckCertificates());
		try {
			KeyStore ksASelect = KeyStore.getInstance("JKS");
			ksASelect.load(new FileInputStream(sbKeystoreLocation.toString()), null);

			Enumeration<String> enumAliases = ksASelect.aliases();
			while (enumAliases.hasMoreElements()) {
				String sAlias = enumAliases.nextElement().toLowerCase();
				java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) ksASelect
						.getCertificate(sAlias);
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Alias=" + sAlias);
				if (checkCertificate("ca_", x509Cert))
					trustedIssuers.put(sAlias, x509Cert);
				else
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Alias=" + sAlias + " not valid!");
			}
		}
		catch (NoSuchAlgorithmException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Algorithm exception, " + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (CertificateException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Certificate exception, " + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (FileNotFoundException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Keystore cannot be found, " + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Keystore cannot be read, " + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (KeyStoreException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Keystore exception: " + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		// Make size() > 0 so this method does not get called again
		if (trustedIssuers.size() == 0)
			trustedIssuers.put("loading_has_been_done", null);
	}

	/**
	 * Handle metadata provider.
	 * List all entries or Remove an entity from the metadata storage
	 * Produces output on stdout!
	 * Can be called from the Operating System to cleanup the cache.
	 * 
	 * @param out
	 *            the out
	 * @param entityId
	 *            the entity id
	 * @param sList
	 *            the s list
	 */
	public void handleMetadataProvider(PrintWriter out, String entityId, boolean sList)
	{
		String sMethod = "handleMetadataProvider";

		if (sList) {
			Set<String> SSOkeys = SSODescriptors.keySet();
			for (String SSOkey : SSOkeys) {
				out.println("EntityId=" + SSOkey);
			}
			return;
		}
		// Remove entries from SSODescriptors
		SSODescriptor descriptorSP = SSODescriptors.remove(makeEntityKey(entityId, "SP"));
		SSODescriptor descriptorIDP = SSODescriptors.remove(makeEntityKey(entityId, "IDP"));
		if (descriptorSP == null && descriptorIDP == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity " + entityId + " not found");
			out.println("Entity " + entityId + " not found");
		}
	}

	/**
	 * Get issuer(entityID) and metadata file location from application.
	 * Put these values in SSODescriptors.
	 * The key is the entityID and the value the Descriptors
	 * 
	 * @param myMetadataProvider
	 *            the Metadata provider
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
					// 20100501, Bauke: metadata can contain both Descriptor types, so check both of them!
					SSODescriptor descriptorValueIDP = entityDescriptorValue.getIDPSSODescriptor(protocolSupportEnumeration);
					if (descriptorValueIDP != null) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "IDP SSODescriptor found");
						if (!checkKeyDescriptorCertificate(descriptorValueIDP))
							throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
						SSODescriptors.put(makeEntityKey(entityId, "IDP"), descriptorValueIDP);
					}
					SSODescriptor descriptorValueSP = entityDescriptorValue.getSPSSODescriptor(protocolSupportEnumeration);
					if (descriptorValueSP != null) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "SP SSODescriptor found");
						if (!checkKeyDescriptorCertificate(descriptorValueSP))
							throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
						SSODescriptors.put(makeEntityKey(entityId, "SP"), descriptorValueSP);
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
	 * Check validity of a metadata certificate. Called when the metadata is read in. Dates must be valid, and the
	 * certificate must be trusted by a ca stored in the trusted_issuers keystore.
	 * 
	 * @param descriptor
	 *            the descriptor
	 * @return true, if check key descriptor
	 */
	private boolean checkKeyDescriptorCertificate(SSODescriptor descriptor)
	{
		String sMethod = "checkKeyDescriptorCertificate";
		List<KeyDescriptor> keyDescriptors = descriptor.getKeyDescriptors();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "CheckCerts=" + getCheckCertificates());
		for (KeyDescriptor keydescriptor : keyDescriptors) {
			UsageType useType = keydescriptor.getUse();
			if (!useType.name().equalsIgnoreCase("SIGNING")) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Use type: " + useType + " != SIGNING");
				continue; // skip
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
							_systemLogger.log(Level.FINER, MODULE, sMethod, "OK "
									+ javaCert.getSubjectX500Principal().getName() + " - Issuer="
									+ javaCert.getIssuerX500Principal().getName());
							return true;
						}
						_systemLogger.log(Level.INFO, MODULE, sMethod, "NOT OK "
								+ javaCert.getSubjectX500Principal().getName() + " - Issuer="
								+ javaCert.getIssuerX500Principal().getName());
					}
				}
				catch (CertificateException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata: ",e);
					return false;
				}
			}
		}
		_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid signing certificate found");
		return false;
	}

	/**
	 * Check dates and/or issuer of the given certificate.
	 * 
	 * @param prefix
	 *            - can be "" or "ca_", the second version checks the ca-certificate as well
	 * @param javaCert
	 *            - the certificate to be checked
	 * @return - is certificate ok?
	 */
	private boolean checkCertificate(String prefix, java.security.cert.X509Certificate javaCert)
	{
		String sMethod = "checkCertificate";
		String sCheckCerts = getCheckCertificates();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Prefix="+prefix+" CheckCerts="+sCheckCerts);
		try {
			if (sCheckCerts != null && sCheckCerts.contains(prefix + "dates")) {
				javaCert.checkValidity();
				// _systemLogger.log(Level.INFO, MODULE, sMethod, "The certificate dates are valid");
			}
			if (sCheckCerts != null && sCheckCerts.contains(prefix + "issuer")) {
				boolean isTrusted = isCertificateTrusted(javaCert);
				if (!isTrusted)
					_systemLogger.log(Level.INFO, MODULE, sMethod, "The certificate issuer is not valid");
				return isTrusted;
			}
			// RM_43_01
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

	/**
	 * Checks if is certificate trusted.
	 * 
	 * @param clientCert
	 *            the client cert
	 * @return true, if is certificate trusted
	 */
	private boolean isCertificateTrusted(java.security.cert.X509Certificate clientCert)
	{
		String sMethod = "isCertificateTrusted";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Check clientCert="
				+ clientCert.getSubjectX500Principal().getName() + " - Issued by "
				+ clientCert.getIssuerX500Principal().getName());
		Set<String> allIssuers = trustedIssuers.keySet();
		for (String ca : allIssuers) {
			java.security.cert.X509Certificate caCert = trustedIssuers.get(ca);
			if (caCert == null) // skip dummy entry
				continue;
			if (caCert.getSubjectX500Principal().equals(clientCert.getIssuerX500Principal())) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Trusted by '" + ca + "': "
						+ caCert.getSubjectX500Principal().getName());
				return true;
			}
		}
		return false;
	}

	/**
	 * Generate the key for the given 'entityId' in 'SSODescriptors'
	 * The key depends on the role of the actual class.
	 * If 'sRole' is null use the role of the partner.
	 * 
	 * @param entityId
	 * @return - the generated key
	 */
	private String makeEntityKey(String entityId, String sRole)
	{
		if (sRole != null)
			return sRole+"_"+entityId;
		
		if ("SP".equals(getMyRole()))
			return "IDP_"+entityId;
		else
			return "SP_"+entityId;
	}
	
	/**
	 * Retrieve the signing key for the given entity id from the metadata cache.
	 * 
	 * @param entityId
	 *            the entity id
	 * @return PublicKey, is null on errors.
	 */
	public PublicKey getSigningKeyFromMetadata(String entityId)
	{
		String sMethod = "getSigningKeyFromMetadata";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "myRole="+getMyRole()+" entityId=" + entityId);
		try {
			ensureMetadataPresence(entityId);
		}
		catch (ASelectException e) {
			return null;
		}

		SSODescriptor descriptor = SSODescriptors.get(makeEntityKey(entityId, null));
		if (descriptor == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Entity id: " + entityId + " not in SSODescriptors: "+SSODescriptors);
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
						_systemLogger.log(Level.FINER, MODULE, sMethod, "Cert: "
								+ javaCert.getSubjectX500Principal().getName() + " - Issuer="
								+ javaCert.getIssuerX500Principal().getName());
						return javaCert.getPublicKey();
					}
					else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Cannot retrieve the public key from metadata for entity id : " + entityId);
					}
				}
				catch (CertificateException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata: ",e);
				}
			}
		}
		return null;
	}
	
	// 20110406, Bauke: added
	/**
	 * Gets the attribute from metadata.
	 * 
	 * @param entityId
	 *            the entity id
	 * @param sAttrName
	 *            the attribute name
	 * @return the attribute value
	 */
	public String getAttributeFromMetadata(String entityId, String sAttrName)
	{
		String sMethod = "getAttributeFromMetadata";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "myRole="+getMyRole()+" entityId=" + entityId);
		try {
			ensureMetadataPresence(entityId);
		}
		catch (ASelectException e) {
			return null;
		}

		SSODescriptor descriptor = SSODescriptors.get(makeEntityKey(entityId, null));
		if (descriptor == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Entity id: " + entityId + " not in SSODescriptors");
			return null;
		}

		String sAttrValue = descriptor.getDOM().getAttribute(sAttrName);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, sAttrName+"="+sAttrValue);
		return sAttrValue;
	}

	/**
	 * Gets the location.
	 * 
	 * @param entityId
	 *            the entity id
	 * @param elementName
	 * <BR>
	 *            SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            ArtifactResolutionService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME
	 * @param bindingName
	 * <BR>
	 *            SAMLConstants.SAML2_SOAP11_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_REDIRECT_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_POST_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_ARTIFACT_BINDING_URI
	 * @return Location
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String getLocation(String entityId, String elementName, String bindingName)
	throws ASelectException
	{
		String locationValue = getAttrFromElementBinding(entityId, elementName, bindingName, "Location", null);
		return locationValue;
	}

	/**
	 * Gets the response location.
	 * 
	 * @param entityId
	 *            the entity id
	 * @param elementName
	 * <BR>
	 *            SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            ArtifactResolutionService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME
	 * @param bindingName
	 * <BR>
	 *            SAMLConstants.SAML2_SOAP11_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_REDIRECT_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_POST_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_ARTIFACT_BINDING_URI
	 * @return ResponseLocation
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String getResponseLocation(String entityId, String elementName, String bindingName)
	throws ASelectException
	{
		return getAttrFromElementBinding(entityId, elementName, bindingName, "ResponseLocation", null);
	}

	/**
	 * Gets the location and binding.
	 * 
	 * @param entityId
	 *            the entity id
	 * @param elementName
	 *            the element name
	 * @param bindingName
	 *            the binding name
	 * @param whichLocation
	 *            the name of the requested location
	 * @param hmBinding
	 *            hash map for the binding found
	 * @return the location found
	 * @throws ASelectException
	 */
	// 20110323, Bauke added to pass back binding from metadata
	public String getLocationAndBinding(String entityId, String elementName, String bindingName,
					String whichLocation, HashMap<String, String> hmBinding)
	throws ASelectException
	{
		return getAttrFromElementBinding(entityId, elementName, bindingName, whichLocation, hmBinding);
	}

	/**
	 * Retrieve the value for "attrName" within the entity 'entityId' looking
	 * for 'elementName' with binding 'bindingName'.
	 * 
	 * @param entityId
	 *            the entity id
	 * @param elementName
	 *            the element name
	 * @param requestedBinding
	 *            the binding name, can be empty meaning "pick any"
	 * @param attrName
	 *            the attribute name we're looking for
	 * @param hmBinding
	 *            the hashmap to receive the binding
	 * @return the requested attribute
	 * @throws ASelectException
	 */
	protected String getAttrFromElementBinding(String entityId, String elementName, String requestedBinding,
					String attrName, HashMap<String, String> hmBinding)
	throws ASelectException
	{
		String sMethod = "getAttrFromElementBinding " + Thread.currentThread().getId();
		String location = null;
		String sDefaultLocation = null;

		_systemLogger.log(Level.INFO, MODULE, sMethod, "myRole="+getMyRole()+" entityId=" + entityId + " elementName=" + elementName
				+ " binding=" + requestedBinding + " attr=" + attrName);
		if (entityId == null)
			return null;
		ensureMetadataPresence(entityId);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Presence ensured for " + entityId);
		
		SSODescriptor descriptor = SSODescriptors.get(makeEntityKey(entityId, null));
		if (descriptor == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No SSODescriptor for " + entityId);
		}
		else {
			try {
				Element domDescriptor = marshallDescriptor(descriptor);
				if (domDescriptor == null)
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "marshallDescriptor failed");
				NodeList nodeList = domDescriptor.getChildNodes();

				//_systemLogger.log(Level.FINE, MODULE, sMethod, "Try "+nodeList.getLength()+" entries");
				for (int i = 0; i < nodeList.getLength(); i++) {
					Node childNode = nodeList.item(i);
					//_systemLogger.log(Level.FINE, MODULE, sMethod, "Node "+childNode.getLocalName());
					if (elementName.equals(childNode.getLocalName())) {
						NamedNodeMap nodeMap = childNode.getAttributes();
						String bindingMDValue = nodeMap.getNamedItem("Binding").getNodeValue();
						Node nIsDefault = nodeMap.getNamedItem("isDefault");
						boolean isDefault = false;
						if (nIsDefault != null && "true".equals(nIsDefault.getNodeValue()))
							isDefault = true;
						_systemLogger.log(Level.FINE, MODULE, sMethod, "Try binding="+bindingMDValue+" isDefault="+isDefault);
						if ((!Utils.hasValue(requestedBinding) && isDefault) || bindingMDValue.equals(requestedBinding)) {
							Node node = nodeMap.getNamedItem(attrName);
							if (node != null) {
								location = node.getNodeValue();
								if (hmBinding != null)
									hmBinding.put("binding", bindingMDValue);
								_systemLogger.log(Level.FINER, MODULE, sMethod, "Found location for entityId="
										+ entityId + " elementName=" + elementName + " bindingName=" + requestedBinding
										+ " attrName=" + attrName + " location=" + location+" binding="+bindingMDValue);
							}
							else {
								if (hmBinding != null)
									hmBinding.clear();
								_systemLogger.log(Level.FINER, MODULE, sMethod, "Did not find location for entityId="
										+ entityId + " elementName=" + elementName + " bindingName=" + requestedBinding
										+ " attrName=" + attrName + " locatione=" + location);
							}
							break;  // ready
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
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Return " + location);
		return location;
	}

	/**
	 * Marshall descriptor.
	 * 
	 * @param descriptor
	 *            the descriptor
	 * @return the element
	 * @throws MarshallingException
	 *             the marshalling exception
	 * @throws XMLParserException
	 *             the XML parser exception
	 */
	private synchronized Element marshallDescriptor(XMLObject descriptor)
	throws MarshallingException, XMLParserException
	{
		String sMethod = "marshallDescriptor";

		BasicParserPool parser = new BasicParserPool();
		parser.setNamespaceAware(true);
		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(descriptor);

		_systemLogger.log(Level.FINER, MODULE, sMethod, "Marshall " + descriptor);
		// _systemLogger.log(Level.INFO, MODULE, sMethod, XMLHelper.prettyPrintXML(descriptor.getDOM()));
		Element domDescriptor = marshaller.marshall(descriptor, parser.newDocument());
		return domDescriptor;
	}

	/**
	 * Gets the check certificates.
	 * 
	 * @return the check certificates
	 */
	public static String getCheckCertificates()
	{
		return _sCheckCertificates;
	}

	/**
	 * Sets the check certificates.
	 * 
	 * @param checkCertificates
	 *            the new check certificates
	 */
	public static void setCheckCertificates(String checkCertificates)
	{
		_sCheckCertificates = checkCertificates;
	}

	/**
	 * Retrieve the session sync URL for the given entity id.
	 * 
	 * @param entityId
	 *            the entity id
	 * @return The session sync URL, or null on errors.
	 */
	public String getSessionSyncURL(String entityId)
	{
		String sMethod = "getSessionSyncURL";
		String sUrl = null;

		PartnerData partnerData = getPartnerDataEntry(entityId);		
		if (partnerData != null)
			sUrl = partnerData.getSessionSyncUrl();
		if (sUrl == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SessionSync not found for Entity id: "+entityId);
		}
		return sUrl;
	}

	/**
	 * Retrieve the session sync URL for the given entity id.
	 * 
	 * @param entityId
	 *            the entity id
	 * @return The session sync URL, or null on errors.
	 */
	public String getMetadataURL(String entityId)
	{
		String sMethod = "getMetadataURL";
		String sUrl = null;

		PartnerData partnerData = getPartnerDataEntry(entityId);
		if (partnerData != null)
			sUrl = partnerData.getMetadataUrl();
		
		if (sUrl == null)
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Metadata not found for Entity id: "+entityId);
		return sUrl;
	}

	/**
	 * Get the PartnerData entry for the given entity id
	 * 
	 * @param entityId
	 * @return - the entry
	 */
	public PartnerData getPartnerDataEntry(String entityId)
	{
		PartnerData partnerData = storeAllIdPData.get(entityId);
		if (partnerData == null)
			partnerData = storeAllIdPData.get("metadata");
		return partnerData;
	}

	/**
	 * Return the number of configured IdPs
	 * 
	 * @return the idp count
	 */
	public int getIdpCount()
	{
		return storeAllIdPData.size();
	}

	/**
	 * Gets the default IdP.
	 * 
	 * @return the default IdP
	 */
	public String getDefaultIdP()
	{
		// Get the first one, useful when there's only one (the default)
		Set<String> keys = storeAllIdPData.keySet();
		for (Object s : keys) {
			String sIdP = (String) s;
			return (sIdP.equals("metadata")) ? _configManager.getFederationUrl() : sIdP;
		}
		return null;
	}
}
