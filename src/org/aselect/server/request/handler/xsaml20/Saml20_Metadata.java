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
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.ProtoRequestHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;

public class Saml20_Metadata extends ProtoRequestHandler
{
	private final static String MODULE = "Saml20_Metadata";

	public final static String PUBLIC_KEYSTORE_NAME = "aselect.keystore";
	public final static String singleSignOnServiceBindingConstantREDIRECT = SAMLConstants.SAML2_REDIRECT_BINDING_URI;
	public final static String artifactResolutionServiceBindingConstantSOAP = SAMLConstants.SAML2_SOAP11_BINDING_URI;
	public final static String assertionConsumerServiceBindingConstantARTIFACT = SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
	public final static String singleLogoutServiceBindingConstantREDIRECT = SAMLConstants.SAML2_REDIRECT_BINDING_URI;
	public final static String singleLogoutServiceBindingConstantSOAP = SAMLConstants.SAML2_SOAP11_BINDING_URI;
	public final static String authzServiceBindingConstantSOAP = SAMLConstants.SAML2_SOAP11_BINDING_URI;

	private String workingDir = null;
	private String redirectURL;
	private String signingCertificate;
	private String publicKeyAlias;
	private String entityIdIdp;

	private Long validUntil = null; // validity period after now() of metadata (seconds)
	private Long cacheDuration = null; // advised period (in seconds) for peer to keep metadata in cache

	// SP
	private String assertionConsumerTarget = "";

	private String spSloHttpLocation = null;
	private String spSloHttpResponse = null;
	private String spSloSoapLocation = null;
	private String spSloSoapResponse = null;

	// IdP
	private String idpSsoUrl = "";
	private String idpArtifactResolverUrl = "";
	private String idpSloSoapRequestUrl = "";
	private String idpSloSoapResponseUrl = "";
	private String idpSloHttpRequestUrl = "";
	private String idpSloHttpResponseUrl = "";
	private String idpSyncUrl = "";

	private String singleSignOnServiceTarget = "";
	private String artifactResolverTarget = "";
	private String idpSloSoapLocation = null;
	private String idpSloSoapResponse = null;
	private String idpSloHttpLocation = null;
	private String idpSloHttpResponse = null;
	private String idpSSSoapLocation = null;

	protected XMLObjectBuilderFactory _oBuilderFactory;

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		try {
			super.init(oServletConfig, oConfig);
			try {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Saml Bootstrap");
				DefaultBootstrap.bootstrap();
			}
			catch (ConfigurationException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "OpenSAML library could not be initialized", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Bootstrap done");
			_oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory(); // RH, 20080722, n

			// TODO, move this to a aselect config parameter (location of keystore)
			// TODO, working_dir only needed for certificate, so only for signed?
			setWorkingDir(oServletConfig.getInitParameter("working_dir")); // from web.xml
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Working directoy: " + getWorkingDir());

			Object oASelect = null;
			try {
				oASelect = _configManager.getSection(null, "aselect");
				setRedirectURL(_configManager.getParam(oASelect, "redirect_url"));
				// redirect_url will be used as entityIdIdp in metadata
				setEntityIdIdp(_configManager.getParam(oASelect, "redirect_url"));

				String sValidUntil = ASelectConfigManager.getSimpleParam(oConfig, "valid_until", false);
				if (sValidUntil != null) {
					setValidUntil(new Long(Long.parseLong(sValidUntil) * 1000));
				}
				String sCacheDuration = ASelectConfigManager.getSimpleParam(oConfig, "cache_duration", false);
				if (sCacheDuration != null) {
					setCacheDuration(new Long(Long.parseLong(sCacheDuration) * 1000));
				}
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config item 'redirect_url' in section 'aselect' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Read meta data public key cert.
	 * 
	 * @param sWorkingDir
	 *            the s working dir
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void readMetaDataPublicKeyCert(String sWorkingDir)
		throws ASelectException
	{
		String sMethod = "readMetaDataPublicKeyCert";

		try {
			StringBuffer sbKeystoreLocation = new StringBuffer(sWorkingDir);
			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append("aselectserver");
			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append("keystores");
			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append(PUBLIC_KEYSTORE_NAME);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Read:" + sbKeystoreLocation);

			File fKeystore = new File(sbKeystoreLocation.toString());
			if (!fKeystore.exists()) {
				StringBuffer sbError = new StringBuffer("Keystore cannot be found: ");
				sbError.append(sbKeystoreLocation.toString());
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_NOT_FOUND);
			}

			KeyStore ksASelect = KeyStore.getInstance("JKS");
			ksASelect.load(new FileInputStream(sbKeystoreLocation.toString()), null);

			Enumeration<?> enumAliases = ksASelect.aliases();
			while (enumAliases.hasMoreElements()) {
				String sAlias = (String) enumAliases.nextElement();

				sAlias = sAlias.toLowerCase();
				if (sAlias.equals(getPublicKeyAlias())) { // server_id A-Select IdP
					java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) ksASelect
							.getCertificate(sAlias);

					String encodedCert = new String(Base64.encodeBase64(x509Cert.getEncoded()));
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Found public key alias for : "
							+ getPublicKeyAlias() + " retrieved encoded signing certificate");
					setSigningCertificate(encodedCert);
				}
			}
			if (getSigningCertificate() == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No alias found for idp public key with name : "
						+ getPublicKeyAlias());
				throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
			}
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer(" Error loading public keys from directory: '");
			sbError.append(sWorkingDir);
			sbError.append("'");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	// Override this method!
	/**
	 * Aselect reader.
	 * Will read all non-handler specific config parameters for metadata request
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void aselectReader()
	throws ASelectException
	{
		// setSingleLogoutServiceTarget(getRedirectURL()); // We use redirect_url for now
		setPublicKeyAlias(get_sASelectServerID());
		// Use server_id from aselect configuration (aselect.xml) as public key alias
	}

	/**
	 * Handle meta data request.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleMetaDataRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
		throws ASelectException
	{
		String sMethod = "handleMetaDataRequest";
		String mdxml = createMetaDataXML();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "metadatXML file for entityID " + getEntityIdIdp() + " " + mdxml);
		httpResponse.setContentType("application/samlmetadata+xml");

		PrintWriter out;
		try {
			out = httpResponse.getWriter();
			out.println(mdxml);
			out.flush();
			out.close();
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not handle the request", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Creates the meta data xml.
	 * 
	 * @return the string
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected String createMetaDataXML()
		throws ASelectException
	{
		String sMethod = "createMetaDataXML";
		String error = "This method should NOT be called directly but must be overridden!";
		_systemLogger.log(Level.SEVERE, MODULE, sMethod, error);
		throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.IRequestHandler#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		try {
			// These method calls could be made more transparent
			// all kind of things get set that we don't know off
			aselectReader(); // among other things this sets the publicKeyAlias
			readMetaDataPublicKeyCert(getWorkingDir()); // This sets the signing certificate using the publicKeyAlias
			handleMetaDataRequest(request, response);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return new RequestState(null);
	}

	/**
	 * Gets the entity id idp.
	 * 
	 * @return the entity id idp
	 */
	public synchronized String getEntityIdIdp()
	{
		return entityIdIdp;
	}

	/**
	 * Sets the entity id idp.
	 * 
	 * @param entityIdIdp
	 *            the new entity id idp
	 */
	public synchronized void setEntityIdIdp(String entityIdIdp)
	{
		this.entityIdIdp = entityIdIdp;
	}

	/**
	 * Gets the sp slo soap location.
	 * 
	 * @return the sp slo soap location
	 */
	public synchronized String getSpSloSoapLocation()
	{
		return spSloSoapLocation;
	}

	/**
	 * Sets the sp slo soap location.
	 * 
	 * @param logoutServiceLocation
	 *            the new sp slo soap location
	 */
	public synchronized void setSpSloSoapLocation(String logoutServiceLocation)
	{
		spSloSoapLocation = logoutServiceLocation;
	}

	/**
	 * Gets the artifact resolver target.
	 * 
	 * @return the artifact resolver target
	 */
	public synchronized String getArtifactResolverTarget()
	{
		return artifactResolverTarget;
	}

	/**
	 * Sets the artifact resolver target.
	 * 
	 * @param target
	 *            the new artifact resolver target
	 */
	public synchronized void setArtifactResolverTarget(String target)
	{
		artifactResolverTarget = target;
	}

	/**
	 * Gets the redirect url.
	 * 
	 * @return the redirect url
	 */
	public synchronized String getRedirectURL()
	{
		return redirectURL;
	}

	/**
	 * Sets the redirect url.
	 * 
	 * @param _redirecturl
	 *            the new redirect url
	 */
	public synchronized void setRedirectURL(String _redirecturl)
	{
		redirectURL = _redirecturl;
	}

	/**
	 * Gets the working dir.
	 * 
	 * @return the working dir
	 */
	public synchronized String getWorkingDir()
	{
		return workingDir;
	}

	/**
	 * Sets the working dir.
	 * 
	 * @param workingDir
	 *            the new working dir
	 */
	public synchronized void setWorkingDir(String workingDir)
	{
		this.workingDir = workingDir;
	}

	/**
	 * Gets the signing certificate.
	 * 
	 * @return the signing certificate
	 */
	public synchronized String getSigningCertificate()
	{
		return signingCertificate;
	}

	/**
	 * Sets the signing certificate.
	 * 
	 * @param certificate
	 *            the new signing certificate
	 */
	public synchronized void setSigningCertificate(String certificate)
	{
		signingCertificate = certificate;
	}

	/**
	 * Gets the public key alias.
	 * 
	 * @return the public key alias
	 */
	public synchronized String getPublicKeyAlias()
	{
		return publicKeyAlias;
	}

	/**
	 * Sets the public key alias.
	 * 
	 * @param keyAlias
	 *            the new public key alias
	 */
	public synchronized void setPublicKeyAlias(String keyAlias)
	{
		publicKeyAlias = keyAlias;
	}

	/**
	 * Gets the idp slo soap location.
	 * 
	 * @return the idp slo soap location
	 */
	public synchronized String getIdpSloSoapLocation()
	{
		return idpSloSoapLocation;
	}

	/**
	 * Sets the idp slo soap location.
	 * 
	 * @param logoutRequestTarget
	 *            the new idp slo soap location
	 */
	public synchronized void setIdpSloSoapLocation(String logoutRequestTarget)
	{
		idpSloSoapLocation = logoutRequestTarget;
	}

	/**
	 * Gets the sp slo http location.
	 * 
	 * @return the sp slo http location
	 */
	public synchronized String getSpSloHttpLocation()
	{
		_systemLogger.log(Level.INFO, MODULE, "getSpSloHttpLocation", "Get " + spSloHttpLocation);
		return spSloHttpLocation;
	}

	/**
	 * Sets the sp slo http location.
	 * 
	 * @param singleLogoutTarget
	 *            the new sp slo http location
	 */
	public synchronized void setSpSloHttpLocation(String singleLogoutTarget)
	{
		_systemLogger.log(Level.INFO, MODULE, "setSpSloHttpLocation", "Set " + singleLogoutTarget);
		this.spSloHttpLocation = singleLogoutTarget;
	}

	/**
	 * Gets the assertion consumer target.
	 * 
	 * @return the assertion consumer target
	 */
	public synchronized String getAssertionConsumerTarget()
	{
		_systemLogger.log(Level.INFO, MODULE, "getAssertionConsumerTarget", "Get " + assertionConsumerTarget);
		return assertionConsumerTarget;
	}

	/**
	 * Sets the assertion consumer target.
	 * 
	 * @param assertionConsumerLocation
	 *            the new assertion consumer target
	 */
	public synchronized void setAssertionConsumerTarget(String assertionConsumerLocation)
	{
		_systemLogger.log(Level.INFO, MODULE, "setAssertionConsumerTarget", "Set " + assertionConsumerLocation);
		this.assertionConsumerTarget = assertionConsumerLocation;
	}

	/**
	 * Gets the single sign on service target.
	 * 
	 * @return the single sign on service target
	 */
	public synchronized String getSingleSignOnServiceTarget()
	{
		return singleSignOnServiceTarget;
	}

	/**
	 * Sets the single sign on service target.
	 * 
	 * @param signOnServiceLocation
	 *            the new single sign on service target
	 */
	public synchronized void setSingleSignOnServiceTarget(String signOnServiceLocation)
	{
		singleSignOnServiceTarget = signOnServiceLocation;
	}

	/**
	 * Gets the idp slo http location.
	 * 
	 * @return the idp slo http location
	 */
	public synchronized String getIdpSloHttpLocation()
	{
		return idpSloHttpLocation;
	}

	/**
	 * Sets the idp slo http location.
	 * 
	 * @param sloTarget
	 *            the new idp slo http location
	 */
	public synchronized void setIdpSloHttpLocation(String sloTarget)
	{
		this.idpSloHttpLocation = sloTarget;
	}

	/**
	 * Gets the idp slo http response.
	 * 
	 * @return the idp slo http response
	 */
	public synchronized String getIdpSloHttpResponse()
	{
		return idpSloHttpResponse;
	}

	/**
	 * Sets the idp slo http response.
	 * 
	 * @param idpSloHttpResponse
	 *            the new idp slo http response
	 */
	public synchronized void setIdpSloHttpResponse(String idpSloHttpResponse)
	{
		this.idpSloHttpResponse = idpSloHttpResponse;
	}

	/**
	 * Gets the idp slo soap response.
	 * 
	 * @return the idp slo soap response
	 */
	public String getIdpSloSoapResponse()
	{
		return idpSloSoapResponse;
	}

	/**
	 * Sets the idp slo soap response.
	 * 
	 * @param idpSloSoapResponse
	 *            the new idp slo soap response
	 */
	public void setIdpSloSoapResponse(String idpSloSoapResponse)
	{
		this.idpSloSoapResponse = idpSloSoapResponse;
	}

	/**
	 * Gets the sp slo soap response.
	 * 
	 * @return the sp slo soap response
	 */
	public String getSpSloSoapResponse()
	{
		return spSloSoapResponse;
	}

	/**
	 * Sets the sp slo soap response.
	 * 
	 * @param spSloSoapResponse
	 *            the new sp slo soap response
	 */
	public void setSpSloSoapResponse(String spSloSoapResponse)
	{
		this.spSloSoapResponse = spSloSoapResponse;
	}

	/**
	 * Gets the sp slo http response.
	 * 
	 * @return the sp slo http response
	 */
	public String getSpSloHttpResponse()
	{
		_systemLogger.log(Level.INFO, MODULE, "getSpSloHttpResponse", "Get " + spSloHttpResponse);
		return spSloHttpResponse;
	}

	/**
	 * Sets the sp slo http response.
	 * 
	 * @param spSloHttpResponse
	 *            the new sp slo http response
	 */
	public void setSpSloHttpResponse(String spSloHttpResponse)
	{
		_systemLogger.log(Level.INFO, MODULE, "setSpSloHttpResponse", "Set " + spSloHttpResponse);
		this.spSloHttpResponse = spSloHttpResponse;
	}

	/**
	 * Gets the idp ss soap location.
	 * 
	 * @return the idp ss soap location
	 */
	public synchronized String getIdpSSSoapLocation()
	{
		return idpSSSoapLocation;
	}

	/**
	 * Sets the idp ss soap location.
	 * 
	 * @param idpSSSoapLocation
	 *            the new idp ss soap location
	 */
	public synchronized void setIdpSSSoapLocation(String idpSSSoapLocation)
	{
		this.idpSSSoapLocation = idpSSSoapLocation;
	}

	/**
	 * Gets the valid until.
	 * 
	 * @return the valid until
	 */
	public synchronized Long getValidUntil()
	{
		return validUntil;
	}

	/**
	 * Sets the valid until.
	 * 
	 * @param validUntil
	 *            the new valid until
	 */
	public synchronized void setValidUntil(Long validUntil)
	{
		this.validUntil = validUntil;
	}

	/**
	 * Gets the cache duration.
	 * 
	 * @return the cache duration
	 */
	public synchronized Long getCacheDuration()
	{
		return cacheDuration;
	}

	/**
	 * Sets the cache duration.
	 * 
	 * @param cacheDuration
	 *            the new cache duration
	 */
	public synchronized void setCacheDuration(Long cacheDuration)
	{
		this.cacheDuration = cacheDuration;
	}

	/**
	 * Gets the idp artifact resolver url.
	 * 
	 * @return the idp artifact resolver url
	 */
	public String getIdpArtifactResolverUrl()
	{
		return idpArtifactResolverUrl;
	}

	/**
	 * Sets the idp artifact resolver url.
	 * 
	 * @param idpArtifactResolverUrl
	 *            the new idp artifact resolver url
	 */
	public void setIdpArtifactResolverUrl(String idpArtifactResolverUrl)
	{
		this.idpArtifactResolverUrl = idpArtifactResolverUrl;
	}

	/**
	 * Gets the idp slo http request url.
	 * 
	 * @return the idp slo http request url
	 */
	public String getIdpSloHttpRequestUrl()
	{
		return idpSloHttpRequestUrl;
	}

	/**
	 * Sets the idp slo http request url.
	 * 
	 * @param idpSloHttpUrl
	 *            the new idp slo http request url
	 */
	public void setIdpSloHttpRequestUrl(String idpSloHttpUrl)
	{
		this.idpSloHttpRequestUrl = idpSloHttpUrl;
	}

	/**
	 * Gets the idp slo soap request url.
	 * 
	 * @return the idp slo soap request url
	 */
	public String getIdpSloSoapRequestUrl()
	{
		return idpSloSoapRequestUrl;
	}

	/**
	 * Sets the idp slo soap request url.
	 * 
	 * @param idpSloSoapUrl
	 *            the new idp slo soap request url
	 */
	public void setIdpSloSoapRequestUrl(String idpSloSoapUrl)
	{
		this.idpSloSoapRequestUrl = idpSloSoapUrl;
	}

	/**
	 * Gets the idp sso url.
	 * 
	 * @return the idp sso url
	 */
	public String getIdpSsoUrl()
	{
		return idpSsoUrl;
	}

	/**
	 * Sets the idp sso url.
	 * 
	 * @param idpSsoUrl
	 *            the new idp sso url
	 */
	public void setIdpSsoUrl(String idpSsoUrl)
	{
		this.idpSsoUrl = idpSsoUrl;
	}

	/**
	 * Gets the idp sync url.
	 * 
	 * @return the idp sync url
	 */
	public String getIdpSyncUrl()
	{
		return idpSyncUrl;
	}

	/**
	 * Sets the idp sync url.
	 * 
	 * @param idpSyncUrl
	 *            the new idp sync url
	 */
	public void setIdpSyncUrl(String idpSyncUrl)
	{
		this.idpSyncUrl = idpSyncUrl;
	}

	/**
	 * Gets the idp slo http response url.
	 * 
	 * @return the idp slo http response url
	 */
	public String getIdpSloHttpResponseUrl()
	{
		return idpSloHttpResponseUrl;
	}

	/**
	 * Sets the idp slo http response url.
	 * 
	 * @param idpSloHttpResponseUrl
	 *            the new idp slo http response url
	 */
	public void setIdpSloHttpResponseUrl(String idpSloHttpResponseUrl)
	{
		this.idpSloHttpResponseUrl = idpSloHttpResponseUrl;
	}

	/**
	 * Gets the idp slo soap response url.
	 * 
	 * @return the idp slo soap response url
	 */
	public String getIdpSloSoapResponseUrl()
	{
		return idpSloSoapResponseUrl;
	}

	/**
	 * Sets the idp slo soap response url.
	 * 
	 * @param idpSloSoapResponseUrl
	 *            the new idp slo soap response url
	 */
	public void setIdpSloSoapResponseUrl(String idpSloSoapResponseUrl)
	{
		this.idpSloSoapResponseUrl = idpSloSoapResponseUrl;
	}
}
