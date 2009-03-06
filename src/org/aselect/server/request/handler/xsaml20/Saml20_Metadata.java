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
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.ProtoRequestHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.xml.XMLObjectBuilderFactory;

public class Saml20_Metadata extends ProtoRequestHandler
{	
	private final static String MODULE = "Saml20_Metadata";

	private String workingDir = null;
	private String redirectURL;
	private String signingCertificate;
	private String publicKeyAlias;
	private String entityIdIdp;
	
	private Long validUntil = null; 	// validity period after now() of metadata (seconds)
	private Long cacheDuration = null; 	// advised period (in seconds) for peer to keep metadata in cache

	private String singleSignOnServiceTarget = "";
	private String artifactResolverTarget = "";
	private String assertionConsumerTarget = "";

	private String spSloHttpLocation = null;
	private String spSloHttpResponse = null;
	private String spSloSoapLocation = null;
	private String spSloSoapResponse = null;
	private String idpSloSoapLocation = null;
	private String idpSloSoapResponse = null;
	private String idpSloHttpLocation = null;
	private String idpSloHttpResponse = null;
	private String idpSSSoapLocation = null;
	
	protected final String PUBLIC_KEYSTORE_NAME = "aselect.keystore";
	protected final String singleSignOnServiceBindingConstantREDIRECT = SAMLConstants.SAML2_REDIRECT_BINDING_URI;
	protected final String artifactResolutionServiceBindingConstantSOAP = SAMLConstants.SAML2_SOAP11_BINDING_URI;
	protected final String assertionConsumerServiceBindingConstantARTIFACT = SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
	protected final String singleLogoutServiceBindingConstantREDIRECT = SAMLConstants.SAML2_REDIRECT_BINDING_URI;
	protected final String singleLogoutServiceBindingConstantSOAP = SAMLConstants.SAML2_SOAP11_BINDING_URI;
	protected final String authzServiceBindingConstantSOAP = SAMLConstants.SAML2_SOAP11_BINDING_URI;

	protected XMLObjectBuilderFactory _oBuilderFactory;  // RH, 20080722, n

	
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init()";

		try {
	        super.init(oServletConfig, oConfig);
			_oBuilderFactory = Configuration.getBuilderFactory(); // RH, 20080722, n

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
                
        		String sValidUntil = Utils.getSimpleParam(oConfig, "valid_until", false);
        		if (sValidUntil != null) {
        			setValidUntil(new Long( Long.parseLong(sValidUntil) * 1000));
        		}
        		String sCacheDuration = Utils.getSimpleParam(oConfig, "cache_duration", false);
        		if (sCacheDuration != null) {
        			setCacheDuration(new Long( Long.parseLong(sValidUntil) * 1000));
        		}
            }
            catch (ASelectConfigException e) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'redirect_url' in section 'aselect' found", e);
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
	
	private void readMetaDataPublicKeyCert(String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "readMetaDataPublicKeyCert";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");
	
		try {
			StringBuffer sbKeystoreLocation = new StringBuffer(sWorkingDir);
			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append("aselectserver");
			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append("keystores");
			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append(PUBLIC_KEYSTORE_NAME);
	
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
				if (sAlias.equals(getPublicKeyAlias())) { //server_id van aselectidp xml federation-idp
	
					java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) ksASelect
							.getCertificate(sAlias);
	
					String encodedCert = new String(Base64.encodeBase64(x509Cert.getEncoded()));
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Found public key alias for : " + getPublicKeyAlias()
							+ " retrieved encoded signing certificate");
	
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
	
	protected void aselectReader() // Will read all non-handler specific config parameters for metadatarequest
	throws ASelectException
	{
		//setSingleLogoutServiceTarget(getRedirectURL()); // We use redirect_url for now
		setPublicKeyAlias(get_sASelectServerID()); // Use server_id from aselect configuration (aselect.xml) as public key alias	
	}
	
	private void handleMetaDataRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
	throws ASelectException
	{
		String sMethod = "handleMetaDataRequest()";
		String mdxml = createMetaDataXML();
	
		_systemLogger.log(Level.INFO, MODULE, sMethod, "metadatXML file for entityID " + getEntityIdIdp() + " " + mdxml);
//		httpResponse.setContentType("text/xml");
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
	
	protected String createMetaDataXML()
	throws ASelectException
	{
		String sMethod = "createMetaDataXML()";
		String error = "This method should NOT be called directly but must be overridden!";
        _systemLogger.log(Level.SEVERE, MODULE, sMethod, error);
        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
	}

	public RequestState process(HttpServletRequest request, HttpServletResponse response)
    throws ASelectException
    {
        String sMethod = "process()";
        try {
        	// TODO make these method calls more transparent
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

	public synchronized String getEntityIdIdp() {
		return entityIdIdp;
	}

	public synchronized void setEntityIdIdp(String entityIdIdp) {
		this.entityIdIdp = entityIdIdp;
	}

	public synchronized String getSpSloSoapLocation() {
		return spSloSoapLocation;
	}

	public synchronized void setSpSloSoapLocation(String logoutServiceLocation) {
		spSloSoapLocation = logoutServiceLocation;
	}

	public synchronized String getArtifactResolverTarget() {
		return artifactResolverTarget;
	}

	public synchronized void setArtifactResolverTarget(String target) {
		artifactResolverTarget = target;
	}

	public synchronized String getRedirectURL() {
		return redirectURL;
	}

	public synchronized void setRedirectURL(String _redirecturl) {
		redirectURL = _redirecturl;
	}

	public synchronized String getWorkingDir() {
		return workingDir;
	}
	public synchronized void setWorkingDir(String workingDir) {
		this.workingDir = workingDir;
	}

	public synchronized String getSigningCertificate() {
		return signingCertificate;
	}

	public synchronized void setSigningCertificate(String certificate) {
		signingCertificate = certificate;
	}

	public synchronized String getPublicKeyAlias() {
		return publicKeyAlias;
	}
	public synchronized void setPublicKeyAlias(String keyAlias) {
		publicKeyAlias = keyAlias;
	}

	public synchronized String getIdpSloSoapLocation() {
		return idpSloSoapLocation;
	}
	public synchronized void setIdpSloSoapLocation(String logoutRequestTarget) {
		idpSloSoapLocation = logoutRequestTarget;
	}

	public synchronized String getSpSloHttpLocation() {
		return spSloHttpLocation;
	}
	public synchronized void setSpSloHttpLocation(String singleLogoutTarget) {
		this.spSloHttpLocation = singleLogoutTarget;
	}

	public synchronized String getAssertionConsumerTarget() {
		return assertionConsumerTarget;
	}

	public synchronized void setAssertionConsumerTarget(String assertionConsumerLocation) {
		this.assertionConsumerTarget = assertionConsumerLocation;
	}

	public synchronized String getSingleSignOnServiceTarget() {
		return singleSignOnServiceTarget;
	}

	public synchronized void setSingleSignOnServiceTarget(String signOnServiceLocation) {
		singleSignOnServiceTarget = signOnServiceLocation;
	}

	public synchronized String getIdpSloHttpLocation()
	{
		return idpSloHttpLocation;
	}
	public synchronized void setIdpSloHttpLocation(String sloTarget)
	{
		this.idpSloHttpLocation = sloTarget;
	}

	public synchronized String getIdpSloHttpResponse()
	{
		return idpSloHttpResponse;
	}

	public synchronized void setIdpSloHttpResponse(String idpSloHttpResponse)
	{
		this.idpSloHttpResponse = idpSloHttpResponse;
	}

	public String getIdpSloSoapResponse()
	{
		return idpSloSoapResponse;
	}

	public void setIdpSloSoapResponse(String idpSloSoapResponse)
	{
		this.idpSloSoapResponse = idpSloSoapResponse;
	}

	public String getSpSloSoapResponse()
	{
		return spSloSoapResponse;
	}

	public void setSpSloSoapResponse(String spSloSoapResponse)
	{
		this.spSloSoapResponse = spSloSoapResponse;
	}

	public String getSpSloHttpResponse()
	{
		return spSloHttpResponse;
	}

	public void setSpSloHttpResponse(String spSloHttpResponse)
	{
		this.spSloHttpResponse = spSloHttpResponse;
	}

	public synchronized String getIdpSSSoapLocation() {
		return idpSSSoapLocation;
	}

	public synchronized void setIdpSSSoapLocation(String idpSSSoapLocation) {
		this.idpSSSoapLocation = idpSSSoapLocation;
	}

	public synchronized Long getValidUntil() {
		return validUntil;
	}

	public synchronized void setValidUntil(Long validUntil) {
		this.validUntil = validUntil;
	}

	public synchronized Long getCacheDuration() {
		return cacheDuration;
	}

	public synchronized void setCacheDuration(Long cacheDuration) {
		this.cacheDuration = cacheDuration;
	}
}
