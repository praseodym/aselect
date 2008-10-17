package org.aselect.server.request.handler.saml20.sp.metadata;

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
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml20.common.Utils;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.opensaml.common.xml.SAMLConstants;

/*
 * Aanroepen via http://localhost:8080/aselectserver/server/metadata.xml
 */
public class MetaDataRequestHandlerSP extends AbstractRequestHandler
{
	private final static String MODULE = "MetaDataRequestHandler";
	private static ASelectConfigManager _configManager;
	private String singleSignOnServiceLocation;
	private String singleLogoutServiceLocation;
	private String artifactresolverTarget;
	private String redirectURL;
	private String signingCertificate;
	private String entityIdIdp;
	private String publicKeyAlias;

	private String workingDir = null;
	private final String PUBLIC_KEYSTORE_NAME = "aselect.keystore";
	private final String artifactResolutionServiceBindingConstantSOAP = SAMLConstants.SAML2_SOAP11_BINDING_URI;
	private final String singleLogoutServiceBindingConstantREDIRECT = SAMLConstants.SAML2_REDIRECT_BINDING_URI;
	private final String singleSignOnServiceBindingConstantREDIRECT = SAMLConstants.SAML2_REDIRECT_BINDING_URI;
	private final String singleLogoutServiceBindingConstantSOAP = SAMLConstants.SAML2_SOAP11_BINDING_URI;
	private final String assertionConsumerServiceBindingConstantARTIFACT = SAMLConstants.SAML2_ARTIFACT_BINDING_URI;

	private String singleLogoutTarget;
	private String assertionConsumerLocation;
	private String singleLogoutRequestTarget;

	/**
	 * Init for class MetaDataRequestHandlerSP.
	 * <br>
	 * @param servletConfig ServletConfig
	 * @param config Object
	 * @throws ASelectException If initialization fails.
	 */
	@Override
	public void init(ServletConfig servletConfig, Object config)
		throws ASelectException
	{
		String sMethod = "init()";
		super.init(servletConfig, config);
		workingDir = servletConfig.getInitParameter("working_dir"); // web.xml
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Working directoy: " + workingDir);
	}

	private void handleMetaDataRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
		throws ASelectException
	{

		String sMethod = "handleMetaDataRequest()";
		String mdxml = createMetaDataXML();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "metadata XML file for entityID " + entityIdIdp + " " + mdxml);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "path="+httpRequest.getRequestURL());
		httpResponse.setContentType("text/xml");
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

	private void readMetaDataPublicKeyCert(String sWorkingDir)
		throws ASelectException
	{
		String sMethod = "readMetaDataPublicKeyCert";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		try {
			StringBuffer sbKeystoreLocation = new StringBuffer(sWorkingDir);
			sbKeystoreLocation.append(File.separator); // added: Bauke
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
				if (sAlias.equals(publicKeyAlias)) { // / server_id van aselectisp xml SP

					java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) ksASelect
							.getCertificate(sAlias);

					String encodedCert = new String(Base64.encodeBase64(x509Cert.getEncoded()));
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Found public key alias for : " + publicKeyAlias
							+ " retrieved encoded signing certificate");

					signingCertificate = encodedCert;
				}
			}
			if (signingCertificate == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No alias found for idp public key with name : "
						+ publicKeyAlias);
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

	private void aselectReader()
		throws ASelectException
	{
		String sMethod = "aselectReader()";

		String sRedirect_url = null;
		String sServer_id = null;
		Object oASelect = null;
		Object oRequest = null;
		Object oHandlers = null;
		Object oHandler = null;

		try {
			oASelect = _configManager.getSection(null, "aselect");
			sRedirect_url = _configManager.getParam(oASelect, "redirect_url");
			sServer_id = _configManager.getParam(oASelect, "server_id");

			redirectURL = sRedirect_url;
			singleSignOnServiceLocation = sRedirect_url;
			singleLogoutServiceLocation = sRedirect_url;
			assertionConsumerLocation = sRedirect_url;
			entityIdIdp = sRedirect_url;
			publicKeyAlias = sServer_id;

		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not retrieve 'redirect_url' or 'server_id' config parameter in 'aselect' config section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		try {

			oRequest = _configManager.getSection(null, "requests");
			oHandlers = _configManager.getSection(oRequest, "handlers");
			oHandler = _configManager.getSection(oHandlers, "handler");

			while (oHandler != null) {
				try {

					String sId = _configManager.getParam(oHandler, "id");

					if (sId.equals("saml20_artifactresolver")) {
						String sTarget = _configManager.getParam(oHandler, "target");
						sTarget = sTarget.replace("\\", "");
						sTarget = sTarget.replace(".*", "");
						artifactresolverTarget = sTarget;

					}
					else if (sId.equals("saml_logout_response_handler")) {
						String sTarget = _configManager.getParam(oHandler, "target");

						int i = sTarget.indexOf("|");
						if (i > 0) {
							sTarget = sTarget.substring(1, i);
						}
						sTarget = sTarget.replace("\\", "");
						sTarget = sTarget.replace(".*", "");
						singleLogoutTarget = sTarget;

					}
					else if (sId.equals("saml_logout_request_handler")) {
						String sTarget = _configManager.getParam(oHandler, "target");

						int l = sTarget.length();

						int i = sTarget.indexOf("|");
						if (i > 0) {
							sTarget = sTarget.substring(i, l);
						}
						sTarget = sTarget.replace("\\", "");
						sTarget = sTarget.replace("|", "");
						sTarget = sTarget.replace(".*", "");
						singleLogoutRequestTarget = sTarget;

					}

				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config next section 'handler' found", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				oHandler = _configManager.getNextSection(oHandler);
			}

		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not find 'aselect' config section in config file",
					e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

	}

	private String createMetaDataXML()
	{

		String artifactResolutionServiceLocation = redirectURL + artifactresolverTarget; // "http://localhost:8080/aselect_sp/server/SAML/Artifact/Resolve";
		String singleLogoutServiceResponseLocation = redirectURL + singleLogoutTarget;// "http://localhost:8080/aselect_sp/server/logoutResponse";
		String singleLogoutRequestLocation = redirectURL + singleLogoutRequestTarget;

		// entityID is redirect_url van aselect idp xml

		String xmlMDRequest = "<?xml version=\"1.0\"?>"
				+ "<m:EntityDescriptor xmlns:m=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\""
				+ entityIdIdp
				+ "\">"
				+ "	<m:SPSSODescriptor WantAuthnRequestsSigned=\"false\"  protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
				+ "<m:KeyDescriptor use=\"signing\">" + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
				+ "<ds:X509Data>" + "<ds:X509Certificate>" + signingCertificate + "</ds:X509Certificate>"
				+ "</ds:X509Data>" + "</ds:KeyInfo>" + "</m:KeyDescriptor>" + "<m:ArtifactResolutionService Binding=\""
				+ artifactResolutionServiceBindingConstantSOAP + "\"" + " Location=\""
				+ artifactResolutionServiceLocation + "\"" + " index=\"0\" isDefault=\"true\">"
				+ "</m:ArtifactResolutionService>" + "<m:AssertionConsumerService Binding=\""
				+ assertionConsumerServiceBindingConstantARTIFACT + "\"" + " Location=\"" + assertionConsumerLocation
				+ "\"" + " index=\"0\" isDefault=\"true\">" + "</m:AssertionConsumerService>"
				+ "<m:SingleLogoutService Binding=\"" + singleLogoutServiceBindingConstantREDIRECT + "\""
				+ " Location=\"" + singleLogoutServiceLocation + "\">" + "</m:SingleLogoutService>"
				+ "<m:SingleLogoutService Binding=\"" + singleLogoutServiceBindingConstantSOAP + "\"" + " Location=\""
				+ singleLogoutRequestLocation + "\"" + " ResponseLocation=\"" + singleLogoutServiceResponseLocation
				+ "\">" + "</m:SingleLogoutService>" + "<m:SingleSignOnService Binding=\""
				+ singleSignOnServiceBindingConstantREDIRECT + "\"" + " Location=\"" + singleSignOnServiceLocation
				+ "\">" + "</m:SingleSignOnService>" + "</m:SPSSODescriptor>" + "</m:EntityDescriptor>";
		return xmlMDRequest;
	}

	/**
	 * Process meta data request.
	 * <br>
	 * @param request HttpServletRequest
	 * @param response HttpServletResponse
	 * @throws ASelectException If processing meta data request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process";

		_configManager = ASelectConfigManager.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();

		if (workingDir == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not retrieve 'working_dir' parameter from deployment descriptor to load public keys.");
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INIT_ERROR);
		}

		aselectReader();
		readMetaDataPublicKeyCert(workingDir); // +"\\aselectserver\\keystores"
		handleMetaDataRequest(request, response);
		return null;
	}

	public void destroy()
	{
	}

}
