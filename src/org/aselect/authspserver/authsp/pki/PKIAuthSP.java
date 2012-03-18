/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 */

/* 
 * $Id: PKIAuthSP.java,v 1.4 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $log$
 *
 */

package org.aselect.authspserver.authsp.pki;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.authsp.pki.cert.handler.ICertificateHandler;
import org.aselect.authspserver.authsp.pki.cert.handler.ldap.LDAPCertificateHandler;
import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.crypto.CryptoEngine;
import org.aselect.authspserver.log.AuthSPAuthenticationLogger;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;

/**
 * PKI AuthSP. <br>
 * <br>
 * <b>Description: </b> <br>
 * The PKI AuthSP implements PKI-based authentication for A-Select 1.4.1 through CA validation, Backend validation and
 * optionally 2-Factor authentication. <br>
 * <br>
 * <b>Requirements: </b> <br>
 * <ul>
 * <li>A-Select AuthSP Server 1.4.1 or higher</li>
 * </ul>
 * <b>Concurrency issues: </b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - pass Subject DN and Issuer DN from the card to the A-select server -
 *         optionally skip the Subject DN check, controled by the <subject_validation> parameter
 * @author Bauke Hiemstra - www.anoigo.nl Copyright UMC Nijmegen (http://www.umcn.nl)
 */
public class PKIAuthSP extends HttpServlet
{
	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "PKIAuthSP";

	private String _sVersion = "1.0";
	private String _sErrorHtmlTemplate = "";
	private String _sTFHtmlTemplate = "";
	private String _sFriendlyName = null;
	private String _sWorkingDir = null;
	private CryptoEngine _oCryptoEngine = null;

	/** The logger that logs authentication information. */
	private AuthSPAuthenticationLogger _authenticationLogger;

	/** The logger that logs system information. */
	private AuthSPSystemLogger _systemLogger;

	private AuthSPConfigManager _oConfigManager = null;
	private Object _oAuthSpConfig = null;
	private PKIManager _oPkiManager = null;

	/**
	 * Initializes the PKI AuthSP <br>
	 * <br>
	 * .
	 * 
	 * @param oServletConfig
	 *            the o servlet config
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	public void init(ServletConfig oServletConfig)
		throws ServletException
	{
		String sMethod = "init()";
		try {
			super.init(oServletConfig);

			ServletContext oServletContext = oServletConfig.getServletContext();

			try {
				_systemLogger = AuthSPSystemLogger.getHandle();
				_authenticationLogger = AuthSPAuthenticationLogger.getHandle();
			}
			catch (Exception e) {
				System.out.println(e.getMessage());
				throw new ServletException("Error occured by init SystemLogger");
			}

			_sWorkingDir = (String) oServletContext.getAttribute("working_dir");
			if (_sWorkingDir == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "working_dir attribute not found");
				throw new ServletException("working_dir attribute not found");
			}
			_oConfigManager = AuthSPConfigManager.getHandle();

			// Retrieve configuration
			String sConfigID = oServletConfig.getInitParameter("config_id");
			if (sConfigID == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'config_id' found as init-parameter in web.xml.");
				throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
			}
			try {
				_oAuthSpConfig = _oConfigManager.getSection(null, "authsp", "id=" + sConfigID);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
				throw new ServletException(
						"Error occured by init PKI AuthSP, see the PKI AuthSP log files for more information");
			}

			_oCryptoEngine = (CryptoEngine) oServletContext.getAttribute("CryptoEngine");
			if (_oCryptoEngine == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "CryptoEngine not found");
				throw new ServletException("CryptoEngine not found");
			}

			_sFriendlyName = (String) oServletContext.getAttribute("friendly_name");
			if (_sFriendlyName == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "friendly_name attribute not found");
				throw new ServletException("friendly_name attribute not found");
			}
			initHtmlTemplates();
			try {
				Object oCaValidationConfig = _oConfigManager.getSection(_oAuthSpConfig, "ca_validation");
				_oPkiManager = new PKIManager();
				_oPkiManager.init(oCaValidationConfig, _systemLogger);

			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to read 'ca_validation' configuration", e);
				throw e;
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to initialize PKIManager", e);
				throw e;
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			throw new ServletException("Initializing failed");
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "PKI AuthSP successfully initialized.");
	}

	/**
	 * Destroys the PKIManager with all its threads.
	 * 
	 * @see javax.servlet.GenericServlet#destroy()
	 */
	public void destroy()
	{
		_systemLogger.log(Level.INFO, MODULE, "destroy", "Destroy PKIManager");
		_oPkiManager.destroy();
		super.destroy();
	}

	/**
	 * Initializes the HTML Templates. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Initialize the Error and the Two Factor HTML Templates<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None<br>
	 * 
	 * @throws ServletException
	 *             when a template file can't be found or read.
	 */
	public void initHtmlTemplates()
	throws ServletException
	{
		StringBuffer sbTemp;
		String sMethod = "initHtmlTemplates()";
		String sLine = null;
		BufferedReader oBufInputReader;

		try {
			sbTemp = new StringBuffer(_sWorkingDir);
			sbTemp.append(File.separator).append("conf").append(File.separator);
			sbTemp.append("pki").append(File.separator).append("html");
			sbTemp.append(File.separator).append("error.html");
			oBufInputReader = new BufferedReader(new InputStreamReader(new FileInputStream(sbTemp.toString())));
			while ((sLine = oBufInputReader.readLine()) != null) {
				_sErrorHtmlTemplate += sLine;
			}
			_sErrorHtmlTemplate = Utils.replaceString(_sErrorHtmlTemplate, "[version]", _sVersion);
			_sErrorHtmlTemplate = Utils.replaceString(_sErrorHtmlTemplate, "[organization_friendly]", _sFriendlyName);

			sbTemp = new StringBuffer(_sWorkingDir);
			sbTemp.append(File.separator).append("conf").append(File.separator);
			sbTemp.append("pki").append(File.separator).append("html");
			sbTemp.append(File.separator).append("twofactor.html");
			oBufInputReader = new BufferedReader(new InputStreamReader(new FileInputStream(sbTemp.toString())));
			while ((sLine = oBufInputReader.readLine()) != null) {
				_sTFHtmlTemplate += sLine + "\r";
			}
			_sTFHtmlTemplate = Utils.replaceString(_sTFHtmlTemplate, "[version]", _sVersion);
			_sTFHtmlTemplate = Utils.replaceString(_sTFHtmlTemplate, "[organization_friendly]", _sFriendlyName);
		}
		catch (FileNotFoundException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
			throw new ServletException(
					"Error occured by init PKI AuthSP, see the PKI AuthSP log files for more information");
		}
		catch (IOException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
			throw new ServletException(
					"Error occured by init PKI AuthSP, see the PKI AuthSP log files for more information");
		}
	}

	/**
	 * Entrypoint for handling 2-Factor user input form. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
		throws ServletException, IOException
	{
		String sMethod = "doPost()";
		StringBuffer sbTemp = null;
		try {
			String sAsUrl = servletRequest.getParameter("as_url");
			String sRid = servletRequest.getParameter("rid");
			String sUserAttributes = servletRequest.getParameter("user_attribute");
			String sAsId = servletRequest.getParameter("a-select-server");
			String sPassword = servletRequest.getParameter("password");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "rid=" + sRid + "user_attr=" + sUserAttributes);

			String sTFAuthSpName = servletRequest.getParameter("tf_authsp");
			String sTFAuthSpUrl = servletRequest.getParameter("tf_url");
			String sTFAuthSpUserAttributes = servletRequest.getParameter("tf_uid");
			String sRetryCounter = servletRequest.getParameter("tf_retries");

			String sMyUrl = servletRequest.getRequestURL().toString();
			String sSignature = servletRequest.getParameter("signature");

			sbTemp = new StringBuffer(sRid).append(sAsUrl).append(sUserAttributes).append(sAsId).append(sTFAuthSpName)
					.append(sTFAuthSpUrl).append(sTFAuthSpUserAttributes).append(sRetryCounter).append(sMyUrl);
			String sGeneratedSignature = _oCryptoEngine.generateSignature(sbTemp.toString());
			if (!sGeneratedSignature.equals(sSignature)) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Invalid signature");
				throw new ASelectException(Errors.PKI_INVALID_REQUEST);
			}
			boolean bVerifiyTFAuthentication = verifyTFAuthentication(sRid, sTFAuthSpUrl, sTFAuthSpUserAttributes,
					sPassword);

			if (!bVerifiyTFAuthentication) {
				int iRetries = new Integer(sRetryCounter).intValue();
				iRetries--;
				if (iRetries <= 0) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No retries for 2-factor authentication left");
					throw new ASelectException(Errors.PKI_2FACTOR_NO_RETRIES_LEFT);
				}
				String sErrorMsg = "invalid password";
				HashMap htParams = new HashMap();
				htParams.put("as_url", sAsUrl);
				htParams.put("rid", sRid);
				htParams.put("user_attribute", sUserAttributes);
				htParams.put("a-select-server", sAsId);
				htParams.put("tf_authsp", sTFAuthSpName);
				htParams.put("tf_url", sTFAuthSpUrl);
				htParams.put("tf_uid", sTFAuthSpUserAttributes);
				htParams.put("tf_retries", "" + iRetries);
				htParams.put("error_msg", sErrorMsg);
				handleTFAuthenticationRequest(servletRequest, servletResponse, sRid, htParams);
			}
			else {
				handleAuthenticate(servletRequest, servletResponse);
			}
		}
		catch (ASelectException e) {
			handleResult(servletRequest, servletResponse, e.getMessage(), null, null, null);
		}
	}

	/**
	 * Entrypoint for handling the A-Select PKI AuthSP protocol requests. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
		throws ServletException
	{
		String sMethod = "doGet()";
		try {
			String sAsUrl = servletRequest.getParameter("as_url");
			String sRid = servletRequest.getParameter("rid");
			String sUserAttributes = servletRequest.getParameter("user_attribute");
			String sAsId = servletRequest.getParameter("a-select-server");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "rid=" + sRid + " user_attr=" + sUserAttributes);

			String sTFAuthSpName = servletRequest.getParameter("tf_authsp");
			String sTFAuthSpUrl = servletRequest.getParameter("tf_url");
			String sTFAuthSpRetries = servletRequest.getParameter("tf_retries");
			String sTFAuthSpUserAttributes = servletRequest.getParameter("tf_uid");

			String sSignature = servletRequest.getParameter("signature");

			boolean isSignatureValid = verifySignature(sRid, sAsUrl, sUserAttributes, sAsId, sTFAuthSpName,
					sTFAuthSpUrl, sTFAuthSpRetries, sTFAuthSpUserAttributes, sSignature);
			// check if incoming request is valid.
			if (!isSignatureValid) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Invalid signature");
				throw new ASelectException(Errors.PKI_INVALID_REQUEST);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Valid Signature");

			// Two-Factor Authentication is enabled.
			if (sTFAuthSpName != null) {
				HashMap htParams = new HashMap();
				htParams.put("as_url", sAsUrl);
				htParams.put("rid", sRid);
				htParams.put("user_attribute", sUserAttributes);
				htParams.put("a-select-server", sAsId);
				htParams.put("tf_authsp", sTFAuthSpName);
				htParams.put("tf_url", sTFAuthSpUrl);
				htParams.put("tf_retries", sTFAuthSpRetries);
				htParams.put("tf_uid", sTFAuthSpUserAttributes);

				handleTFAuthenticationRequest(servletRequest, servletResponse, sRid, htParams);
			}
			else {
				handleAuthenticate(servletRequest, servletResponse);
			}
		}
		catch (ASelectException e) {
			handleResult(servletRequest, servletResponse, e.getMessage(), null, null, null);
		}
	}

	/**
	 * Handles the PKI authentication. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * After the request is handled by doGet and/or doPost and eventually 2-Factor authentication is handled
	 * successfully the PKI part of the authentication will be handled by this function<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * PKI AuthSP must be successfully initialized<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            Incoming Request
	 * @param servletResponse
	 *            Outgoing Response
	 * @throws ServletException
	 *             If something goes wrong with the handle result
	 */
	public void handleAuthenticate(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
		throws ServletException
	{
		String sResultCode = Errors.PKI_CLIENT_CERT_SUCCESS;
		StringBuffer sbTemp;
		String sSubjectDN = ""; // Bauke: added
		String sIssuerDN = ""; // Bauke: added
		String sSubjectId = ""; // Bauke: added
		String sMethod = "handleAuthenticate()";
		try {
			X509Certificate[] oCerts = null;
			X509Certificate oClientCert = null;
			String sCaAlias = null;

			String sValidateDateCheck = "true";
			String sSignedByCaCheck = "true";
			String sCrlCheck = "true";
			String sBinBlobCheck = "false";
			String sUserAttributes = servletRequest.getParameter("user_attribute");
			// Read some necessary information from the configuration file
			Object oValidationConfig = _oConfigManager.getSection(_oAuthSpConfig, "date_validation");
			sValidateDateCheck = _oConfigManager.getParam(oValidationConfig, "enabled");
			Object oCaValidationConfig = _oConfigManager.getSection(_oAuthSpConfig, "ca_validation");
			sSignedByCaCheck = _oConfigManager.getParam(oCaValidationConfig, "enabled");

			// Bauke: added option to skip the SubjectDN check
			String sValidateSubjectCheck = "true";
			try {
				Object oCnValidationConfig = _oConfigManager.getSection(_oAuthSpConfig, "subject_validation");
				sValidateSubjectCheck = _oConfigManager.getParam(oCnValidationConfig, "enabled");
			}
			catch (ASelectConfigException e) {
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Get certificate for '" + sUserAttributes + "'");
			// Get Client Certificate from user
			oCerts = (X509Certificate[])servletRequest.getAttribute("javax.servlet.request.X509Certificate");
    		if (oCerts == null || oCerts.length <= 0) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No Client Certificate Provided");
				throw new ASelectException(Errors.PKI_NO_CLIENT_CERT_PROVIDED);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "oCerts=" + oCerts + " length=" + oCerts.length);
			oClientCert = oCerts[0];
			_systemLogger.log(Level.INFO, MODULE, sMethod, "ClientCert=" + oClientCert);

			if (!sValidateDateCheck.equalsIgnoreCase("false")) {
				// throws an ASelectException when certificate isn't
				// valid (expired/not yet valid)
				_oPkiManager.validateCertificateDate(oClientCert);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Date OK, check CA=" + sSignedByCaCheck);
			}

			// Check if the supplied user certificate is signed by a CA which
			// is trusted by the AuthSP and return the Certificate of that CA

			if (!sSignedByCaCheck.equalsIgnoreCase("false")) {
				// Throws ASelectException when no trusted
				// Certificate is found.
				HashMap htResult = _oPkiManager.getTrustedCACertificate(oClientCert);

				sCaAlias = (String) htResult.get("caAlias");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "CA Cert alias=" + sCaAlias);
				X509Certificate oCaCert = (X509Certificate) htResult.get("caCert");
				try {
					_oPkiManager.validateCertificateDate(oCaCert);
				}
				catch (ASelectException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "CA cert: " + sCaAlias + " is expired.");
					throw new ASelectException(Errors.PKI_CA_CERT_IS_EXPIRED);
				}
				Object oCaConfig = _oConfigManager.getSection(oCaValidationConfig, "ca", "alias=" + sCaAlias);
				Object oCrlConfig = _oConfigManager.getSection(oCaConfig, "crl_check");
				sCrlCheck = _oConfigManager.getParam(oCrlConfig, "enabled");
				if (!sCrlCheck.equalsIgnoreCase("false")) {
					if (_oPkiManager.isClientCertRevoked(sCaAlias, oClientCert)) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Client Certifcate is Revoked.");
						throw new ASelectException(Errors.PKI_CLIENT_CERT_REVOKED);
					}
					_systemLogger.log(Level.INFO, MODULE, sMethod, "CA Cert alias=" + sCaAlias + " OK");
				}

				Object oBinBlobConfig = _oConfigManager.getSection(oCaConfig, "binary_blob_check");
				sBinBlobCheck = _oConfigManager.getParam(oBinBlobConfig, "enabled");
				if (sBinBlobCheck.equalsIgnoreCase("true")) {
					if (!validateBinaryBlob(oBinBlobConfig, sUserAttributes, oClientCert)) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Client Certifcate Blob is not valid.");
						throw new ASelectException(Errors.PKI_CLIENT_CERT_BLOB_NOT_VALID);
					}
				}
			}
			// Bauke: Retrieve data
			sSubjectDN = oClientCert.getSubjectDN().toString().trim();
			sIssuerDN = oClientCert.getIssuerDN().toString().trim();
			try {
				Collection altNames = oClientCert.getSubjectAlternativeNames();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "altNames=" + altNames);
				for (Iterator i = altNames.iterator(); i.hasNext();) {
					Object obj = i.next();
					List item = (List) obj;
					Integer type = (Integer) item.get(0);
					Object value = item.get(1);
					byte[] bValue = (byte[]) value;
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Type=" + type.toString() + " Value="
							+ value.toString() + " Bytes=" + bValue.length);
					String result = "";
					for (int j = 0; j < bValue.length; j++)
						result += "." + Integer.toHexString(bValue[j]);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Value=" + result);
					int j;
					for (j = bValue.length - 1; j >= 0; j--) {
						Character c = (char) bValue[j];
						if (!(Character.isLetterOrDigit(c) || c == '-' || c == '.'))
							break;
					}
					if (j < 0)
						j = 0;
					for (; j < bValue.length; j++) {
						Character c = (char) bValue[j];
						if (c == '-')
							break;
					}
					if (j < bValue.length)
						j++;
					for (; j < bValue.length; j++) {
						sSubjectId += Character.toString((char) bValue[j]);
					}
				}
			}
			catch (CertificateParsingException e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Cert.Pars.Exc=" + e.toString());
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SubjectDN=" + sSubjectDN);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "IssuerDN=" + sIssuerDN);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SubjectId=" + sSubjectId);

			// Bauke: Skip optionally
			if (sBinBlobCheck.equalsIgnoreCase("false") && sValidateSubjectCheck.equalsIgnoreCase("true")) {
				if (!sUserAttributes.trim().equalsIgnoreCase(sSubjectDN)) {
					sbTemp = new StringBuffer("Subject DN: '").append(sSubjectDN).append(
							"' is different from the one provided in the ASelect UDB: '").append(sUserAttributes)
							.append("'");
					_systemLogger.log(Level.INFO, MODULE, sMethod, sbTemp.toString());
					throw new ASelectException(Errors.PKI_SUBJECT_DN_NOT_VALID);
				}
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
			sResultCode = Errors.PKI_INTERNAL_SERVER_ERROR;
		}
		catch (ASelectException e) {
			sResultCode = e.getMessage();
		}
		handleResult(servletRequest, servletResponse, sResultCode, sSubjectDN, sIssuerDN, sSubjectId);
	}

	/**
	 * Validates the the binary blob of the incoming client certificate. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Validates if the the binary blob of a client certificate is equals with the one stored in the back-end<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * oConfig != null, sSubjectDn != null oClientCertificate != null<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * none<br>
	 * 
	 * @param oConfig
	 *            The binary blob configuration
	 * @param sSubjectDn
	 *            The Id used as index in the backend
	 * @param oClientCert
	 *            The incoming client certificate
	 * @return true if oClientCert is equals with the one stored in the back-end
	 * @throws ASelectException
	 *             the a select exception
	 */
	public boolean validateBinaryBlob(Object oConfig, String sSubjectDn, X509Certificate oClientCert)
		throws ASelectException
	{
		String sMethod = "validateBinaryBlob()";
		boolean bFound = false;
		KeyStore oCertificates = null;
		ICertificateHandler oCertificateHandler = new LDAPCertificateHandler();

		try {
			Object oBackendConfig = _oConfigManager.getSection(oConfig, "backend");
			oCertificateHandler.init(_systemLogger, oBackendConfig);

			oCertificates = oCertificateHandler.getCertificates(sSubjectDn);
			int iHashCode = oClientCert.hashCode();
			Enumeration enumCertAliases = oCertificates.aliases();

			while (enumCertAliases.hasMoreElements() && !bFound) {
				String sCertAlias = (String) enumCertAliases.nextElement();
				X509Certificate oTmpCert = (X509Certificate) oCertificates.getCertificate(sCertAlias);
				if (iHashCode == oTmpCert.hashCode()) {
					bFound = true;
				}
			}
		}
		catch (KeyStoreException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not find retrieve certificates", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not find 'backend' configuration", e);
			throw new ASelectException(Errors.PKI_CONFIG_ERROR);
		}
		return bFound;
	}

	/**
	 * Sends the authentication result to the A-Select PKI AuthSP protocol handler by redirecting the user using HTTP
	 * GET. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * sResultCode != null<br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * none <br>
	 * 
	 * @param servletRequest
	 *            the incoming request
	 * @param servletResponse
	 *            the outgoing response
	 * @param sResultCode
	 *            the Result Code
	 * @param sSubjectDN
	 *            the s subject dn
	 * @param sIssuerDN
	 *            the s issuer dn
	 * @param sSubjectId
	 *            the s subject id
	 * @throws ServletException
	 *             if something goes wrong during handling the response
	 */
	private void handleResult(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sResultCode, String sSubjectDN, String sIssuerDN, String sSubjectId)
		throws ServletException
	{
		String sMethod = "handleResult()";
		StringBuffer sbTemp = null;
		String sRid = servletRequest.getParameter("rid");
		String sAsUrl = servletRequest.getParameter("as_url");
		String sAsId = servletRequest.getParameter("a-select-server");
		String sUid = servletRequest.getParameter("uid");
		String sLanguage = servletRequest.getParameter("language");

		if (sRid == null || sAsUrl == null || sAsId == null) {
			String sError = Errors.PKI_INVALID_REQUEST;
			String sErrorMessage = "Invalid Request";
			String sErrorForm = new String(_sErrorHtmlTemplate);
			sErrorForm = Utils.replaceString(sErrorForm, "[error]", sError);  // obsoleted 20100817
			sErrorForm = Utils.replaceString(sErrorForm, "[error_code]", sError);
			sErrorForm = Utils.replaceString(sErrorForm, "[error_message]", sErrorMessage);
			sErrorForm = Utils.replaceString(sErrorForm, "[language]", sLanguage);
			sErrorForm = Utils.replaceConditional(sErrorForm, "if_error", sErrorMessage != null && !sErrorMessage.equals(""));
			try {
				sendPage(sErrorForm, servletRequest, servletResponse);
			}
			catch (IOException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to show error message", e);
				throw new ServletException("Failed to show error message");
			}
			return;
		}

		String sSignature = null;
		try {
			// Bauke, 20091002: Base64 encoded to pass non ASCII characters
			BASE64Encoder base64Encoder = new BASE64Encoder();
			sSubjectDN = base64Encoder.encode(sSubjectDN.getBytes("UTF-8"));
			sIssuerDN = base64Encoder.encode(sIssuerDN.getBytes("UTF-8"));
			sSubjectId = base64Encoder.encode(sSubjectId.getBytes("UTF-8"));
			sbTemp = new StringBuffer(sRid);
			sbTemp.append(sAsUrl).append(sResultCode).append(sAsId);
			if (sSubjectDN != null)
				sbTemp.append(sSubjectDN); // Bauke: added
			if (sIssuerDN != null)
				sbTemp.append(sIssuerDN); // Bauke: added
			if (sSubjectId != null)
				sbTemp.append(sSubjectId); // Bauke: added

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign[" + sbTemp + "]");
			sSignature = _oCryptoEngine.generateSignature(sbTemp.toString());
			if (sSignature == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error occured during signature creation");
				throw new ServletException("Error occured during signature creation");
			}
			sSignature = URLEncoder.encode(sSignature, "UTF-8");
		}
		catch (UnsupportedEncodingException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
			throw new ServletException("Unsupported character encoding");
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error occured during signature creation");
			throw new ServletException("Error occured during signature creation");
		}

		sbTemp = new StringBuffer(sAsUrl);
		sbTemp.append("&rid=").append(sRid);
		sbTemp.append("&result_code=").append(sResultCode);
		sbTemp.append("&a-select-server=").append(sAsId);
		if (sSubjectDN != null)
			sbTemp.append("&pki_subject_dn=").append(sSubjectDN); // Bauke: added
		if (sIssuerDN != null)
			sbTemp.append("&pki_issuer_dn=").append(sIssuerDN); // Bauke: added
		if (sSubjectId != null)
			sbTemp.append("&pki_subject_id=").append(sSubjectId); // Bauke: added
		sbTemp.append("&signature=").append(sSignature);
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT: " + sbTemp);
			servletResponse.sendRedirect(sbTemp.toString());

			if (sResultCode.equals(Errors.PKI_CLIENT_CERT_SUCCESS)) // user authenticated
			{
				// Authentication successfull
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "granted"
				});
			}
			else {
				// authenticate failed
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "denied: " + sResultCode
				});
			}
		}
		catch (IOException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
			throw new ServletException("Error by sending response. See the PKI Authsp log files for more information ");
		}
		return;
	}

	/**
	 * Verifies the signature of an incoming request. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Uses the default crypto engine of the AuthSP Server. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * bValid is set<br>
	 * 
	 * @param sRid
	 *            Contains the A-Select Request Id.
	 * @param sAsUrl
	 *            The url of the A-Select Server.
	 * @param sUserAttributes
	 *            The necessary user attributes.
	 * @param sAsId
	 *            The A-Select Server Id.
	 * @param sTFAuthSpName
	 *            The name of the 2-Factor AuthSp.
	 * @param sTFAuthSpUrl
	 *            The Url of the 2-Factor AuthSp.
	 * @param sTFAuthSpRetries
	 *            The number of retries left for the 2-Factor AuthSp.
	 * @param sTFAuthSpUserAttributes
	 *            The necessary user attributes for the 2-Factor AuthSp..
	 * @param sSignature
	 *            The signature of the request parameters
	 * @return true if signature is valid and false otherwise.
	 * @throws ASelectException
	 *             if sRid, sAsUrl, sUserAttributes, sAsId, sSignature are null
	 */
	private boolean verifySignature(String sRid, String sAsUrl, String sUserAttributes, String sAsId,
			String sTFAuthSpName, String sTFAuthSpUrl, String sTFAuthSpRetries, String sTFAuthSpUserAttributes,
			String sSignature)
		throws ASelectException
	{
		String sMethod = "verifySignature()";
		boolean bValid = false;
		if (sRid == null || sAsUrl == null || sUserAttributes == null || sAsId == null || sSignature == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "not all parameters are provided");
			throw new ASelectException(Errors.PKI_INVALID_REQUEST);
		}
		StringBuffer sbTemp = new StringBuffer(sRid);
		sbTemp.append(sAsUrl);
		sbTemp.append(sUserAttributes);
		sbTemp.append(sAsId);
		if (sTFAuthSpName != null && sTFAuthSpUrl != null && sTFAuthSpRetries != null
				&& sTFAuthSpUserAttributes != null) {
			sbTemp.append(sTFAuthSpName);
			sbTemp.append(sTFAuthSpUrl);
			sbTemp.append(sTFAuthSpRetries);
			sbTemp.append(sTFAuthSpUserAttributes);
		}
		bValid = _oCryptoEngine.verifySignature(sAsId, sbTemp.toString(), sSignature);
		return bValid;
	}

	/**
	 * Handles the 2-Factor Authentication Request. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Handles the 2-Factor Authentication by redirecting the user to a HTML page where the user can submit his/her
	 * password<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * none<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * htSessionInfo != null<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * none <br>
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @param sRid
	 *            contains the A-Select Request Id
	 * @param htSessionInfo
	 *            contains nessecary information which will be used if the user comes back to the authsp after
	 *            submitting its password.
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleTFAuthenticationRequest(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sRid, HashMap htSessionInfo)
		throws ASelectException
	{
		String sMethod = "handleTFAuthenticationRequest()";
		StringBuffer sbTemp;
		String sTFHtmlTemplate = _sTFHtmlTemplate;

		String sAsUrl = (String) htSessionInfo.get("as_url");
		String sUserAttributes = (String) htSessionInfo.get("user_attribute");
		String sAsId = (String) htSessionInfo.get("a-select-server");
		String sTFAuthSpName = (String) htSessionInfo.get("tf_authsp");
		String sTFAuthSpUrl = (String) htSessionInfo.get("tf_url");
		String sRetries = (String) htSessionInfo.get("tf_retries");
		String sTFAuthSpUserAttributes = (String) htSessionInfo.get("tf_uid");
		String sMyUrl = servletRequest.getRequestURL().toString();

		String sErrorMsg = (String) htSessionInfo.get("error_msg");
		if (sErrorMsg == null) {
			sErrorMsg = "";
		}
		sbTemp = new StringBuffer(sRid).append(sAsUrl).append(sUserAttributes).append(sAsId).append(sTFAuthSpName)
				.append(sTFAuthSpUrl).append(sTFAuthSpUserAttributes).append(sRetries).append(sMyUrl);

		String sSignature = _oCryptoEngine.generateSignature(sbTemp.toString());
		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[server]", sMyUrl);

		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[rid]", sRid);
		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[as_url]", sAsUrl);
		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[user_attribute]", sUserAttributes);
		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[a-select-server]", sAsId);
		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[tf_authsp]", sTFAuthSpName);
		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[tf_url]", sTFAuthSpUrl);
		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[tf_uid]", sTFAuthSpUserAttributes);
		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[tf_retries]", sRetries);
		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[signature]", sSignature);
		sTFHtmlTemplate = Utils.replaceString(sTFHtmlTemplate, "[error_msg]", sErrorMsg);
		try {
			sendPage(sTFHtmlTemplate, servletRequest, servletResponse);
		}
		catch (IOException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error by Sending 2-factor authentication page", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);

		}
	}

	/**
	 * Verifies the 2-Factor Authentication. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Verfies the 2-Factor Authentication user credentials by sending an HTTP GET API call to a username/password
	 * AuthSP.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * none<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * sTFAuthSpUrl, sTFUserAttributes and sPassword may not be null<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * none <br>
	 * 
	 * @param sRid
	 *            contains the A-Select Request Id
	 * @param sTFAuthSpUrl
	 *            contains the url of the 2-Factor AuthSP
	 * @param sTFAuthSpUserAttributes
	 *            contains the necessary userattributes, such as Uid
	 * @param sPassword
	 *            contains the password
	 * @return true if 2-Factor authentication was successful and false otherwise
	 * @throws ASelectException
	 *             the a select exception
	 */
	private boolean verifyTFAuthentication(String sRid, String sTFAuthSpUrl, String sTFAuthSpUserAttributes,
			String sPassword)
		throws ASelectException
	{
		String sMethod = "verifyTFAuthentication()";
		boolean bAuthenticated = false;
		try {
			// create API call URL
			sTFAuthSpUserAttributes = URLEncoder.encode(sTFAuthSpUserAttributes, "UTF-8");

			StringBuffer sbRequest = new StringBuffer(sTFAuthSpUrl);
			sbRequest.append("?request=authenticate");
			sbRequest.append("&rid=").append(sRid);
			sbRequest.append("&user=").append(sTFAuthSpUserAttributes);
			sbRequest.append("&password=").append(sPassword);

			sbRequest.append("&as_url=").append("DUMMY");
			sbRequest.append("&uid=").append("DUMMY");
			sbRequest.append("&a-select-server=").append("DUMMY");
			sbRequest.append("&retry_counter=").append("DUMMY");
			sbRequest.append("&signature=").append("DUMMY");

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Send:" + sbRequest);
			String sResponseString = send(sbRequest.toString());

			HashMap xResponse = Utils.convertCGIMessage(sResponseString, false);
			String sResponseCode = ((String) xResponse.get("status"));
			if (sResponseCode == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "invalid response from 2-Factor AuthSP");
				throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);

			}
			sResponseCode.trim();
			if (sResponseCode.equals("000")) // authentication succeeded
			{
				bAuthenticated = true;
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error from 2-Factor AuthSP: " + sResponseCode);
			}
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error by sending request to the 2-Factor AuthSP" + e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);

		}
		return bAuthenticated;
	}

	/**
	 * Calls a URL using HTTP GET. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * sUrl may not be null <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * sResponse may not be null <br>
	 * 
	 * @param sUrl
	 *            Url including query string.
	 * @return sResponse the response of the HTTP Get request.
	 * @throws IOException
	 *             when connection is failed.
	 */
	private String send(String sUrl)
		throws IOException
	{
		URL oServer = new URL(sUrl.toString());
		BufferedReader oInputReader = new BufferedReader(new InputStreamReader(oServer.openStream()), 16000);
		String sResponse = oInputReader.readLine();
		oInputReader.close();
		return sResponse;
	}

	/**
	 * Outputs a HTML page to the client. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Sends a page to the user's browser and sets the required HTTP headers. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * sTemplate, servletRequest and servletResponse may not be null <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param sTemplate
	 *            The Template to send back
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws IOException
	 *             when something goes wrong
	 */
	private void sendPage(String sTemplate, HttpServletRequest servletRequest, HttpServletResponse servletResponse)
		throws IOException
	{
		// disable caching
		if (servletRequest.getProtocol().equals("HTTP/1.1"))// HTTP 1.1 protocol
		// used
		{
			servletResponse.setHeader("Cache-Control", "no-cache, must-revalidate");
		}
		else
		// other protocol versions
		{
			servletResponse.setHeader("Pragma", "no-cache");
		}
		servletResponse.setHeader("Expires", "0"); // date in the past

		// sent content type and length
		servletResponse.setContentType("text/html");
		servletResponse.setContentLength(sTemplate.length());

		// write to output
		servletResponse.getWriter().write(sTemplate);
	}
}