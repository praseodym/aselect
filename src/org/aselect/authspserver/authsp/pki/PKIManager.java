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
 * $Id: PKIManager.java,v 1.3 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $log$
 *
 */
package org.aselect.authspserver.authsp.pki;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.authspserver.authsp.pki.crl.handler.ICRLHandler;
import org.aselect.authspserver.authsp.pki.crl.handler.file.FileCRLHandler;
import org.aselect.authspserver.authsp.pki.crl.handler.html.HttpCRLHandler;
import org.aselect.authspserver.authsp.pki.crl.handler.ldap.LDAPCRLHandler;
import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * The PKI Manager. <br>
 * <br>
 * <b>Description:</b><br>
 * Handles all the PKI functionality of the PKI AuthSP <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss
 */
public class PKIManager
{
	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "PKIManager";

	private AuthSPConfigManager _oConfigManager;
	private Object _oConfig;
	private KeyStore _oCaKeystore;
	private String _sCaKeyStorePassword;
	private String _sCaKeyStoreLocation;
	private HashMap _htCRLs;
	private HashMap _htFailedCRLs;
	private Thread _tAutoCrlUpdater;
	private AutoCRLUpdater _oAutoCrlUpdater;
	private Thread _tCrlRecoverer;
	private CRLRecoverer _oCrlRecoverer;
	private Thread _tPkiAdminServer;
	private PKIAdminServer _oPkiAdminServer;

	/** The logger that logs system information. */
	private AuthSPSystemLogger _systemLogger;

	private final String _sCrlDistributionPointOid = "2.5.29.31";

	/**
	 * Initializes the PKI Manager.
	 * 
	 * @param oConfig
	 *            necessary configuration
	 * @param oSystemLogger
	 *            the systemlogger
	 * @throws ASelectException
	 *             if something goes wrong during init.
	 */
	public void init(Object oConfig, AuthSPSystemLogger oSystemLogger)
		throws ASelectException
	{
		String sMethod = "init";
		_oConfig = oConfig;
		_systemLogger = oSystemLogger;
		_htCRLs = new HashMap();
		_htFailedCRLs = new HashMap();

		Integer intTmp;
		_oConfigManager = AuthSPConfigManager.getHandle();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "PKI mgr init");
		try {
			String sCaValidationCheck = _oConfigManager.getParam(oConfig, "enabled");
			if (!sCaValidationCheck.equalsIgnoreCase("false")) {
				_oConfigManager = AuthSPConfigManager.getHandle();
				Object oKeystoreConfig = _oConfigManager.getSection(oConfig, "ca_keystore");
				_sCaKeyStoreLocation = _oConfigManager.getParam(oKeystoreConfig, "location");
				_sCaKeyStorePassword = _oConfigManager.getParam(oKeystoreConfig, "password");

				// Load CA KeyStore
				loadCaKeyStoreFromPFXFile(_sCaKeyStoreLocation, _sCaKeyStorePassword);

				// Load CRL's in HashMap
				loadCRLs();

				// init and start auto CRL updater Thread
				intTmp = new Integer(_oConfigManager.getParam(oConfig, "crl_update_timer"));
				_oAutoCrlUpdater = new AutoCRLUpdater(intTmp.intValue());
				_tAutoCrlUpdater = new Thread(_oAutoCrlUpdater);
				_tAutoCrlUpdater.start();

				// init and start auto CRL Recoverer Thread
				intTmp = new Integer(_oConfigManager.getParam(oConfig, "crl_recover_timer"));
				_oCrlRecoverer = new CRLRecoverer(intTmp.intValue());
				_tCrlRecoverer = new Thread(_oCrlRecoverer);
				_tCrlRecoverer.start();

				// init and start Admin Server Thread
				intTmp = new Integer(_oConfigManager.getParam(oConfig, "pki_admin_port"));
				_oPkiAdminServer = new PKIAdminServer(intTmp.intValue());
				_tPkiAdminServer = new Thread(_oPkiAdminServer);
				_tPkiAdminServer.start();
			}
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to initialize " + MODULE, e);
			throw e;
		}
	}

	/**
	 * Destroy all running threads.
	 */
	public void destroy()
	{
		String sMethod = "destroy";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Destroy running PKI mgr threads");
		if (_oAutoCrlUpdater!=null) _oAutoCrlUpdater.destroy();
		if (_oCrlRecoverer!=null) _oCrlRecoverer.destroy();
		if (_oPkiAdminServer!=null) _oPkiAdminServer.destroy();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Running PKI mgr threads destroyed");
	}

	/**
	 * Load the CRL's for all the CA's where CRL Checking is enabled.
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void loadCRLs()
		throws ASelectException
	{
		_htCRLs = new HashMap();
		String sMethod = "loadCRLs()";
		Enumeration oCaAliases;
		try {
			oCaAliases = _oCaKeystore.aliases();
			while (oCaAliases.hasMoreElements()) {
				String sCaAlias = (String) oCaAliases.nextElement();
				try {
					loadCRLForCA(sCaAlias);
				}
				catch (ASelectException e) {
					_htFailedCRLs.put(sCaAlias, e);
				}
			}
		}
		catch (KeyStoreException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unable to read keystore aliases", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);
		}

	}

	/**
	 * Loads the CRL for a particular CA. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Loads the CRL for a particular CA. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * sAlias may not be null. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * none <br>
	 * 
	 * @param sCaAlias
	 *            The alias of the CA.
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void loadCRLForCA(String sCaAlias)
		throws ASelectException
	{
		String sMethod = "loadCRLForCA()";
		Object oCaConfig;
		Object oCrlConfig;
		String sCrlCheck;
		try {
			oCaConfig = _oConfigManager.getSection(_oConfig, "ca", "alias=" + sCaAlias);
			oCrlConfig = _oConfigManager.getSection(oCaConfig, "crl_check");
			sCrlCheck = _oConfigManager.getParam(oCrlConfig, "enabled");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No config found for CA: " + sCaAlias, e);
			throw e;
		}
		if (!sCrlCheck.equalsIgnoreCase("false")) {
			X509CRL oCrl = null;
			X509Certificate oCaCert = null;
			boolean bFoundCrl = false;
			int i = 0;
			try {
				oCaCert = getCA(sCaAlias);
			}
			catch (KeyStoreException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Keystore does not contain CA Certificate: "
						+ sCaAlias, e);
				throw new ASelectException(Errors.PKI_NO_CA_FOUND);
			}
			Vector vCrlUrls = getCRLUrls(oCrlConfig, sCaAlias);
			while (i < vCrlUrls.size() && !bFoundCrl) {
				String sUrl = (String) vCrlUrls.get(i);
				X509CRL oTmpCrl = getCRL((sUrl));
				if (oTmpCrl != null) {
					if (validateCrl(oTmpCrl, oCaCert)) {
						oCrl = oTmpCrl;
						bFoundCrl = true;
					}
				}
				i++;
				if (!bFoundCrl) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "CA '" + sCaAlias + "' CRL distribution point '"
							+ sUrl + "' failed, trying next distributionpoint.");
				}
			}
			if (!bFoundCrl) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No CRL Found which is signed by CA: " + sCaAlias);
				throw new ASelectException(Errors.PKI_NO_CRL_FOUND_FOR_CA);
			}
			_htCRLs.put(sCaAlias, oCrl);
		}
	}

	/**
	 * Looks up the certifcate and alias of the CA for a client certificate. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Looks up the certifcate of the CA which have signed the client certificate. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * oCert may not be null <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param oCert
	 *            the client certificate
	 * @return HashMap containing alias and certificate of CA which signed the client cert.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public HashMap getTrustedCACertificate(X509Certificate oCert)
		throws ASelectException
	{
		String sMethod = "getTrustedCACertificate()";
		HashMap htResult = new HashMap();
		Certificate oCaCert = null;
		String sCaAlias = null;
		Enumeration oKeyAliases = null;

		boolean bCaCertFound = false;
		try {
			oKeyAliases = _oCaKeystore.aliases();
			while (oKeyAliases.hasMoreElements() && !bCaCertFound) {
				sCaAlias = (String) oKeyAliases.nextElement();
				oCaCert = _oCaKeystore.getCertificate(sCaAlias);
				bCaCertFound = validateCertificateIsSignedByCA(oCert, oCaCert);
			}
		}
		catch (KeyStoreException e) {
			_systemLogger
					.log(Level.SEVERE, MODULE, sMethod, "Keystore does not contain CA Certificate: " + sCaAlias, e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);

		}
		if (!bCaCertFound) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Client Certificate is not signed by a Trusted CA: "
					+ sCaAlias);
			throw new ASelectException(Errors.PKI_CLIENT_CERT_NOT_NOT_SIGNED_BY_TRUSTED_CA);
		}
		htResult.put("caCert", oCaCert);
		htResult.put("caAlias", sCaAlias);
		return htResult;
	}

	/**
	 * Validates if the provided client certificate is signed by the provided CA cert. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Validates if the provided client certificate is signed by the provided CA cert. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * oClientCert, oCaCert may not be null <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * none <br>
	 * 
	 * @param oClientCert
	 *            Client certificate
	 * @param oCaCert
	 *            CA certificate
	 * @return true if client cert is signed by CA and false otherwise.
	 */
	public boolean validateCertificateIsSignedByCA(Certificate oClientCert, Certificate oCaCert)
	{
		String sMethod = "validateCertificateIsSignedByCA()";
		boolean isSignedByCA = true;
		PublicKey caPublicKey = oCaCert.getPublicKey();
		try {
			oClientCert.verify(caPublicKey);
		}
		catch (InvalidKeyException e) {
			isSignedByCA = false;
			_systemLogger.log(Level.FINE, MODULE, sMethod, e.getMessage(), e);
		}
		catch (CertificateException e) {
			isSignedByCA = false;
			_systemLogger.log(Level.FINE, MODULE, sMethod, e.getMessage(), e);
		}
		catch (NoSuchAlgorithmException e) {
			isSignedByCA = false;
			_systemLogger.log(Level.FINE, MODULE, sMethod, e.getMessage(), e);
		}
		catch (NoSuchProviderException e) {
			isSignedByCA = false;
			_systemLogger.log(Level.FINE, MODULE, sMethod, e.getMessage(), e);
		}
		catch (SignatureException e) {
			isSignedByCA = false;
			_systemLogger.log(Level.FINE, MODULE, sMethod, e.getMessage(), e);
		}
		return isSignedByCA;
	}

	/**
	 * Gets the cA.
	 * 
	 * @param sCaAlias
	 *            the s ca alias
	 * @return the cA
	 * @throws KeyStoreException
	 *             the key store exception
	 */
	private X509Certificate getCA(String sCaAlias)
		throws KeyStoreException
	{
		return (X509Certificate) _oCaKeystore.getCertificate(sCaAlias);
	}

	/**
	 * Checks if the provided certificate is valid. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if the provided certificate is valid yet and not expired. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * oCert may not be null. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param oCert
	 *            the o cert
	 * @throws ASelectException
	 *             if cert is not yet valid or expired.
	 */
	public void validateCertificateDate(X509Certificate oCert)
		throws ASelectException
	{
		String sMethod = "validateCertificateDate()";
		try {
			oCert.checkValidity();
		}
		catch (CertificateExpiredException e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Certificate expired", e);
			throw new ASelectException(Errors.PKI_CLIENT_CERT_EXPIRED, e);
		}
		catch (CertificateNotYetValidException e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Certificate not yet valid", e);
			throw new ASelectException(Errors.PKI_CLIENT_CERT_NOT_YET_VALID, e);
		}
	}

	/**
	 * Validates if the provided CRL is signed by the provided Issuer. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Validates if the provided CRL is signed by the provided Issuer. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * crl and crlIssuerCert may not be null <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * none <br>
	 * 
	 * @param crl
	 *            The Certificate Revocation List
	 * @param crlIssuerCert
	 *            the CRL Issuer
	 * @return true if crl is valid and false otherwise
	 */
	public boolean validateCrl(X509CRL crl, X509Certificate crlIssuerCert)
	{
		String sMethod = "getValidCrl()";
		boolean bValidCRL = true;
		PublicKey oPublicKey = crlIssuerCert.getPublicKey();
		try {
			crl.verify(oPublicKey);
		}
		catch (InvalidKeyException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, e.getMessage(), e);
			bValidCRL = false;
		}
		catch (CRLException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, e.getMessage(), e);
			bValidCRL = false;
		}
		catch (NoSuchAlgorithmException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, e.getMessage(), e);
			bValidCRL = false;
		}
		catch (NoSuchProviderException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, e.getMessage(), e);
			bValidCRL = false;
		}
		catch (SignatureException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, e.getMessage(), e);
			bValidCRL = false;
		}
		return bValidCRL;
	}

	/**
	 * Checks if a certificate is revoked. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if a certificate stands on the CRL <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * sCaAlias and oClientCert may not be null <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param sCaAlias
	 *            The Alias of the CA.
	 * @param oClientCert
	 *            The certificate to be checked
	 * @return true if the certicate is listed on the CRL and false otherwise.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public boolean isClientCertRevoked(String sCaAlias, X509Certificate oClientCert)
		throws ASelectException
	{
		String sMethod = "isCRLisSignedByCA()";
		X509CRL oCrl = null;
		if (!_htCRLs.containsKey(sCaAlias)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No Valid CRL Found for CA: " + sCaAlias);
			throw new ASelectException(Errors.PKI_NO_CRL_FOUND_FOR_CA);
		}
		oCrl = (X509CRL) _htCRLs.get(sCaAlias);
		return oCrl.isRevoked(oClientCert);
	}

	/**
	 * Get all defined CRLs for a corresponding CA. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Get all defined CRLs for a corresponding CA can be from confiration or from the CA certificate. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param oCrlConfig
	 *            necessary configuration
	 * @param sCaAlias
	 *            the ca alias
	 * @return a vector containing URL to CRL files.
	 * @throws ASelectException
	 *             the a select exception
	 */
	private Vector getCRLUrls(Object oCrlConfig, String sCaAlias)
		throws ASelectException
	{
		String sMethod = "getCRLUrls()";
		Vector oCrlUrls = null;
		String sCRLDistrPointLocation;
		try {
			Object oCrlDistributionPoints = _oConfigManager.getSection(oCrlConfig, "crl_distributionpoints");
			sCRLDistrPointLocation = _oConfigManager.getParam(oCrlDistributionPoints, "location");

			if (sCRLDistrPointLocation.equalsIgnoreCase("cacert")) {
				X509Certificate oCaCert = (X509Certificate) _oCaKeystore.getCertificate(sCaAlias);
				oCrlUrls = getCrlUrls(oCaCert);
			}
			else if (sCRLDistrPointLocation.equalsIgnoreCase("config")) {
				oCrlUrls = new Vector();

				Object oCrlDistributionPoint = _oConfigManager.getSection(oCrlDistributionPoints, "distributionpoint");
				while (oCrlDistributionPoint != null) {
					String sCrlDistributionlocation = _oConfigManager.getParam(oCrlDistributionPoint, "location");
					oCrlUrls.add(sCrlDistributionlocation);
					oCrlDistributionPoint = _oConfigManager.getNextSection(oCrlDistributionPoint);
				}
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Config Error: Invalid location specified for CRL distribution points: " + sCaAlias);
				throw new ASelectConfigException(Errors.PKI_CONFIG_ERROR);
			}
		}
		catch (KeyStoreException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No Certificate found in Keystore for: " + sCaAlias, e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);
		}
		return oCrlUrls;
	}

	/**
	 * Get the CRL File for the given URI. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Get the CRL File for the given URI. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * sUri != null <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param sUri
	 *            the location of the CRL file
	 * @return a CRL
	 */
	private X509CRL getCRL(String sUri)
	{
		String sMethod = "getCRL()";
		ICRLHandler oCrlHandler = null;
		X509CRL oCrl = null;
		if (sUri.indexOf("http://") >= 0) {
			oCrlHandler = new HttpCRLHandler();
			oCrlHandler.init(_systemLogger);
		}
		else if (sUri.indexOf("ldap://") >= 0) {
			oCrlHandler = new LDAPCRLHandler();
			oCrlHandler.init(_systemLogger);
		}
		else if (sUri.indexOf("file://") >= 0) {
			oCrlHandler = new FileCRLHandler();
			oCrlHandler.init(_systemLogger);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "can't handle supplied CRL uri: " + sUri);
		}
		try {
			oCrl = (X509CRL) oCrlHandler.getCRL(sUri);
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "sUri: " + e.getMessage());
		}
		return oCrl;
	}

	/**
	 * loads the CA certificate from the CA Keystore. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * loads the CA certificate from the CA Keystore. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param aFileName
	 *            Filename of ca keystore
	 * @param aKeyStorePassword
	 *            password for keystore
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void loadCaKeyStoreFromPFXFile(String aFileName, String aKeyStorePassword)
		throws ASelectException
	{
		String sMethod = "loadCaKeyStoreFromPFXFile()";
		try {
			KeyStore oKeyStore = KeyStore.getInstance("JKS");
			FileInputStream keyStoreStream = new FileInputStream(aFileName);
			char[] password = aKeyStorePassword.toCharArray();
			oKeyStore.load(keyStoreStream, password);
			_oCaKeystore = oKeyStore;
		}
		catch (KeyStoreException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to initialize JKS Keystore", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);
		}
		catch (FileNotFoundException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, aFileName, e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, aFileName, e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);
		}
		catch (NoSuchAlgorithmException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, aFileName, e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);
		}
		catch (CertificateException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, aFileName, e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);
		}
	}

	/**
	 * Returns the CRL Url located in the (CA) Certificate. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the CRL Distribution Points located in the CA Cert. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * oCertificate may not be null. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param oCertificate
	 *            the Certificate to get the CRL distribution points from.
	 * @return a Vector with CRL urls.
	 * @throws ASelectException
	 *             the a select exception
	 */
	private Vector getCrlUrls(X509Certificate oCertificate)
		throws ASelectException
	{
		String sMethod = "getCRLUrls()";
		Vector vOctetValues = new Vector();
		Vector vCrlUrls = new Vector();
		byte[] baCrlDistributionPoints = oCertificate.getExtensionValue(_sCrlDistributionPointOid);
		if (baCrlDistributionPoints == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No CRL Distribution Points in Ca Certificate");
			throw new ASelectException(Errors.PKI_NO_CRL_DISTR_POINT_IN_CA_CERT);
		}
		vOctetValues = getOctetValues(baCrlDistributionPoints);
		for (int i = 0; i < vOctetValues.size(); i++) {
			String sUrl = new String((byte[]) vOctetValues.get(i));
			vCrlUrls.add(sUrl);
		}

		return vCrlUrls;
	}

	/**
	 * Return a vector with the octet Values for the binary input. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Return a vector with the octet Values for the binary input. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * None <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param baExtensionValue
	 *            DER encoded binary input
	 * @return a vector with octet values.
	 * @throws ASelectException
	 *             the a select exception
	 */
	private Vector getOctetValues(byte[] baExtensionValue)
		throws ASelectException
	{
		return getOctetValues(getDERObject(baExtensionValue));
	}

	/**
	 * private Helper function for DER Decoding. <br>
	 * <br>
	 * 
	 * @param baExtensionValue
	 *            the ba extension value
	 * @return a DER object
	 * @throws ASelectException
	 *             the a select exception
	 */
	private DERObject getDERObject(byte[] baExtensionValue)
		throws ASelectException
	{
		String sMethod = "getDERObject()";
		try {
			ASN1InputStream oInputStream = new ASN1InputStream(new ByteArrayInputStream(baExtensionValue));
			byte[] baExtOctets = ((ASN1OctetString) oInputStream.readObject()).getOctets();
			oInputStream = new ASN1InputStream(new ByteArrayInputStream(baExtOctets));
			return oInputStream.readObject();
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);
		}
	}

	/**
	 * private Helper function for DER Decoding. <br>
	 * <br>
	 * 
	 * @param derObject
	 *            the der object
	 * @return a DER object
	 * @throws ASelectException
	 *             the a select exception
	 */
	private Vector getOctetValues(DERObject derObject)
		throws ASelectException
	{
		String sMethod = "getOctetValues(DERObject derObject)";
		Vector vDerValues = new Vector();

		if (derObject == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Supplied derObject is null");
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}
		else if (derObject instanceof DERSequence) {
			Enumeration enumDerObjects = ((DERSequence) derObject).getObjects();

			while (enumDerObjects.hasMoreElements()) {
				DERObject nestedDerObject = (DERObject) enumDerObjects.nextElement();

				vDerValues.addAll(getOctetValues(nestedDerObject));
			}
		}
		else if (derObject instanceof DERTaggedObject) {
			DERTaggedObject derTaggedObject = (DERTaggedObject) derObject;

			if (derTaggedObject.isExplicit() && !derTaggedObject.isEmpty()) {
				DERObject nestedDerObject = derTaggedObject.getObject();
				vDerValues = getOctetValues(nestedDerObject);
			}
			else {
				DEROctetString derOctetString = (DEROctetString) derTaggedObject.getObject();
				byte[] octetValue = derOctetString.getOctets();
				vDerValues = new Vector();
				vDerValues.add(octetValue);
			}
		}
		return vDerValues;
	}

	class AutoCRLUpdater implements Runnable
	{
		private boolean _bActive;
		private long _lMilliSeconds;

		/**
		 * Thread that keeps track of the latest CRLs <br>
		 * <br>
		 * <b>Description:</b> <br>
		 * Thread that runs with a configurable interval. Every CRL is checked on its 'NextUpdate' time. If the
		 * 'NextUpdate' time was in the history, a new CRL will be retrieved from one of the CRL distibution points
		 * configured for that particular CA.<br>
		 * If retrieval of the CRL fails, the CA will be added to a 'failed_CRL' list that will be processed by the
		 * <code>CRLRecoverer</code> <br>
		 * <br>
		 * <b>Concurrency issues:</b> <br>
		 * - <br>
		 * <br>
		 * <b>Preconditions:</b> <br>
		 * - <br>
		 * <br>
		 * <b>Postconditions:</b> <br>
		 * - <br>
		 * 
		 * @param lSeconds
		 *            the interval between the checks.
		 */
		public AutoCRLUpdater(long lSeconds)
		{
			_lMilliSeconds = lSeconds * 1000;
			_bActive = true;
		}

		/**
		 * tries to auto update the CRL's when they are expired. <br>
		 * <br>
		 * 
		 * @see java.lang.Runnable#run()
		 */
		public void run()
		{
			String sMethod = "AutoCRLUpdater.run";
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Run "+_bActive);
			while (_bActive) {
				try {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Sleep "+_lMilliSeconds);
					System.out.println(sMethod+" Sleep "+_lMilliSeconds);
					Thread.sleep(_lMilliSeconds);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Slept "+_lMilliSeconds);
					System.out.println(sMethod+" Slept "+_lMilliSeconds);
					Set keys = _htCRLs.keySet();
					for (Object oCrlKey : keys) {
						// Enumeration oCrlKeys = _htCRLs.keys();
						// while(oCrlKeys.hasMoreElements())
						// {
						// Object oCrlKey = oCrlKeys.nextElement();
						X509CRL oCrl = (X509CRL) _htCRLs.get(oCrlKey);
						Date oCrlExpirtationDate = oCrl.getNextUpdate();
						Date oCurrentDate = new Date(System.currentTimeMillis());
						if (oCurrentDate.after(oCrlExpirtationDate)) {
							try {
								loadCRLForCA((String) oCrlKey);
							}
							catch (ASelectException e) {
								_htFailedCRLs.put(oCrlKey, e);
								_htCRLs.remove(oCrlKey);
								_systemLogger.log(Level.WARNING, MODULE, sMethod,
										"Reloading CRL for CA with alias: " + oCrlKey.toString() + " failed");
							}
						}
					}
				}
				catch (InterruptedException e) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "InterruptedException");
				}
				System.out.println(sMethod+" Stopped");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Stopped");
			}
		}

		/**
		 * Destroys the AutoUpdater. <br>
		 * <br>
		 * <b>Description: </b> <br>
		 * Stop the thread from running. <br>
		 * <br>
		 * <b>Concurrency issues: </b> <br>
		 * -<br>
		 * <br>
		 * <b>Preconditions: </b> <br>
		 * <br>
		 * <br>
		 * <b>Postconditions: </b> <br>
		 * -
		 * 
		 * @see java.lang.Thread#destroy()
		 */
		public void destroy()
		{
			String sMethod = "AutoCRLUpdater.destroy";
			_systemLogger.log(Level.INFO, MODULE, sMethod, "---");
			_bActive = false;
			try {  // interrupt if sleeping
				_tAutoCrlUpdater.interrupt();
				//Thread.currentThread().interrupt();
			}
			catch (Exception e) {
				// no logging
			}

		}
	}

	class CRLRecoverer implements Runnable
	{
		private boolean _bActive;
		private long _lMilliSeconds;

		/**
		 * Thread that keeps tries to recover failed CRL updates. <br>
		 * <br>
		 * <b>Description:</b> <br>
		 * Thread that runs with a configurable interval. Every expired CRL that could not be updated is put in a list.
		 * This thread runs through the list of failed CRL updates and will keep trying to recover the CRL. <br>
		 * <br>
		 * <b>Concurrency issues:</b> <br>
		 * - <br>
		 * <br>
		 * <b>Preconditions:</b> <br>
		 * - <br>
		 * <br>
		 * <b>Postconditions:</b> <br>
		 * - <br>
		 * 
		 * @param lSeconds
		 *            the interval between the checks.
		 */
		public CRLRecoverer(long lSeconds)
		{
			_lMilliSeconds = lSeconds * 1000;
			_bActive = true;
		}

		/**
		 * tries to auto update the CRL's when retrieval failed. <br>
		 * <br>
		 * 
		 * @see java.lang.Runnable#run()
		 */
		public void run()
		{
			String sMethod = "CRLRecoverer.run";
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Run "+_bActive);
			while (_bActive) {
				try {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Sleep "+_lMilliSeconds);
					System.out.println(sMethod+" Sleep "+_lMilliSeconds);
					Thread.sleep(_lMilliSeconds);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Slept "+_lMilliSeconds);
					System.out.println(sMethod+" Slept "+_lMilliSeconds);
					Set keys = _htFailedCRLs.keySet();
					for (Object oFailedCrlKey : keys) {
						try {
							loadCRLForCA((String) oFailedCrlKey);
							_htFailedCRLs.remove(oFailedCrlKey);
						}
						catch (ASelectException e) {
							_systemLogger.log(Level.WARNING, MODULE, sMethod,
									"Reloading CRL for CA with alias: " + oFailedCrlKey.toString() + " failed");
						}
					}
				}
				catch (InterruptedException e) {
					System.out.println(sMethod+" InterruptedException");
				}
			}
			System.out.println(sMethod+" Stopped");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Stopped");
		}

		/**
		 * Destroys the CRLRecoverer. <br>
		 * <br>
		 * <b>Description: </b> <br>
		 * Stop the thread from running. <br>
		 * <br>
		 * <b>Concurrency issues: </b> <br>
		 * -<br>
		 * <br>
		 * <b>Preconditions: </b> <br>
		 * <br>
		 * <br>
		 * <b>Postconditions: </b> <br>
		 * -
		 * 
		 * @see java.lang.Thread#destroy()
		 */
		public void destroy()
		{
			String sMethod = "CRLRecoverer.destroy";
			_systemLogger.log(Level.INFO, MODULE, sMethod, "---");
			_bActive = false;
			try {  // interrupt if sleeping
				_tCrlRecoverer.interrupt();
				//Thread.currentThread().interrupt();
			}
			catch (Exception e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Interrupt failed");
			}
		}
	}

	class PKIAdminServer implements Runnable
	{
		private ServerSocket oSocket;
		private boolean _bActive;

		/**
		 * Thread that handles incoming requests from the admin tool. <br>
		 * <br>
		 * <b>Description:</b> <br>
		 * Thread that creates a new <code>PKIAdminRequestDispatcher</code> thread to interact with the client. <br>
		 * <br>
		 * <b>Concurrency issues:</b> <br>
		 * - <br>
		 * <br>
		 * <b>Preconditions:</b> <br>
		 * - <br>
		 * <br>
		 * <b>Postconditions:</b> <br>
		 * - <br>
		 * 
		 * @param iPort
		 *            the i port
		 * @throws ASelectException
		 *             the a select exception
		 */
		public PKIAdminServer(int iPort)
		throws ASelectException
		{
			try {
				oSocket = new ServerSocket(iPort, 0, InetAddress.getByName("localhost"));
			}
			catch (UnknownHostException e) {
				_systemLogger.log(Level.SEVERE, MODULE, "PKIAdminServer", "localhost", e);
				throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);

			}
			catch (IOException e) {
				_systemLogger.log(Level.SEVERE, MODULE, "PKIAdminServer", "localhost", e);
				throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR, e);
			}
			_bActive = true;
		}

		/**
		 * Listen for incoming requests. <br>
		 * <br>
		 * 
		 * @see java.lang.Runnable#run()
		 */
		public void run()
		{
			String sMethod = "PKIAdminServer.run";
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Run "+_bActive);
			PKIAdminRequestDispatcher oRequestDispatcher;
			Thread oRequestThread;
			while (_bActive) {
				try {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Accept");
					System.out.println(sMethod+" Accept");
					Socket clientSocket = oSocket.accept();
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Accepted");
					System.out.println(sMethod+" Accepted");
					oRequestDispatcher = new PKIAdminRequestDispatcher(clientSocket);
					oRequestThread = new Thread(oRequestDispatcher);
					oRequestThread.setDaemon(true);
					System.out.println(sMethod+" Start Thread");
					oRequestThread.start();
					System.out.println(sMethod+" Started Thread");
				}
				catch (Exception e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
				}
			}
			System.out.println(sMethod+" Stopped");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Stopped");
		}

		/**
		 * Destroys the PKIAdminServer. <br>
		 * <br>
		 * <b>Description: </b> <br>
		 * Stop the thread from running. <br>
		 * <br>
		 * <b>Concurrency issues: </b> <br>
		 * -<br>
		 * <br>
		 * <b>Preconditions: </b> <br>
		 * <br>
		 * <br>
		 * <b>Postconditions: </b> <br>
		 * -
		 * 
		 * @see java.lang.Thread#destroy()
		 */
		public void destroy()
		{
			String sMethod = "PKIAdminServer.destroy";
			_systemLogger.log(Level.INFO, MODULE, sMethod, "---");
			_bActive = false;
			try {  // interrupt if sleeping
				_tPkiAdminServer.interrupt();
				//Thread.currentThread().interrupt();
				oSocket.close();
			}
			catch (Exception e) {	// no logging
			}
		}
	}

	class PKIAdminRequestDispatcher implements Runnable
	{
		private Socket _oClientSocket;
		private boolean _bActive;
		private BufferedReader _oInputReader;
		private PrintWriter _pwOutput;

		/**
		 * Thread that offers admin functionality. <br>
		 * <br>
		 * <b>Description:</b> <br>
		 * Thread created by the <code>PKIAdminServer</code>. Offers functionality to reload CA keystores and/or CRL
		 * files. <br>
		 * <br>
		 * <b>Concurrency issues:</b> <br>
		 * - <br>
		 * <br>
		 * <b>Preconditions:</b> <br>
		 * - <br>
		 * <br>
		 * <b>Postconditions:</b> <br>
		 * - <br>
		 * 
		 * @param oClientSocket
		 *            the o client socket
		 */
		public PKIAdminRequestDispatcher(Socket oClientSocket) {

			_bActive = true;
			_oClientSocket = oClientSocket;
		}

		/**
		 * Reads input from admin client to proces desired functionality. <br>
		 * <br>
		 * 
		 * @see java.lang.Runnable#run()
		 */
		public void run()
		{
			String sMethod = "PKIAdminRequestDispatcher.run";
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Run "+_bActive);
			try {
				_oInputReader = new BufferedReader(new InputStreamReader(_oClientSocket.getInputStream()));
				_pwOutput = new PrintWriter(_oClientSocket.getOutputStream(), true);
				while (_bActive) {
					handleRequest("menu");
					String sRequest = _oInputReader.readLine();
					if (sRequest == null) {
						_bActive = false;
					}
					else {
						handleRequest(sRequest);
					}
				}
				_oClientSocket.close();
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			}
			System.out.println(sMethod+" Stopped");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Stopped");
		}

		/**
		 * Provides an ASCII menu and reads input from admin client.
		 * 
		 * @param sRequest
		 *            the s request
		 */
		public void handleRequest(String sRequest)
		{
			if (sRequest.equalsIgnoreCase("menu")) {
				_pwOutput.println("1 ) Reload All (CA Keystore and CRL's)");
				_pwOutput.println("2 ) Reload CRL's only ");
				_pwOutput.println("3 ) Reload CRL for CA (usage: 3 <CA alias>)");
				_pwOutput.println("Type \"quit\" to stop and \"menu\" for this menu.");
				_pwOutput.flush();
			}
			else if (sRequest.equalsIgnoreCase("1")) {
				try {
					loadCaKeyStoreFromPFXFile(_sCaKeyStoreLocation, _sCaKeyStorePassword);
					loadCRLs();
					_pwOutput.println("Succesfully Reloaded CA Keystore and CRL's");
				}
				catch (ASelectException e) {
					_pwOutput.println("The Following exception occured: " + e.getMessage());
					_systemLogger.log(Level.WARNING, MODULE, "PKIAdminRequestDispatcher->handleRequest()", e
							.getMessage(), e);
				}
			}
			else if (sRequest.equalsIgnoreCase("2")) {
				try {
					loadCRLs();
				}
				catch (ASelectException e) {
					_pwOutput.println("The Following exception occured: " + e.getMessage());
					_systemLogger.log(Level.WARNING, MODULE, "PKIAdminRequestDispatcher->handleRequest()", e
							.getMessage(), e);
				}
				_pwOutput.println("Succesfully Reloaded CRL's");
			}
			else if (sRequest.equalsIgnoreCase("3")) {
				try {
					_pwOutput.println("CA alias: ");
					_pwOutput.flush();
					String sAlias = _oInputReader.readLine();
					if (_oCaKeystore.containsAlias(sAlias)) {
						try {
							loadCRLForCA(sAlias);
							_pwOutput.println("Succesfully Reloaded CRL for CA with Alias: " + sAlias);
						}
						catch (ASelectException e) {
							_htCRLs.remove(sAlias);
							_htFailedCRLs.put(sAlias, e);
							_pwOutput.println("Failed to reload CRL for CA with Alias: " + sAlias);
							_pwOutput.println("CRL is added to the auto recovery list");
						}
					}
					else {
						_pwOutput.println("\nNo Such CA Alias found in CA Keystore.");
					}
				}
				catch (IOException e) {
					_pwOutput.println("The Following exception occured: " + e.getMessage());
					_systemLogger.log(Level.WARNING, MODULE, "PKIAdminRequestDispatcher->handleRequest()", e
							.getMessage(), e);
				}
				catch (KeyStoreException e) {
					_pwOutput.println("The Following exception occured: " + e.getMessage());
					_systemLogger.log(Level.WARNING, MODULE, "PKIAdminRequestDispatcher->handleRequest()", e
							.getMessage(), e);
				}
			}
			else if (sRequest.equalsIgnoreCase("quit")) {
				_bActive = false;
				_pwOutput.println("Connection Closed");
			}
			else {
				_pwOutput.println("Unknown Command");
			}
		}

		/**
		 * Destroys the PKIAdminRequestDispatcher. <br>
		 * <br>
		 * <b>Description: </b> <br>
		 * Stop the thread from running. <br>
		 * <br>
		 * <b>Concurrency issues: </b> <br>
		 * -<br>
		 * <br>
		 * <b>Preconditions: </b> <br>
		 * <br>
		 * <br>
		 * <b>Postconditions: </b> <br>
		 * -
		 * 
		 * @see java.lang.Thread#destroy()
		 */
		public void destroy()
		{
			String sMethod = "PKIAdminRequestDispatcher.destroy";
			_systemLogger.log(Level.INFO, MODULE, sMethod, "---");
			_bActive = false;
			try {  // interrupt if sleeping
				Thread.currentThread().interrupt();
			}
			catch (Exception e) {
				// no logging
			}
		}
	}
}
