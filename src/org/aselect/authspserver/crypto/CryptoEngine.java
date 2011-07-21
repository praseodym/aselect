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
 * $Id: CryptoEngine.java,v 1.14 2006/05/03 10:08:49 tom Exp $ 
 * 
 * Changelog:
 * $Log: CryptoEngine.java,v $
 * Revision 1.14  2006/05/03 10:08:49  tom
 * Removed Javadoc version
 *
 * Revision 1.13  2005/09/08 12:47:54  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.12  2005/04/15 11:52:35  tom
 * Removed old logging statements
 *
 * Revision 1.11  2005/03/16 11:42:26  tom
 * Fixed Javadoc comment
 *
 * Revision 1.10  2005/03/15 13:42:01  martijn
 * The crypto configuration is changed, providers are now also configurable.
 *
 * Revision 1.9  2005/03/11 13:27:07  erwin
 * Improved error handling.
 *
 * Revision 1.8  2005/03/11 08:46:22  martijn
 * fixed bug: When retrieving aliasses from the keystore, the alias must be lowercased.
 *
 * Revision 1.7  2005/03/11 07:55:03  martijn
 * added FIXMe
 *
 * Revision 1.6  2005/03/09 17:26:28  remco
 * added <crypto> section to authsp config
 *
 * Revision 1.5  2005/03/09 09:23:54  erwin
 * Renamed and moved errors.
 *
 * Revision 1.4  2005/02/24 13:48:10  martijn
 * fixed minor logging faults
 *
 * Revision 1.3  2005/02/24 12:16:11  martijn
 * added java documentation and changed variable names
 *
 */

package org.aselect.authspserver.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.BASE64Encoder;

/**
 * The A-Select AuthSP CryptoEngine. <br>
 * <br>
 * <b>Description: </b> <br>
 * Its function is to load the default AuthSP signing key and generate/verify signatures.<br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class CryptoEngine
{
	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "CryptoEngine";

	/**
	 * The name of the AuthSP keystore
	 */
	private final static String SERVER_KEYSTORE_NAME = "authsp.keystore";

	/**
	 * The name of the A-Select keystore
	 */
	private final static String PUBLIC_KEYSTORE_NAME = "aselect.keystore";

	/**
	 * The name of the alias of the AuthSP signing key
	 */
	private final static String KEY_ALIAS = "authsp_sign";

	/**
	 * Default signing algorithm
	 */
	private final String DEFAULT_SIGNATURE_ALGORITHM = "SHA1withRSA";

	/**
	 * The AuthSP private key for generating signatures
	 */
	private PrivateKey _oPrivateKey = null;

	/**
	 * The AuthSP public key for verifying signatures
	 */
	private PublicKey _oPublicKey = null;

	/**
	 * The config manager
	 */
	private AuthSPConfigManager _oAuthSPConfigManager = null;

	/**
	 * The logger used for system logging
	 */
	private AuthSPSystemLogger _systemLogger = null;

	/**
	 * Contains all public keys of the A-Select Servers connected with this AuthSP Server.
	 */
	private HashMap _htPublicKeys = null;

	/**
	 * The name of the algorithm used to generate/verify signatures
	 */
	private String _sSignatureAlgorithm = null;

	/**
	 * The algorithm provider used to generate/verify signatures
	 */
	private Provider _oSignatureProvider = null;

	/**
	 * Constructor for <code>CryptoEngine</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Loads AuthSP Server keys: private and public. It also loads the public keys of the A-Select Servers that are
	 * connected. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <i>sWorkingDir</i> may not be <code>null</code><br>
	 * - <i>oAuthSPSystemLogger</i> may not be <code>null</code> and must be initialized<br>
	 * <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - Will start if no A-Select Server public keys are found. <br>
	 * 
	 * @param sWorkingDir
	 *            The directory of the AuthSP Server where the keystores are located.
	 * @param oAuthSPSystemLogger
	 *            The logger that is used for system logging.
	 * @throws ASelectException
	 *             if the Crypto engine can not be initialized.
	 */
	public CryptoEngine(String sWorkingDir, AuthSPSystemLogger oAuthSPSystemLogger)
	throws ASelectException
	{
		_systemLogger = oAuthSPSystemLogger;
		_htPublicKeys = new HashMap();
		String sMethod = "CryptoEngine()";

		try {
			_oAuthSPConfigManager = AuthSPConfigManager.getHandle();

			Object oAuthSPServer = null;
			try {
				oAuthSPServer = _oAuthSPConfigManager.getSection(null, "authspserver");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod,
						"Could not find aselect config section in config file", eAC);
				throw eAC;
			}

			Object oCryptoSection = null;
			try {
				oCryptoSection = _oAuthSPConfigManager.getSection(oAuthSPServer, "crypto");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not find crypto config section in config file", eAC);
				throw eAC;
			}

			// Add crypto provider(s)
			Object oProvidersSection = null;
			try {
				oProvidersSection = _oAuthSPConfigManager.getSection(oCryptoSection, "providers");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Could not find 'providers' config section in configuration. No providers specified", eAC);
			}

			Object oCryptoProvider = null;

			HashMap htProviders = new HashMap();
			if (oProvidersSection != null) {
				try {
					oCryptoProvider = _oAuthSPConfigManager.getSection(oProvidersSection, "provider");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.CONFIG, MODULE, sMethod,
							"Could not find a 'provider' config section in config file. No providers specified", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				while (oCryptoProvider != null) // for all providers
				{
					String sProviderID = null;
					try {
						sProviderID = _oAuthSPConfigManager.getParam(oCryptoProvider, "id");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No valid 'id' config item found", e);
						throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					String sCryptoProvider = null;
					try {
						sCryptoProvider = _oAuthSPConfigManager.getParam(oCryptoProvider, "class");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No valid 'class' config item found", e);
						throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					Provider oProvider = null;
					try {
						oProvider = (Provider) Class.forName(sCryptoProvider).newInstance();
					}
					catch (Exception e) {
						StringBuffer sbError = new StringBuffer(
								"The configured provider is not a valid Provider class: ");
						sbError.append(sCryptoProvider);
						_systemLogger.log(Level.CONFIG, MODULE, sMethod, sCryptoProvider, e);
						throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					java.security.Security.addProvider(oProvider);
					htProviders.put(sProviderID, oProvider);
					oCryptoProvider = _oAuthSPConfigManager.getNextSection(oCryptoProvider);
				}
			}

			// Obtain algorithm for generating/verifying signatures
			readSignatureConfig(oCryptoSection, htProviders);

			// loading authsp private and public key for generating
			// and verifying signatures
			loadDefaultKeys(sWorkingDir);

			// loading public keys of all A-Select Servers that use the AuthSP
			// Server
			loadPublicKeys(sWorkingDir);

			if (_htPublicKeys.size() == 0) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No public keys of any A-Select Server found.");
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", eAS);
			throw eAS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialise due to internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Generates a signature of the supplied data. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Generates a signature of the supplied data <code>String</code> by using the AuthSP private key. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <i>sData</i> may not be <code>null</code><br>
	 * <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - Doesn't throw exceptions, not even when something went wrong. <br>
	 * 
	 * @param sData
	 *            the data that should be signed
	 * @return <code>null</code> when signature could not be generated or the signatue of the supplied data as a
	 *         <code>String</code>
	 * @throws ASelectException
	 *             If generating fails.
	 */
	public synchronized String generateSignature(String sData)
	throws ASelectException
	{
		String sMethod = "generateSignature()";
		String sSignature = null;
		try {
			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(_sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(_sSignatureAlgorithm);

			oSignature.initSign(_oPrivateKey);
			oSignature.update(sData.getBytes());
			byte[] baRawSignature = oSignature.sign();

			BASE64Encoder oBASE64Encoder = new BASE64Encoder();
			sSignature = oBASE64Encoder.encode(baRawSignature);
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not compute signature for data: \"");
			sbError.append(sData).append("\"");

			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return sSignature;
	}

	/**
	 * Verifies a signature. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Verifies the given signature for the given data with the key that is known by the given alias. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <i>sAlias</i> may not be <code>null</code><br>
	 * - <i>sData</i> may not be <code>null</code><br>
	 * - <i>sSignature</i> may not be <code>null</code><br>
	 * <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - Will also log with <code>Level.FINE</code> if the verification was not succesfull. <br>
	 * 
	 * @param sAlias
	 *            the alias that is used to identify the public key that is used for verification
	 * @param sData
	 *            contains the data that is signed
	 * @param sSignature
	 *            the signature that must be verified
	 * @return <code>TRUE</code> if the signature is successfully verified or <code>FALSE</code> if it could not be
	 *         verified.
	 */
	public synchronized boolean verifySignature(String sAlias, String sData, String sSignature)
	{
		String sMethod = "verifySignature()";
		boolean bVerifies = false;
		sAlias = sAlias.toLowerCase();

		try {
			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(_sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(_sSignatureAlgorithm);

			PublicKey oPublicKey = (PublicKey) _htPublicKeys.get(sAlias);
			if (oPublicKey == null) {
				StringBuffer sbError = new StringBuffer("Could not find public key with alias: ");
				sbError.append(sAlias);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				return bVerifies;
			}

			oSignature.initVerify(oPublicKey);
			oSignature.update(sData.getBytes());

			BASE64Decoder oBASE64Decoder = new BASE64Decoder();
			bVerifies = oSignature.verify(oBASE64Decoder.decodeBuffer(sSignature));
			if (!bVerifies) {
				StringBuffer sbInfo = new StringBuffer("Could not verify Signature '");
				sbInfo.append(sSignature);
				sbInfo.append("' for data: '");
				sbInfo.append(sData);
				sbInfo.append("' with a public key with Alias: ");
				sbInfo.append(sAlias);

				_systemLogger.log(Level.FINE, MODULE, sMethod, sbInfo.toString());
			}
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not verify signature for data: '");
			sbError.append(sData);
			sbError.append("' signature: '");
			sbError.append(sSignature);
			sbError.append("' alias: ");
			sbError.append(sAlias);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
		}
		return bVerifies;
	}

	/**
	 * Short description. <br>
	 * <br>
	 * 
	 * @return a <code>String</code> representation of this <code>Object</code>.
	 */
	public String getDescription()
	{
		return MODULE;
	}

	/**
	 * This function verifies a signature generated with our private key. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * It can be used to verify a signature of a request that is created by the AuthSP Server itself. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <i>sData</i> may not be <code>null</code><br>
	 * - <i>sSignature</i> may not be <code>null</code><br>
	 * <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - Will also log with <code>Level.FINE</code> if the verification was not succesfull. <br>
	 * 
	 * @param sData
	 *            The data from which the supplied signature is created.
	 * @param sSignature
	 *            The signature of the supplied data.
	 * @return <code>TRUE</code> if the signature is successfully verified or <code>FALSE</code> if it could not be
	 *         verified.
	 */
	public synchronized boolean verifyMySignature(String sData, String sSignature)
	{
		String sMethod = "verifyMySignature()";

		boolean bVerifies = false;

		try {
			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(_sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(_sSignatureAlgorithm);

			oSignature.initVerify(_oPublicKey);
			oSignature.update(sData.getBytes());

			BASE64Decoder oBASE64Decoder = new BASE64Decoder();
			bVerifies = oSignature.verify(oBASE64Decoder.decodeBuffer(sSignature));

			if (!bVerifies) {
				StringBuffer sbInfo = new StringBuffer("Signature '");
				sbInfo.append(sSignature);
				sbInfo.append("' is invalid for data: ");
				sbInfo.append(sData);
				_systemLogger.log(Level.FINE, MODULE, sMethod, sbInfo.toString());
			}
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Error while verifying data: '");
			sbError.append(sData);
			sbError.append("' with signature: '");
			sbError.append(sSignature).append("'");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
		}
		return bVerifies;
	}

	/**
	 * This method loads the private and public key of this AuthSP Server from the specified keystore.
	 * 
	 * @param sWorkingDir
	 *            directory in which the keystores are located
	 * @throws ASelectException
	 *             if any error occurs while loading the default keys
	 */
	private void loadDefaultKeys(String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "loadDefaultKeys()";
		Object oAuthSPConfig = null;
		String sPassword = null;

		try {
			AuthSPConfigManager oAuthSPConfigManager = AuthSPConfigManager.getHandle();

			try {
				oAuthSPConfig = oAuthSPConfigManager.getSection(null, "authspserver");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'authspserver' config section found", eAC);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}

			try {
				sPassword = oAuthSPConfigManager.getParam(oAuthSPConfig, "keystore_password");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'keystore_password' config item in 'authspserver' section found.", eAC);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}

			if (sPassword == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Missing 'keystore_password' config item in AuthSP Server configuration.");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			StringBuffer sbKeystoreLocation = new StringBuffer(sWorkingDir);
			sbKeystoreLocation.append(File.separator).append("keystores");
			sbKeystoreLocation.append(File.separator).append(SERVER_KEYSTORE_NAME);

			File fKeystore = new File(sbKeystoreLocation.toString());
			if (!fKeystore.exists()) {
				StringBuffer sbError = new StringBuffer("Keystore cannot be found: ");
				sbError.append(sbKeystoreLocation.toString());
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_NOT_FOUND);
			}

			KeyStore ksPrivate = KeyStore.getInstance("JKS");
			ksPrivate.load(new FileInputStream(sbKeystoreLocation.toString()), null);

			char[] caPasswordChars = sPassword.toCharArray();
			_oPrivateKey = (PrivateKey) ksPrivate.getKey(KEY_ALIAS, caPasswordChars);

			java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) ksPrivate
					.getCertificate(KEY_ALIAS);

			// public key is needed for verifying signatures
			_oPublicKey = x509Cert.getPublicKey();
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Error loading private key from directory: '");
			sbError.append(sWorkingDir).append("'");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * This method loads the public keys of A-Select Servers.
	 * 
	 * @param sWorkingDir
	 *            directory in which the keystores are located
	 * @throws ASelectException
	 *             if any error occurs while loading the A-Select public keys
	 */
	private void loadPublicKeys(String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "loadPublicKeys()";

		try {
			StringBuffer sbKeystoreLocation = new StringBuffer(sWorkingDir);
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

			Enumeration enumAliases = ksASelect.aliases();
			while (enumAliases.hasMoreElements()) {
				String sAlias = (String) enumAliases.nextElement();
				sAlias = sAlias.toLowerCase();
				java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) ksASelect.getCertificate(sAlias);
				PublicKey oPublicKey = x509Cert.getPublicKey();
				_htPublicKeys.put(sAlias, oPublicKey);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer(" Error loading public keys from directory: '");
			sbError.append(sWorkingDir);
			sbError.append("'");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Read signature config.
	 * 
	 * @param oCryptoSection
	 *            the o crypto section
	 * @param htProviders
	 *            the ht providers
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void readSignatureConfig(Object oCryptoSection, HashMap htProviders)
	throws ASelectException
	{
		String sMethod = "readSignatureConfig()";
		String sProvider = null;

		Object oSection = null;
		try {
			oSection = _oAuthSPConfigManager.getSection(oCryptoSection, "signature_algorithm");
		}
		catch (ASelectConfigException e) {
			oSection = null;
			_sSignatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;

			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
				"Could not retrieve 'signature_algorithm' config section in crypto config section. Using default algorithm and provider.");
		}

		if (oSection != null) {
			// retrieve algorithm
			try {
				_sSignatureAlgorithm = _oAuthSPConfigManager.getParam(oSection, "algorithm");
			}
			catch (ASelectConfigException e) {
				_sSignatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;

				StringBuffer sbConfig = new StringBuffer(
						"Could not retrieve 'algorithm' config parameter in crypto config section. Using default algorithm: ");
				sbConfig.append(_sSignatureAlgorithm);
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbConfig.toString());
			}
		}

		// retrieve provider
		if (oSection != null) {
			try {
				sProvider = _oAuthSPConfigManager.getParam(oSection, "provider");
			}
			catch (ASelectConfigException e) {
				sProvider = null;
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Could not retrieve 'provider' config section in crypto config section. Using default provider.");
			}

			if (sProvider != null) {
				if (!htProviders.containsKey(sProvider)) {
					StringBuffer sbError = new StringBuffer("Unknown 'provider': ");
					sbError.append(sProvider);
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}
				_oSignatureProvider = (Provider) htProviders.get(sProvider);

				StringBuffer sbInfo = new StringBuffer("Using provider '");
				sbInfo.append(sProvider);
				sbInfo.append("' for signature generation");
				_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
			}
		}
	}
}
