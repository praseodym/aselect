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
 * $Id: ASelectAgentConfigManager.java,v 1.21 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectAgentConfigManager.java,v $
 * Revision 1.21  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.20  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.19  2005/05/02 10:48:31  martijn
 * changed config item: application_keystore_password to applications_keystore_password
 *
 * Revision 1.18  2005/04/06 15:14:48  tom
 * Changed application.keystore to applications.keystore
 *
 * Revision 1.17  2005/03/18 16:06:29  tom
 * Removed attribute rule
 *
 * Revision 1.16  2005/03/18 09:37:03  martijn
 * now attribute forwarding will only be disabled if the config section 'attribute_forwarding' can't be found
 *
 * Revision 1.15  2005/03/17 20:21:32  martijn
 * made attribute forwarding optional
 *
 * Revision 1.14  2005/03/17 14:07:51  remco
 * Attributes functionality
 *
 * Revision 1.13  2005/03/15 13:15:21  martijn
 * removed old code for retrieving 'signature_algorithm'
 *
 * Revision 1.12  2005/03/15 12:56:43  martijn
 * fixed a small bug in retrieving the new crypto config
 *
 * Revision 1.11  2005/03/15 10:52:17  martijn
 * The crypto configuration is changed, providers are now also configurable. The 'do_signing' config parameter is changed to 'sign_requests'
 *
 * Revision 1.10  2005/03/10 17:02:43  martijn
 * moved reading of the system logger configuration to the right classes, so changed init() methods
 *
 * Revision 1.9  2005/03/09 17:11:15  remco
 * fixed compiler warnings
 *
 * Revision 1.8  2005/03/09 16:23:34  remco
 * agent always signed requests, even when this option was turned off
 *
 * Revision 1.7  2005/03/09 12:09:59  remco
 * added preliminary signing
 *
 * Revision 1.6  2005/03/08 13:41:05  erwin
 * Added truststore parameter in configuration/init.
 *
 * Revision 1.5  2005/03/07 14:43:24  erwin
 * asp -> authsp in requests and admin monitor.
 *
 * Revision 1.4  2005/03/03 17:24:20  erwin
 * Applied code style, added javadoc comment.
 *
 * Revision 1.3  2005/02/25 15:51:33  erwin
 * Improved logging.
 *
 * Revision 1.2  2005/02/24 15:09:09  ali
 * Added IAgentEventListener class and updates internal Javadoc.
 */

package org.aselect.agent.config;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.agent.log.ASelectAgentSystemLogger;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * Implements the ConfigManager for the A-Select Agent package. <br>
 * <br>
 * <b>Description: </b> <br>
 * Implements the ConfigManager for the A-Select Agent package as a single pattern. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * None. <br>
 * 
 * @author Alfa & Ariss
 */
public class ASelectAgentConfigManager extends ConfigManager
{
	private final String MODULE = "ASelectAgentConfigManager";

	/**
	 * The default signature algorithm name
	 */
	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA1withRSA";

	/**
	 * The singleton instance
	 */
	private static ASelectAgentConfigManager _oASelectAgentConfigManager;

	/**
	 * The agent system logger
	 */
	private ASelectAgentSystemLogger _systemLogger;

	/**
	 * The working directory
	 */
	private String _sWorkingDir = null;

	/**
	 * Indicates whether or not API calls to the A-Select Server must be signed
	 */
	private boolean _bSignRequests;

	/**
	 * The signature algorithm name
	 */
	private String _sSignatureAlgorithm = null;

	/**
	 * The signature algorithm prover object
	 */
	private Provider _oSignatureProvider;

	/**
	 * The private key used to sign API calls to the A-Select Server
	 */
	private PrivateKey _privateKey = null;

	/**
	 * The attribute forwarding rules
	 */
	private HashMap _htAttributeForwarding = null;

	// Send "upgrade_tgt" to server only after a number of seconds have elapsed:
	int _upgradeTgtInterval = 0;

	public int getUpgradeTgtInterval() {
		return _upgradeTgtInterval;
	}

	/**
	 * returns a static ASelectAgentConfigManager handle to this singleton.
	 * 
	 * @return A static <code>ASelectAgentConfigManager</code>.
	 */
	public static ASelectAgentConfigManager getHandle()
	{
		if (_oASelectAgentConfigManager == null)
			_oASelectAgentConfigManager = new ASelectAgentConfigManager();

		return _oASelectAgentConfigManager;
	}

	/**
	 * Initializes the configuration.
	 * 
	 * @param sWorkingDir
	 *            The working directory.
	 * @throws ASelectConfigException
	 *             the aselect config exception
	 */
	public void init(String sWorkingDir)
	throws ASelectConfigException
	{
		_systemLogger = ASelectAgentSystemLogger.getHandle();
		_sWorkingDir = sWorkingDir;
		loadConfiguration(sWorkingDir);
	}
	
	public void init_next()
	throws ASelectException
	{
		String sMethod = "init_next";
		Object _oAgentSection = getSection(null, "agent");
		_upgradeTgtInterval = Utils.getSimpleIntParam(this, _systemLogger, _oAgentSection, "upgrade_tgt_interval", false);
		if (_upgradeTgtInterval < 0)
//			_upgradeTgtInterval = 60;  // seconds, value 0 means send always 
			_upgradeTgtInterval = 0; 	//  for backward compatibility we now use default = 0 (always upgrade_tgt)
		_systemLogger.log(Level.INFO, MODULE, sMethod, "upgrade_tgt_interval="+_upgradeTgtInterval);

		loadCrypto();
	}

	/**
	 * Load configuration.
	 * 
	 * @param sWorkingDir
	 *            the s working dir
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public void loadConfiguration(String sWorkingDir)
	throws ASelectConfigException
	{
		StringBuffer sb = new StringBuffer(sWorkingDir).append(File.separator).append("agent.xml");
		super.init(sb.toString(), ASelectAgentSystemLogger.getHandle());
	}

	/**
	 * Returns signature algorithm. <br>
	 * <br>
	 * 
	 * @return a <code>String</code> representation signature algorithm
	 */
	public String getSignatureAlgorithm()
	{
		return _sSignatureAlgorithm;
	}

	/**
	 * Returns signature algorithm Provider. <br>
	 * <br>
	 * 
	 * @return the configured <code>Provider</code> for the signature algorithm
	 */
	public Provider getSignatureProvider()
	{
		return _oSignatureProvider;
	}

	/**
	 * Returns signing key. <br>
	 * <br>
	 * 
	 * @return signing key
	 */
	public PrivateKey getSigningKey()
	{
		return _privateKey;
	}

	/**
	 * Returns TRUE if siging is enabled in config. <br>
	 * <br>
	 * 
	 * @return FALSE if signing is disabled in config
	 */
	public boolean isSigningEnabled()
	{
		return _bSignRequests;
	}

	/**
	 * Retrieve the attribute-forwarding rules for an application. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Returns the attribute forwarding rules for <code>sAppId</code> in a <code>HashMap</code>. It returns:
	 * <ul>
	 * <li>send_once: Boolean indicating whether to send once (during verify_credentials reply) or always (during
	 * verify_ticket reply too)
	 * <li>prefix: String that must be prefixed to each attribute when they are forwarded
	 * <li>attributes: A String Array containing the attribute masks.
	 * </ul>
	 * 
	 * @param sAppId
	 *            the s app id
	 * @return HashMap The forwarding rules, or <code>null</code> when no rules where found.
	 */
	public HashMap getAttributeForwardingRule(String sAppId)
	{
		HashMap htRules = (HashMap) _htAttributeForwarding.get(sAppId);
		if (htRules == null)
			htRules = (HashMap) _htAttributeForwarding.get("*");
		return htRules;
	}

	/**
	 * Private constructor.
	 */
	private ASelectAgentConfigManager() {
	}

	/**
	 * Load crypto.
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void loadCrypto()
	throws ASelectException
	{
		String sMethod = "loadCrypto";

		// Retrieve crypto configuration
		Object oAgent = null;
		try {
			oAgent = getSection(null, "agent");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not find aselect config section in config file", e);
			throw e;
		}

		Object oCryptoSection = null;
		try {
			oCryptoSection = getSection(oAgent, "crypto");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not find crypto config section in config file", e);
			throw e;
		}

		// Add crypto provider(s)
		Object oProvidersSection = null;
		try {
			oProvidersSection = getSection(oCryptoSection, "providers");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
					"Could not find 'providers' config section in configuration. No providers specified", eAC);
		}

		Object oCryptoProvider = null;

		HashMap htProviders = new HashMap();
		if (oProvidersSection != null) {
			try {
				oCryptoProvider = getSection(oProvidersSection, "provider");
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
					sProviderID = getParam(oCryptoProvider, "id");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No valid 'id' config item found", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				String sCryptoProvider = null;
				try {
					sCryptoProvider = getParam(oCryptoProvider, "class");
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
					StringBuffer sbError = new StringBuffer("The configured provider is not a valid Provider class: ");
					sbError.append(sCryptoProvider);
					_systemLogger.log(Level.CONFIG, MODULE, sMethod, sCryptoProvider, e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				java.security.Security.addProvider(oProvider);
				htProviders.put(sProviderID, oProvider);
				oCryptoProvider = getNextSection(oCryptoProvider);
			}
		}

		// Obtain algorithm for generating/verifying signatures
		readSignatureConfig(oCryptoSection, htProviders);

		// Retrieve signing parameter
		String sSignRequests;
		try {
			sSignRequests = getParam(oCryptoSection, "sign_requests");
			_bSignRequests = new Boolean(sSignRequests).booleanValue();
		}
		catch (ASelectConfigException e) {
			_bSignRequests = false;
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Missing 'sign_requests' parameter"
					+ " in 'crypto' section of agent configuration, disabling request signing.", e);
		}

		// Load signing key if necessary
		if (_bSignRequests) {
			String sPassword;
			try {
				sPassword = getParam(oCryptoSection, "applications_keystore_password");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Missing 'applications_keystore_password' parameter'"
						+ " in 'crypto section of agent configuration.", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			StringBuffer sbKeystore = new StringBuffer(_sWorkingDir);
			sbKeystore.append(File.separator);
			sbKeystore.append("applications.keystore");

			loadDefaultPrivateKey(sbKeystore.toString(), sPassword);
		}
	}

	/**
	 * Load default private key.
	 * 
	 * @param sKeystorePath
	 *            the s keystore path
	 * @param sPassword
	 *            the s password
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void loadDefaultPrivateKey(String sKeystorePath, String sPassword)
	throws ASelectException
	{
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(sKeystorePath), null);
			Enumeration e = ks.aliases();
			String sAlias = (String) e.nextElement();
			char[] caPassword = sPassword.toCharArray();
			_privateKey = (PrivateKey) ks.getKey(sAlias, caPassword);
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not load default private key from keystore: ");
			sbError.append(sKeystorePath);
			_systemLogger.log(Level.SEVERE, MODULE, "loadDefaultPrivateKey", sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
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
		String sMethod = "readSignatureConfig";
		String sProvider = null;

		Object oSection = null;
		try {
			oSection = getSection(oCryptoSection, "signature_algorithm");
		}
		catch (ASelectConfigException e) {
			oSection = null;
			_sSignatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;

			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Could not retrieve 'signature_algorithm' config section"
					+ " in crypto config section. Using default algorithm and provider.", e);
		}

		if (oSection != null) {
			// retrieve algorithm
			try {
				_sSignatureAlgorithm = getParam(oSection, "algorithm");
			}
			catch (ASelectConfigException e) {
				_sSignatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;

				StringBuffer sbConfig = new StringBuffer("Could not retrieve 'signature_algorithm' config parameter"
						+ " in crypto config section. Using default algorithm: ");
				sbConfig.append(_sSignatureAlgorithm);
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbConfig.toString());
			}
		}

		if (oSection != null) {
			// retrieve provider
			try {
				sProvider = getParam(oSection, "provider");
			}
			catch (ASelectConfigException e) {
				sProvider = null;

				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Could not retrieve 'provider' config section"
						+ " in crypto config section. Using default provider.", e);
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