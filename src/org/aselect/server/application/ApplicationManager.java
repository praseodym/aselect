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
 * $Id: ApplicationManager.java,v 1.26 2006/04/26 12:15:44 tom Exp $ 
 * 
 * Changelog:
 * $Log: ApplicationManager.java,v $
 * Revision 1.26  2006/04/26 12:15:44  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.25  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.24.4.8  2006/04/07 09:10:45  leon
 * java doc
 *
 * Revision 1.24.4.7  2006/03/17 07:34:44  martijn
 * config item show_app_url changed to show_url
 *
 * Revision 1.24.4.6  2006/03/16 13:54:58  martijn
 * now reading the optional attribute_policy config from application during initialization
 *
 * Revision 1.24.4.5  2006/03/16 10:32:28  leon
 * removed some redundant code and placed it in the private function getApplication
 *
 * Revision 1.24.4.4  2006/03/16 09:21:57  leon
 * added extra functions for
 * - Maintainer email
 * - Friendly name
 * - Show app url
 * - Use opaque uid
 *
 * Revision 1.24.4.3  2006/03/16 07:55:00  leon
 * - ApplicationManager almost completely rewritten.
 * - fixed bug #139
 *
 * Revision 1.24  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.23  2005/04/22 06:51:49  tom
 * Changed error type in getSigningKey
 *
 * Revision 1.22  2005/04/22 06:45:55  tom
 * Change loglevel in getSigningKey
 *
 * Revision 1.21  2005/04/13 12:00:40  tom
 * Applications not defined in SSO groups are put in the default group "0"
 *
 * Revision 1.20  2005/04/11 14:20:59  peter
 * resolved a fix-me
 *
 * Revision 1.19  2005/04/08 11:47:21  tom
 *
 * Revision 1.18  2005/04/07 14:36:17  martijn
 * added javadoc
 *
 * Revision 1.17  2005/04/07 12:13:23  martijn
 * changed isValidSSOGroup(): now verifying 2 Vector objects
 *
 * Revision 1.16  2005/04/07 07:07:47  martijn
 * fixed resolveSSOGroups()
 *
 * Revision 1.15  2005/04/07 06:37:12  erwin
 * Renamed "attribute" -> "param" to be compatible with configManager.
 *
 * Revision 1.14  2005/04/06 15:42:31  martijn
 * added signle sign-on groups configuration resolving
 *
 * Revision 1.13  2005/04/05 07:50:11  martijn
 * added forced_authenticate
 *
 * Revision 1.12  2005/03/31 15:38:34  peter
 *
 * Revision 1.11  2005/03/16 13:12:11  remco
 * added attributes (initial version)
 *
 * Revision 1.10  2005/03/15 15:00:50  martijn
 * renamed special authsp to privileged application
 *
 * Revision 1.9  2005/03/10 16:45:33  erwin
 * Fixed typo
 *
 * Revision 1.8  2005/03/10 14:17:45  erwin
 * Improved Javadoc.
 *
 * Revision 1.7  2005/03/10 10:08:27  erwin
 * Improved error handling
 *
 * Revision 1.6  2005/03/09 17:08:54  remco
 * Fixed whole bunch of warnings
 *
 * Revision 1.5  2005/03/09 12:10:53  remco
 * added application signing (untested)
 *
 * Revision 1.4  2005/03/09 09:24:50  erwin
 * Renamed and moved errors.
 *
 * Revision 1.3  2005/03/04 11:24:41  peter
 * naming convention, javadoc, code style
 *
 */

package org.aselect.server.application;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

/**
 * The application manager for the A-Select Server. <br>
 * <br>
 * <b>Description:</b><br>
 * A singleton application manager, containing the application configuration. It loads several application settings in
 * memory during initialization. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * The class is a singleton, so the same class is used in all the classes of the A-Select Server. <br>
 * 
 * @author Alfa & Ariss
 */
public class ApplicationManager
{
	// These could be drawn from saml20 libraries but we don't want this dependency here
	private static final String AUTHN_CONTEXT_DECL_REF = "AuthnContextDeclRef";
	private static final String AUTHN_CONTEXT_DECL = "AuthnContextDecl";

	// All
	private HashMap _htApplications;

	// 
	private HashMap _htSSOGroupedApplications;

	// Name of this module, used for logging
	private static final String MODULE = "ApplicationManager";

	// Needed to make this class a singleton.
	private static ApplicationManager _oApplicationManager;

	// The A-Select config manager used for reading config parameters
	private ASelectConfigManager _oASelectConfigManager;

	// The logger that is used for system logging
	private ASelectSystemLogger _systemLogger;

	// Boolean indicating whether or not application API calls must be signed
	private boolean _bRequireSigning;

	// Location of applications.keystore when signing is required.
	private String _sApplicationsKeystoreName = null;

	// Do I know applications?
	private boolean _bApplicationsConfigured = false;

	private Object _oApplicationsConfigSection = null;

	
	
	/**
	 * Must be used to get an ApplicationManager instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new <code>ApplicationManager</code> instance if it's still <code>null</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * Always the same instance of the application manager is returned, because it's a singleton. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return A static handle to the <code>ApplicationManager</code>.
	 */
	public static ApplicationManager getHandle()
	{
		if (_oApplicationManager == null) {
			_oApplicationManager = new ApplicationManager();
		}
		return _oApplicationManager;
	}

	/**
	 * Initialization of the ApplicationManager singleton <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Must be successfully run once, before it can be used. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - Singleton <code>ASelectConfigManager</code> should be initialized.<BR>
	 * - At least one application should be configured. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	public void init()
	throws ASelectException
	{
		String sMethod = "init()";
		// FIXME: Double initialization of _oApplicationsConfigSection
		Object _oApplicationsConfigSection;
		_htApplications = new HashMap();
		try {
			_oASelectConfigManager = ASelectConfigManager.getHandle();
			_systemLogger = ASelectSystemLogger.getHandle();

			try {
				_oApplicationsConfigSection = _oASelectConfigManager.getSection(null, "applications");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'applications' section found in A-Select config",
						eAC);
				return;
			}
			try {
				String sRequireSigning = _oASelectConfigManager
						.getParam(_oApplicationsConfigSection, "require_signing");
				_bRequireSigning = new Boolean(sRequireSigning).booleanValue();
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No 'require_signing' parameter found in section 'applications', using default value 'false'");
			}

			// RH, 20100909, so
//			if (_bRequireSigning) {
//				_sApplicationsKeystoreName = new StringBuffer(_oASelectConfigManager.getWorkingdir()).append(
//						File.separator).append("keystores").append(File.separator).append("applications").append(
//						File.separator).append("applications.keystore").toString();
//			}
			// RH, 20100909, eo
			
			Object oApplication = null;
			try { // Check if at least one application is defined
				oApplication = _oASelectConfigManager.getSection(_oApplicationsConfigSection, "application");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No 'application' section found in 'applications' section", eAC);
				return;
			}

			// Read config data for all applications
			while (oApplication != null) {
				Application application = new Application();

				String sAppId = ASelectConfigManager.getSimpleParam(oApplication, "id", true);
				Integer intLevel = null;
				String sLevel = ASelectConfigManager.getSimpleParam(oApplication, "level", true);
				intLevel = new Integer(sLevel);

				Integer intMaxLevel = null;
				String sMax = ASelectConfigManager.getSimpleParam(oApplication, "max_level", false);
				if (sMax != null)
					intMaxLevel = new Integer(sMax);
				
				Integer intSubLevel = null;
				String sSub = ASelectConfigManager.getSimpleParam(oApplication, "sub_level", false);
				if (sSub != null)
					intSubLevel = new Integer(sSub);
				String sForced = ASelectConfigManager.getSimpleParam(oApplication, "forced_authenticate", false);
				boolean bForced = new Boolean(sForced);
				String sFriendlyName = ASelectConfigManager.getSimpleParam(oApplication, "friendly_name", false);
				String sMaintainerEmail = ASelectConfigManager.getSimpleParam(oApplication, "maintainer_email", false);
				boolean bShowUrl = false;
				String sShowUrl = ASelectConfigManager.getSimpleParam(oApplication, "show_url", false);
				if (sShowUrl != null)
					bShowUrl = new Boolean(sShowUrl).booleanValue();
				boolean bUseOpaqueId = false;
				String sUseOpaqueUid = ASelectConfigManager.getSimpleParam(oApplication, "use_opaque_uid", false);
				if (sUseOpaqueUid != null)
					bUseOpaqueId = new Boolean(sUseOpaqueUid).booleanValue();
				String sAttributePolicy = ASelectConfigManager.getSimpleParam(oApplication, "attribute_policy", false);

				String sSharedSecret = ASelectConfigManager.getSimpleParam(oApplication, "shared_secret", false);
				String sForcedUid = ASelectConfigManager.getSimpleParam(oApplication, "forced_uid", false);
				String sForcedAuthsp = ASelectConfigManager.getSimpleParam(oApplication, "forced_authsp", false);
				String sLevelName = ASelectConfigManager.getSimpleParam(oApplication, "level_name", false);
				boolean bDoUrlEncode = true;
				String sDoUrlEncode = ASelectConfigManager.getSimpleParam(oApplication, "use_url_encoding", false);
				if (sDoUrlEncode != null)
					bDoUrlEncode = new Boolean(sDoUrlEncode).booleanValue();
				// RH, 20100909, sn
				String sAppRequireSigning = ASelectConfigManager.getSimpleParam(oApplication, "require_signing", false);
				// RH, 20100909, en

				// RH, 20101206, sn
				String sAddedPatching = ASelectConfigManager.getSimpleParam(oApplication, "added_patching", false);
				// RH, 20101206, en

				// RH, 20101206, sn
				HashMap<String, String> _htLevels = new HashMap<String, String>(); // contains level -> urn
				_htLevels = ASelectConfigManager.getTableFromConfig(oApplication,  _htLevels, "authentication_method", "security", "level",/*->*/"uri",
						false/* mandatory */, false/* unique values */);
				// check if all levels are valid for integer conversion
				if (_htLevels != null) {
					Set<String> levelSet = _htLevels.keySet();
					if ( !SecurityLevel.ALLOWEDLEVELS.containsAll(levelSet) ) {
						throw new ASelectConfigException("Level not allowed in 'authentication_method/security' for application: " + sAppId );
					}
				}
				// RH, 20101206, en
				
				// 20101229, Bauke: fixed attributes to be added to a returned SAML token
				HashMap<String, String> _htAdditionalAttributes = new HashMap<String, String>();
				_htAdditionalAttributes = ASelectConfigManager.getTableFromConfig(oApplication, _htAdditionalAttributes,
						"additional_attributes", "attribute", "name",/*->*/"value", false/* mandatory */, false/* unique values */);

				// 20110928, Bauke
				HashMap<String, String> _htValidResources = new HashMap<String, String>();
				_htValidResources = ASelectConfigManager.getTableFromConfig(oApplication, _htValidResources, 
						"resources", "resource", "id", null, false/* mandatory */, false/* unique values */);

				// RH, 20101217, sn
				String sAuthnContextDeclValue = ASelectConfigManager.getSimpleParam(oApplication, "authn_context_decl",  false);
				String sAuthnContextDeclType = ASelectConfigManager.getParamFromSection(oApplication, "authn_context_decl", "type", sAuthnContextDeclValue == null ? false : true);
				if ( sAuthnContextDeclValue != null && !(AUTHN_CONTEXT_DECL.equals(sAuthnContextDeclType) || AUTHN_CONTEXT_DECL_REF.equals(sAuthnContextDeclType)) ) {
					throw new ASelectConfigException("AuthnContextDeclValue=" + sAuthnContextDeclValue + ", AuthnContextDeclType=" + sAuthnContextDeclType +   ",  authn_context_decl/type should be '" +AUTHN_CONTEXT_DECL + "' or '" + AUTHN_CONTEXT_DECL_REF + "' for application: " + sAppId );
				}
				// RH, 20101217, en

				// RH, 20110920, sn
				String sFirstAuthsp = ASelectConfigManager.getSimpleParam(oApplication, "first_authsp", false);
				// RH, 20110920, en
				
				String sSelectform = ASelectConfigManager.getSimpleParam(oApplication, "selectform", false); // RH, 20121119, n

				boolean onBehalfOf = Boolean.parseBoolean(ASelectConfigManager.getSimpleParam(oApplication, "onbehalfof", false));  // RH, 20140303, n

				// Bauke 20101125: For DigiD4Bedrijven:
				String sUseSsn = ASelectConfigManager.getSimpleParam(oApplication, "use_ssn", false);
				application.setUseSsn(sUseSsn);

				// required params
				application.setId(sAppId);
				application.setMinLevel(intLevel);

				// optional params.
				application.setMaxLevel(intMaxLevel);
				application.setSubLevel(intSubLevel);  // RH, 20140424, n
				application.setForcedAuthenticate(bForced);
				application.setFriendlyName(sFriendlyName);
				application.setMaintainerEmail(sMaintainerEmail);
				application.setUseOpaqueUId(bUseOpaqueId);
				application.setShowUrl(bShowUrl);
				application.setAttributePolicy(sAttributePolicy);
				
				// RH, 20100909, sn
				application.setSigningRequired(calculateRequireSigning(_bRequireSigning, sAppRequireSigning));
				// RH, 20100909, en

				// 20090305, Bauke added for DigiD-ization
				application.setSharedSecret(sSharedSecret);
				application.setForcedUid(sForcedUid);
				application.setForcedAuthsp(sForcedAuthsp);
				application.setLevelName(sLevelName);
				application.setDoUrlEncode(bDoUrlEncode);

				// RH, 20100909, so
//				if (_bRequireSigning) {
//					application.setSigningKey(loadPublicKeyFromKeystore(sAppId));
//				}
				// RH, 20100909, eo

				// RH, 20100909, sn
				if (application.isSigningRequired()) {
					// RH, 20100909, sn
					if (_sApplicationsKeystoreName == null || "".equals(_sApplicationsKeystoreName)) {
						_sApplicationsKeystoreName = new StringBuffer(_oASelectConfigManager.getWorkingdir()).append(
								File.separator).append("keystores").append(File.separator).append("applications").append(
								File.separator).append("applications.keystore").toString();
					}
					// RH, 20100909, en
					application.setSigningKey(loadPublicKeyFromKeystore(sAppId));
				}
				// RH, 20100909, en
				
				application.setAddedPatching(sAddedPatching);// RH, 20101206, n
				application.setSecLevels(_htLevels); // RH, 20101214, n
				application.setAdditionalAttributes(_htAdditionalAttributes); // Bauke, 20101229
				application.set_ValidResources(_htValidResources);

				application.setAuthnContextDeclValue(sAuthnContextDeclValue); // RH, 20101217, n
				application.setAuthnContextDeclType(sAuthnContextDeclType); // RH, 20101217, n

				application.setFirstAuthsp(sFirstAuthsp);// RH, 20110920, n
				
				application.setSelectform(sSelectform);	// RH, 20121119, n
				
				application.setOBOEnabled(onBehalfOf);  // RH, 20140303, n

				_htApplications.put(sAppId, application);
				oApplication = _oASelectConfigManager.getNextSection(oApplication);
			}
			if (_htApplications.size() >= 0) {
				_bApplicationsConfigured = true;
			}
			_htSSOGroupedApplications = resolveSSOGroups();
		}
		catch (ASelectException eA) {
			throw eA;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error during initializing", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Checks for applications configured.
	 * 
	 * @return true if there are applications configured.
	 */
	public boolean hasApplicationsConfigured()
	{
		return _bApplicationsConfigured;
	}

	/**
	 * Checks if is application.
	 * 
	 * @param sAppId
	 *            the Id of the application
	 * @return true if the application exists.
	 */
	public boolean isApplication(String sAppId)
	{
		return _htApplications.containsKey(sAppId);
	}


	// RH, 20100909, sn
	/**
	 * Checks if signing is required. Per application
	 * If sAppId == null, Return top-level signing_required
	 * 
	 * @param sAppId
	 *            the Id of the application
	 * @return true if signing is required, otherwise false.
	 */
	public boolean isSigningRequired(String sAppId)
	throws ASelectException
	{
		if (sAppId == null) {
			return _bRequireSigning;
		}
		else {
			Application oApplication = getApplication(sAppId);
			return oApplication.isSigningRequired();
		}
	}
	// RH, 20100909, en
	
	/**
	 * Checks if is signing required.
	 * 
	 * @return true if signing is required, otherwise false.
	 */
	public boolean isSigningRequired()	// for backward compatibility, for signing this is still used
	{
		return _bRequireSigning;
	}

	/**
	 * Returns the required level for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured required level for the application. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return String containing the level. <code>null</code> if no level was found.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public Integer getRequiredLevel(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return oApplication.getMinLevel();
	}

	/**
	 * Returns the maximum level for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured maximum level for the application. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return String containing the level. <code>null</code> if no level was found.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public Integer getMaxLevel(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return oApplication.getMaxLevel();
	}

	
	/**
	 * Returns the sub level for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured sub_level for the application. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return String containing the level. <code>null</code> if no level was found.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public Integer getSubLevel(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return oApplication.getSubLevel();
	}

	
	/**
	 * Retrieve a signing key.
	 * 
	 * @param sAppId
	 *            The application ID.
	 * @return The signing key of the given application ID.
	 * @throws ASelectException
	 *             If retrieving fails.
	 */
	public PublicKey getSigningKey(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return oApplication.getSigningKey();
	}

	/**
	 * Checks if is forced authenticate enabled.
	 * 
	 * @param sAppId
	 *            The application id that will be checked for enabled forced authentication
	 * @return true if forced_authenticate="true", otherwise false.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public boolean isForcedAuthenticateEnabled(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return oApplication.isForcedAuthenticate();
	}

	/**
	 * Returns the attribute policy for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured attribute policy for the application. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return String containing the level. <code>null</code> if no level was found.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String getAttributePolicy(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return (oApplication==null)? null: oApplication.getAttributePolicy();
	}

	/**
	 * Returns the Friendly Name for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured Friendly Name for the application. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return String containing the friendly name. <code>null</code> if no friendly name was found.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String getFriendlyName(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return (oApplication==null)? null: oApplication.getFriendlyName();
	}

	/**
	 * Returns the maintainer email address for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured maintainer email address for the application. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return String containing the maintainer email address. <code>null</code> if no level was found.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String getMaintainerEmail(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return (oApplication==null)? null: oApplication.getMaintainerEmail();
	}

	/**
	 * Returns if an opaque uid must be used for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns true if an opaque uid must be used for an application and false if the 'normal' A-Select uid must be
	 * used. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return true or false.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public boolean isUseOpaqueUid(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return oApplication.isUseOpaqueUId();
	}

	/**
	 * Returns if the app url must be shown or not <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns true if app url must be shown and false if not. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return true or false.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public boolean isShowUrl(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return (oApplication==null)? null: oApplication.isShowUrl();
	}

	/**
	 * Returns a all configured single sign-on groups for the supplied <i> sAppID</i>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns a <code>Vector</code> containing all configured single sign-on groups for the supplied app_id. If now
	 * groups is configured the default group "0" is returned. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * <li><i>sAppID</i> may not be <code>null</code></li> <li><i>_htSSOGroupedApplications</i> may not be
	 * <code>null</code></li> <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sAppId
	 *            The single sign-on groups in which this app id is contained
	 * @return <code>null</code> if the supplied app id isn't configured in a single sign-on group
	 */
	public Vector getSSOGroups(String sAppId)
	{
		Vector vReturn = null;
		if (_htSSOGroupedApplications.containsKey(sAppId))
			vReturn = (Vector) _htSSOGroupedApplications.get(sAppId);
		else {
			vReturn = new Vector();
			vReturn.add(new String("0"));
		}

		return vReturn;
	}

	/**
	 * Verifies if one of the supplied single sign-on groups contains in the existing TGT <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Verifies if one sso_group that exists in the <i>vValidSSOGroups</i> correspond with one sso_group in the
	 * <i>vOldSSOGroups</i> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li><i>vValidSSOGroups</i> may not be <code>null</code></li> <li><i>vOldSSOGroups</i> may not be
	 * <code>null</code></li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * .
	 * 
	 * @param vValidSSOGroups
	 *            <code>Vector</code> containing the sso_group id's of the current application
	 * @param vOldSSOGroups
	 *            <code>Vector</code> containing the sso_group id's that are known in the TGT
	 * @return TRUE if one sso_group from <i>vValidSSOGroups</i> contains in the <i>vOldSSOGroups</i>
	 */
	public boolean isValidSSOGroup(Vector vValidSSOGroups, Vector vOldSSOGroups)
	{
		String sMethod = "isValidSSOGroup";
		try {
			for (int i = 0; i < vValidSSOGroups.size(); i++) {
				String sItem = (String) vValidSSOGroups.get(i);
				if (vOldSSOGroups.contains(sItem))
					return true;
			}
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not check if sso_groups: ");
			sbError.append(vOldSSOGroups);
			sbError.append(" contains in one of these sso_groups: ");
			sbError.append(vValidSSOGroups);
			_systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString(), e);
		}
		return false;
	}

	/**
	 * Returns the requested parameter for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured value of the parameter asked for. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @param sName
	 *            <code>String</code> containing the parameter name asked for.
	 * @return String containing the parameter value asked for, or <code>null</code> if the attribute was not found.
	 */
	public String getParam(String sAppId, String sName)
	{
		String sReturn = null;
		String sMethod = "getParam()";
		Object oApp = null;

		try {
			try {
				oApp = _oASelectConfigManager.getSection(_oApplicationsConfigSection, "application", "id=" + sAppId);
			}
			catch (ASelectConfigException eAC) {
				StringBuffer sbMessage = new StringBuffer("No valid 'application' section found for '");
				sbMessage.append(sAppId).append("' in A-Select config");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbMessage.toString(), eAC);
				return null;
			}
			try {
				sReturn = _oASelectConfigManager.getParam(oApp, sName);
			}
			catch (ASelectConfigException eAC) {
				StringBuffer sbMessage = new StringBuffer("No valid '");
				sbMessage.append(sName).append("' found for '");
				sbMessage.append(sAppId).append("' in 'application' section");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbMessage.toString(), eAC);
				return null;
			}
			sReturn = sReturn.trim();
			return sReturn;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			return null;
		}
	}

	/**
	 * Returns the requested optional parameter for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured value of the parameter asked for, or <code>null</code> if the attribute is not present.
	 * Unlike the {@link #getParam(String, String)} method, this method does not complain about missing parameters in
	 * the system log. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @param sName
	 *            <code>String</code> containing the parameter name asked for.
	 * @return String containing the parameter value asked for, or <code>null</code> if the attribute was not found.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String getOptionalParam(String sAppId, String sName)
	throws ASelectException
	{
		String sReturn = null;
		String sMethod = "getOptionalParam()";
		Object oApp = null;

		try {
			oApp = _oASelectConfigManager.getSection(_oApplicationsConfigSection, "application", "id=" + sAppId);
		}
		catch (ASelectConfigException eAC) {
			StringBuffer sbMessage = new StringBuffer("No valid 'application' section found for '");
			sbMessage.append(sAppId).append("' in A-Select config");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbMessage.toString(), eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
		}

		try {
			sReturn = _oASelectConfigManager.getParam(oApp, sName);
		}
		catch (ASelectConfigException eAC) {
			return null;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		sReturn = sReturn.trim();
		return sReturn;
	}

	// private function which get the Application with sAppId from htApplications
	/**
	 * Gets the application.
	 * 
	 * @param sAppId
	 *            the s app id
	 * @return the application
	 * @throws ASelectException
	 *             the a select exception
	 */
	public Application getApplication(String sAppId)
	throws ASelectException
	{
		String sMethod = "getApplication()";
		Application oApplication = (Application) _htApplications.get(sAppId);
		if (oApplication == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No application found with Id: '" + sAppId + "'.");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
		}
		return oApplication;
	}

	/*
	 * loads the single sign-on groups configuration, like: <sso_groups> <sso_group id="1"> <application id="app1"/>
	 * <application id="app2"/> </sso_group> <sso_group id="2"> <application id="app1"/> <application id="app3"/>
	 * </sso_group> <sso_group id="3"> <application id="app1"/> <application id="app4"/> </sso_group> </sso_groups>
	 */
	/**
	 * Resolve sso groups.
	 * 
	 * @return the hash map
	 * @throws ASelectException
	 *             the a select exception
	 */
	private HashMap resolveSSOGroups()
	throws ASelectException
	{
		String sMethod = "resolveSSOGroups()";
		HashMap htReturn = new HashMap();
		try {
			Object oSSOGroups = null;
			try {
				oSSOGroups = _oASelectConfigManager.getSection(null, "sso_groups");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid 'sso_groups' config item found, disabling single sign-on groups.");
			}

			if (oSSOGroups != null) {
				Object oSSOGroup = null;
				try {
					oSSOGroup = _oASelectConfigManager.getSection(oSSOGroups, "sso_group");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Not even one valid 'sso_group' config section defined.");
					throw e;
				}

				while (oSSOGroup != null) {
					String sSSOGroupID = null;
					try {
						sSSOGroupID = _oASelectConfigManager.getParam(oSSOGroup, "id");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"No valid 'id' config item defined in 'sso_group' config item.");
						throw e;
					}

					Object oApplication = null;
					try {
						oApplication = _oASelectConfigManager.getSection(oSSOGroup, "application");
					}
					catch (ASelectConfigException e) {
						StringBuffer sbError = new StringBuffer(
								"Not even one valid 'application' config section defined in 'sso_group' with id: ");
						sbError.append(sSSOGroupID);
						_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
						throw e;
					}

					while (oApplication != null) {
						String sAppId = null;
						try {
							sAppId = _oASelectConfigManager.getParam(oApplication, "id");
						}
						catch (ASelectConfigException e) {
							StringBuffer sbError = new StringBuffer(
									"No valid 'id' config item defined in 'application' config section within the 'sso_group with id:'");
							sbError.append(sSSOGroupID);
							_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
							throw e;
						}

						Vector vGroups = null;
						if (!htReturn.containsKey(sAppId)) {
							vGroups = new Vector();
							vGroups.add(sSSOGroupID);
							htReturn.put(sAppId, vGroups);
						}
						else {
							vGroups = (Vector) htReturn.get(sAppId);
							if (vGroups.contains(sSSOGroupID)) {
								StringBuffer sbError = new StringBuffer("'sso_group' with id='");
								sbError.append(sSSOGroupID);
								sbError.append("' isn't unique");
								_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
								throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
							}
							vGroups.add(sSSOGroupID);
						}
						htReturn.put(sAppId, vGroups);

						oApplication = _oASelectConfigManager.getNextSection(oApplication);
					}
					oSSOGroup = _oASelectConfigManager.getNextSection(oSSOGroup);
				}
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not load the ss_groups config");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return htReturn;
	}

	// Private function which loads the public keys from the keystore
	/**
	 * Load public key from keystore.
	 * 
	 * @param sAlias
	 *            the s alias
	 * @return the public key
	 * @throws ASelectException
	 *             the a select exception
	 */
	private PublicKey loadPublicKeyFromKeystore(String sAlias)
	throws ASelectException
	{
		String sMethod = "loadPublicKeyFromKeystore()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Load public key=" + sAlias + ", from="
				+ _sApplicationsKeystoreName);
		try {
			sAlias = sAlias.toLowerCase();
			KeyStore ksJKS = KeyStore.getInstance("JKS");
			ksJKS.load(new FileInputStream(_sApplicationsKeystoreName), null);

			java.security.cert.X509Certificate x509Privileged = (java.security.cert.X509Certificate) ksJKS
					.getCertificate(sAlias);

			return x509Privileged.getPublicKey();
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not load public key of application '");
			sbError.append(sAlias).append("'");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
		}
		// no public key found for application.
		_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load application public key.");
		throw new ASelectException(Errors.ERROR_ASELECT_NOT_FOUND);
	}
	
	// RH, 20100909, sn
	/**
	 * Calculate whether signing is required based on top and sub level requirements.
	 * 
	 * @param toplevelSigning
	 *            the top level boolean variable
	 * @param sublevelSigning
	 *            the sub level String variable
	 * @return boolean result of the calculation
	 * Sub level overrules top level, top level rules when sub level == null
	 */
	boolean calculateRequireSigning(boolean toplevelSigning, String sublevelSigning)
	{
		boolean returnValue = false;
		if (toplevelSigning) {
			if ( sublevelSigning == null) {
				returnValue = true;
			} else {
				returnValue = new Boolean(sublevelSigning).booleanValue();
			}
		} else {
			if ( sublevelSigning == null) {
				returnValue = false;
			} else {
				returnValue = new Boolean(sublevelSigning).booleanValue();
			}
		}
		return returnValue;
	}
	// RH, 20100909, en	

	/**
	 * Returns the any special patching parameters for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured patching parameters for the application. <br>
	 * 
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return String containing the patching parameters. <code>null</code> if no patching parameters were found.
	 */
	public String getAddedPatching(String sAppId)
	{
		Application oApplication;
		try {
			oApplication = getApplication(sAppId);
		}
		catch (ASelectException e) {
			String sMethod = "getAddedPatching()";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No application configuration found for: " + sAppId);
			return null;
		}
		return oApplication.getAddedPatching();
	}
	
	/**
	 * Returns the application specific security level mappings. level -> urn (or any string for that matters) <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured security level mappings for the application. <br>
	 *
	 * @return the _htSecLevels
	 */
	public synchronized HashMap<String, String> getSecLevels(String sAppId)
	{
		Application oApplication;
		try {
			oApplication = getApplication(sAppId);
		}
		catch (ASelectException e) {
			String sMethod = "getSecLevels()";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No application configuration found for: " + sAppId);
			return null;
		}
		return oApplication.getSecLevels();
	}
	
	/**
	 * Returns the application specific Attributes to be added to a Saml token<br>
	 *
	 * @return the Attributes to be added
	 */
	public synchronized HashMap<String, String> getAdditionalAttributes(String sAppId)
	{
		String sMethod = "getAdditionalAttributes";
		Application oApplication;

		try {
			oApplication = getApplication(sAppId);
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No application configuration found for: " + sAppId);
			return null;
		}
		return oApplication.getAdditionalAttributes();
	}

	/**
	 * Returns the AuthnContextDeclValue for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured AuthnContextDeclValue  for the application. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return String containing the AuthnContextDeclValue. <code>null</code> if no AuthnContextDeclValue was found.
	 */
	public String getAuthnContextDeclValue(String sAppId)
	{
		Application oApplication;
		try {
			oApplication = getApplication(sAppId);
		}
		catch (ASelectException e) {
			String sMethod = "getAuthnContextDeclValue()";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No application configuration found for: " + sAppId);
			return null;
		}
		return oApplication.getAuthnContextDeclValue();
	}

	/**
	 * Returns the AuthnContextDeclType for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured AuthnContextDeclType ( either "AuthnContextDecl" or "AuthnContextDeclRef" ) for the application. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return String containing the AuthnContextDeclType. <code>null</code> if no AuthnContextDeclType was found.
	 */
	public String getAuthnContextDeclType(String sAppId)
	{
		Application oApplication;
		try {
			oApplication = getApplication(sAppId);
		}
		catch (ASelectException e) {
			String sMethod = "getAuthnContextDeclType()";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No application configuration found for: " + sAppId);
			return null;
		}
		return oApplication.getAuthnContextDeclType();
	}
	
	
	
	/**
	 * Returns the Application specific select form for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured selectform name for the application. <br>
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
	 * @param sAppId
	 *            <code>String</code> containing an application id.
	 * @return String containing the friendly name. <code>null</code> if no friendly name was found.
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String getSelectForm(String sAppId)
	throws ASelectException
	{
		Application oApplication = getApplication(sAppId);
		return oApplication.getSelectform();
	}

}