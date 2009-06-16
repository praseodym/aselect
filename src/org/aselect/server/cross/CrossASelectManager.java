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
 * $Id: CrossASelectManager.java,v 1.15 2006/04/26 12:17:17 tom Exp $ 
 * 
 * Changelog:
 * $Log: CrossASelectManager.java,v $
 * Revision 1.15  2006/04/26 12:17:17  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.14  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.11.4.5  2006/04/06 10:53:30  martijn
 * fixed bug in log message
 *
 * Revision 1.11.4.4  2006/03/20 11:08:13  martijn
 * added optional local_server config support
 *
 * Revision 1.11.4.3  2006/03/16 08:39:11  leon
 * fixed bug #140
 *
 * Revision 1.11.4.2  2006/03/13 12:13:27  martijn
 * config item 'sign_requests' in remote_servers has been made optional
 *
 * Revision 1.11.4.1  2006/02/28 08:44:56  jeroen
 * Bugfix for 117:
 *
 * CrossASelectManager -> loadLocalServerSigningKeys
 * Resolved by putting the server signing keys lowercase into the hashtable.
 *
 * _htLocalServerPublicKeys.put(sOrgID.toLowerCase(),
 *                     loadPublicKeyFromKeystore(sKeystoreName, sOrgID));
 *
 * and Bugfix for 139:
 *
 * CrossASelectManager -> init()
 * 'require_signing' made optional.
 *
 * Revision 1.11  2005/09/12 10:55:22  erwin
 * Improved logging getHandlerConfig()
 *
 * Revision 1.10  2005/09/08 12:46:34  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.9  2005/05/04 10:29:08  martijn
 * fixed wrong comparisson
 *
 * Revision 1.8  2005/05/04 09:58:40  martijn
 * fixed bugs
 *
 * Revision 1.7  2005/05/04 09:34:44  martijn
 * bugfixes, improved logging
 *
 * Revision 1.6  2005/04/15 14:01:49  peter
 * javadoc
 *
 * Revision 1.5  2005/04/11 12:48:35  erwin
 * Added forced_logon functionality for local A-Select Servers
 *
 * Revision 1.4  2005/04/11 08:56:17  erwin
 * - Removed A-Select Server ID from local server keystore alias.
 * - removed remote server signing support.
 *
 * Revision 1.3  2005/04/07 08:57:38  erwin
 * Added gather atributes support for remote A-Select servers.
 *
 * Revision 1.2  2005/04/07 06:37:12  erwin
 * Renamed "attribute" -> "param" to be compatible with configManager.
 *
 * Revision 1.1  2005/04/01 14:22:57  peter
 * cross aselect redesign
 *
 * Revision 1.1  2005/03/22 15:12:58  peter
 * Initial version
 *
 */

package org.aselect.server.cross;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

/**
 * This class loads all necessary configuration needed to set up a 'cross' A-Select environment. <br>
 * <br>
 * <b>Description:</b><br>
 * A singleton cross aselect manager, containing the cross aselect configuration.<br>
 * <br>
 * <b>remote_servers</b><br>
 * An A-Select Server might have configured <code>&lt;remote_servers/&gt;</code> to forward an authentication request
 * to an other A-Select Server.<br>
 * <br>
 * <b>cross_selector</b><br>
 * If there are more than one remote servers you might want to dynamically determine to which remote_server the request
 * should be forwarded. This can be realized by configuring a <code>&lt;cross_selector/&gt;</code>. This selector
 * should implement <code>ISelectorHandler</code>. Only one handler can be active and is initialized by this
 * CrossASelectManager.<br>
 * <br>
 * <b>local_servers</b><br>
 * An A-Select Server can also act as remote server for other A-Select Servers. In that case authentication requests are
 * forwarded to this A-Select Server by other A-Select Servers. These A-Select Servers should be configured as
 * <code>&lt;local_servers/&gt;</code>. If configured to require signing from local_servers, the public key of each
 * local_server is loaded at initialization. <br>
 * <br>
 * <b>Examples:</b><br>
 * An A-Select Server that has configured a trust relationship with other A-Select Servers, may grant access to an
 * application while the user is actually authenticated at an other A-Select Server.<br>
 * 
 * <pre>
 *  -------------    -----------------    -----------------    --------
 *  |           |    |               |    |               |    |      |
 *  |Application| -&gt; |     Local     | -&gt; |    Remote     | -&gt; |AuthSP|
 *  |           |    |A-Select Server|    |A-Select Server|    |      |
 *  -------------    -----------------    -----------------    --------
 * </pre>
 * 
 * In the figure above, a user is authenticated at the 'Remote A-Select Server' to get access to an application that was
 * secured with the 'Local A-Select Server'.<br>
 * The 'Local Server' in this scenario has configured <code>&lt;remote_servers/&gt;</code> and acts like an
 * application. This A-Select Server may not have a user database and no connection with AuthSP's.<br>
 * The 'Remote Server' in this scenario has configured <code>&lt;local_servers/&gt;</code> and is configured like a
 * 'normal' A-Select Server except that it may not have any applications configured.<br>
 * <br>
 * The 'Local Server' might have configured <code>&lt;cross_selector/&gt;</code> to dynamicaly select a 'Remote
 * Server' by using an <code>ISelectorHandler</code>. This is an optional configuration since the application is able
 * to request for a specific 'Remote Server' in it's authenticate request.<br>
 * <br>
 * <br>
 * An A-Select Server might have configured both <code>&lt;local_servers/&gt;</code> and
 * <code>&lt;remote_servers/&gt;</code>. This A-Select Server will act as 'Remote Server' for the configured
 * <code>&lt;local_servers/&gt;</code>. But it will also act as 'Local Server' for the configured
 * <code>&lt;remote_servers/&gt;</code>.
 * 
 * <pre>
 *  -------------    -----------------    ------------------    -----------------    --------
 *  |           |    |               |    |Remote and Local|    |               |    |      |
 *  |Application| -&gt; |     Local     | -&gt; |    (Proxy)     | -&gt; |    Remote     | -&gt; |AuthSP|
 *  |           |    |A-Select Server|    |A-Select Server |    |A-Select Server|    |      |
 *  -------------    -----------------    ------------------    -----------------    --------
 * </pre>
 * 
 * Such an A-Select Server is referred to as Proxy A-Select Server if it is used to parse request from 'Local Servers'
 * to 'Remote Servers'.<br>
 * <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * The class is a singleton, so the same class is used in all the classes of the A-Select Server. <br>
 * 
 * @author Alfa & Ariss
 */
public class CrossASelectManager
{
	// Name of this module, used for logging
	private static final String MODULE = "CrossASelectManager";

	private final static String TAG_FRIENLDY_NAME = "[requestor_friendly_name]";
	private final static String TAG_MAINTAINER_EMAIL = "[requestor_maintainer_email]";
	private final static String TAG_SHOW_URL = "[requestor_url]";

	// Needed to make this class a singleton.
	private static CrossASelectManager _oCrossASelectManager;

	// The A-Select config manager used for reading config parameters
	private ASelectConfigManager _oASelectConfigManager;

	// The logger that is used for system logging
	private ASelectSystemLogger _systemLogger;

	// Only one cross selector handler can be active
	private static ISelectorHandler _iSelectorHandler;

	// Config section containing all cross aselect configuration
	private Object _oCrossConfigSection;
	private Object _oHandlerConfigSection;
	private Object _oRemoteConfigSection;
	private Object _oLocalConfigSection;

	// At startup these booleans are set. It keeps track
	// of the configuration settings since these are optional
	// and not mandatory for A-Select to work.
	// Can I set up an authentication request with other A-Select Servers?
	private boolean _bRemoteServersEnabled = false;
	// Do I have configured a Remote Selector?
	private boolean _bCrossSelectorEnabled = false;
	// Are there any registered A-Select Servers that want to set up an authentication request with me?
	private boolean _bLocalServersEnabled = false;
	// Boolean indicating wether or not aselect server API calls must be signed (local servers)
	private boolean _bRequireLocalSigning;
	// Boolean indicating wether or not aselect server API calls should be signed (remote servers)
	private boolean _bUseRemoteSigning;

	// HashMap containing the public key (to check signatures) of each local aselect server
	private HashMap _htLocalServerPublicKeys = null;

	// HashMap containing the forced_authenticate value of each local aselect server
	private HashMap _htForcedOrganisations = null;

	// HashMap containing the friendly name of all Remote Server
	// indexed by the organization id
	// used by the ISelectorHandler
	private HashMap _htRemoteServers;

	// The A-Select Server organization id
	private String _sMyOrg;

	private HashMap _htLocalServerInfo;

	/**
	 * Must be private, so it can not be used. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Must be private because getHandle() must be used to retrieve an instance. This is done for singleton purposes.
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br> - <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 */
	private CrossASelectManager() {
	}

	/**
	 * Must be used to get an CrossASelectManager instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new <code>CrossASelectManager</code> instance if it's still <code>null</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * Always the same instance of the cross aselect manager is returned, because it's a singleton. <br>
	 * <br>
	 * <b>Preconditions:</b> <br> - <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @return A static handle to the <code>CrossASelectManager</code>.
	 */
	public static CrossASelectManager getHandle()
	{
		if (_oCrossASelectManager == null) {
			_oCrossASelectManager = new CrossASelectManager();
		}
		return _oCrossASelectManager;
	}

	/**
	 * Initialization of the CrossASelectManager singleton. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Must be successfully run once, before it can be used. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br> - Singleton <code>ASelectConfigManager</code> should be initialized.<BR> -
	 * cross_aselect configuaration is optional. <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @throws ASelectConfigException
	 */
	public void init()
		throws ASelectConfigException
	{
		String sMethod = "init()";
		_oASelectConfigManager = ASelectConfigManager.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
		_bRemoteServersEnabled = false;
		_bCrossSelectorEnabled = false;
		_bLocalServersEnabled = false;
		_htForcedOrganisations = new HashMap();
		_htLocalServerInfo = new HashMap();

		Object oASelect = null;
		try {
			oASelect = _oASelectConfigManager.getSection(null, "aselect");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'aselect' config section found", e);
			throw e;
		}

		try {
			_sMyOrg = _oASelectConfigManager.getParam(oASelect, "organization");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not retrieve 'organization' config parameter in aselect config section", e);
			throw e;
		}

		try {
			_oCrossConfigSection = _oASelectConfigManager.getSection(null, "cross_aselect");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "'cross_aselect' disabled.");
			return;
		}

		try {
			_bLocalServersEnabled = loadLocalServerSettings();
			if (_bLocalServersEnabled) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "This server can act as remote server.");
			}
		}
		catch (ASelectException ae) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to load local servers.", ae);
			throw new ASelectConfigException(ae.getMessage());
		}
		try {
			_bRemoteServersEnabled = loadRemoteServerSettings();
			if (_bRemoteServersEnabled) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "This server can act as local server.");
			}
		}
		catch (ASelectException ae) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to load remote servers.", ae);
			throw new ASelectConfigException(ae.getMessage());
		}
		try {
			if (_bRemoteServersEnabled) {
				_bCrossSelectorEnabled = loadRemoteSelectorSettings();
			}
			if (_bCrossSelectorEnabled) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "cross_selector enabled.");
			}
		}
		catch (ASelectException ae) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to load cross_selector.", ae);
			throw new ASelectConfigException(ae.getMessage());
		}
	}

	/**
	 * @return true if the request done by a local A-Select Server should be signed, otherwise false.
	 */
	public boolean isLocalSigningRequired()
	{
		return _bRequireLocalSigning;
	}

	/**
	 * @param sOrg
	 *            The organization id that will be checked for enabled forced authentication
	 * @return true if forced_authenticate="true", otherwise false.
	 */
	public boolean isForcedAuthenticateEnabled(String sOrg)
	{
		String sMethod = "isForcedAuthenticateEnabled()";
		boolean bForced = false;
		try {
			Boolean boolForced = (Boolean) _htForcedOrganisations.get(sOrg.toLowerCase());
			bForced = boolForced.booleanValue();
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Organization id not found:");
			sbError.append(sOrg);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
		}
		return bForced;
	}

	/**
	 * @return true if the request done by a local A-Select Server to a remote A-Select Server should be signed,
	 *         otherwise false.
	 */
	public boolean useRemoteSigning()
	{
		return _bUseRemoteSigning;
	}

	/**
	 * @return true if there are configured remote servers, otherwise false.
	 */
	public boolean remoteServersEnabled()
	{
		return _bRemoteServersEnabled;
	}

	/**
	 * @return true if the dynamic remote server selection is configured, otherwise false.
	 */
	public boolean isCrossSelectorEnabled()
	{
		return _bCrossSelectorEnabled;
	}

	/**
	 * @return true if there are configured local servers, otherwise false.
	 */
	public boolean localServersEnabled()
	{
		return _bLocalServersEnabled;
	}

	/**
	 * Gives a handle to the <code>ISelectorHandler</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Only one <code>ISelectorHandler</code> can be active within A-Select. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br> - <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @return <code>ISelectorHandler</code>
	 */
	public ISelectorHandler getSelectorHandler()
	{
		return _iSelectorHandler;
	}

	/**
	 * Returns the requested parameter for an organisation. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured value of the parameter asked for. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br> - <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param sOrgId
	 *            <code>String</code> containing an organisation id.
	 * @param sName
	 *            <code>String</code> containing the parameter id asked for.
	 * @return String containing the parameter value asked for, or <code>null</code> if the attribute was not found.
	 */
	public String getRemoteParam(String sOrgId, String sName)
	{
		String sReturn = null;
		String sMethod = "getRemoteParam()";
		Object oRemoteOrg = null;

		try {
			try {
				oRemoteOrg = _oASelectConfigManager.getSection(_oRemoteConfigSection, "organization", "id=" + sOrgId);
			}
			catch (ASelectConfigException eAC) {
				StringBuffer sbMessage = new StringBuffer("No valid 'organization' section found for '");
				sbMessage.append(sOrgId).append("' in 'remote_servers' config.");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbMessage.toString(), eAC);
				return null;
			}
			try {
				sReturn = _oASelectConfigManager.getParam(oRemoteOrg, sName);
			}
			catch (ASelectConfigException eAC) {
				StringBuffer sbMessage = new StringBuffer("No valid '");
				sbMessage.append(sName).append("' found for '");
				sbMessage.append(sOrgId).append("' in 'organization' section");
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
	 * Returns the requested parameter for an organization. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured value of the attribute asked for. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br> - <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param sOrgId
	 *            <code>String</code> containing an local organization id.
	 * @param sName
	 *            <code>String</code> containing the parameter id asked for.
	 * @return String containing the attribute value asked for, or <code>null</code> if the attribute was not found.
	 */
	public String getLocalParam(String sOrgId, String sName)
	{
		String sReturn = null;
		String sMethod = "getLocalParam()";
		Object oLocalOrg = null;

		try {
			try {
				oLocalOrg = _oASelectConfigManager.getSection(_oLocalConfigSection, "organization", "id=" + sOrgId);
			}
			catch (ASelectConfigException eAC) {
				StringBuffer sbMessage = new StringBuffer("No valid 'organization' section found for '");
				sbMessage.append(sOrgId).append("' in 'local_servers' config");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbMessage.toString(), eAC);
				return null;
			}
			try {
				sReturn = _oASelectConfigManager.getParam(oLocalOrg, sName);
			}
			catch (ASelectConfigException eAC) {
				StringBuffer sbMessage = new StringBuffer("No valid '");
				sbMessage.append(sName).append("' found for '");
				sbMessage.append(sOrgId).append("' in 'organization' section");
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
	 * Returns the requested optional paramater for an local organisation. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the configured value of the parameter asked for, or <code>null</code> if the parameter is not present.
	 * Unlike the {@link #getLocalParam(String, String)} method, this method does not complain about missing attributes
	 * in the system log. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br> - <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param sOrgId
	 *            <code>String</code> containing an local organization id.
	 * @param sName
	 *            <code>String</code> containing the parameter name asked for.
	 * @return String containing the paramater value asked for, or <code>null</code> if the attribute was not found.
	 * @throws ASelectException
	 *             If the entire section was not found, or a internal error occurred.
	 */
	public String getOptionalLocalParam(String sOrgId, String sName)
		throws ASelectException
	{
		String sReturn = null;
		String sMethod = "getOptionalLocalParam()";
		Object oLocalOrg = null;

		try {
			oLocalOrg = _oASelectConfigManager.getSection(_oLocalConfigSection, "organization", "id=" + sOrgId);
		}
		catch (ASelectConfigException eAC) {
			StringBuffer sbMessage = new StringBuffer("No valid 'organisation' section found for '");
			sbMessage.append(sOrgId).append("' in A-Select config");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbMessage.toString(), eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
		}

		try {
			sReturn = _oASelectConfigManager.getParam(oLocalOrg, sName);
			sReturn = sReturn.trim();
		}
		catch (ASelectConfigException eAC) {
			// sReturn is allready null
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return sReturn;
	}

	/**
	 * Get the public key of one of the A-Select Servers that are configured as Cross A-Select local servers. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Will search for the public key of one of the A-Select Servers that are configured as Cross A-Select local
	 * servers. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sLocalOrg != null</code>. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * If the key has not been found <code>null</code> will be returned. <br>
	 * 
	 * @param sLocalOrg
	 *            The local organization of the cross A-Select Server.
	 * @return The <code>PublicKey</code> of the requested Cross A-Select Server.
	 */
	public PublicKey getLocalASelectServerPublicKey(String sLocalOrg)
	{
		// All keys are stored in lowercase, so the key must be Lower Case
		return (PublicKey) _htLocalServerPublicKeys.get(sLocalOrg.toLowerCase());
	}

	/**
	 * A Simple function to retrieve a value of a <code>ISelectorHandler</code> configuration parameter. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the value of a configuration parameter in the main configuration file of A-Select. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * Manager should be initialized. <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param sKey
	 *            String containing the identifier of the configuration.
	 * @return String containing the value of the config parameter or an empty string if no configuration was found.
	 */
	public String getHandlerConfig(String sKey)
	{
		String sMethod = "getHandlerConfig()";
		String sValue;
		try {
			sValue = _oASelectConfigManager.getParam(_oHandlerConfigSection, sKey);
		}
		catch (ASelectConfigException ace) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "No handler configuration found", ace);
			sValue = "";
		}
		return sValue;
	}

	/**
	 * Retrieve Remote Server configuration. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Function that will return a <code>HashMap</code> containing all 'friendly_name' values for the configured
	 * remote A-Select Servers. The <code>HashMap</code> is indexed by the 'organization' value of the remote A-Select
	 * Servers.<br>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * Manager should be initialized. <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @return HashMap containing all 'friendly_name' values for the configured remote A-Select Servers. The
	 *         <code>HashMap</code> is indexed by the 'organization' value of the remote A-Select Servers.<br>
	 */
	public HashMap getRemoteServers()
	{
		return _htRemoteServers;
	}

	/**
	 * Returns configuration used as optional template tags. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns a <code>HashMap</code> containing information that must be showed in templates.<br/> The information
	 * is configured per <br/> 'local_server'. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br> - <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param sLocalOrganization
	 *            organization ID configured in the local_server config section
	 * @return HashMap Containing optional local_server configuration
	 */
	public HashMap getLocalServerInfo(String sLocalOrganization)
	{
		HashMap htReturn = new HashMap();
		if (_htLocalServerInfo != null && sLocalOrganization != null)
			htReturn = (HashMap) _htLocalServerInfo.get(sLocalOrganization);

		return htReturn;
	}

	private boolean loadLocalServerSettings()
		throws ASelectException
	{
		String sMethod = "loadLocalServerSettings()";
		Object oLocalServer = null;
		try {
			_oLocalConfigSection = _oASelectConfigManager.getSection(_oCrossConfigSection, "local_servers");
		}
		catch (ASelectConfigException ace) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
							"No 'local_servers' section found. This A-Select Server can not act as remote server (cross).", ace);
			return false;
		}

		try {
			// for testing purposes: check if at least one organisation is
			// defined
			oLocalServer = _oASelectConfigManager.getSection(_oLocalConfigSection, "organization");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid 'organization' section found in 'local_servers' section", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

		try {
			String sRequireSigning = _oASelectConfigManager.getParam(_oLocalConfigSection, "require_signing");
			_bRequireLocalSigning = new Boolean(sRequireSigning).booleanValue();
		}
		catch (ASelectConfigException eAC) {
			_bRequireLocalSigning = false;
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
					"No valid 'require_signing' parameter found in section 'local_servers',"
							+ " Using default value 'false'", eAC);
		}
		if (_bRequireLocalSigning) {
			loadLocalServerSigningKeys(_oASelectConfigManager.getWorkingdir());
		}

		while (oLocalServer != null) {
			String sOrg = null;
			Boolean boolForced = new Boolean(false);
			try {
				sOrg = _oASelectConfigManager.getParam(oLocalServer, "id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'id' parameter found in section 'organisation'", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				String sForced = _oASelectConfigManager.getParam(oLocalServer, "forced_authenticate");
				boolForced = new Boolean(sForced);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid 'forced_authenticate' parameter found in section 'local_servers',"
								+ " setting forced_authenticate to FALSE", e);
			}

			if (sOrg.equalsIgnoreCase(_sMyOrg)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Organization conflict: The configured local organization is equal to the current A-Select Server organization.");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			_htForcedOrganisations.put(sOrg.toLowerCase(), boolForced);

			HashMap htServerInfo = new HashMap();

			String sMaintainerEmail = null;
			try {
				sMaintainerEmail = _oASelectConfigManager.getParam(oLocalServer, "maintainer_email");
				htServerInfo.put(TAG_MAINTAINER_EMAIL, sMaintainerEmail);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No optional 'maintainer_email' config item found in 'organization' config section", e);
			}

			String sFriendlyName = null;
			try {
				sFriendlyName = _oASelectConfigManager.getParam(oLocalServer, "friendly_name");
				htServerInfo.put(TAG_FRIENLDY_NAME, sFriendlyName);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No optional 'friendly_name' config item found in 'organization' config section", e);
			}

			String sShowUrl = null;
			try {
				sShowUrl = _oASelectConfigManager.getParam(oLocalServer, "show_url");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No optional 'show_url' config item found in 'organization' config section", e);
			}

			Boolean boolShowUrl = null;
			if (sShowUrl == null)
				boolShowUrl = new Boolean(true);
			else
				boolShowUrl = new Boolean(sShowUrl);

			htServerInfo.put(TAG_SHOW_URL, boolShowUrl);

			_htLocalServerInfo.put(sOrg.toLowerCase(), htServerInfo);

			oLocalServer = _oASelectConfigManager.getNextSection(oLocalServer);
		}

		return true;
	}

	private boolean loadRemoteServerSettings()
		throws ASelectException
	{
		String sMethod = "loadRemoteServerSettings()";
		_htRemoteServers = new HashMap();
		try {
			_oRemoteConfigSection = _oASelectConfigManager.getSection(_oCrossConfigSection, "remote_servers");
		}
		catch (ASelectConfigException ace) {
			_systemLogger
					.log(
							Level.CONFIG,
							MODULE,
							sMethod,
							"No 'remote_servers' section found. This A-Select Server can not act as local server (cross).",
							ace);
			return false;
		}
		try {
			String sUseSigning = _oASelectConfigManager.getParam(_oRemoteConfigSection, "sign_requests");
			_bUseRemoteSigning = new Boolean(sUseSigning).booleanValue();
		}
		catch (ASelectConfigException eAC) {
			_bRequireLocalSigning = false;
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
					"No valid 'sign_requests' parameter found in section 'local_servers', Using default value 'false'",
					eAC);
		}

		Object oRemoteOrg = null;
		try {
			oRemoteOrg = _oASelectConfigManager.getSection(_oRemoteConfigSection, "organization");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Not even one 'organization' config section found in 'remote_servers' section", e);
		}

		while (oRemoteOrg != null) {

			String sRemoteOrganization = null;
			try {
				sRemoteOrganization = _oASelectConfigManager.getParam(oRemoteOrg, "id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'id' config item found in 'organization' config section", e);
				throw e;
			}

			String sRemoteName = null;
			try {
				sRemoteName = _oASelectConfigManager.getParam(oRemoteOrg, "friendly_name");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'friendly_name' config item found in 'organization' config section", e);
				throw e;
			}

			if (sRemoteOrganization.equalsIgnoreCase(_sMyOrg)) {
				_systemLogger
						.log(Level.WARNING, MODULE, sMethod,
								"Organization conflict: The configured remote organization is equal to the current A-Select Server organization.");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
			_htRemoteServers.put(sRemoteOrganization, sRemoteName);

			oRemoteOrg = _oASelectConfigManager.getNextSection(oRemoteOrg);
		}

		return true;
	}

	private boolean loadRemoteSelectorSettings()
		throws ASelectException
	{
		String sMethod = "loadRemoteSelectorSettings()";
		Object ocross_selector_ConfigSection;
		try {
			ocross_selector_ConfigSection = _oASelectConfigManager.getSection(_oCrossConfigSection, "cross_selector");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "'cross_selector' disabled", e);
			return false;
		}
		try {
			String sHandlerName = _oASelectConfigManager.getParam(ocross_selector_ConfigSection, "handler");
			_oHandlerConfigSection = _oASelectConfigManager.getSection(ocross_selector_ConfigSection, "handler", "id="
					+ sHandlerName);

			_iSelectorHandler = null;
			Class oClass = Class.forName(getHandlerConfig("class"));
			_iSelectorHandler = (ISelectorHandler) oClass.newInstance();
			_iSelectorHandler.init(_oHandlerConfigSection);
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to initialize cross_selector: ", e);
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to initialize cross_selector: ", e);
			throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}
		return true;
	}

	/**
	 * Loads the siging keys of the local servers, if they require signing. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Loads the public signing key for every local server in the keystore:<br>
	 * .\keystores\cross\local_servers.keystore <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b> <br> - <i>sWorkingDir</i> may not be <code>null</code>. <br>
	 * <br>
	 * <b>Postconditions:</b> <br> - <br>
	 * 
	 * @param sWorkingDir
	 *            contains the A-Select Server working dir specified in the web.xml.
	 * @throws ASelectException
	 *             If loading fails.
	 */
	private void loadLocalServerSigningKeys(String sWorkingDir)
		throws ASelectException
	{
		String sMethod = "loadLocalServerSigningKeys()";

		try {
			// Build local_servers.keystore path
			String sKeystoreName = new StringBuffer(sWorkingDir).append(File.separator).append("keystores").append(
					File.separator).append("cross").append(File.separator).append("local_servers.keystore").toString();

			// Initialize local servers signing-key table
			_htLocalServerPublicKeys = new HashMap();

			// Enumerate applications and load their public key
			Object oLocalServer = null;
			try {
				oLocalServer = _oASelectConfigManager.getSection(_oLocalConfigSection, "organization");
			}
			catch (ASelectConfigException e) {
			}
			while (oLocalServer != null) {
				String sOrgID = _oASelectConfigManager.getParam(oLocalServer, "id");
				_htLocalServerPublicKeys.put(sOrgID.toLowerCase(), loadPublicKeyFromKeystore(sKeystoreName, sOrgID));
				oLocalServer = _oASelectConfigManager.getNextSection(oLocalServer);
			}
		}
		catch (ASelectConfigException ace) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to load configuration of local servers.", ace);
			throw ace;
		}
		catch (ASelectException ae) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to load public keys of local servers.", ae);
			throw ae;
		}
	}

	// Load a public key from a keystore
	private PublicKey loadPublicKeyFromKeystore(String sKeystorePath, String sAlias)
		throws ASelectException
	{
		String sMethod = "loadPublicKeyFromKeystore()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Loading public key " + sAlias + " from " + sKeystorePath);
		try {
			sAlias = sAlias.toLowerCase();
			KeyStore ksJKS = KeyStore.getInstance("JKS");
			ksJKS.load(new FileInputStream(sKeystorePath), null);

			java.security.cert.X509Certificate x509Privileged = (java.security.cert.X509Certificate) ksJKS
					.getCertificate(sAlias);

			return x509Privileged.getPublicKey();
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("could not load '");
			sbError.append(sAlias);
			sbError.append("' from '");
			sbError.append(sKeystorePath);
			sbError.append("'.");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_NOT_FOUND);
		}
	}
}