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
 * $Id: Application.java,v 1.3 2006/04/26 12:15:44 tom Exp $ 
 * 
 * Changelog:
 * $Log: Application.java,v $
 * Revision 1.3  2006/04/26 12:15:44  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.2  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.1.2.5  2006/04/07 09:52:05  leon
 * java doc
 *
 * Revision 1.1.2.4  2006/04/07 09:10:45  leon
 * java doc
 *
 * Revision 1.1.2.3  2006/03/17 07:34:44  martijn
 * config item show_app_url changed to show_url
 *
 * Revision 1.1.2.2  2006/03/16 09:22:27  leon
 * added extra get/set functions for
 * - Maintainer email
 * - Friendly name
 * - Show app url
 * - Use opaque uid
 *
 * Revision 1.1.2.1  2006/03/16 07:38:40  leon
 * new application class which is used to store all the features of the configured applications
 *
 */

package org.aselect.server.application;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Vector;

/**
 * The Application (Bean) class <br>
 * <br>
 * <b>Description:</b><br>
 * Contains all the required features of an Application needed in A-Select. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class Application
{
	private String _sId;
	private String _sAttributePolicy;
	private String _sFriendlyName;
	private String _sMaintainerEmail;
	private boolean _bShowUrl;
	private boolean _bUseOpaqueUId;
	private Integer _iMinLevel;
	private Integer _iMaxLevel;
	private boolean _bSigningRequired;
	private boolean _bForcedAuthenticate;
	private boolean _bDirectAuthSPPrefered;
	private PublicKey _oSigningKey;
	private Vector _vSSOGroups;

	private String _shared_secret;
	private String _forced_uid;
	private String _forced_authsp;
	private String _level_name;
	private boolean _doUrlEncode;
	private String _useSsn;
	
	private String _added_patching;	// RH, 20101207, n
	
	// Security level mappings for this application
	private HashMap<String, String> _htSecLevels = null;	// RH, 20101214, n

	// Fixed attributes for a SAML token
	private HashMap<String, String> _htAdditionalAttributes = null;	// Bauke, 20101229, n

	private String _AuthnContextDeclValue;	// RH, 20101217, n
	private String _AuthnContextDeclType;	// RH, 20101217, n

	private String _first_authsp = null;	// RH, 20110920, n


	/**
	 * Constructor which contains the default parameters for an Application <br>
	 * <br>
	 * .
	 * 
	 * @param id
	 *            Application Id
	 * @param minLevel
	 *            Minimum required level
	 * @param maxLevel
	 *            Maximum allowed level
	 * @param signingRequired
	 *            Is signing required or not, default is false
	 * @param forcedAuthenticate
	 *            Is forced authenticate required or not.
	 * @param attributePolicy
	 *            The attribute policy
	 * @param signingKey
	 *            The signing key if signing is required.
	 */
	public Application(String id, Integer minLevel, Integer maxLevel, boolean signingRequired,
			boolean forcedAuthenticate, String attributePolicy, PublicKey signingKey) {
		_sId = id;
		_iMinLevel = minLevel;
		_iMaxLevel = maxLevel;
		_bSigningRequired = signingRequired;
		_bForcedAuthenticate = forcedAuthenticate;
		_sAttributePolicy = attributePolicy;
		_oSigningKey = signingKey;
		_vSSOGroups = new Vector();
	}

	/**
	 * Default constructor.
	 */
	public Application() {
		_sId = null;
		_sAttributePolicy = null;
		_iMinLevel = null;
		_iMaxLevel = null;
		_bSigningRequired = false;
		_bForcedAuthenticate = false;
		_oSigningKey = null;
		_bUseOpaqueUId = false;
		_bShowUrl = false;
		_sFriendlyName = null;
		_sMaintainerEmail = null;
		_vSSOGroups = new Vector();
	}

	/**
	 * Gets the max level.
	 * 
	 * @return Returns the _iMaxLevel.
	 */
	public Integer getMaxLevel()
	{
		return _iMaxLevel;
	}

	/**
	 * Sets the max level.
	 * 
	 * @param maxLevel
	 *            The _iMaxLevel to set.
	 */
	public void setMaxLevel(Integer maxLevel)
	{
		_iMaxLevel = maxLevel;
	}

	/**
	 * Gets the min level.
	 * 
	 * @return Returns the _iMinLevel.
	 */
	public Integer getMinLevel()
	{
		return _iMinLevel;
	}

	/**
	 * Sets the min level.
	 * 
	 * @param minLevel
	 *            The _iMinLevel to set.
	 */
	public void setMinLevel(Integer minLevel)
	{
		_iMinLevel = minLevel;
	}

	/**
	 * Gets the id.
	 * 
	 * @return Returns the _sId.
	 */
	public String getId()
	{
		return _sId;
	}

	/**
	 * Sets the id.
	 * 
	 * @param id
	 *            The _sId to set.
	 */
	public void setId(String id)
	{
		_sId = id;
	}

	/**
	 * Gets the signing key.
	 * 
	 * @return Returns the _sSigningKey.
	 */
	public PublicKey getSigningKey()
	{
		return _oSigningKey;
	}

	/**
	 * Sets the signing key.
	 * 
	 * @param signingKey
	 *            The _sSigningKey to set.
	 */
	public void setSigningKey(PublicKey signingKey)
	{
		_oSigningKey = signingKey;
	}

	/**
	 * Gets the sso groups.
	 * 
	 * @return Returns the _vSSOGroups.
	 */
	public Vector getSSOGroups()
	{
		return _vSSOGroups;
	}

	/**
	 * Sets the sso groups.
	 * 
	 * @param groups
	 *            The _vSSOGroups to set.
	 */
	public void setSSOGroups(Vector groups)
	{
		_vSSOGroups = groups;
	}

	/**
	 * Checks if is forced authenticate.
	 * 
	 * @return Returns the _bForcedAuthenticate.
	 */
	public boolean isForcedAuthenticate()
	{
		return _bForcedAuthenticate;
	}

	/**
	 * Sets the forced authenticate.
	 * 
	 * @param forcedAuthenticate
	 *            The _bForcedAuthenticate to set.
	 */
	public void setForcedAuthenticate(boolean forcedAuthenticate)
	{
		_bForcedAuthenticate = forcedAuthenticate;
	}

	/**
	 * Checks if is signing required.
	 * 
	 * @return Returns the _bSigningRequired.
	 */
	public boolean isSigningRequired()
	{
		return _bSigningRequired;
	}

	/**
	 * Sets the signing required.
	 * 
	 * @param signingRequired
	 *            The _bSigningRequired to set.
	 */
	public void setSigningRequired(boolean signingRequired)
	{
		_bSigningRequired = signingRequired;
	}

	/**
	 * Gets the attribute policy.
	 * 
	 * @return Returns the _sAttributePolicy.
	 */
	public String getAttributePolicy()
	{
		return _sAttributePolicy;
	}

	/**
	 * Sets the attribute policy.
	 * 
	 * @param attributePolicy
	 *            The _sAttributePolicy to set.
	 */
	public void setAttributePolicy(String attributePolicy)
	{
		_sAttributePolicy = attributePolicy;
	}

	/**
	 * Checks if is direct auth sp prefered.
	 * 
	 * @return Returns the _bDirectAuthSPPrefered.
	 */
	public boolean isDirectAuthSPPrefered()
	{
		return _bDirectAuthSPPrefered;
	}

	/**
	 * Sets the direct auth sp prefered.
	 * 
	 * @param directAuthSPPrefered
	 *            The _bDirectAuthSPPrefered to set.
	 */
	public void setDirectAuthSPPrefered(boolean directAuthSPPrefered)
	{
		_bDirectAuthSPPrefered = directAuthSPPrefered;
	}

	/**
	 * Checks if is show url.
	 * 
	 * @return Returns the _bShowUrl.
	 */
	public boolean isShowUrl()
	{
		return _bShowUrl;
	}

	/**
	 * Sets the show url.
	 * 
	 * @param showUrl
	 *            The _bShowUrl to set.
	 */
	public void setShowUrl(boolean showUrl)
	{
		_bShowUrl = showUrl;
	}

	/**
	 * Checks if is use opaque u id.
	 * 
	 * @return Returns the _bUseOpaqueUId.
	 */
	public boolean isUseOpaqueUId()
	{
		return _bUseOpaqueUId;
	}

	/**
	 * Sets the use opaque u id.
	 * 
	 * @param useOpaqueUId
	 *            The _bUseOpaqueUId to set.
	 */
	public void setUseOpaqueUId(boolean useOpaqueUId)
	{
		_bUseOpaqueUId = useOpaqueUId;
	}

	/**
	 * Gets the friendly name.
	 * 
	 * @return Returns the _sFriendlyName.
	 */
	public String getFriendlyName()
	{
		return _sFriendlyName;
	}

	/**
	 * Sets the friendly name.
	 * 
	 * @param friendlyName
	 *            The _sFriendlyName to set.
	 */
	public void setFriendlyName(String friendlyName)
	{
		_sFriendlyName = friendlyName;
	}

	/**
	 * Gets the maintainer email.
	 * 
	 * @return Returns the _sMaintainerEmail.
	 */
	public String getMaintainerEmail()
	{
		return _sMaintainerEmail;
	}

	/**
	 * Sets the maintainer email.
	 * 
	 * @param maintainerEmail
	 *            The _sMaintainerEmail to set.
	 */
	public void setMaintainerEmail(String maintainerEmail)
	{
		_sMaintainerEmail = maintainerEmail;
	}

	/**
	 * Gets the forced authsp.
	 * 
	 * @return the forced authsp
	 */
	public String getForcedAuthsp()
	{
		return _forced_authsp;
	}

	/**
	 * Sets the forced authsp.
	 * 
	 * @param _forced_authsp
	 *            the new forced authsp
	 */
	public void setForcedAuthsp(String _forced_authsp)
	{
		this._forced_authsp = _forced_authsp;
	}

	/**
	 * Gets the forced uid.
	 * 
	 * @return the forced uid
	 */
	public String getForcedUid()
	{
		return _forced_uid;
	}

	/**
	 * Sets the forced uid.
	 * 
	 * @param _forced_uid
	 *            the new forced uid
	 */
	public void setForcedUid(String _forced_uid)
	{
		this._forced_uid = _forced_uid;
	}

	/**
	 * Gets the level name.
	 * 
	 * @return the level name
	 */
	public String getLevelName()
	{
		return _level_name;
	}

	/**
	 * Sets the level name.
	 * 
	 * @param _level_name
	 *            the new level name
	 */
	public void setLevelName(String _level_name)
	{
		this._level_name = _level_name;
	}

	/**
	 * Gets the shared secret.
	 * 
	 * @return the shared secret
	 */
	public String getSharedSecret()
	{
		return _shared_secret;
	}

	/**
	 * Sets the shared secret.
	 * 
	 * @param _shared_secret
	 *            the new shared secret
	 */
	public void setSharedSecret(String _shared_secret)
	{
		this._shared_secret = _shared_secret;
	}

	/**
	 * Checks if is do url encode.
	 * 
	 * @return true, if is do url encode
	 */
	public boolean isDoUrlEncode()
	{
		return _doUrlEncode;
	}

	/**
	 * Sets the do url encode.
	 * 
	 * @param urlEncode
	 *            the new do url encode
	 */
	public void setDoUrlEncode(boolean urlEncode)
	{
		_doUrlEncode = urlEncode;
	}
	
	public void setUseSsn(String sUseSsn)
	{
		_useSsn = sUseSsn;
	}
	
	public String getUseSsn()
	{
		return _useSsn;
	}

	/**
	 * Gets the added patching parameter. (can be delimited list of parameters)
	 * 
	 * @return the patching parameter
	 */

	public String getAddedPatching()
	{
		return _added_patching;
	}

	/**
	 * Sets the  patching parameter. (can be delimited list of parameters)
	 * 
	 * @param addedPatching
	 *            the new patching parameter
	 */

	public void setAddedPatching(String addedPatching)
	{
		_added_patching = addedPatching;
	}

	/**
	 * @return the _htSecLevels
	 */
	public synchronized HashMap<String, String> getSecLevels()
	{
		return _htSecLevels;
	}

	/**
	 * @param htSecLevels the _htSecLevels to set
	 */
	public synchronized void setSecLevels(HashMap<String, String> htSecLevels)
	{
		_htSecLevels = htSecLevels;
	}

	/**
	 * @return _htAdditionalAttributes
	 */
	public synchronized HashMap<String, String> getAdditionalAttributes()
	{
		return _htAdditionalAttributes;
	}

	/**
	 * @param set _htAdditionalAttributes
	 */
	public synchronized void setAdditionalAttributes(HashMap<String, String> htAdditionalAttributes)
	{
		_htAdditionalAttributes = htAdditionalAttributes;
	}

	/**
	 * @return the _AuthnContextDeclValue
	 */
	public synchronized String getAuthnContextDeclValue()
	{
		return _AuthnContextDeclValue;
	}

	/**
	 * @param authnContextDeclValue the _AuthnContextDeclValue to set
	 */
	public synchronized void setAuthnContextDeclValue(String authnContextDeclValue)
	{
		_AuthnContextDeclValue = authnContextDeclValue;
	}

	/**
	 * @return the _AuthnContextDeclType
	 */
	public synchronized String getAuthnContextDeclType()
	{
		return _AuthnContextDeclType;
	}

	/**
	 * @param authnContextDeclType the _AuthnContextDeclType to set
	 */
	public synchronized void setAuthnContextDeclType(String authnContextDeclType)
	{
		_AuthnContextDeclType = authnContextDeclType;
	}

	/**
	 * @return the _first_autsp
	 */
	public synchronized String getFirstAuthsp()
	{
		return _first_authsp;
	}

	/**
	 * @param firstAuthsp the _first_autsp to set
	 */
	public synchronized void setFirstAuthsp(String firstAuthsp)
	{
		_first_authsp = firstAuthsp;
	}
}
