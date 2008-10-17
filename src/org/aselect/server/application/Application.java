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
import java.util.Vector;

/**
 * The Application (Bean) class
 * <br><br>
 * <b>Description:</b><br>
 * Contains all the required features of an Application needed in A-Select.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class Application
{
    private String _sId;
    private String _sAttributePolicy;
    private String _sFriendlyName;
    private String _sMaintainerEmail;
    private boolean	_bShowUrl;
    private boolean	_bUseOpaqueUId;
    private Integer _iMinLevel;
    private Integer _iMaxLevel;
    private boolean _bSigningRequired;
    private boolean _bForcedAuthenticate;
    private boolean _bDirectAuthSPPrefered;
    private PublicKey _oSigningKey;
    private Vector _vSSOGroups;
   
    /**
     * Contructor which contains the default parameters for an Application
     * <br><br>
     * @param id Application Id
     * @param minLevel Minimum required level
     * @param maxLevel Maximum allowed level
     * @param signingRequired Is signing required or not, default is false
     * @param forcedAuthenticate  Is forced authenticate required or not.      
     * @param attributePolicy The attribute policy 
     * @param signingKey The signing key if signing is required.
     */
    public Application (String id, Integer minLevel, Integer maxLevel,
        boolean signingRequired, boolean forcedAuthenticate, String attributePolicy, PublicKey signingKey)
    {
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
     * Default contructor.
     */
    public Application ()
    {
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
     * @return Returns the _iMaxLevel.
     */
    public Integer getMaxLevel()
    {
        return _iMaxLevel;
    }
    
    /**
     * @param maxLevel The _iMaxLevel to set.
     */
    public void setMaxLevel(Integer maxLevel)
    {
        _iMaxLevel = maxLevel;
    }
    
    /**
     * @return Returns the _iMinLevel.
     */
    public Integer getMinLevel()
    {
        return _iMinLevel;
    }
    /**
     * @param minLevel The _iMinLevel to set.
     */
    public void setMinLevel(Integer minLevel)
    {
        _iMinLevel = minLevel;
    }
    
    /**
     * @return Returns the _sId.
     */
    public String getId()
    {
        return _sId;
    }
    
    /**
     * @param id The _sId to set.
     */
    public void setId(String id)
    {
        _sId = id;
    }
    /**
     * @return Returns the _sSigningKey.
     */
    public PublicKey getSigningKey()
    {
        return _oSigningKey;
    }
    
    /**
     * @param signingKey The _sSigningKey to set.
     */
    public void setSigningKey(PublicKey signingKey)
    {
        _oSigningKey = signingKey;
    }
    
    /**
     * @return Returns the _vSSOGroups.
     */
    public Vector getSSOGroups()
    {
        return _vSSOGroups;
    }
    
    /**
     * @param groups The _vSSOGroups to set.
     */
    public void setSSOGroups(Vector groups)
    {
        _vSSOGroups = groups;
    }
    /**
     * @return Returns the _bForcedAuthenticate.
     */
    public boolean isForcedAuthenticate()
    {
        return _bForcedAuthenticate;
    }
    
    /**
     * @param forcedAuthenticate The _bForcedAuthenticate to set.
     */
    public void setForcedAuthenticate(boolean forcedAuthenticate)
    {
        _bForcedAuthenticate = forcedAuthenticate;
    }
    
    /**
     * @return Returns the _bSigningRequired.
     */
    public boolean isSigningRequired()
    {
        return _bSigningRequired;
    }
    /**
     * @param signingRequired The _bSigningRequired to set.
     */
    public void setSigningRequired(boolean signingRequired)
    {
        _bSigningRequired = signingRequired;
    }
    
    /**
     * @return Returns the _sAttributePolicy.
     */
    public String getAttributePolicy()
    {
        return _sAttributePolicy;
    }
    /**
     * @param attributePolicy The _sAttributePolicy to set.
     */
    public void setAttributePolicy(String attributePolicy)
    {
        _sAttributePolicy = attributePolicy;
    }
    /**
     * @return Returns the _bDirectAuthSPPrefered.
     */
    public boolean isDirectAuthSPPrefered()
    {
        return _bDirectAuthSPPrefered;
    }
    /**
     * @param directAuthSPPrefered The _bDirectAuthSPPrefered to set.
     */
    public void setDirectAuthSPPrefered(boolean directAuthSPPrefered)
    {
        _bDirectAuthSPPrefered = directAuthSPPrefered;
    }
    /**
     * @return Returns the _bShowUrl.
     */
    public boolean isShowUrl()
    {
        return _bShowUrl;
    }
    /**
     * @param showUrl The _bShowUrl to set.
     */
    public void setShowUrl(boolean showUrl)
    {
        _bShowUrl = showUrl;
    }
    
    /**
     * @return Returns the _bUseOpaqueUId.
     */
    public boolean isUseOpaqueUId()
    {
        return _bUseOpaqueUId;
    }
    
    /**
     * @param useOpaqueUId The _bUseOpaqueUId to set.
     */
    public void setUseOpaqueUId(boolean useOpaqueUId)
    {
        _bUseOpaqueUId = useOpaqueUId;
    }
    
    /**
     * @return Returns the _sFriendlyName.
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }
    
    /**
     * @param friendlyName The _sFriendlyName to set.
     */
    public void setFriendlyName(String friendlyName)
    {
        _sFriendlyName = friendlyName;
    }
    
    /**
     * @return Returns the _sMaintainerEmail.
     */
    public String getMaintainerEmail()
    {
        return _sMaintainerEmail;
    }
    
    /**
     * @param maintainerEmail The _sMaintainerEmail to set.
     */
    public void setMaintainerEmail(String maintainerEmail)
    {
        _sMaintainerEmail = maintainerEmail;
    }
}
