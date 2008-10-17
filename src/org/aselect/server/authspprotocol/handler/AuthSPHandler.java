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
 * $Id: AuthSPHandler.java,v 1.3 2006/04/26 12:16:36 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthSPHandler.java,v $
 * Revision 1.3  2006/04/26 12:16:36  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.2  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.1.2.2  2006/04/07 09:52:05  leon
 * java doc
 *
 * Revision 1.1.2.1  2006/03/16 08:05:56  leon
 * AuthSP Handler bean
 *
 */
 
package org.aselect.server.authspprotocol.handler;

/**
 * The AuthSPHandlers (Bean) class
 * <br><br>
 * <b>Description:</b><br>
 * Contains all the required features of an AuthSPHandler needed in A-Select.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class AuthSPHandler
{
    private String _sId;    
    private String _sHandler;    
    private String _sType;
    private String _sFriendlyName;
    private String _sResourceGroup; 
    private Integer _intLevel;    
    private boolean _bPopup;
    private boolean _bDirectAuthSP;
 
    
    
    /**
     * Default condtructor
     */
    public AuthSPHandler ()
    {
        _sId = null;
        _sHandler = null;
        _sType = null;
        _sFriendlyName = null;
        _intLevel = new Integer(0);
        _bPopup = false;
        _bDirectAuthSP = false;
    }
        
    
    /**
     * Contructor which contains the default parameters for an AuthSPHandler
     * @param id
     * @param handler
     * @param resourceGroup
     * @param type
     * @param friendlyName
     * @param popup
     * @param level
     */
    public AuthSPHandler (String id, String handler, String resourceGroup, String type, String friendlyName, Integer level, boolean popup)
    {
        _sId = id;
        _sHandler = handler;
        _sResourceGroup = resourceGroup;
        _sType = type;
        _sFriendlyName = friendlyName;
        _intLevel = level;
        _bPopup = popup;
        _bDirectAuthSP = false;
    }
    
    /**
     * @return Returns the sType.
     */
    public String getType()
    {
        return _sType;
    }
    /**
     * @param type The sType to set.
     */
    public void setType(String type)
    {
        _sType = type;
    }
    
    /**
     * @return Returns the bDirectAuthSP.
     */
    public boolean isDirectAuthSP()
    {
        return _bDirectAuthSP;
    }
    /**
     * @param directAuthSP The bDirectAuthSP to set.
     */
    public void setDirectAuthSP(boolean directAuthSP)
    {
        _bDirectAuthSP = directAuthSP;
    }
    /**
     * @return Returns the iLevel.
     */
    public Integer getLevel()
    {
        return _intLevel;
    }
    /**
     * @param level The iLevel to set.
     */
    public void setLevel(Integer level)
    {
        _intLevel = level;
    }
    /**
     * @return Returns the sHandler.
     */
    public String getHandler()
    {
        return _sHandler;
    }
    /**
     * @param handler The sHandler to set.
     */
    public void setHandler(String handler)
    {
        _sHandler = handler;
    }
    /**
     * @return Returns the sLevel.
     */

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
     * @return Returns the _bPopup.
     */
    public boolean isPopup()
    {
        return _bPopup;
    }
    /**
     * @param popup The _bPopup to set.
     */
    public void setPopup(boolean popup)
    {
        _bPopup = popup;
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
     * @return Returns the _sResourceGroup.
     */
    public String getResourceGroup()
    {
        return _sResourceGroup;
    }
    /**
     * @param resourceGroup The _sResourceGroup to set.
     */
    public void setResourceGroup(String resourceGroup)
    {
        _sResourceGroup = resourceGroup;
    }


}
