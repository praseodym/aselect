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
 * The AuthSPHandlers (Bean) class <br>
 * <br>
 * <b>Description:</b><br>
 * Contains all the required features of an AuthSPHandler needed in A-Select. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
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
	 * Default constructor.
	 */
	public AuthSPHandler()
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
	 * Contructor which contains the default parameters for an AuthSPHandler.
	 * 
	 * @param id
	 *            the id
	 * @param handler
	 *            the handler
	 * @param resourceGroup
	 *            the resource group
	 * @param type
	 *            the type
	 * @param friendlyName
	 *            the friendly name
	 * @param popup
	 *            the popup
	 * @param level
	 *            the level
	 */
	public AuthSPHandler(String id, String handler, String resourceGroup, String type, String friendlyName,
			Integer level, boolean popup)
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
	 * Gets the type.
	 * 
	 * @return Returns the sType.
	 */
	public String getType()
	{
		return _sType;
	}

	/**
	 * Sets the type.
	 * 
	 * @param type
	 *            The sType to set.
	 */
	public void setType(String type)
	{
		_sType = type;
	}

	/**
	 * Checks if is direct auth sp.
	 * 
	 * @return Returns the bDirectAuthSP.
	 */
	public boolean isDirectAuthSP()
	{
		return _bDirectAuthSP;
	}

	/**
	 * Sets the direct auth sp.
	 * 
	 * @param directAuthSP
	 *            The bDirectAuthSP to set.
	 */
	public void setDirectAuthSP(boolean directAuthSP)
	{
		_bDirectAuthSP = directAuthSP;
	}

	/**
	 * Gets the level.
	 * 
	 * @return Returns the iLevel.
	 */
	public Integer getLevel()
	{
		return _intLevel;
	}

	/**
	 * Sets the level.
	 * 
	 * @param level
	 *            The iLevel to set.
	 */
	public void setLevel(Integer level)
	{
		_intLevel = level;
	}

	/**
	 * Gets the handler.
	 * 
	 * @return Returns the sHandler.
	 */
	public String getHandler()
	{
		return _sHandler;
	}

	/**
	 * Sets the handler.
	 * 
	 * @param handler
	 *            The sHandler to set.
	 */
	public void setHandler(String handler)
	{
		_sHandler = handler;
	}

	/**
	 * Gets the friendly name.
	 * 
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
	 * Checks if is popup.
	 * 
	 * @return Returns the _bPopup.
	 */
	public boolean isPopup()
	{
		return _bPopup;
	}

	/**
	 * Sets the popup.
	 * 
	 * @param popup
	 *            The _bPopup to set.
	 */
	public void setPopup(boolean popup)
	{
		_bPopup = popup;
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
	 * Gets the resource group.
	 * 
	 * @return Returns the _sResourceGroup.
	 */
	public String getResourceGroup()
	{
		return _sResourceGroup;
	}

	/**
	 * Sets the resource group.
	 * 
	 * @param resourceGroup
	 *            The _sResourceGroup to set.
	 */
	public void setResourceGroup(String resourceGroup)
	{
		_sResourceGroup = resourceGroup;
	}

}
