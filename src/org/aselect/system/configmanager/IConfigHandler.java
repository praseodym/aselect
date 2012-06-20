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
 * $Id: IConfigHandler.java,v 1.5 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: IConfigHandler.java,v $
 * Revision 1.5  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.4  2005/09/08 12:47:12  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/02/21 14:21:28  erwin
 * Applied code style and improved JavaDoc.
 *
 * Revision 1.2  2005/02/08 10:15:53  martijn
 * added javadoc
 *
 * Revision 1.1  2005/02/07 15:14:15  martijn
 * changed all variable names to naming convention
 *
 */

package org.aselect.system.configmanager;

import java.io.File;

import org.aselect.system.exception.ASelectConfigException;

/**
 * Interface for all ConfigHandlers. <br>
 * <br>
 * <b>Description: </b> <br>
 * -<br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public interface IConfigHandler
{
	
	/**
	 * Initializes the <code>ConfigHandler</code>. <br>
	 * br> <b>Description: </b> <br>
	 * Initializes the <code>ConfigHandler</code> using a <code>File</code> as source. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>fConfig != null</code><br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The <code>IConfigHandler</code> is initialized. <br>
	 * 
	 * @param fConfig
	 *            The <code>File</code> that contains the configuration
	 * @throws ASelectConfigException
	 *             If initialization fails.
	 */
	public void init(File fConfig)
	throws ASelectConfigException;

	/**
	 * Initializes the <code>ConfigHandler</code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Initializes the <code>ConfigHandler</code> using a database as source. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li>Only JDBC (MySQL) is supported</li>
	 * <li><code>sUser != null</code></li>
	 * <li><code>sPassword != null</code></li>
	 * <li><code>sDatabaseURL != null</code></li>
	 * <li><code>sDatabaseTable != null</code></li>
	 * <li><code>sDriverName != null</code></li>
	 * <li><code>sConfigId != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The <code>IConfigHandler</code> implementation is initialized. <br>
	 * 
	 * @param sUser
	 *            Username that must be used to coneect to the database
	 * @param sPassword
	 *            Password for the user that must be used to connect to the database
	 * @param sDatabaseURL
	 *            URL to the database
	 * @param sDatabaseTable
	 *            Database table in which the configuration is stored
	 * @param sDriverName
	 *            The name of the driver that will be used to connect to the database
	 * @param sConfigId
	 *            The ID of the configuration in which the specific configuration is located
	 * @throws ASelectConfigException
	 *             If initialization fails.
	 */
	public void init(String sUser, String sPassword, String sDatabaseURL, String sDatabaseTable, String sDriverName,
			String sConfigId)
	throws ASelectConfigException;

	/**
	 * Returns a sub-section from the configuration of the given root-section. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The sub-section is of the given type and has the given section ID. The root section can be null: the first
	 * section will be returned. The requested section ID must be a <code>String</code> containing one '=' character
	 * (syntax: [param]=[value]). <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * If the section can't be found, an ASelectConfigException will be thrown. <br>
	 * 
	 * @param oRootSection
	 *            The section in which the requested section is located.
	 * @param sSectionType
	 *            The type of the section, in XML the XML tag name.
	 * @param sSectionID
	 *            The id of a section (syntax: [param]=[value])
	 * @return Object that indicates a specific section within the configuration.
	 * @throws ASelectConfigException
	 *             If retrieving fails.
	 */
	public Object getSection(Object oRootSection, String sSectionType, String sSectionID)
	throws ASelectConfigException;

	/**
	 * Get the first section. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * get the first configuration section of the specified sectionType. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param rootSection
	 *            The root section.
	 * @param sectionType
	 *            The type of section.
	 * @return First configuration section of the specified sectionType
	 * @throws ASelectConfigException
	 *             If retrieving fails.
	 */
	public Object getSection(Object rootSection, String sectionType)
	throws ASelectConfigException;

	/**
	 * Get a sub-section. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Returns a sub-section from the configuration of the given root section specified by the given type. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * If the root section is <code>null</code>: the first section will be returned. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oRootSection
	 *            Section that is used to resulve the subsection
	 * @param sSectionType
	 *            Type of the subsection that should be returned
	 * @return Object containing the subsection
	 * @throws ASelectConfigException
	 *             Is setting session fails.
	 */
	public Object setSection(Object oRootSection, String sSectionType)
	throws ASelectConfigException;

	/**
	 * Removes a specified configuration section. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Removes a section perminently from the configuration. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oRootSection
	 *            Section containing the section that must be removed
	 * @param sSectionType
	 *            Type of the section that must be removed
	 * @return TRUE if section is successfully removed, otherwise false.
	 * @throws ASelectConfigException
	 *             If removinf fails.
	 */
	public boolean removeSection(Object oRootSection, String sSectionType)
	throws ASelectConfigException;

	/**
	 * Removes a configuration section specified by section ID. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Removes a section, specified by section type and section ID, perminently from the configuration. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oRootSection
	 *            Section containing the section that must be removed
	 * @param sSectionType
	 *            Type of the section that must be removed
	 * @param sSectionID
	 *            ID of section that must be removed (syntax: [name]=[value])
	 * @return TRUE if section is successfully removed
	 * @throws ASelectConfigException
	 *             If removing fails.
	 */
	public boolean removeSection(Object oRootSection, String sSectionType, String sSectionID)
	throws ASelectConfigException;

	/**
	 * Returns a <code>String</code> that contains the requested configuration parameter. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The <code>String</code> that will be returned will be retrieved from the given config section and has the
	 * specified config item name. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oSection
	 *            Section from which contains the parameter
	 * @param sConfigItem
	 *            The name of the config parameter
	 * @return <code>String</code> containing the requested config parameter
	 * @throws ASelectConfigException
	 *             If retrieving fails.
	 */
	public String getParam(Object oSection, String sConfigItem)
	throws ASelectConfigException;

	/**
	 * Adds a config parameter to the given section. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Adds a config parameter to the given section in the configuration. The parameter has the name <i>sConfigItem </i>
	 * and the value <i>sConfigValue </i>. With the <i>bMandatory </i> attribute can be set if the config parameter is
	 * part of the required configuration. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oSection
	 *            The config section to which the parameter will be added
	 * @param sConfigItem
	 *            Name of the config parameter that will be added
	 * @param sConfigValue
	 *            Value of the config parameter that will be added
	 * @param bMandatory
	 *            TRUE if config parameter is requered in the section
	 * @return TRUE if parameter is successfully added
	 * @throws ASelectConfigException
	 *             If setting fails.
	 */
	public boolean setParam(Object oSection, String sConfigItem, String sConfigValue, boolean bMandatory)
	throws ASelectConfigException;

	/**
	 * Returns the next section. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Returns the next section with the same type that is direclty located after the given section. It will return
	 * <code>null</code> if no next section can be found. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oSection
	 *            Section that has the same type as the section that must be returned
	 * @return Object That contains the next section
	 * @throws ASelectConfigException
	 *             If retrieving fails
	 */
	public Object getNextSection(Object oSection)
	throws ASelectConfigException;

	/**
	 * Saves the configuration as is known by the <code>ConfigHandler<code>.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Writes the configuration to the physical storage. It will overwrite the
	 * existing configuration.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br>
	 * 
	 * @throws ASelectConfigException
	 *             If saving fails
	 */
	public void saveConfig()
	throws ASelectConfigException;

	/**
	 * Import configuration items into this configuration. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Imports the configuration file within the configuration that is present in the <code>ConfigHandler</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <code>ConfigManager</code> must be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param fConfig
	 *            The configuration <code>File</code> that will be imported in the configuration that is known in the
	 *            memory of the <code>ConfigHandler</code>
	 * @throws ASelectConfigException
	 *             If importing fails.
	 * @deprecated All config should be stored in only one config file.
	 */
	@Deprecated
	public void importConfig(File fConfig)
	throws ASelectConfigException;

}