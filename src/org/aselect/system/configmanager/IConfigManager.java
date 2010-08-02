package org.aselect.system.configmanager;

import java.io.File;

import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.logging.SystemLogger;

public interface IConfigManager
{

	/**
	 * Initialize the <code>ConfigManager</code> for use with a config file. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The <code>ConfigManager</code> will create an <code>ConfigHandler</code> with file support. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * Only one <code>ConfigHandler</code> per <code>ConfigManager</code> will be created. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <i>oSystemLogger </i> object must be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param sConfigFile
	 *            <code>String</code> that contains the full path and filename of the configuration file.
	 * @param oSystemLogger
	 *            <code>SystemLogger</code> initialized SystemLogger Object.
	 * @throws ASelectConfigException
	 *             If initialization fails.
	 */
	public abstract void init(String sConfigFile, SystemLogger oSystemLogger)
		throws ASelectConfigException;

	/**
	 * Initialize the <code>ConfigManager</code> for use with a database. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The initialize function for storage of the config file in a database. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <i>oSystemLogger </i> object must be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param sDriverName
	 *            JDBC Driver name
	 * @param sUser
	 *            JDBC Username
	 * @param sPassword
	 *            Password for sUser to access JDBC database
	 * @param sDatabaseURL
	 *            URL to JDBC database
	 * @param sDatabaseTable
	 *            Name of table that contains the A-Select config
	 * @param sConfigId
	 *            Unique ID of the configuration in the table.
	 * @param oSystemLogger
	 *            <code>SystemLogger</code> initialized SystemLogger Object.
	 * @throws ASelectConfigException
	 *             If initialization fails.
	 */
	public abstract void init(String sDriverName, String sUser, String sPassword, String sDatabaseURL,
			String sDatabaseTable, String sConfigId, SystemLogger oSystemLogger)
		throws ASelectConfigException;

	/**
	 * Returns a sub-section from the configuration of the given root-section. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The returned sub-section is of the given type and has the given section ID. The root section can be
	 * <code>null</code>: the first section will be returned. The requested section ID must be a <code>String</code>
	 * containing one '=' character (syntax: [param]=[value]). <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * If the section can't be found, an <code>ASelectConfigException</code> will be thrown. <br>
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
	public abstract Object getSection(Object oRootSection, String sSectionType, String sSectionID)
		throws ASelectConfigException;

	/**
	 * Returns a sub-section from the configuration of the given root section specified by the given type. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The root section can be <code>null</code>: the first section will be returned. <br>
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
	 *            Section that is used to resulve the subsection
	 * @param sSectionType
	 *            Type of the subsection that should be returned
	 * @return Object containing the subsection
	 * @throws ASelectConfigException
	 *             If retrieving fails
	 */
	public abstract Object getSection(Object oRootSection, String sSectionType)
		throws ASelectConfigException;

	/**
	 * Adds an empty configuration section of the specified <code>sectionType
	 * </code> of the rootSection. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Must be used to create a new configuration section of a given section type. <br>
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
	 *            Section to which the new section is added
	 * @param sSectionType
	 *            Type of the section that will be added
	 * @return An empty section added to the supplied root section
	 * @throws ASelectConfigException
	 *             If setting fails
	 */
	public abstract Object setSection(Object oRootSection, String sSectionType)
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
	 * @return TRUE if section is successfully removed
	 * @throws ASelectConfigException
	 *             If removing fails
	 */
	public abstract boolean removeSection(Object oRootSection, String sSectionType)
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
	 *             if removing fails
	 */
	public abstract boolean removeSection(Object oRootSection, String sSectionType, String sSectionID)
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
	 *             If retrieving fails
	 */
	public abstract String getParam(Object oSection, String sConfigItem)
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
	 *             If setting fails
	 */
	public abstract boolean setParam(Object oSection, String sConfigItem, String sConfigValue, boolean bMandatory)
		throws ASelectConfigException;

	/**
	 * Returns the next section with the same type that is direclty located after the given section. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * It will return <code>null</code> if no next section can be found. <br>
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
	public abstract Object getNextSection(Object oSection)
		throws ASelectConfigException;

	/**
	 * Saves the configuration as is known by the ConfigHandler. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Writes the configuration to the physical storage. It will overwrite the existing configuration. <br>
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
	 * @throws ASelectConfigException
	 *             If saving fails
	 */
	public abstract void saveConfig()
		throws ASelectConfigException;

	/**
	 * Imports the configuration file within the configuration that is present in the <code>ConfigHandler</code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * -<br>
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
	 *             If importing fails
	 * @deprecated All config should be stored in only one config file.
	 */
	@Deprecated
	public abstract void importConfig(File fConfig)
		throws ASelectConfigException;

}