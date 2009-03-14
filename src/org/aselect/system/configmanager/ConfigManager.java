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
 * $Id: ConfigManager.java,v 1.9 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: ConfigManager.java,v $
 * Revision 1.9  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.8  2005/09/08 12:47:12  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.6  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.5  2005/03/01 08:03:33  erwin
 * _sModule -> MODULE and levels improved.
 *
 * Revision 1.4  2005/02/21 14:21:28  erwin
 * Applied code style and improved JavaDoc.
 *
 * Revision 1.3  2005/02/08 10:15:53  martijn
 * added javadoc
 *
 * Revision 1.2  2005/02/07 15:14:15  martijn
 * changed all variable names to naming convention
 *
 */

package org.aselect.system.configmanager;

import java.io.File;
import java.util.logging.Level;

import org.aselect.system.configmanager.handler.XMLConfigHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.logging.SystemLogger;

/**
 * A common configuration manager. 
 * <br><br>
 * <b>Description: </b> 
 * <br>
 * The <code>ConfigManager</code> offers an interface to the configuration,
 * which can be used by all A-Select components. It's set up like a factory to
 * resolve the right <code>ConfigHandler</code>.<br>
 * <br>
 * The <code>ConfigManager</code> offers an interface to the
 * <code>ConfigHandler
 * </code> that is created during initialization. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>-<br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class ConfigManager
{
	/** name of this module, used for logging */
	private static final String MODULE = "ConfigManager";

	/** ConfigHandler object used by this ConfigManager. */
	private IConfigHandler _oConfigHandler;

	/** SystemLogger object were system logging is sent to. */
	private SystemLogger _oSystemLogger;

	/**
	 * Default constructor. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * Default constructor which initializes class variables. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 */
	public ConfigManager() {
		_oConfigHandler = null;
		_oSystemLogger = null;
	}

	/**
	 * Initialize the <code>ConfigManager</code> for use with a config file.
	 * <br><br>
	 * <b>Description: </b> <br>
	 * The <code>ConfigManager</code> will create an
	 * <code>ConfigHandler</code> with file support. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * Only one <code>ConfigHandler</code> per <code>ConfigManager</code>
	 * will be created. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <i>oSystemLogger </i> object must be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @param sConfigFile
	 *            <code>String</code> that contains the full path and filename
	 *            of the configuration file.
	 * @param oSystemLogger
	 *            <code>SystemLogger</code> initialized SystemLogger Object.
	 * @throws ASelectConfigException
	 *             If initialization fails.
	 */
	public void init(String sConfigFile, SystemLogger oSystemLogger)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "init()";

		try {
			_oSystemLogger = oSystemLogger;
			File fConfig = new File(sConfigFile);

			if (fConfig != null && fConfig.exists()) {//only start initializing when config file exists
				_oConfigHandler = resolveConfigHandler(fConfig);
				if (_oConfigHandler != null)
					_oConfigHandler.init(fConfig);
				else {
					sbError.append("Can't open file: ");
					sbError.append(sConfigFile);
					_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
					throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN);
				}
			}
			else {
				sbError.append("File doesn't exist: ");
				sbError.append(sConfigFile);
				_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
				throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
			}
		}
		catch (ASelectConfigException e) {
			throw e;
		}
		catch (Exception e) {
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Initialize the <code>ConfigManager</code> for use with a database. 
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>
	 * The initialize function for storage of the config file in a database.
	 * <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <i>oSystemLogger </i> object must be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
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
	public void init(String sDriverName, String sUser, String sPassword, String sDatabaseURL, String sDatabaseTable,
			String sConfigId, SystemLogger oSystemLogger)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "init()";

		try {
			_oSystemLogger = oSystemLogger;

			if (sDriverName == null || sUser == null || sPassword == null || sDatabaseURL == null
					|| sDatabaseTable == null || sConfigId == null) {
				sbError.append("One or more required arguments are null.");
				_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());

				throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN);
			}

			_oConfigHandler = resolveConfigHandler();

			if (_oConfigHandler != null) {
				_oConfigHandler.init(sUser, sPassword, sDatabaseURL, sDatabaseTable, sDriverName, sConfigId);
			}
			else {
				sbError.append("Can't resolve configuration from database.");
				_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());

				throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN);
			}

		}
		catch (Exception e) {
			sbError.append("Error initializing using database configuration: ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());

			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Returns a sub-section from the configuration of the given root-section.
	 * <br><br>
	 * <b>Description: </b> <br>
	 * The returned sub-section is of the given type and has the given section
	 * ID. The root section can be <code>null</code>: the first section will
	 * be returned. The requested section ID must be a <code>String</code>
	 * containing one '=' character (syntax: [param]=[value]). <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * If the section can't be found, an <code>ASelectConfigException</code>
	 * will be thrown. <br>
	 * 
	 * @param oRootSection
	 *            The section in which the requested section is located.
	 * @param sSectionType
	 *            The type of the section, in XML the XML tag name.
	 * @param sSectionID
	 *            The id of a section (syntax: [param]=[value])
	 * @return Object that indicates a specific section within the
	 *         configuration.
	 * @throws ASelectConfigException
	 *             If retrieving fails.
	 */
	public Object getSection(Object oRootSection, String sSectionType, String sSectionID)
		throws ASelectConfigException
	{
		return _oConfigHandler.getSection(oRootSection, sSectionType, sSectionID);
	}

	/**
	 * Returns a sub-section from the configuration of the given root section
	 * specified by the given type. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * The root section can be <code>null</code>: the first section will be
	 * returned. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @param oRootSection
	 *            Section that is used to resulve the subsection
	 * @param sSectionType
	 *            Type of the subsection that should be returned
	 * @return Object containing the subsection
	 * @throws ASelectConfigException
	 *             If retrieving fails
	 */
	public Object getSection(Object oRootSection, String sSectionType)
		throws ASelectConfigException
	{
		return _oConfigHandler.getSection(oRootSection, sSectionType);
	}

	/**
	 * Adds an empty configuration section of the specified <code>sectionType
	 * </code> of the rootSection. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * Must be used to create a new configuration section of a given section
	 * type. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @param oRootSection
	 *            Section to which the new section is added
	 * @param sSectionType
	 *            Type of the section that will be added
	 * @return An empty section added to the supplied root section
	 * @throws ASelectConfigException
	 *             If setting fails
	 */
	public Object setSection(Object oRootSection, String sSectionType)
		throws ASelectConfigException
	{
		return _oConfigHandler.setSection(oRootSection, sSectionType);
	}

	/**
	 * Removes a specified configuration section. 
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>
	 * Removes a section perminently from the configuration. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @param oRootSection
	 *            Section containing the section that must be removed
	 * @param sSectionType
	 *            Type of the section that must be removed
	 * @return TRUE if section is successfully removed
	 * @throws ASelectConfigException
	 *             If removing fails
	 */
	public boolean removeSection(Object oRootSection, String sSectionType)
		throws ASelectConfigException
	{
		return _oConfigHandler.removeSection(oRootSection, sSectionType);
	}

	/**
	 * Removes a configuration section specified by section ID. 
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>
	 * Removes a section, specified by section type and section ID, perminently
	 * from the configuration. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
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
	public boolean removeSection(Object oRootSection, String sSectionType, String sSectionID)
		throws ASelectConfigException
	{
		return _oConfigHandler.removeSection(oRootSection, sSectionType, sSectionID);
	}

	/**
	 * Returns a <code>String</code> that contains the requested configuration
	 * parameter. 
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>
	 * The <code>String</code> that will be returned will be retrieved from
	 * the given config section and has the specified config item name. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @param oSection
	 *            Section from which contains the parameter
	 * @param sConfigItem
	 *            The name of the config parameter
	 * @return <code>String</code> containing the requested config parameter
	 * @throws ASelectConfigException
	 *             If retrieving fails
	 */
	public String getParam(Object oSection, String sConfigItem)
		throws ASelectConfigException
	{
		return _oConfigHandler.getParam(oSection, sConfigItem);
	}

	/**
	 * Adds a config parameter to the given section. 
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>
	 * Adds a config parameter to the given section in the configuration. The
	 * parameter has the name <i>sConfigItem </i> and the value <i>sConfigValue
	 * </i>. With the <i>bMandatory </i> attribute can be set if the config
	 * parameter is part of the required configuration. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
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
	public boolean setParam(Object oSection, String sConfigItem, String sConfigValue, boolean bMandatory)
		throws ASelectConfigException
	{
		return _oConfigHandler.setParam(oSection, sConfigItem, sConfigValue, bMandatory);
	}

	/**
	 * Returns the next section with the same type that is direclty located
	 * after the given section. 
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>
	 * It will return <code>null</code> if no next section can be found. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @param oSection
	 *            Section that has the same type as the section that must be
	 *            returned
	 * @return Object That contains the next section
	 * @throws ASelectConfigException
	 *             If retrieving fails
	 */
	public Object getNextSection(Object oSection)
		throws ASelectConfigException
	{
		return _oConfigHandler.getNextSection(oSection);
	}

	/**
	 * Saves the configuration as is known by the ConfigHandler. 
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>
	 * Writes the configuration to the physical storage. It will overwrite the
	 * existing configuration. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @throws ASelectConfigException
	 *             If saving fails
	 */
	public void saveConfig()
		throws ASelectConfigException
	{
		_oConfigHandler.saveConfig();
	}

	/**
	 * Imports the configuration file within the configuration that is present
	 * in the <code>ConfigHandler</code>.
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>-<br>
	 * <br>
	 * <b>Concurrency issues: </b> 
	 * <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <code>ConfigManager</code> must be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> 
	 * <br>-<br>
	 * 
	 * @param fConfig
	 *            The configuration <code>File</code> that will be imported in
	 *            the configuration that is known in the memory of the
	 *            <code>ConfigHandler</code>
	 * @throws ASelectConfigException
	 *             If importing fails
	 * @deprecated All config should be stored in only one config file.
	 */
	public void importConfig(File fConfig)
		throws ASelectConfigException
	{
		String sMethod = "importConfig()";

		if (fConfig != null) {
			_oConfigHandler.importConfig(fConfig);
		}
		else {
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, "File object is null.");

			throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN);
		}
	}

	/**
	 * Resolves a <code>ConfigHandler</code> from the extension of the given
	 * <code>File</code>.
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>-<br>
	 * <br>
	 * <b>Concurrency issues: </b> 
	 * <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <i>fConfig </I> Object may not be <code>null</code>.<br>
	 * <br>
	 * <b>Postconditions: </b> 
	 * <br>-<br>
	 * 
	 * @param fConfig
	 *            The <code>File</code> that contains the configuration.
	 * @return IConfigHandler The <code>ConfigHandler</code> for the specific
	 *         config file.
	 */
	private IConfigHandler resolveConfigHandler(File fConfig)
	{
		String sMethod = "resolveConfigHandler()";

		IConfigHandler oConfigHandler = null;
		int iSepIndex = -1;
		String sFileName = null;
		String sExtension = null;

		sFileName = fConfig.getName();
		if (sFileName == null) {
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Filename is null.");
		}
		//resolve extension
		iSepIndex = sFileName.lastIndexOf(".");
		sExtension = fConfig.getName().substring(iSepIndex + 1);

		if (sExtension.equalsIgnoreCase("XML")) {//XML confighandler
			oConfigHandler = new XMLConfigHandler(_oSystemLogger);
		}
		//else if (strExtension.equalsIgnoreCase("CFG"))
		//{
		//cfg = new CFGConfigHandler();
		//}
		//else if (strExtension.equalsIgnoreCase("PROP"))
		//{
		//cfg = new PROPConfigHandler();
		//}
		else {//default confighandler
			oConfigHandler = new XMLConfigHandler(_oSystemLogger);
		}

		return oConfigHandler;
	}

	/**
	 * Resolves a <code>ConfigHandler</code> the default <code>ConfigHandler
	 * </code>.
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>
	 * Is needed if the configuration is stored in a database <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @return IConfigHandler The <code>ConfigHandler</code> for the specific
	 *         configuration.
	 */
	private IConfigHandler resolveConfigHandler()
	{
		//only XML is supported at this moment
		return new XMLConfigHandler(_oSystemLogger);
	}

}