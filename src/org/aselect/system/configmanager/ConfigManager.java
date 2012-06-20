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
import java.util.Timer;
import java.util.logging.Level;

import org.aselect.system.configmanager.handler.XMLConfigHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.servlet.ASelectHttpServlet;
import org.aselect.system.storagemanager.SendQueue;
import org.aselect.system.storagemanager.SendQueueSender;
import org.aselect.system.utils.Utils;

/**
 * A common configuration manager. <br>
 * <br>
 * <b>Description: </b> <br>
 * The <code>ConfigManager</code> offers an interface to the configuration, which can be used by all A-Select
 * components. It's set up like a factory to resolve the right <code>ConfigHandler</code>.<br>
 * <br>
 * The <code>ConfigManager</code> offers an interface to the <code>ConfigHandler
 * </code> that is created during initialization. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public class ConfigManager implements IConfigManager
{
	/** name of this module, used for logging */
	private static final String MODULE = "ConfigManager";

	/** ConfigHandler object used by this ConfigManager. */
	private IConfigHandler _oConfigHandler;

	/** SystemLogger object were system logging is sent to. */
	private SystemLogger _oSystemLogger;
	
	private ASelectHttpServlet _oMainServlet = null;
	private boolean isLbSensorConfigured;

	/**
	 * Default constructor. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Default constructor which initializes class variables. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 */
	public ConfigManager()
	{
		_oConfigHandler = null;
		_oSystemLogger = null;
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#init(java.lang.String, org.aselect.system.logging.SystemLogger)
	 */
	public void init(String sConfigFile, SystemLogger oSystemLogger)
	throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "init()";

		try {
			_oSystemLogger = oSystemLogger;
			File fConfig = new File(sConfigFile);

			if (fConfig != null && fConfig.exists()) { // only start initializing when config file exists
				_oConfigHandler = resolveConfigHandler(fConfig);
				if (_oConfigHandler != null) {
					_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Read configuration from: "+sConfigFile);
					_oConfigHandler.init(fConfig);
				}
				else {
					sbError.append("Can't open file: ").append(sConfigFile);
					_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
					throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN);
				}
			}
			else {
				sbError.append("File doesn't exist: ").append(sConfigFile);
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

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#init(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, org.aselect.system.logging.SystemLogger)
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

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#getSection(java.lang.Object, java.lang.String, java.lang.String)
	 */
	public Object getSection(Object oRootSection, String sSectionType, String sSectionID)
	throws ASelectConfigException
	{
		return _oConfigHandler.getSection(oRootSection, sSectionType, sSectionID);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#getSection(java.lang.Object, java.lang.String)
	 */
	public Object getSection(Object oRootSection, String sSectionType)
	throws ASelectConfigException
	{
		return _oConfigHandler.getSection(oRootSection, sSectionType);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#setSection(java.lang.Object, java.lang.String)
	 */
	public Object setSection(Object oRootSection, String sSectionType)
	throws ASelectConfigException
	{
		return _oConfigHandler.setSection(oRootSection, sSectionType);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#removeSection(java.lang.Object, java.lang.String)
	 */
	public boolean removeSection(Object oRootSection, String sSectionType)
	throws ASelectConfigException
	{
		return _oConfigHandler.removeSection(oRootSection, sSectionType);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#removeSection(java.lang.Object, java.lang.String, java.lang.String)
	 */
	public boolean removeSection(Object oRootSection, String sSectionType, String sSectionID)
	throws ASelectConfigException
	{
		return _oConfigHandler.removeSection(oRootSection, sSectionType, sSectionID);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#getParam(java.lang.Object, java.lang.String)
	 */
	public String getParam(Object oSection, String sConfigItem)
	throws ASelectConfigException
	{
		return _oConfigHandler.getParam(oSection, sConfigItem);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#setParam(java.lang.Object, java.lang.String, java.lang.String, boolean)
	 */
	public boolean setParam(Object oSection, String sConfigItem, String sConfigValue, boolean bMandatory)
	throws ASelectConfigException
	{
		return _oConfigHandler.setParam(oSection, sConfigItem, sConfigValue, bMandatory);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#getNextSection(java.lang.Object)
	 */
	public Object getNextSection(Object oSection)
	throws ASelectConfigException
	{
		return _oConfigHandler.getNextSection(oSection);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#saveConfig()
	 */
	public void saveConfig()
	throws ASelectConfigException
	{
		_oConfigHandler.saveConfig();
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.configmanager.IConfigManager#importConfig(java.io.File)
	 */
	@Deprecated
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
	 * Resolves a <code>ConfigHandler</code> from the extension of the given <code>File</code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <i>fConfig </I> Object may not be <code>null</code>.<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param fConfig
	 *            The <code>File</code> that contains the configuration.
	 * @return IConfigHandler The <code>ConfigHandler</code> for the specific config file.
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
		// resolve extension
		iSepIndex = sFileName.lastIndexOf(".");
		sExtension = fConfig.getName().substring(iSepIndex + 1);

		if (sExtension.equalsIgnoreCase("XML")) {// XML confighandler
			oConfigHandler = new XMLConfigHandler(_oSystemLogger);
		}
		// else if (strExtension.equalsIgnoreCase("CFG"))
		// {
		// cfg = new CFGConfigHandler();
		// }
		// else if (strExtension.equalsIgnoreCase("PROP"))
		// {
		// cfg = new PROPConfigHandler();
		// }
		else {// default confighandler
			oConfigHandler = new XMLConfigHandler(_oSystemLogger);
		}

		return oConfigHandler;
	}

	/**
	 * Resolves a <code>ConfigHandler</code> the default <code>ConfigHandler
	 * </code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Is needed if the configuration is stored in a database <br>
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
	 * @return IConfigHandler The <code>ConfigHandler</code> for the specific configuration.
	 */
	private IConfigHandler resolveConfigHandler()
	{
		// only XML is supported at this moment
		return new XMLConfigHandler(_oSystemLogger);
	}
	
	/**
	 * Timer sensor config.
	 * 
	 * @param configManager
	 *            the config manager
	 * @param systemLogger
	 *            the system logger
	 * @param _oMainConfig
	 *            the main config section
	 * @param sMainTag
	 *            the main tag
	 * @throws ASelectConfigException
	 * @throws ASelectException
	 */
	private static int timerSensorConfig(ConfigManager configManager, SystemLogger systemLogger, String sMainTag)
	throws ASelectConfigException, ASelectException
	{
		String sMethod = "timerSensorConfig";
		int iBatchPeriod = -1;
		int iBatchSize = -1;
		
		// The Timer Queue and config
		Object _oMainConfig = configManager.getSection(null, sMainTag);  // main section
		Object oSensorSection = Utils.getSimpleSection(configManager, systemLogger, _oMainConfig, "timer_sensor", false);
		if (oSensorSection == null)
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Section "+sMainTag+"/"+"timer_sensor"+" not found, no timer_sensor logging");
		else {
			iBatchPeriod  = Utils.getSimpleIntParam(configManager, systemLogger, oSensorSection, "batch_period", false);
			if (iBatchPeriod <= 0)
				iBatchPeriod = 60;  // seconds
			iBatchSize = Utils.getSimpleIntParam(configManager, systemLogger, oSensorSection, "batch_size", false);
			if (iBatchSize < 0)  // can be set to 0 to deactivate timer_sensor
				iBatchSize = 100;
		}
		SendQueue.getHandle().setBatchPeriod(iBatchPeriod);
		SendQueue.getHandle().setBatchSize(iBatchSize);
		return iBatchPeriod;
	}

	public static Timer timerSensorStartThread(ConfigManager configManager, SystemLogger systemLogger, String sMainTag)
	throws ASelectConfigException, ASelectException
	{
		String sMethod = "timerSensorStartThread";
		int iBatchPeriod = ConfigManager.timerSensorConfig(configManager, systemLogger, sMainTag);
		if (iBatchPeriod <= 0) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "No timerSensor logging, batch_period="+iBatchPeriod+" seconds");
			return null;
		}
		
		try {
			SendQueueSender dcExporter = new SendQueueSender(systemLogger);
			SendQueue hQueue = SendQueue.getHandle();
			// Will get <sensor_url> and <client_communicator> from config too:
			hQueue.initialize(configManager, systemLogger, sMainTag, "timer_sensor"/*section*/);
			
			Timer _dataSendTimer = new Timer();
			_dataSendTimer.schedule(dcExporter, 0, hQueue.getBatchPeriod() * 1000);  // in milliseconds
			systemLogger.log(Level.INFO, MODULE, sMethod, "SendQueueSender scheduled every "+hQueue.getBatchPeriod()+" seconds"+" batchSize="+hQueue.getBatchSize());
			return _dataSendTimer;
		}
		catch (Exception e) {
			systemLogger.log(Level.SEVERE, MODULE, sMethod, "Can't start SendQueueSender", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}
	
	public static void timerSensorStopThread(Timer tThread)
	{
		tThread.cancel();
	}
	
	public boolean isTimerSensorConfigured() {
		return SendQueue.getHandle().getBatchSize() > 0;
	}

	public void setMainServlet(ASelectHttpServlet oMainServlet) {
		_oMainServlet = oMainServlet;
	}
	public ASelectHttpServlet getMainServlet() {
		return _oMainServlet;
	}
	
	public boolean isLbSensorConfigured() {
		return isLbSensorConfigured;
	}
	public void setLbSensorConfigured(boolean isLbSensorConfigured) {
		this.isLbSensorConfigured = isLbSensorConfigured;
	}
}