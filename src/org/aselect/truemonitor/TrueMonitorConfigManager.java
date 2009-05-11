package org.aselect.truemonitor;

import java.io.File;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

public class TrueMonitorConfigManager extends ConfigManager
{
	private final String MODULE = "TrueMonitorConfigManager";

	// The singleton instance
	private static TrueMonitorConfigManager _oTrueMonitorConfigManager;

	// The system logger
	private TrueMonitorSystemLogger _systemLogger;
	
	// The working directory
	private String _sWorkingDir = null;

	// The private constructor forces a singleton
	private TrueMonitorConfigManager() {
	}

	// Return the singleton class
	public static TrueMonitorConfigManager getHandle()
	{
		if (_oTrueMonitorConfigManager == null)
			_oTrueMonitorConfigManager = new TrueMonitorConfigManager();

		return _oTrueMonitorConfigManager;
	}

	/**
	 * Initialize the configuration.
	 *    
	 * @param sWorkingDir The working directory.
	 */
	public void init(String sWorkingDir)
	throws ASelectConfigException, ASelectException
	{
		final String sMethod = "init";
		
		_sWorkingDir = sWorkingDir;
		_systemLogger = TrueMonitorSystemLogger.getHandle();

		StringBuffer sb = new StringBuffer(_sWorkingDir).append(File.separator).append("truemonitor.xml");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "xml="+sb);
		super.init(sb.toString(), _systemLogger);
		
		// Get our main section
		Object oMainSection = getSimpleSection(null, "truemonitor", true);

		// Initialize the system logger
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Init SystemLogger");
		Object oLogSection = getSectionFromSection(oMainSection, "logging", "id=system", true);
		String sLogLevel = getSimpleParam(oLogSection, "level", true);
		Level logLevel = Level.parse(sLogLevel);
		String sLogTarget = getSimpleParam(oLogSection, "target", true);
		Object oLogTarget = getSectionFromSection(oLogSection, "target", "id=" + sLogTarget, true);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Go logTarget="+oLogTarget);
		_systemLogger.init("system", "org.aselect.truemonitor.TrueMonitorSystemLogger",
							getHandle(), oLogTarget, _sWorkingDir);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		_systemLogger.setLevel(logLevel);

		// First line that will go to the log file
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Starting True Monitor");
	}

	// Convenience function
	public String getParamFromSection(Object oConfig, String sSection, String sParam, boolean bMandatory)
	throws ASelectConfigException
	{
		return Utils.getParamFromSection(getHandle(), TrueMonitorSystemLogger.getHandle(),
								oConfig, sSection, sParam, bMandatory);
	}

	// Convenience function
	public Object getSimpleSection(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectConfigException
	{
		return Utils.getSimpleSection(getHandle(), TrueMonitorSystemLogger.getHandle(),
								oConfig, sParam, bMandatory);
	}

	// Convenience function
	public String getSimpleParam(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectException
	{
		return Utils.getSimpleParam(getHandle(), TrueMonitorSystemLogger.getHandle(),
								oConfig, sParam, bMandatory);
	}

	// Convenience function
	public Object getSectionFromSection(Object oConfig, String sParam, String sValue, boolean bMandatory)
	throws ASelectConfigException
	{
		return Utils.getSectionFromSection(getHandle(), TrueMonitorSystemLogger.getHandle(),
								oConfig, sParam, sValue, bMandatory);
	}

}
