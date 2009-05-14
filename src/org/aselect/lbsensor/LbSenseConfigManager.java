package org.aselect.lbsense;

import java.io.File;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

public class LbSenseConfigManager extends ConfigManager
{
	private final String MODULE = "LbSenseConfigManager";

	// The singleton instance
	private static LbSenseConfigManager _oLbSenseConfigManager;

	// The system logger
	private LbSenseSystemLogger _systemLogger;
	
	// The working directory
	private String _sWorkingDir = null;

	// The private constructor forces a singleton
	private LbSenseConfigManager() {
	}

	// Return the singleton class
	public static LbSenseConfigManager getHandle()
	{
		if (_oLbSenseConfigManager == null)
			_oLbSenseConfigManager = new LbSenseConfigManager();

		return _oLbSenseConfigManager;
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
		_systemLogger = LbSenseSystemLogger.getHandle();

		StringBuffer sb = new StringBuffer(_sWorkingDir).append(File.separator).append("lbsense.xml");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "xml="+sb);
		super.init(sb.toString(), _systemLogger);
	}

	// Convenience function
	public String getParamFromSection(Object oConfig, String sSection, String sParam, boolean bMandatory)
	throws ASelectConfigException
	{
		return Utils.getParamFromSection(getHandle(), LbSenseSystemLogger.getHandle(),
								oConfig, sSection, sParam, bMandatory);
	}

	// Convenience function
	public Object getSimpleSection(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectConfigException
	{
		return Utils.getSimpleSection(getHandle(), LbSenseSystemLogger.getHandle(),
								oConfig, sParam, bMandatory);
	}

	// Convenience function
	public String getSimpleParam(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectException
	{
		return Utils.getSimpleParam(getHandle(), LbSenseSystemLogger.getHandle(),
								oConfig, sParam, bMandatory);
	}

	// Convenience function
	public Object getSectionFromSection(Object oConfig, String sParam, String sValue, boolean bMandatory)
	throws ASelectConfigException
	{
		return Utils.getSectionFromSection(getHandle(), LbSenseSystemLogger.getHandle(),
								oConfig, sParam, sValue, bMandatory);
	}

}
