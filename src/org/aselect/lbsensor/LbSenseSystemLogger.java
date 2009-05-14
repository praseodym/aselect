package org.aselect.lbsense;

import java.util.logging.Level;

import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;

public class LbSenseSystemLogger extends SystemLogger
{
	private static final String MODULE = "LbSenseSystemLogger";

	private static LbSenseSystemLogger _oLbSenseSystemLogger;

	// This is a Singleton
	private LbSenseSystemLogger() {
	}

	// @return A static handle to the system logger.
	public static LbSenseSystemLogger getHandle()
	{
		if (_oLbSenseSystemLogger == null)
			_oLbSenseSystemLogger = new LbSenseSystemLogger();

		return _oLbSenseSystemLogger;
	}
	
	public void init(LbSenseConfigManager oConfigManager, Object oLogSection, String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "init";
		LbSenseSystemLogger oLbSenseLogger = LbSenseSystemLogger.getHandle();

		
		String sLogLevel = oConfigManager.getSimpleParam(oLogSection, "level", true);
		Level logLevel = Level.parse(sLogLevel);
		String sLogTarget = oConfigManager.getSimpleParam(oLogSection, "target", true);
		Object oLogTarget = oConfigManager.getSectionFromSection(oLogSection, "target", "id=" + sLogTarget, true);

		oLbSenseLogger.init("system", "org.aselect.lbsense.LbSenseSystemLogger", oConfigManager, oLogTarget, sWorkingDir);
		oLbSenseLogger.setLevel(logLevel);

		// First line that will go to the log file
		log(Level.INFO, MODULE, sMethod, "Systemlogger initialized");
	}
}
