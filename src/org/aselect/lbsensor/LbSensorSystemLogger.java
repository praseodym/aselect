package org.aselect.lbsensor;

import java.util.logging.Level;

import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;

public class LbSensorSystemLogger extends SystemLogger
{
	private static final String MODULE = "LbSensorSystemLogger";

	private static LbSensorSystemLogger _oLbSensorSystemLogger;

	// This is a Singleton
	private LbSensorSystemLogger() {
	}

	// @return A static handle to the system logger.
	public static LbSensorSystemLogger getHandle()
	{
		if (_oLbSensorSystemLogger == null)
			_oLbSensorSystemLogger = new LbSensorSystemLogger();

		return _oLbSensorSystemLogger;
	}
	
	public void init(LbSensorConfigManager oConfigManager, Object oLogSection, String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "init";
		LbSensorSystemLogger oLbSensorLogger = LbSensorSystemLogger.getHandle();

		
		String sLogLevel = oConfigManager.getSimpleParam(oLogSection, "level", true);
		Level logLevel = Level.parse(sLogLevel);
		String sLogTarget = oConfigManager.getSimpleParam(oLogSection, "target", true);
		Object oLogTarget = oConfigManager.getSectionFromSection(oLogSection, "target", "id=" + sLogTarget, true);

		oLbSensorLogger.init("system", "org.aselect.lbsensor.LbSensorSystemLogger", oConfigManager, oLogTarget, sWorkingDir);
		oLbSensorLogger.setLevel(logLevel);

		// First line that will go to the log file
		log(Level.INFO, MODULE, sMethod, "Systemlogger initialized");
	}
}
