package org.aselect.truemonitor;

import java.util.logging.Level;

import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;

public class TrueMonitorSystemLogger extends SystemLogger
{
	private static final String MODULE = "TrueMonitorSystemLogger";

	private static TrueMonitorSystemLogger _oTrueMonitorSystemLogger;

	// This is a Singleton
	private TrueMonitorSystemLogger() {
	}

	// @return A static handle to the system logger.
	public static TrueMonitorSystemLogger getHandle()
	{
		if (_oTrueMonitorSystemLogger == null)
			_oTrueMonitorSystemLogger = new TrueMonitorSystemLogger();

		return _oTrueMonitorSystemLogger;
	}
	
	public void init(TrueMonitorConfigManager oConfigManager, Object oLogSection, String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "init";
		TrueMonitorSystemLogger oTrueMonitorLogger = TrueMonitorSystemLogger.getHandle();

		
		String sLogLevel = oConfigManager.getSimpleParam(oLogSection, "level", true);
		Level logLevel = Level.parse(sLogLevel);
		String sLogTarget = oConfigManager.getSimpleParam(oLogSection, "target", true);
		Object oLogTarget = oConfigManager.getSectionFromSection(oLogSection, "target", "id=" + sLogTarget, true);

		oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "Go logTarget="+oLogTarget);
		oTrueMonitorLogger.init("system", "org.aselect.truemonitor.TrueMonitorSystemLogger", oConfigManager, oLogTarget, sWorkingDir);
		oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "====");
		oTrueMonitorLogger.setLevel(logLevel);

		// First line that will go to the log file
		log(Level.INFO, MODULE, sMethod, "Starting True Monitor 2");
	}
}
