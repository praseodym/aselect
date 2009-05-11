package org.aselect.truemonitor;

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
}
