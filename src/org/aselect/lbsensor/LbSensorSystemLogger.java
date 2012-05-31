/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.lbsensor;

import java.util.logging.Level;

import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;

public class LbSensorSystemLogger extends SystemLogger
{
	private static final String MODULE = "LbSensorSystemLogger";

	private static LbSensorSystemLogger _oLbSensorSystemLogger;

	// This is a Singleton
	/**
	 * Instantiates a new lb sensor system logger.
	 */
	private LbSensorSystemLogger() {
	}

	// @return A static handle to the system logger.
	/**
	 * Gets the handle.
	 * 
	 * @return the handle
	 */
	public static LbSensorSystemLogger getHandle()
	{
		if (_oLbSensorSystemLogger == null)
			_oLbSensorSystemLogger = new LbSensorSystemLogger();

		return _oLbSensorSystemLogger;
	}

	/**
	 * Initializes the logger.
	 * 
	 * @param oConfigManager
	 *            the config manager
	 * @param oLogSection
	 *            the log section
	 * @param sWorkingDir
	 *            the working dir
	 * @throws ASelectException
	 *             the aselect exception
	 */
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
		log(Level.INFO, MODULE, sMethod, "Systemlogger initialized, level="+logLevel);
	}
}
