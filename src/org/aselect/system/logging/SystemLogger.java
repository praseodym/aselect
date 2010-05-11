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
package org.aselect.system.logging;

import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;

public class SystemLogger implements ISystemLogger
{
	// private String className = "org.aselect.system.logging.SystemLoggerAudit";
	private final static String DEFAULTSYSTEMLOGGER = "org.aselect.system.logging.SystemLogger_org";
	private ISystemLogger _logger;
	private String className;

	/**
	 * Instantiates a new system logger.
	 */
	public SystemLogger()
	{
		try {
			className = System.getProperty("org.aselect.system.logging.SystemLogger");
			if (className == null)
				className = DEFAULTSYSTEMLOGGER;
			_logger = (ISystemLogger) Class.forName(className).newInstance();
			System.out.println("Using systemlogger:" + className);
		}
		catch (InstantiationException e) {
			System.err.println(Errors.ERROR_ASELECT_INIT_ERROR + ":" + e);
		}
		catch (IllegalAccessException e) {
			System.err.println(Errors.ERROR_ASELECT_INIT_ERROR + ":" + e);
		}
		catch (ClassNotFoundException e) {
			System.err.println(Errors.ERROR_ASELECT_INIT_ERROR + ":" + e);
		}
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.logging.ISystemLogger#closeHandlers()
	 */
	public void closeHandlers()
	{
		_logger.closeHandlers();
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.logging.ISystemLogger#init(java.lang.String, java.lang.String, org.aselect.system.configmanager.ConfigManager, java.lang.Object, java.lang.String)
	 */
	public void init(String logFileNamePrefix, String loggerNamespace, ConfigManager configManager,
			Object logTargetConfig, String workingDir)
	throws ASelectException
	{
		_logger.init(logFileNamePrefix, loggerNamespace, configManager, logTargetConfig, workingDir);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.logging.ISystemLogger#isDebug()
	 */
	public boolean isDebug()
	{
		return _logger.isDebug();
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.logging.ISystemLogger#log(java.util.logging.Level, java.lang.String)
	 */
	public void log(Level level, String message)
	{
		_logger.log(level, message);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.logging.ISystemLogger#log(java.util.logging.Level, java.lang.String, java.lang.Throwable)
	 */
	public void log(Level level, String message, Throwable cause)
	{
		_logger.log(level, message, cause);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.logging.ISystemLogger#log(java.util.logging.Level, java.lang.String, java.lang.String, java.lang.String)
	 */
	public void log(Level level, String module, String method, String message)
	{
		_logger.log(level, module, method, message);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.logging.ISystemLogger#log(java.util.logging.Level, java.lang.String, java.lang.String, java.lang.String, java.lang.Throwable)
	 */
	public void log(Level level, String module, String method, String message, Throwable cause)
	{
		_logger.log(level, module, method, message, cause);
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.logging.ISystemLogger#setLevel(java.util.logging.Level)
	 */
	public void setLevel(Level level)
	{
		_logger.setLevel(level);
	}
}
