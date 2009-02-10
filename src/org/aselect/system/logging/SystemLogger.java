package org.aselect.system.logging;

import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;

public class SystemLogger implements ISystemLogger {

//	private String className = "org.aselect.system.logging.SystemLoggerAudit"; 
	private final static String DEFAULTSYSTEMLOGGER = "org.aselect.system.logging.SystemLogger_org"; 
	private ISystemLogger _logger;
	private String className;
	
	public SystemLogger()
	{
        
        try
        {
            className = System.getProperty("org.aselect.system.logging.SystemLogger");
        	if (className == null) className = DEFAULTSYSTEMLOGGER;
        	_logger = (ISystemLogger) Class.forName(className).newInstance();
        	System.out.println("Using systemlogger:" + className);
		} catch (InstantiationException e) {
			System.err.println(Errors.ERROR_ASELECT_INIT_ERROR + ":" + e);
		} catch (IllegalAccessException e) {
			System.err.println(Errors.ERROR_ASELECT_INIT_ERROR + ":" + e);
		} catch (ClassNotFoundException e) {
			System.err.println(Errors.ERROR_ASELECT_INIT_ERROR + ":" + e);
		}
	}

	public void closeHandlers() {
		_logger.closeHandlers();
	}

	public void init(String logFileNamePrefix, String loggerNamespace,
			ConfigManager configManager, Object logTargetConfig,
			String workingDir) throws ASelectException {
		_logger.init(logFileNamePrefix, loggerNamespace, configManager, logTargetConfig, workingDir);
	}

	public boolean isDebug() {
		return _logger.isDebug();
	}

	public void log(Level level, String message) {
		_logger.log(level, message);
	}

	public void log(Level level, String message, Throwable cause) {
		_logger.log(level, message, cause);
	}

	public void log(Level level, String module, String method, String message) {
		_logger.log(level, module, method, message);
	}

	public void log(Level level, String module, String method, String message,
			Throwable cause) {
		_logger.log(level, module, method, message, cause);

	}

	public void setLevel(Level level) {
		_logger.setLevel(level);
	}

}
