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
 * $Id: SystemLogger.java,v 1.24 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: SystemLogger.java,v $
 * Revision 1.24  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.23  2006/04/12 13:20:41  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.22.4.1  2006/02/06 09:42:35  martijn
 * log level for stack traces moved from FINER to FINEST
 *
 * Revision 1.22  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.21  2005/08/19 07:52:18  martijn
 * fixed logging bug in init() method
 *
 * Revision 1.20  2005/04/15 10:15:22  martijn
 * fixed bug in closeHandlers() that threw a NullPointerException if the SystemLogger init() method was is been called
 *
 * Revision 1.19  2005/03/21 09:58:31  tom
 * Removed constant replacing
 *
 * Revision 1.17  2005/03/15 16:29:22  tom
 * Fixed Javadoc
 *
 * Revision 1.16  2005/03/10 17:29:43  martijn
 * fixed bug in building the logging directory structure
 *
 * Revision 1.15  2005/03/10 17:02:43  martijn
 * moved reading of the system logger configuration to the right classes, so changed init() methods
 *
 * Revision 1.14  2005/03/09 12:50:52  erwin
 * Added throwable to System.err log message.
 *
 * Revision 1.13  2005/03/09 12:09:43  tom
 * nieuwe log functie bepaalt de opmaak van de logging
 *
 * Revision 1.12  2005/03/09 11:33:02  erwin
 * Added additional log methods. format... methods are deprecated.
 *
 * Revision 1.11  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.10  2005/02/25 15:53:30  erwin
 * Renamed private Logger.
 *
 * Revision 1.9  2005/02/25 08:36:34  erwin
 * Added isDebug()
 *
 * Revision 1.8  2005/02/24 15:22:42  erwin
 * Added extra '\n' after stacktrace.
 *
 * Revision 1.7  2005/02/24 15:16:47  erwin
 * Moved set default level to init method.
 *
 * Revision 1.5  2005/02/24 14:36:53  erwin
 * Improved debug logging.
 *
 * Revision 1.4  2005/02/23 15:55:19  erwin
 * Added setLevel()
 *
 * Revision 1.3  2005/02/21 16:25:58  erwin
 * Applied code style and improved JavaDoc.
 *
 */

package org.aselect.system.logging;

import java.io.File;
import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.logging.Level;

import org.apache.log4j.Logger;

import org.aselect.system.configmanager.IConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;

/**
 * The logger to write system log entries. <br>
 * <br>
 * <b>Description: </b> <br>
 * The system logger writes system log entries to a file. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public class SystemLoggerAudit implements ISystemLogger
{
	/** The module name. */
	private final String MODULE = "SystemLoggerAudit";
	/**
	 * The default value of the maximum log file size
	 */
	private final static int MAXLOGSIZE = 307200;
	/**
	 * The default value for the seperate log files that are used
	 */
	private final static int LOGFILES = 4;

	/** The logger. */
	private Logger _oLogger;

	/** debug mode */
	private boolean _bDebug = false;

	/**
	 * Default constructor.
	 */
	public SystemLoggerAudit() {
	}

	/**
	 * Initializes the System logger. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * <li>Reads configuration</li> <li>Creates a <code>FileHandler</code> object and sets it's log level.</li> <li>
	 * Creates a <code>Logger</code> object and sets it's log level.</li> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li><i>oConfigManager</i> must be initialized</li> <li><i>oConfigManager</i> may not be <code>null</code></li>
	 * <li><i>oLogTargetConfig</i> may not be <code>null</code></li> <li><i>oSystemLoggerAudit</i> may not be
	 * <code>null</code></li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * Sets <i>_systemLogger</i> class vairable and initializes it. <br>
	 * 
	 * @param sLogFileNamePrefix
	 *            The log file name prefix (".log" is appended).
	 * @param sLoggerNamespace
	 *            The namespace of this system logger.
	 * @param oConfigManager
	 *            The config manager used to retrieve the configuration from
	 * @param oLogTargetConfig
	 *            The 'target' config section containing the file configuration
	 * @param sWorkingDir
	 *            The workingdir that must be used when no directory is configured
	 * @throws ASelectException
	 *             if initializing failed (missing config items)
	 */
	public void init(String sLogFileNamePrefix, String sLoggerNamespace, IConfigManager oConfigManager,
			Object oLogTargetConfig, String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "init";

		int iLogMaxSize = -1;
		int iLogFiles = -1;
		StringBuffer sbSysLogDir = null;

		this.log(Level.INFO, MODULE, sMethod, "Initialize SystemLoggerAudit");
		try {
			if (oLogTargetConfig == null) {
				this.log(Level.CONFIG, MODULE, sMethod,
						"No valid config section supplied, using default logging settings.");

				iLogMaxSize = MAXLOGSIZE;
				iLogFiles = LOGFILES;

				sbSysLogDir = new StringBuffer(sWorkingDir);
				sbSysLogDir.append(File.separator);
				sbSysLogDir.append("log");
				sbSysLogDir.append(File.separator);
			}
			else {
				try {
					iLogMaxSize = new Integer(oConfigManager.getParam(oLogTargetConfig, "max_file_size")).intValue();
				}
				catch (Exception e) {
					iLogMaxSize = MAXLOGSIZE;

					StringBuffer sbInfo = new StringBuffer(
							"No valid config item: 'max_file_size' in config section 'target' found, using default value: ");
					sbInfo.append(iLogMaxSize);
					this.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString(), e);
				}

				try {
					iLogFiles = new Integer(oConfigManager.getParam(oLogTargetConfig, "nr_of_files")).intValue();
				}
				catch (Exception e) {
					iLogFiles = LOGFILES;

					StringBuffer sbInfo = new StringBuffer(
							"No valid config item: 'nr_of_files' in config section 'target' found, using default value: ");
					sbInfo.append(iLogFiles);
					this.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString(), e);
				}

				try {
					String sSysLogDir = oConfigManager.getParam(oLogTargetConfig, "directory");

					// prepare the logging dir variable
					if (!sSysLogDir.endsWith(File.separator))
						sSysLogDir += File.separator;

					File fSysLogDir = new File(sSysLogDir);
					if (!fSysLogDir.exists()) {
						StringBuffer sbInfo = new StringBuffer(
								"The configured system logging dir doesn't exist, try to create directory: ");
						sbInfo.append(sSysLogDir);
						this.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

						if (!fSysLogDir.mkdirs())
							throw new ASelectException(Errors.ERROR_ASELECT_IO);
					}

					sbSysLogDir = new StringBuffer(sSysLogDir);
				}
				catch (Exception e) {
					sbSysLogDir = new StringBuffer(sWorkingDir);
					sbSysLogDir.append(File.separator);
					sbSysLogDir.append("log");
					sbSysLogDir.append(File.separator);

					StringBuffer sbInfo = new StringBuffer(
							"No valid config item: 'directory' in config section 'target' found, using default directory: ");
					sbInfo.append(sbSysLogDir.toString());

					this.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString(), e);
				}
			}

			// logging dir
			sbSysLogDir.append(sLogFileNamePrefix);

			// check if logging dir exists, otherwise try to create
			File fSysLogDir = new File(sbSysLogDir.toString());
			if (!fSysLogDir.exists()) {
				StringBuffer sbInfo = new StringBuffer("System logging dir doesn't exist, try to create directory: ");
				sbInfo.append(sbSysLogDir.toString());
				this.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

				if (!fSysLogDir.mkdirs()) {
					StringBuffer sbFailed = new StringBuffer("Could not access the system logging directory: ");
					sbFailed.append(sbSysLogDir.toString());
					// This is actually an error, we cannot/want not continue
					// this.log(Level.CONFIG, MODULE, sMethod, sbFailed.toString());
					this.log(Level.SEVERE, MODULE, sMethod, sbFailed.toString());
					throw new ASelectException(Errors.ERROR_ASELECT_IO);
				}
			}

			// create log file
			StringBuffer sbLogFile = new StringBuffer(sbSysLogDir.toString());
			sbLogFile.append(File.separator);
			sbLogFile.append(sLogFileNamePrefix);
			sbLogFile.append("%g.log");

			// create file handler
			// FileHandler oFileHandler = new FileHandler(sbLogFile.toString(), iLogMaxSize, iLogFiles, true);
			// oFileHandler.setFormatter(new SystemLogFormatter());
			// oFileHandler.setLevel(Level.ALL);

			// getlogger and set handler
			// 1.5.4 Avoid multiple A-Select servers in the same VM all writing to the same logfile
			// _oLogger = Logger.getLogger(sLoggerNamespace+"."+this.hashCode());
			_oLogger = Logger.getLogger(sLoggerNamespace);
			// _oLogger.addHandler(oFileHandler);
			setLevel(Level.FINE);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			// This is actually an error, we cannot/want not continue
			// this.log(Level.CONFIG, MODULE, sMethod, "Could not initialize System Logger", e);
			this.log(Level.SEVERE, MODULE, sMethod, "Could not initialize System Logger", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Write a log item. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Log the given message with the given level to the system log. <br>
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
	 * @param level
	 *            The level of the log item.
	 * @param sMessage
	 *            The message to be logged.
	 */
	public void log(Level level, String sMessage)
	{
		try {
			_oLogger.log(mapLevel(level), sMessage);
		}
		catch (Exception e) // logging to file failed
		{
			// log to system.err
			StringBuffer sbLogMessage = new StringBuffer("[");
			sbLogMessage.append(new Date().toString()).append("] ");
			sbLogMessage.append(sMessage);
			System.err.println(sbLogMessage);
		}
	}

	/**
	 * Write a log item with a cause. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Log the given message with extended information from the cause and the given level to the system log. <br>
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
	 * @param level
	 *            The level of the log item.
	 * @param sMessage
	 *            The message to be logged.
	 * @param cause
	 *            The <code>Throwable</code> that causes this log item.
	 */
	public void log(Level level, String sMessage, Throwable cause)
	{
		try {
			// _oLogger.log(level, sMessage, cause);
			// RH, 20090127, sn
			// We only want stacktraces if debug is enabled
			// This used to be done by the SystemLogFormatter, but we don 't use that anymore
			if (!isDebug()) {
				_oLogger.log(mapLevel(level), sMessage);
			}
			else
				// RH, 20090127, en
				_oLogger.log(mapLevel(level), sMessage, cause);

		}
		catch (Exception e) // loggen naar file mislukt
		{
			StringBuffer sbLogMessage = new StringBuffer("[");
			sbLogMessage.append(new Date().toString()).append("] ");
			sbLogMessage.append(sMessage);
			sbLogMessage.append(", cause: ");
			sbLogMessage.append(cause.getMessage());
			System.err.println(sbLogMessage);
		}
	}

	/**
	 * Write a log item with additional information. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Formats a log message and log this message. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>level != null</code></li>
	 * <li><code>sModule != null</code></li>
	 * <li><code>sMethod != null</code></li>
	 * <li><code>sMessage != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param level
	 *            The log level.
	 * @param sModule
	 *            The module name.
	 * @param sMethod
	 *            The method name.
	 * @param sMessage
	 *            The log message.
	 */
	public void log(Level level, String sModule, String sMethod, String sMessage)
	{
		StringBuffer sbError = new StringBuffer(sModule);
		sbError.append(".");
		sbError.append(sMethod);
		sbError.append(" -> ");
		sbError.append(sMessage);
		log(level, sbError.toString());

	}

	/**
	 * Write a log item with additional information and a cause. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Formats a log message and log this message including the cause. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>level != null</code></li>
	 * <li><code>sModule != null</code></li>
	 * <li><code>sMethod != null</code></li>
	 * <li><code>sMessage != null</code></li>
	 * <li><code>cause != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param level
	 *            The log level.
	 * @param sModule
	 *            The module name.
	 * @param sMethod
	 *            The method name.
	 * @param sMessage
	 *            The log message.
	 * @param cause
	 *            the logging cause.
	 */
	public void log(Level level, String sModule, String sMethod, String sMessage, Throwable cause)
	{
		StringBuffer sbError = new StringBuffer(sModule);
		sbError.append(".");
		sbError.append(sMethod);
		sbError.append(" -> ");
		sbError.append(sMessage);
		log(level, sbError.toString(), cause);
	}

	/**
	 * Set the level of the system logger. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Set the log level of this system logger. The follwoing levels are valid: <br>
	 * <br>
	 * <table border=1 cellspacing=0 cellpadding=2>
	 * <tr BGCOLOR="#CCCCFF" CLASS="TableHeadingColor">
	 * <th align=left>Level</th>
	 * <th align=left>Description</th>
	 * </tr>
	 * <tr>
	 * <td><code>SEVERE</code></td>
	 * <td>highest value; severe problems</td>
	 * </tr>
	 * <tr>
	 * <td><code>WARNING</code></td>
	 * <td>warning messages</td>
	 * </tr>
	 * <tr>
	 * <td><code>INFO</code></td>
	 * <td>Information messages</td>
	 * </tr>
	 * <tr>
	 * <td><code>CONFIG</code></td>
	 * <td>Configuration messages</td>
	 * </tr>
	 * <tr>
	 * <td><code>FINE</code></td>
	 * <td>Extra information like received or sent data.</td>
	 * </tr>
	 * <tr>
	 * <td><code>FINER</code></td>
	 * <td>If this level is specified the logger will also log stacktraces if available.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>oLevel != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b>
	 * <ul>
	 * <li>The new level is set</li>
	 * <li>If <code>Level &lt;= FINER</code> bebug mode is enabled.</li>
	 * </ul>
	 * 
	 * @param oLevel
	 *            The new <code>Level</code> to use.
	 */
	public void setLevel(Level oLevel)
	{
		_bDebug = (oLevel.intValue() < Level.FINER.intValue());
		// _oLogger.setUseParentHandlers(_bDebug);
		_oLogger.setLevel(mapLevel(oLevel));
	}

	/**
	 * Cleanup logger resources. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Closes all openend log handlers. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All used log handlers are closed. <br>
	 */
	public void closeHandlers()
	{
		// if (_oLogger != null)
		// {
		// Handler[] handlers = _oLogger.getHandlers();
		// for (int c = 0; c < handlers.length; c++)
		// {
		// if (handlers[c] instanceof FileHandler)
		// {
		// FileHandler handler = (FileHandler)handlers[c];
		// handler.close();
		// }
		// _oLogger.removeHandler(handlers[c]);
		// }
		// }
	}

	/**
	 * A log formatter for system log items. SystemLogFormatter <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This formatter formats log messages with the following syntax: <br>
	 * <code>"[" [timestamp] "]" - [Level]: [message]</code> <br>
	 * <br>
	 * If dedugging is enabled (Log level &lt;= FINER) the stacktraces of exceptions are also logged if available. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * 
	 * @author Alfa & Ariss
	 */
	class SystemLogFormatter extends Formatter
	{
		
		/**
		 * Format the log message for system logging.
		 * 
		 * @param oRecord
		 *            the o record
		 * @return the string
		 * @see java.util.logging.Formatter#format(java.util.logging.LogRecord)
		 */
		@Override
		public String format(LogRecord oRecord)
		{
			// Default log message
			StringBuffer sbBuffer = new StringBuffer("[");
			sbBuffer.append(new Date().toString());
			sbBuffer.append("] - ");
			String sLevel = oRecord.getLevel().getName();
			sbBuffer.append(sLevel);
			sbBuffer.append(": ");
			for (int i = 0; i < 7 - sLevel.length(); i++)
				sbBuffer.append(' ');
			sbBuffer.append(oRecord.getMessage());

			// additional throwable
			Throwable oThrowable = oRecord.getThrown();
			if (oThrowable != null) // throwable available
			{
				sbBuffer.append(", Cause: " + oThrowable.getMessage());
				if (_bDebug) // debugging enabled
				{
					// additional Stacktrace
					sbBuffer.append("\nStacktrace {\n");
					sbBuffer.append("\t").append(oThrowable).append("\n");

					StackTraceElement soElements[] = oThrowable.getStackTrace();
					for (int i = 0; i < soElements.length; i++) {
						sbBuffer.append("\t\t at ").append(soElements[i]).append("\n");
					}
					sbBuffer.append("}\n");
				}
			}
			sbBuffer.append("\n");
			return sbBuffer.toString();
		}
	}

	/**
	 * Checks if is debug.
	 * 
	 * @return Returns true if debug level is enabled otherwise false.
	 */
	public boolean isDebug()
	{
		return _bDebug;
	}

	// Custom mapping from a-select (j.u.l.) levels to log4j levels
	/**
	 * Map level.
	 * 
	 * @param level
	 *            the level
	 * @return the org.apache.log4j. level
	 */
	protected org.apache.log4j.Level mapLevel(Level level)
	{
		// a-select (incorrectly?) issues CONFIG levels for configuration errors
		// These would normally be mapped to DEBUG which in turn issues a stacktrace
		// This is not what we wan't so treat CONFIG differently here
		if (level.equals(Level.CONFIG))
			return org.apache.log4j.Level.WARN;

		if (level.intValue() <= Level.ALL.intValue()) {
			return org.apache.log4j.Level.ALL;
		}
		else if (level.intValue() <= Level.FINEST.intValue()) {
			return org.apache.log4j.Level.TRACE;
		}
		else if (level.intValue() <= Level.FINE.intValue()) {
			return org.apache.log4j.Level.DEBUG;
		}
		else if (level.intValue() <= Level.INFO.intValue()) {
			return org.apache.log4j.Level.INFO;
		}
		else if (level.intValue() <= Audit.AUDIT.intValue()) {
			return AuditLevel.AUDIT;
		}
		else if (level.intValue() <= Level.WARNING.intValue()) {
			return org.apache.log4j.Level.WARN;
		}
		else if (level.intValue() <= Level.SEVERE.intValue()) {
			return org.apache.log4j.Level.ERROR;
		}
		else
			return org.apache.log4j.Level.OFF;
	}
}