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

import java.util.logging.Level; //import org.apache.log4j.Level;

import org.aselect.system.configmanager.IConfigManager;
import org.aselect.system.exception.ASelectException;

public interface ISystemLogger
{

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
	 * <li><i>oLogTargetConfig</i> may not be <code>null</code></li> <li><i>oSystemLogger</i> may not be
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
	public abstract void init(String sLogFileNamePrefix, String sLoggerNamespace, IConfigManager oConfigManager,
			Object oLogTargetConfig, String sWorkingDir)
	throws ASelectException;

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
	public abstract void log(Level level, String sMessage);

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
	public abstract void log(Level level, String sMessage, Throwable cause);

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
	public abstract void log(Level level, String sModule, String sMethod, String sMessage);

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
	public abstract void log(Level level, String sModule, String sMethod, String sMessage, Throwable cause);

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
	public abstract void setLevel(Level oLevel);

	/**
	 * Cleanup logger resources. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Closes all opened log handlers. <br>
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
	public abstract void closeHandlers();

	/**
	 * Checks if is debug.
	 * 
	 * @return Returns true if debug level is enabled otherwise false.
	 */
	public abstract boolean isDebug();

}