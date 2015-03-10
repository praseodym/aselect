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
 * $Id: ASelectAuthenticationLogger.java,v 1.14 2006/04/26 12:18:08 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectAuthenticationLogger.java,v $
 * Revision 1.14  2006/04/26 12:18:08  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.13  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.12  2005/04/15 11:51:23  tom
 * Removed old logging statements
 *
 * Revision 1.11  2005/03/11 12:32:01  erwin
 * Changed log levels.
 *
 * Revision 1.10  2005/03/10 14:17:45  erwin
 * Improved Javadoc.
 *
 * Revision 1.9  2005/03/10 12:49:28  martijn
 * fixed typo in logging
 *
 * Revision 1.8  2005/03/10 12:06:18  martijn
 * added javadoc to the new functions
 *
 * Revision 1.7  2005/03/10 11:11:54  martijn
 * moved the config retrieving from the ASelect component to the AuthenticationLogger
 *
 * Revision 1.6  2005/03/09 10:58:25  tom
 * Javadoc: added return value description to getHandle
 *
 * Revision 1.5  2005/03/04 13:30:47  peter
 * naming convention, javadoc, code style
 *
 * Revision 1.4  2005/02/25 15:02:34  martijn
 * it now inherits from org.aselect.system.log.AuthenticationLogger
 *
 */

package org.aselect.server.log;

import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.AuthenticationLogger;


/**
 * The authentication logger for the A-Select Server. <br>
 * <br>
 * <b>Description:</b><br>
 * A singleton authentication logger that inherits from <code>org.aselect.system.logging.AuthenticationLogger</code>.
 * This logger creates a log file that can be used for user accounting. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - The class is a singleton, so the same class is used in all the classes of the A-Select Server. <br>
 * 
 * @author Alfa & Ariss
 */
public class ASelectAuthenticationLogger extends AuthenticationLogger
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "ASelectAuthenticationLogger";

	// Needed to make this class a singleton.
	private static ASelectAuthenticationLogger _oASelectAuthenticationLogger;

	/**
	 * Must be used to get an ASelectAuthenticationLogger instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new <code>ASelectAuthenticationLogger</code> instance if it's still <code>null</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * Always the same instance of the authentication logger is returned, because it's a singleton. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return handle to the ASelectAuthenticationLogger
	 */
	public static ASelectAuthenticationLogger getHandle()
	{
		if (_oASelectAuthenticationLogger == null) {
			_oASelectAuthenticationLogger = new ASelectAuthenticationLogger();
		}
		return _oASelectAuthenticationLogger;
	}

	/**
	 * Initializes the Authentication Logger. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * <li>Reads the 'target' config section</li> <li>Calls the init of the <i>_oASelectAuthenticationLogger</i></li>
	 * <li>Reads the 'target' config section</li> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>The <i>ASelectSystemLogger</i> must be initialized.</li> <li>The <i>ASelectConfigManager</i> must be
	 * initialized.</li> <li>The <i>oAuthLogging</i> may not be <code>NULL</code>.</li> <li>The <i>sWorkingDir</i> may
	 * not be <code>NULL</code>.</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * An initialized <i>_oASelectAuthenticationLogger</i>. <br>
	 * 
	 * @param oAuthLogging
	 *            The logger config section with id='authentication'
	 * @param sWorkingDir
	 *            The A-Select working dir
	 * @throws ASelectException
	 *             if initialization went wrong
	 */
	public void init(Object oAuthLogging, String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "init";
		String sAuthLogTarget = null;
		Object oAuthLogTarget = null;
		ASelectSystemLogger oASelectSystemLogger = null;
		ASelectConfigManager oASelectConfigManager = null;
		try {
			try {
				oASelectSystemLogger = ASelectSystemLogger.getHandle();
				oASelectConfigManager = ASelectConfigManager.getHandle();

				try {
					sAuthLogTarget = oASelectConfigManager.getParam(oAuthLogging, "target");
				}
				catch (Exception e) {
					sAuthLogTarget = null;

					oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
							"No valid config item: 'target' in config section 'logging' with id='authentication' found.", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}

				try {
					oAuthLogTarget = oASelectConfigManager.getSection(oAuthLogging, "target", "id=" + sAuthLogTarget);
				}
				catch (Exception e) {
					oAuthLogTarget = null;

					StringBuffer sbInfo = new StringBuffer("No valid config section: 'target' with id='");
					sbInfo.append(sAuthLogTarget);
					sbInfo.append("' in config section 'logging' with id='authentication' found.");
					oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbInfo.toString(), e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}
			}
			catch (Exception e) {
				oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid config section 'logging' with id='authentication' found, using default logging settings.", e);
			}

			if (oAuthLogTarget != null && sAuthLogTarget != null && sAuthLogTarget.equalsIgnoreCase("database")) {
				_oASelectAuthenticationLogger.init("A-Select Server", oASelectConfigManager, oAuthLogTarget,
						oASelectSystemLogger);
			}
			else {
				_oASelectAuthenticationLogger.init("A-Select Server", "authentication",
						"org.aselect.server.log.ASelectAuthenticationLogger", oASelectConfigManager, oAuthLogTarget,
						oASelectSystemLogger, sWorkingDir);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not initialize A-Select Authentication Logger.", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

	}

	/**
	 * Must be private, so it can not be used. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Must be private because getHandle() must be used to retrieve an instance. This is done for singleton purposes. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 */
	private ASelectAuthenticationLogger() {
	}

}