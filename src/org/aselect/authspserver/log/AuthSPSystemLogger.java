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
 * $Id: AuthSPSystemLogger.java,v 1.8 2006/05/03 10:08:49 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthSPSystemLogger.java,v $
 * Revision 1.8  2006/05/03 10:08:49  tom
 * Removed Javadoc version
 *
 * Revision 1.7  2005/09/08 12:47:54  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.6  2005/04/28 09:15:31  erwin
 * Default level set to CONFIG
 *
 * Revision 1.5  2005/03/11 13:27:07  erwin
 * Improved error handling.
 *
 * Revision 1.4  2005/03/10 17:18:10  martijn
 * moved reading of the system logger configuration to the right classes, so changed init() methods
 *
 * Revision 1.3  2005/02/24 12:16:11  martijn
 * added java documentation and changed variable names
 *
 * Revision 1.2  2005/02/24 08:45:05  martijn
 * added java documentation and changed variable names
 *
 */
package org.aselect.authspserver.log;

import java.util.logging.Level;

import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;

// TODO: Auto-generated Javadoc
/**
 * A singleton class for the <code>SystemLogger</code> that logs system information. <br>
 * <br>
 * <b>Description:</b><br>
 * Singleton class for the <code>SystemLogger</code> that is located in the org.aselect.system package. It is used for
 * logging system information only. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class AuthSPSystemLogger extends SystemLogger
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "AuthSPSystemLogger";

	/**
	 * The singleton instance of this object
	 */
	private static AuthSPSystemLogger _oAuthSPSystemLogger;

	/**
	 * Method to return the instance of the <code>SystemLogger</code>. <br>
	 * 
	 * @return Static <code>SystemLogger</code> instance
	 */
	public static AuthSPSystemLogger getHandle()
	{
		if (_oAuthSPSystemLogger == null)
			_oAuthSPSystemLogger = new AuthSPSystemLogger();

		return _oAuthSPSystemLogger;
	}

	/**
	 * Initializes the System Logger. <br>
	 * <br>
	 * <b>Description:</b>
	 * <ul>
	 * <li>Reads the 'target' config section</li>
	 * <li>Calls the init of the <i>_oAuthSPSystemLogger</i></li>
	 * <li>Reads the 'target' config section</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The <i>AuthSPSystemLogger</i> must be initialized.</li>
	 * <li>The <i>AuthSPConfigManager</i> must be initialized.</li>
	 * <li>The <i>oSysLogging</i> may not be <code>NULL</code>.</li>
	 * <li>The <i>sWorkingDir</i> may not be <code>NULL</code>.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * An initialized <i>_oAuthSPSystemLogger</i>. <br>
	 * 
	 * @param oSysLogging
	 *            The logger config section with id='system'
	 * @param sWorkingDir
	 *            The AuthSP working dir
	 * @throws ASelectException
	 *             if initialization went wrong
	 */
	public void init(Object oSysLogging, String sWorkingDir)
		throws ASelectException
	{
		String sMethod = "init()";

		Level levelSysLog = null;
		String sSysLogTarget = null;
		Object oSysLogTarget = null;
		AuthSPSystemLogger oAuthSPSystemLogger = null;
		AuthSPConfigManager oAuthSPConfigManager = null;
		try {
			try {
				oAuthSPSystemLogger = AuthSPSystemLogger.getHandle();
				oAuthSPConfigManager = AuthSPConfigManager.getHandle();

				try {
					String sSysLogLevel = oAuthSPConfigManager.getParam(oSysLogging, "level");
					levelSysLog = Level.parse(sSysLogLevel);
				}
				catch (Exception e) {
					levelSysLog = Level.CONFIG;
					oAuthSPSystemLogger
							.log(
									Level.CONFIG,
									MODULE,
									sMethod,
									"No valid config item: 'level' in config section 'logging' with id='system' found, using default level: CONFIG",
									e);
				}

				try {
					sSysLogTarget = oAuthSPConfigManager.getParam(oSysLogging, "target");
				}
				catch (Exception e) {
					sSysLogTarget = null;
					oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod,
							"No valid config item: 'target' in config section 'logging' with id='system' found", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					oSysLogTarget = oAuthSPConfigManager.getSection(oSysLogging, "target", "id=" + sSysLogTarget);
				}
				catch (Exception e) {
					oSysLogTarget = null;

					StringBuffer sbInfo = new StringBuffer("No valid config section: 'target' with id='");
					sbInfo.append(sSysLogTarget);
					sbInfo.append("' in config section 'logging' with id='system' found");
					oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, sbInfo.toString(), e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
			}
			catch (Exception e) {
				oAuthSPSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid config section 'logging' with id='system' found, using default logging settings", e);
			}

			_oAuthSPSystemLogger.init("system", "org.aselect.authspserver.log.AuthSPSystemLogger",
					oAuthSPConfigManager, oSysLogTarget, sWorkingDir);

			_oAuthSPSystemLogger.setLevel(levelSysLog);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			oAuthSPSystemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not initialize A-Select AuthSP System Logger.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

	}

	/**
	 * Constructor that has been made private for singleton purposes.
	 */
	private AuthSPSystemLogger() {
	}
}