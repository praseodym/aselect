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
 * $Id: AuthSPAuthenticationLogger.java,v 1.6 2006/05/03 10:08:49 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthSPAuthenticationLogger.java,v $
 * Revision 1.6  2006/05/03 10:08:49  tom
 * Removed Javadoc version
 *
 * Revision 1.5  2005/09/08 12:47:54  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.4  2005/03/15 16:26:47  tom
 * Fixed Javadoc
 *
 * Revision 1.3  2005/03/11 13:27:07  erwin
 * Improved error handling.
 *
 * Revision 1.2  2005/03/10 12:44:13  martijn
 * moved the config retrieving from the ASelect component to the AuthenticationLogger: resulted in a new init() method in the AuthSPAuthenticationLogger class
 *
 * Revision 1.1  2005/03/01 13:11:59  martijn
 * renamed AuthenticationLogger to AuthSPAuthenticationLogger
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
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.AuthenticationLogger;

// TODO: Auto-generated Javadoc
/**
 * A singleton class for the <code>SystemLogger</code> that logs Authentication information. <br>
 * <br>
 * <b>Description:</b><br>
 * Singleton class for the <code>SystemLogger</code> that is located in the org.aselect.system package. It is used for
 * logging authentication information only. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class AuthSPAuthenticationLogger extends AuthenticationLogger
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "AuthSPAuthenticationLogger";

	/**
	 * The singleton instance of this object
	 */
	private static AuthSPAuthenticationLogger _oAuthSPAuthenticationLogger;

	/**
	 * Method to return the instance of the <code>SystemLogger</code>. <br>
	 * 
	 * @return always the same <code>SystemLogger</code> instance
	 */
	public static AuthSPAuthenticationLogger getHandle()
	{
		if (_oAuthSPAuthenticationLogger == null)
			_oAuthSPAuthenticationLogger = new AuthSPAuthenticationLogger();

		return _oAuthSPAuthenticationLogger;
	}

	/**
	 * Initializes the Authentication Logger. <br>
	 * <br>
	 * <b>Description:</b>
	 * <ul>
	 * <li>Reads the 'target' config section</li>
	 * <li>Calls the init of the <i>_oAuthSPAuthenticationLogger</i></li>
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
	 * <li>The <i>oAuthLogging</i> may not be <code>NULL</code>.</li>
	 * <li>The <i>sWorkingDir</i> may not be <code>NULL</code>.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * An initialized <i>_oAuthSPAuthenticationLogger</i>. <br>
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
		String sMethod = "init()";

		String sAuthLogTarget = null;
		Object oAuthLogTarget = null;
		AuthSPSystemLogger oAuthSPSystemLogger = null;
		AuthSPConfigManager oAuthSPConfigManager = null;
		try {
			try {
				oAuthSPSystemLogger = AuthSPSystemLogger.getHandle();
				oAuthSPConfigManager = AuthSPConfigManager.getHandle();

				try {
					sAuthLogTarget = oAuthSPConfigManager.getParam(oAuthLogging, "target");
				}
				catch (ASelectConfigException eAC) {
					sAuthLogTarget = null;
					oAuthSPSystemLogger
							.log(
									Level.WARNING,
									MODULE,
									sMethod,
									"No valid config item: 'target' in config section 'logging' with id='authentication' found.",
									eAC);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
				}

				try {
					oAuthLogTarget = oAuthSPConfigManager.getSection(oAuthLogging, "target", "id=" + sAuthLogTarget);
				}
				catch (ASelectConfigException eAC) {
					oAuthLogTarget = null;

					StringBuffer sbInfo = new StringBuffer("No valid config section: 'target' with id='");
					sbInfo.append(sAuthLogTarget);
					sbInfo.append("' in config section 'logging' with id='authentication' found.");
					oAuthSPSystemLogger.log(Level.WARNING, MODULE, sMethod, sbInfo.toString(), eAC);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
				}
			}
			catch (Exception e) {
				oAuthSPSystemLogger
						.log(
								Level.CONFIG,
								MODULE,
								sMethod,
								"No valid config section 'logging' with id='authentication' found, using default logging settings.",
								e);
			}

			if (oAuthLogTarget != null && sAuthLogTarget != null && sAuthLogTarget.equalsIgnoreCase("database")) {
				_oAuthSPAuthenticationLogger.init("A-Select AuthSP Server", oAuthSPConfigManager, oAuthLogTarget,
						oAuthSPSystemLogger);
			}
			else {
				_oAuthSPAuthenticationLogger.init("A-Select AuthSP Server", "authentication",
						"org.aselect.server.log.AuthSPAuthenticationLogger", oAuthSPConfigManager, oAuthLogTarget,
						oAuthSPSystemLogger, sWorkingDir);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			oAuthSPSystemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not initialize A-Select AuthSP Authentication Logger", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

	}

	/**
	 * Constructor that has been made private for singleton purposes.
	 */
	private AuthSPAuthenticationLogger() {
	}
}