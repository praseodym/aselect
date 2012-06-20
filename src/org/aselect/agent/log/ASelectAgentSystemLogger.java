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
 * $Id: ASelectAgentSystemLogger.java,v 1.8 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectAgentSystemLogger.java,v $
 * Revision 1.8  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.7  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.6  2005/04/28 09:14:53  erwin
 * Default level set to CONFIG
 *
 * Revision 1.5  2005/03/10 17:07:15  martijn
 * small bug fixed, now _oASelectAgentSystemLogger will be initialized
 *
 * Revision 1.4  2005/03/10 17:02:43  martijn
 * moved reading of the system logger configuration to the right classes, so changed init() methods
 *
 * Revision 1.3  2005/02/25 15:51:33  erwin
 * Improved logging.
 *
 * Revision 1.2  2005/02/24 15:09:09  ali
 * Added IAgentEventListener class and updates internal Javadoc.
 *
 */
package org.aselect.agent.log;

import java.util.logging.Level;

import org.aselect.agent.config.ASelectAgentConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;


/**
 * Implements the System logger for the A-Select Agent package. <br>
 * <br>
 * <b>Description:</b><br>
 * Implements the System logger for the A-Select Agent package as a single pattern. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class ASelectAgentSystemLogger extends SystemLogger
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "ASelectAgentSystemLogger";

	/** static instance */
	private static ASelectAgentSystemLogger _oASelectAgentSystemLogger;

	/**
	 * Gets the handle.
	 * 
	 * @return A static handle to the A-Select Agent system logger.
	 */
	public static ASelectAgentSystemLogger getHandle()
	{
		if (_oASelectAgentSystemLogger == null)
			_oASelectAgentSystemLogger = new ASelectAgentSystemLogger();

		return _oASelectAgentSystemLogger;
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
	 * initialized.</li> <li>The <i>oSysLogging</i> may not be <code>NULL</code>.</li> <li>The <i>sWorkingDir</i> may
	 * not be <code>NULL</code>.</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * An initialized <i>_oASelectAuthenticationLogger</i>. <br>
	 * 
	 * @param oSysLogging
	 *            The logger config section with id='system'
	 * @param sWorkingDir
	 *            The A-Select working dir
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
		ASelectAgentSystemLogger oASelectAgentSystemLogger = null;
		ASelectAgentConfigManager oASelectAgentConfigManager = null;
		try {
			try {
				oASelectAgentSystemLogger = ASelectAgentSystemLogger.getHandle();
				oASelectAgentConfigManager = ASelectAgentConfigManager.getHandle();

				try {
					String sSysLogLevel = oASelectAgentConfigManager.getParam(oSysLogging, "level");
					levelSysLog = Level.parse(sSysLogLevel);
				}
				catch (Exception e) {
					levelSysLog = Level.CONFIG;
					oASelectAgentSystemLogger.log(Level.CONFIG, MODULE, sMethod,
							"No valid config item: 'level' in config section 'logging'"
									+ " with id='system' found, using default level: CONFIG", e);
				}

				try {
					sSysLogTarget = oASelectAgentConfigManager.getParam(oSysLogging, "target");
				}
				catch (Exception e) {
					sSysLogTarget = null;

					StringBuffer sbInfo = new StringBuffer(
							"No valid config item: 'target' in config section 'logging' with id='system' found.");
					oASelectAgentSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString(), e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					oSysLogTarget = oASelectAgentConfigManager.getSection(oSysLogging, "target", "id=" + sSysLogTarget);
				}
				catch (Exception e) {
					oSysLogTarget = null;

					StringBuffer sbInfo = new StringBuffer("No valid config section: 'target' with id='");
					sbInfo.append(sSysLogTarget);
					sbInfo.append("' in config section 'logging' with id='system' found");
					oASelectAgentSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString(), e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
			}
			catch (Exception e) {
				oASelectAgentSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid config section 'logging' with id='system' found, using default logging settings", e);
			}

			_oASelectAgentSystemLogger.init("system", "org.aselect.agent.log.ASelectAgentSystemLogger",
					oASelectAgentConfigManager, oSysLogTarget, sWorkingDir);

			_oASelectAgentSystemLogger.setLevel(levelSysLog);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			oASelectAgentSystemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not initialize A-Select Agent System Logger.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * private default constructor (singleton).
	 */
	private ASelectAgentSystemLogger() {
	}
}
