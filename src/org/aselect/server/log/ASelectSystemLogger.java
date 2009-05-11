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
 * $Id: ASelectSystemLogger.java,v 1.9 2006/04/26 12:18:08 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectSystemLogger.java,v $
 * Revision 1.9  2006/04/26 12:18:08  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.8  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/04/28 09:14:20  erwin
 * Default level set to CONFIG
 *
 * Revision 1.6  2005/03/11 12:44:06  erwin
 * fixed typo.
 *
 * Revision 1.5  2005/03/10 17:02:43  martijn
 * moved reading of the system logger configuration to the right classes, so changed init() methods
 *
 * Revision 1.4  2005/03/09 10:58:25  tom
 * Javadoc: added return value description to getHandle
 *
 * Revision 1.3  2005/03/04 13:30:47  peter
 * naming convention, javadoc, code style
 *
 */

package org.aselect.server.log;

import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.Audit;
import org.aselect.system.logging.SystemLogger;

/**
 * The system logger for the A-Select Server.
 * <br><br>
 * <b>Description:</b><br>
 * A singleton authentication logger that inherits from
 * <code>org.aselect.system.logging.SystemLogger</code>. This logger creates a log file containing all A-Select system logging and 
 * can be used in situations where A-Select is not functioning.  
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * - The class is a singleton, so the same class is used in all the classes of 
 * the A-Select Server.
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class ASelectSystemLogger extends SystemLogger
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "ASelectSystemLogger";

	// Needed to make this class a singleton.
	private static ASelectSystemLogger _oASelectSystemLogger;

	/**
	 * Must be used to get an ASelectSystemLogger instance.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Creates a new <code>ASelectSystemLogger</code> instance if it's still <code>null</code>.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * Always the same instance of the system logger is returned, because it's a
	 * singleton.
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br>
	 * @return handle to the ASelectAuthenticationLogger
	 */
	public static ASelectSystemLogger getHandle()
	{
		if (_oASelectSystemLogger == null) {
			_oASelectSystemLogger = new ASelectSystemLogger();
		}
		return _oASelectSystemLogger;
	}

	/**
	 * Initializes the System Logger.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * <li>Reads the 'target' config section</li>
	 * <li>Calls the init of the <i>_oASelectSystemLogger</i></li>
	 * <li>Reads the 'target' config section</li>
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * <li>The <i>ASelectSystemLogger</i> must be initialized.</li>
	 * <li>The <i>ASelectConfigManager</i> must be initialized.</li>
	 * <li>The <i>oSysLogging</i> may not be <code>NULL</code>.</li>
	 * <li>The <i>sWorkingDir</i> may not be <code>NULL</code>.</li>
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * An initialized <i>_oASelectSystemLogger</i>.
	 * <br>
	 * @param oSysLogging The logger config section with id='system'
	 * @param sWorkingDir The A-Select working dir
	 * @throws ASelectException if initialization went wrong
	 */
	public void init(Object oSysLogging, String sWorkingDir)
		throws ASelectException
	{
		String sMethod = "init()";

		Level levelSysLog = null;
		String sSysLogTarget = null;
		Object oSysLogTarget = null;
		ASelectSystemLogger oASelectSystemLogger = null;
		ASelectConfigManager oASelectConfigManager = null;
		try {
			try {
				oASelectSystemLogger = ASelectSystemLogger.getHandle();
				oASelectConfigManager = ASelectConfigManager.getHandle();

				try {
					String sSysLogLevel = oASelectConfigManager.getParam(oSysLogging, "level");
					//		            levelSysLog = Level.parse(sSysLogLevel);
					levelSysLog = Audit.parse(sSysLogLevel);
				}
				catch (Exception e) {
					levelSysLog = Level.CONFIG;
					oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
							"No valid config item: 'level' in config section 'logging'"
									+ " with id='system' found, using default level: CONFIG", e);
				}

				try {
					sSysLogTarget = oASelectConfigManager.getParam(oSysLogging, "target");
				}
				catch (Exception e) {
					sSysLogTarget = null;

					StringBuffer sbInfo = new StringBuffer(
							"No valid config item: 'target' in config section 'logging' with id='system' found.");
					oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString(), e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					oSysLogTarget = oASelectConfigManager.getSection(oSysLogging, "target", "id=" + sSysLogTarget);
				}
				catch (Exception e) {
					oSysLogTarget = null;

					StringBuffer sbInfo = new StringBuffer("No valid config section: 'target' with id='");
					sbInfo.append(sSysLogTarget);
					sbInfo.append("' in config section 'logging' with id='system' found");
					oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString(), e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
			}
			catch (Exception e) {
				oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid config section 'logging' with id='system' found, using default logging settings", e);
			}

			_oASelectSystemLogger.init("system", "org.aselect.server.log.ASelectSystemLogger", oASelectConfigManager,
					oSysLogTarget, sWorkingDir);
			_oASelectSystemLogger.setLevel(levelSysLog);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize A-Select System Logger.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Must be private, so it can not be used.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Must be private because getHandle() must be used to retrieve an instance. 
	 * This is done for singleton purposes.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br>
	 * 
	 */
	private ASelectSystemLogger() {
	}
}