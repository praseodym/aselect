/**
 * 
 */
package org.aselect.server.log;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.AuthenticationLogger;

/**
 * @author RH
 *
 */
public class ASelectEntrustmentLogger extends AuthenticationLogger {
	
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "ASelectEntrustmentLogger";

	// Needed to make this class a singleton.
	private static ASelectEntrustmentLogger _oASelectEntrustmentLogger;
	private boolean initialized = false;	// This class might not be initialized in which case a call to method log will void


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
	private ASelectEntrustmentLogger() {
	}
	
	/**
	 * Must be used to get an ASelectEntrustmentLogger instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new <code>ASelectEntrustmentLogger</code> instance if it's still <code>null</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * Always the same instance of the entrustment logger is returned, because it's a singleton. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return handle to the ASelectEntrustmentLogger
	 */
	public static ASelectEntrustmentLogger getHandle()
	{
		if (_oASelectEntrustmentLogger == null) {
			_oASelectEntrustmentLogger = new ASelectEntrustmentLogger();
		}
		return _oASelectEntrustmentLogger;
	}

	
	/**
	 * Initializes the ASelectEntrustmentLogger Logger. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * <li>Reads the 'target' config section</li> <li>Calls the init of the <i>_oASelectEntrustmentLogger</i></li>
	 * <li>Reads the 'target' config section</li> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>The <i>ASelectSystemLogger</i> must be initialized.</li> <li>The <i>ASelectConfigManager</i> must be
	 * initialized.</li><li>The <i>sWorkingDir</i> may
	 * not be <code>NULL</code>.</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * An initialized <i>_oASelectEntrustmentLogger</i>. <br>
	 * 
	 * @param oEntrustLogging
	 *            The logger config section with id='authentication'
	 * @param sWorkingDir
	 *            The A-Select working dir
	 * @throws ASelectException
	 *             if initialization went wrong
	 */
	public void init(Object oEntrustLogging, String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "init";
		String sEntrustLogTarget = null;
		Object oEntrustLogTarget = null;
		ASelectSystemLogger oASelectSystemLogger = null;
		ASelectConfigManager oASelectConfigManager = null;
		try {
			try {
				oASelectSystemLogger = ASelectSystemLogger.getHandle();
				oASelectConfigManager = ASelectConfigManager.getHandle();

				try {
					sEntrustLogTarget = oASelectConfigManager.getParam(oEntrustLogging, "target");
				}
				catch (Exception e) {
					sEntrustLogTarget = null;

					oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
							"No valid config item: 'target' in config section 'logging' with id='entrustment' found.", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}

				try {
					oEntrustLogTarget = oASelectConfigManager.getSection(oEntrustLogging, "target", "id=" + sEntrustLogTarget);
				}
				catch (Exception e) {
					oEntrustLogTarget = null;

					StringBuffer sbInfo = new StringBuffer("No valid config section: 'target' with id='");
					sbInfo.append(sEntrustLogTarget);
					sbInfo.append("' in config section 'logging' with id='entrustment' found.");
					oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbInfo.toString(), e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}
			}
			catch (Exception e) {
				oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid config section 'logging' with id='entrustment' found, using default logging settings.", e);
			}

			if (oEntrustLogTarget != null && sEntrustLogTarget != null && sEntrustLogTarget.equalsIgnoreCase("database")) {
				_oASelectEntrustmentLogger.init("A-Select Server", oASelectConfigManager, oEntrustLogTarget,
						oASelectSystemLogger);
				
			}
			else {
				_oASelectEntrustmentLogger.init("A-Select Server", "entrustment",
						"org.aselect.server.log.ASelectEntrustmentLogger", oASelectConfigManager, oEntrustLogTarget,
						oASelectSystemLogger, sWorkingDir);
			}
			setInitialized(true);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not initialize A-Select EntrustmentLogger Logger.", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

	}

	
	
	/**
	 * Write a log item. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Write a log item with detailed information. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <code>ASelectEntrustmentLogger</code> is initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param sAction
	 *            The action that should be logged.
	 * @param sUser
	 *            The original user that should be logged.
	 * @param sIP
	 *            The remote IP address.
	 * @param sAppID
	 *            The application id.
	 * @param oboBSN
	 *            The user entrust ( on-behalf-of) id.
	 * @param status
	 *            The application status (result) of the (on-behalf-of) authentication.
	 */
	public void log(String sUser, String sIP, String sAppID, String oboBSN, String status)
	{
		if (isInitialized()) {
			Calendar calendar = new GregorianCalendar();
			// Fixme, get this from config
			SimpleDateFormat dateFormat = new SimpleDateFormat("ddMMyyyy");
			SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
			String sDate = dateFormat.format(calendar.getTime());
			String sTime = timeFormat.format(calendar.getTime());
			
			/* datum, tijd, BSN, gebruiker, IP-adres, oboBSN, applicatie, status machtiging	*/
			Object[] oaFields = {
					sDate, sTime, sUser, sIP, oboBSN, sAppID, status
			};
	
			log(oaFields);
		}	// else there is nothing much we can do
	}

	public boolean isInitialized() {
		return initialized;
	}

	public void setInitialized(boolean initialized) {
		this.initialized = initialized;
	}

}
