package org.aselect.lbsense;

import java.util.logging.Level;

import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;

public class TrueMonitor
{
	public final static String MODULE = "TrueMonitor";
	
	private static TrueMonitorSystemLogger _oTrueMonitorLogger;
	
	TrueMonitorConfigManager _oConfigManager = null;
	
	public static void main(String[] sArgs)
	{
		String sMethod = "main";
		TrueMonitorSystemLogger oTrueMonitorSystemLogger = TrueMonitorSystemLogger.getHandle();
		TrueMonitor oTrueMonitor = null;

		try {
			oTrueMonitor = new TrueMonitor();
			oTrueMonitor.initialize();
			oTrueMonitor.startServices();

			System.out.println("Successfully started" + MODULE);
			oTrueMonitorSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Successfully started" + MODULE);
		}
		catch (Exception e) {
			System.out.println("Failed to start" + MODULE + ", exception="+e);
			oTrueMonitorSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to start " + MODULE, e);

			if (oTrueMonitor != null)
				oTrueMonitor.destroy();

			System.exit(1);
		}
	}
	
	public void initialize()
	throws ASelectException
	{
		String sMethod = "initialize";
		_oTrueMonitorLogger = TrueMonitorSystemLogger.getHandle();
		
		// Get handle to the ConfigManager and initialize it
		String sWorkingDir = System.getProperty("user.dir");
		_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "Working dir=" + sWorkingDir);
		
		_oConfigManager = TrueMonitorConfigManager.getHandle();
		_oConfigManager.init(sWorkingDir);
		
		// Get our main section
		Object oMainSection = _oConfigManager.getSimpleSection(null, "lbsense", true);

		// Initialize the system logger
		Object oLogSection = _oConfigManager.getSectionFromSection(oMainSection, "logging", "id=system", true);
		_oTrueMonitorLogger.init(_oConfigManager, oLogSection, sWorkingDir);
		// Logging goes to the system logfile now
		_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "Starting True Monitor");
	}
	
	public void startServices()
	throws ASelectException
	{
		String sMethod = "startServices";

		_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "====");
		Object oHandlers = _oConfigManager.getSimpleSection(null, "handlers", true);
		Object oConfigHandler = _oConfigManager.getSimpleSection(oHandlers, "handler", true);

		for ( ; oConfigHandler != null; ) {
			String sId = _oConfigManager.getParam(oConfigHandler, "id");
			String sClass = _oConfigManager.getParam(oConfigHandler, "class");
			_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "id="+sId+" class="+sClass);
            
			Class cTrueHandler = null;
            ISenseHandler oSenseHandler = null;
            try {
            	cTrueHandler = Class.forName(sClass);
                oSenseHandler = (ISenseHandler)cTrueHandler.newInstance();
            }
            catch (Exception e) {
            	_oTrueMonitorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot instantiate class '" + sClass + "'", e);
                throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            oSenseHandler.initialize(oConfigHandler);
    		Thread _tMyServiceHandler = new Thread(oSenseHandler);
			_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "run handler");
    		_tMyServiceHandler.start();  // don't use run() here!
    		oConfigHandler = _oConfigManager.getNextSection(oConfigHandler);
			_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "handler="+oConfigHandler);
		}
	}
	
	public void destroy()
	{
		String sMethod = "destroy";
		_oTrueMonitorLogger.log(Level.SEVERE, MODULE, sMethod, "Stopping all components.");
	}
}
