package org.aselect.truemonitor;

import java.net.InetAddress;
import java.net.ServerSocket;
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
		
		TrueMonitorConfigManager _oConfigManager = TrueMonitorConfigManager.getHandle();
		_oConfigManager.init(sWorkingDir);
		
		// Get our main section
		Object oMainSection = _oConfigManager.getSimpleSection(null, "truemonitor", true);

		// Initialize the system logger
		_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "Init SystemLogger");
		Object oLogSection = _oConfigManager.getSectionFromSection(oMainSection, "logging", "id=system", true);
		_oTrueMonitorLogger.init(_oConfigManager, oLogSection, sWorkingDir);
		_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "Starting True Monitor 1");
		// Logging goes to the system logfile now
	}
	
	public void startServices()
	throws ASelectException
	{
		String sMethod = "startServices";
		ServerSocket oServiceSocket;
		String sServicePort;
		int iPort;
		_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "====");

		// Get configuration items
		Object oMainSection = _oConfigManager.getSimpleSection(null, "truemonitor", true);
		sServicePort = _oConfigManager.getSimpleParam(oMainSection, "serviceport", true);
		_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "sServicePort="+sServicePort);
		try {
			iPort = Integer.parseInt(sServicePort);
		}
		catch (NumberFormatException e) {
			_oTrueMonitorLogger.log(Level.WARNING, MODULE, sMethod, "Bad <serviceport> value");
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		// try to allocate the listening ports on localhost.
		try {
			oServiceSocket = new ServerSocket(iPort, 50, InetAddress.getByName("127.0.0.1"));
			_oTrueMonitorLogger.log(Level.INFO, MODULE, sMethod, "Socket=" + oServiceSocket + " for "+InetAddress.getByName("127.0.0.1"));
		}
		catch (Exception e) {
			_oTrueMonitorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot create serversocket on port "+sServicePort);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		// Start the listening thread
		Thread _tServiceHandler = new Thread(new TrueMonitorHandler(oServiceSocket, iPort));
		_tServiceHandler.start();
	}
	
	public void destroy()
	{
		String sMethod = "destroy";
		_oTrueMonitorLogger.log(Level.SEVERE, MODULE, sMethod, "Stopping all components.");
	}
}
