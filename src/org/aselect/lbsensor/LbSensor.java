package org.aselect.lbsensor;

import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.lbsensor.handler.SensorStore;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;

public class LbSensor
{
	public final static String MODULE = "LbSensor";
	private static HashMap<String, SensorStore> _hmStores = new HashMap<String, SensorStore>();
	
	private static LbSensorSystemLogger _oLbSensorLogger;
	private LbSensorConfigManager _oConfigManager = null;
	
	public static void main(String[] sArgs)
	{
		String sMethod = "main";
		LbSensorSystemLogger oLbSensorLogger = LbSensorSystemLogger.getHandle();
		LbSensor oLbSensor = null;

		try {
			oLbSensor = new LbSensor();
			oLbSensor.initialize();
			oLbSensor.startServices();

			System.out.println("Successfully started" + MODULE);
			oLbSensorLogger.log(Level.SEVERE, MODULE, sMethod, "Successfully started LB Sensor");
		}
		catch (Exception e) {
			System.out.println("Failed to start" + MODULE + ", exception="+e);
			oLbSensorLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to start LB Sensor", e);

			if (oLbSensor != null)
				oLbSensor.destroy();

			System.exit(1);
		}
	}
	
	public void initialize()
	throws ASelectException
	{
		String sMethod = "initialize";
		_oLbSensorLogger = LbSensorSystemLogger.getHandle();
		
		// Get handle to the ConfigManager and initialize it
		String sWorkingDir = System.getProperty("user.dir");
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Working dir=" + sWorkingDir);
		
		_oConfigManager = LbSensorConfigManager.getHandle();
		_oConfigManager.init(sWorkingDir);
		
		// Get our main section
		Object oMainSection = _oConfigManager.getSimpleSection(null, "lbsensor", true);

		// Initialize the system logger
		Object oLogSection = _oConfigManager.getSectionFromSection(oMainSection, "logging", "id=system", true);
		_oLbSensorLogger.init(_oConfigManager, oLogSection, sWorkingDir);
		// Logging goes to the system logfile now
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Starting LB Sensor");
	}
	
	public void startServices()
	throws ASelectException
	{
		String sMethod = "startServices";

		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "====");
		Object oHandlers = _oConfigManager.getSimpleSection(null, "handlers", true);
		Object oConfigHandler = _oConfigManager.getSimpleSection(oHandlers, "handler", true);

		for ( ; oConfigHandler != null; ) {
			String sId = _oConfigManager.getParam(oConfigHandler, "id");
			String sClass = _oConfigManager.getParam(oConfigHandler, "class");
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "id="+sId+" / class="+sClass);
            
			Class cTrueHandler = null;
            ISensorHandler oSenseHandler = null;
            try {
            	cTrueHandler = Class.forName(sClass);
                oSenseHandler = (ISensorHandler)cTrueHandler.newInstance();
            }
            catch (Exception e) {
            	_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot instantiate class '" + sClass + "'", e);
                throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            oSenseHandler.initialize(oConfigHandler, sId);
    		Thread _tMyServiceHandler = new Thread(oSenseHandler);
    		
    		// The data store must be accessible by other ISensorHandler threads
    		_hmStores.put(sId, oSenseHandler.getMyStore());
			
    		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "run handler: "+sId);
    		_tMyServiceHandler.start();  // don't use run() here!
    		
    		oConfigHandler = _oConfigManager.getNextSection(oConfigHandler);
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "handler="+oConfigHandler);
		}
	}
	
	public static SensorStore getSensorStore(String sId)
	{
		return (_hmStores != null)? _hmStores.get(sId): null;
	}
	
	public void destroy()
	{
		String sMethod = "destroy";
		_oLbSensorLogger.log(Level.SEVERE, MODULE, sMethod, "Stopping all components.");
	}
}
