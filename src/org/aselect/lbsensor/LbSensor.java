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
package org.aselect.lbsensor;

import java.util.HashMap;
import java.util.Timer;
import java.util.logging.Level;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.aselect.lbsensor.handler.DataCollectStore;
import org.aselect.lbsensor.handler.SensorStore;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;

public class LbSensor
{
	public final static String MODULE = "LbSensor";
	private static HashMap<String, SensorStore> _hmStores = new HashMap<String, SensorStore>();

	private static LbSensorSystemLogger _oLbSensorLogger;
	private LbSensorConfigManager _oConfigManager = null;

	private static Logger log4j;
	public static Logger getLog4j() { return log4j; }

	protected Timer _dataCollectTimer;

	/**
	 * The main method.
	 * 
	 * @param sArgs
	 *            the arguments
	 */
	public static void main(String[] sArgs)
	{
		String sMethod = "main";
		LbSensorSystemLogger oLbSensorLogger = LbSensorSystemLogger.getHandle();
		LbSensor oLbSensor = null;
		System.out.println("java.class.path="+System.getProperty("java.class.path"));
		System.out.println("java.library.path="+System.getProperty("java.library.path"));
		System.out.println("user.dir="+System.getProperty("user.dir"));

		PropertyConfigurator.configure("lbsensor.properties");
		log4j = Logger.getLogger(LbSensor.class.getName());
		log4j.info("====\nMain="+LbSensor.class.getName());

		try {
			oLbSensor = new LbSensor();
			oLbSensor.initialize();
			oLbSensor.startServices();

			System.out.println("Successfully started " + MODULE);
			oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Successfully started LB Sensor");
		}
		catch (Exception e) {
			System.out.println("Failed to start " + MODULE + ", exception=" + e);
			oLbSensorLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to start LB Sensor", e);

			if (oLbSensor != null)
				oLbSensor.destroy();

			System.exit(1);
		}
		log4j.info("Main Ready");
	}

	/**
	 * Initialize.
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
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

	/**
	 * Start services.
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	public void startServices()
	throws ASelectException
	{
		String sMethod = "startServices";

		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "====");
		Object oHandlers = _oConfigManager.getSimpleSection(null, "handlers", true);
		Object oConfigHandler = _oConfigManager.getSimpleSection(oHandlers, "handler", true);

		for (; oConfigHandler != null;) {
			String sId = _oConfigManager.getParam(oConfigHandler, "id");
			String sClass = _oConfigManager.getParam(oConfigHandler, "class");
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Handler id=" + sId + " / class=" + sClass);

			Class cTrueHandler = null;
			ISensorHandler oSenseHandler = null;
			try {
				cTrueHandler = Class.forName(sClass);
				oSenseHandler = (ISensorHandler) cTrueHandler.newInstance();
			}
			catch (Exception e) {
				_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot instantiate class '" + sClass + "'", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			oSenseHandler.initialize(oConfigHandler, sId);
			Thread _tMyServiceHandler = new Thread(oSenseHandler);

			// The data store must be accessible by other ISensorHandler threads
			_hmStores.put(sId, oSenseHandler.getMyStore());

			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Start handler: " + sId);
			_tMyServiceHandler.start(); // don't use run() here!

			oConfigHandler = _oConfigManager.getNextSection(oConfigHandler);
			//_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "next handler=" + oConfigHandler);
		}
		
		// When the DataCollectSensor was configured it has accumulated it's parameters,
		// including <run_export>
		long runExport = DataCollectStore.getHandle().getRunExport();  // default, milliseconds
		if (runExport > 0) {
			// Run a timer thread to empty the DataCollectStore once in a while
			DataCollectExporter dcExporter = new DataCollectExporter();
			_dataCollectTimer = new Timer();
			_dataCollectTimer.schedule(dcExporter, 0, runExport * 1000);  // in milliseconds
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "DataCollectExporter scheduled every "+runExport+" seconds");
		}
	}

	/**
	 * Gets the sensor store.
	 * 
	 * @param sId
	 *            the s id
	 * @return the sensor store
	 */
	public static SensorStore getSensorStore(String sId)
	{
		return (_hmStores != null) ? _hmStores.get(sId) : null;
	}

	/**
	 * Destroy.
	 */
	public void destroy()
	{
		String sMethod = "destroy";
		
		if (_dataCollectTimer != null) _dataCollectTimer.cancel();
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Stopping all components.");
	}
}
