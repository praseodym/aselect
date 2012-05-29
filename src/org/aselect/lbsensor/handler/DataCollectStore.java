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
package org.aselect.lbsensor.handler;

import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.aselect.lbsensor.LbSensor;
import org.aselect.lbsensor.LbSensorSystemLogger;
import org.aselect.system.utils.TimeSensor;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.TimeSensor.TimeVal;

/**
 * The Class DataCollectStore.
 * 
 * @author bauke
 */
public class DataCollectStore
{
	public static final String MODULE = "DataCollectStore";

	private static DataCollectStore _oDataCollectStore;

	protected LbSensorSystemLogger _oLbSensorLogger = LbSensorSystemLogger.getHandle();
	private ConcurrentHashMap<String, TimeSensor> dataStore = new ConcurrentHashMap<String, TimeSensor>();
	private String _myIP = "";
	private int _myPort = 0;
	private String _sExportFile = "";
	private int _iExportAfter = -1;  // seconds
	private int _iRunExport = -1;  // seconds
	private int _iCollectLevel = 1; // logging level

	private static Logger _log4jExport;  // exporting data uses log4j for it's output

	private DataCollectStore()
	{
		_log4jExport = Logger.getLogger("lb_export");
		_oLbSensorLogger.log(Level.INFO, MODULE, "DataCollectStore", "Created"); 
	}

	/**
	 * This is a singleton, get it's handle.
	 */
	public static DataCollectStore getHandle()
	{
		if (_oDataCollectStore == null) {
			_oDataCollectStore = new DataCollectStore();
		}
		return _oDataCollectStore;
	}
	
	/**
	 * Add new data to the entry store.
	 * 
	 * @param sKey
	 *            the key
	 * @param ts
	 *            the TimeSensor struct
	 */
	synchronized public void addEntry(String sKey, TimeSensor ts)
	{
		String sMethod = "addEntry";
		
		//_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Get "+sKey);
		// Look for a level 1 TimeSensorId record
		TimeSensor tsStore = dataStore.get(sKey);
		
		if (tsStore == null) {  // ID is not present yet
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "NEW "+sKey+ " data="+ts.timeSensorPack());
			dataStore.put(sKey, ts);
		}
		else {
			//_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "UPD0 "+sKey+ " data="+tsStore.timeSensorPack());
			// Manipulate contents of tsStore
			if (tsStore.td_start.timeValCompare(ts.td_start) > 0) {  // save lowest start time
				tsStore.td_start = ts.td_start;
			}
			tsStore.timeSensorSpentPlus(ts);
			if (tsStore.td_finish.timeValCompare(ts.td_finish) < 0) {  // save highest finish time
				// ts is the latest, use it's values
				tsStore.td_finish = ts.td_finish;
				tsStore.setTimeSensorSender(ts.getTimeSensorSender());
				tsStore.setTimeSensorSuccess(ts.isTimeSensorSuccess());
			}
			
			if (tsStore.getTimeSensorType() < ts.getTimeSensorType())  // save highest type
				tsStore.setTimeSensorType(ts.getTimeSensorType());

			if (!Utils.hasValue(tsStore.getTimeSensorAppId()))  // grab first app_id
				tsStore.setTimeSensorAppId(ts.getTimeSensorAppId());
			
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "UPD "+sKey+ " data="+tsStore.timeSensorPack());
			dataStore.put(sKey, tsStore);
		}
		
		// And store the detail as a level 2 line
		exportSingleEntry(ts, 2);
	}
	
	/**
	 * Export all entries due to the .csv file.
	 */
	synchronized public void exportEntries()
	{
		String sMethod = "exportEntries";		
		//LbSensor.getLog4j().info("MainLogger - begin");
		try {
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "started, export_after="+_iExportAfter);
			Enumeration<String> eKeys = dataStore.keys();
			while (eKeys.hasMoreElements()) {
				String sKey = (String)eKeys.nextElement();

				TimeSensor ts = dataStore.get(sKey);
				TimeVal tv = ts.new TimeVal();
				tv.timeValNow();  // set current time
				
				long iAge = tv.getSeconds() - ts.td_start.getSeconds();
				//_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "key="+sKey+" sender="+ts.getTimeSender()+" age="+iAge);
				if (iAge > _iExportAfter) {
					exportSingleEntry(ts, /* total overall = */ 1);
					dataStore.remove(sKey);  // get's us a java.util.ConcurrentModificationException
				}
			}
		}
		catch (Exception e) {
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Exception: "+e.getClass()+"="+e.getMessage());
		}
		//LbSensor.getLog4j().info("MainLogger - end");
	}

	/**
	 * Export single entry to .csv file.
	 * 
	 * @param ts - the TimeSensor data
	 * @param exportLevel - the level to be stored in the .csv file
	 */
	private void exportSingleEntry(TimeSensor ts, int exportLevel)
	{
		String sMethod = "exportSingleEntry";
		int iType = ts.getTimeSensorType();

		if (exportLevel > _iCollectLevel)
			return;
		_oLbSensorLogger.log(Level.FINE, MODULE, sMethod, "EXPORT="+ts.timeSensorPack()+" iType="+iType+" level="+exportLevel);

		// type should be at least 1 at this point
		String sType = iType==1? "filter": iType==2? "agent": iType==3? "server":
					iType==4? "authsp": iType==5? "remote": iType==0? "error": iType==-1? "unused": "?:"+Integer.toString(iType);
		long iSpent = 1000*ts.td_spent.getSeconds()+ts.td_spent.getMicro();
		// Fieldnumbers in doc:        1  2    3  4  5  6      7  8  9 10     11 12 13
		String sLine = String.format("%s;%d;SIAM;%s;%d;%s;SERVER;%s;%d;%s;SIAMID;%s;%s",
					_myIP, _myPort, /*4*/ts.getTimeSensorSender(), /*5*/exportLevel, 
					/*6*/sType, /*8*/ts.td_start.toString().replace(".", ""),
					/*9*/iSpent, ts.getTimeSensorAppId(), /*12*/ts.getTimeSensorId(), Boolean.toString(ts.isTimeSensorSuccess()));
		
		//long now = System.currentTimeMillis();
		appendToFile(_sExportFile, sLine);
		_log4jExport.log(org.apache.log4j.Level.INFO, sLine);  // or info(sLine)
		_oLbSensorLogger.log(Level.FINE, MODULE, sMethod, "Append["+sLine+"]"/*+" mSec="+(System.currentTimeMillis() - now)*/);
	}

	/**
	 * Append a line to a file.
	 * 
	 * @param fileName
	 *            the file name
	 * @param sLine
	 *            the line to be added
	 */
	public void appendToFile(String fileName, String sLine)
	{
		String sMethod = "appendToFile";
	    try {
	    	//_oLbSensorLogger.log(Level.FINE, MODULE, sMethod, fileName+": append ["+sLine+"]");
			FileOutputStream fileout = new FileOutputStream(fileName, true);
			PrintWriter printer = new PrintWriter(fileout);
			printer.println(sLine);
			printer.close();
			fileout.close();
	    }
		catch (Exception e) {
			_oLbSensorLogger.log(Level.SEVERE, MODULE, sMethod, "Exception: "+e.getClass()+" :" + e.getMessage());
		}
	}
	
	public void set_myIP(String myIP) { _myIP = myIP; }
	public void set_myPort(int myPort) { _myPort = myPort; }
	
	public void setExportAfter(int iExportAfter) { _iExportAfter = iExportAfter; }
	public void setExportFile(String sExportFile) { _sExportFile = sExportFile; }

	public int getRunExport() { return _iRunExport; }
	public void setRunExport(int iRunExport) { _iRunExport = iRunExport; }

	public int getCollectLevel() { return _iCollectLevel; }
	public void setCollectLevel(int iCollectLevel) { _iCollectLevel = iCollectLevel; }
}
