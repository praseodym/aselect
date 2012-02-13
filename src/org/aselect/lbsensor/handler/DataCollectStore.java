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

import org.aselect.lbsensor.LbSensorSystemLogger;
import org.aselect.system.utils.TimeSensor;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.TimeSensor.TimeVal;

/**
 * @author bauke
 *
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

	private DataCollectStore()
	{
		_oLbSensorLogger.log(Level.INFO, MODULE, "DataCollectStore", "Created"); 
	}

	// This is a singleton
	public static DataCollectStore getHandle()
	{
		if (_oDataCollectStore == null) {
			_oDataCollectStore = new DataCollectStore();
		}
		return _oDataCollectStore;
	}
	
	synchronized public void addEntry(String sKey, TimeSensor ts)
	{
		String sMethod = "addEntry";
		
		//_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Get "+sKey);
		TimeSensor tsStore = dataStore.get(sKey);
		
		if (tsStore == null) {
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
				// ts is more recent, use it's values
				tsStore.td_finish = ts.td_finish;
				tsStore.setTimeSender(ts.getTimeSender());
				tsStore.setTimeSensorSuccess(ts.isTimeSensorSuccess());
			}
			
			if (tsStore.getTimeSensorType() < ts.getTimeSensorType())  // save highest type
				tsStore.setTimeSensorType(ts.getTimeSensorType());

			if (!Utils.hasValue(tsStore.getTimeSensorAppId()))
				tsStore.setTimeSensorAppId(ts.getTimeSensorAppId());
			
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "UPD "+sKey+ " data="+tsStore.timeSensorPack());
			dataStore.put(sKey, tsStore);
		}
	}
	
	synchronized public void exportEntries()
	{
		String sMethod = "exportEntries";
		
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
					_oLbSensorLogger.log(Level.FINE, MODULE, sMethod, "EXPORT="+ts.timeSensorPack());
					int iType = ts.getTimeSensorType();
					// type should be at least 1 at this point
					String sType = iType==-1? "unused": iType==0? "error": iType==1? "filter": iType==2? "agent": iType==3? "server": "authsp";
					long iSpent = 1000*ts.td_spent.getSeconds()+ts.td_spent.getMicro();
					String sLine = String.format("%s;%d;SIAM;SESSION_%s;%d;%s;SERVER;%s;%d;%s;SIAMID;999;%s",
								_myIP, _myPort, ts.getTimeSensorId(), ts.getTimeSensorLevel(), sType, ts.td_start.toString().replace(".", ""),
								iSpent, ts.getTimeSensorAppId(), Boolean.toString(ts.isTimeSensorSuccess()));
					
					//long now = System.currentTimeMillis();
					appendToFile(_sExportFile, sLine);
					_oLbSensorLogger.log(Level.FINE, MODULE, sMethod, "Append["+sLine+"]"/*+" mSec="+(System.currentTimeMillis() - now)*/);
					dataStore.remove(sKey);  // get's us a java.util.ConcurrentModificationException
				}
			}
		}
		catch (Exception e) {
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Exception: "+e.getClass()+"="+e.getMessage());
		}
	}

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
	
	public void set_iExportAfter(int iExportAfter) { _iExportAfter = iExportAfter; }
	public void set_sExportFile(String sExportFile) { _sExportFile = sExportFile; }

	public int get_iRunExport() { return _iRunExport; }
	public void set_iRunExport(int iRunExport) { _iRunExport = iRunExport; }
}
