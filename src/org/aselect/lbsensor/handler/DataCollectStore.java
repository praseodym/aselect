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
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
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
	private HashMap<String, TimeSensor> dataStore = new HashMap<String, TimeSensor>();
	private int _iMinAge = 80;  // seconds
	
	private DataCollectStore()
	{
	}

	// This is a singleton
	public static DataCollectStore getHandle()
	{
		if (_oDataCollectStore == null)
			_oDataCollectStore = new DataCollectStore();
		return _oDataCollectStore;
	}
	
	synchronized public void addEntry(String sKey, TimeSensor ts)
	{
		String sMethod = "addEntry";
		
		TimeSensor tsStore = dataStore.get(sKey);
		
		if (tsStore == null) {
			dataStore.put(sKey, ts);
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "NEW "+sKey+ " spent="+ts.td_spent.toString());
		}
		else {
			// Manipulate contents of tsStore
			tsStore.timeSensorSpentPlus(ts);
			if (tsStore.td_start.timeValCompare(ts.td_start) > 0) {  // save lowest start time
				tsStore.td_start = ts.td_start;
			}
			if (tsStore.td_finish.timeValCompare(ts.td_finish) < 0) {  // save highest finish time
				// ts is more recent, use it's values
				tsStore.td_finish = ts.td_finish;
				tsStore.setTimeSensorType(ts.getTimeSensorType());
				tsStore.setTimeSensorSuccess(ts.isTimeSensorSuccess());
			}
			if (tsStore.getTimeSensorType() < ts.getTimeSensorType())  // save highest type
				tsStore.setTimeSensorType(ts.getTimeSensorType());
			
			if (!Utils.hasValue(tsStore.getTimeSensorAppId()))
				tsStore.setTimeSensorAppId(ts.getTimeSensorAppId());
			
			dataStore.put(sKey, tsStore);
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "UPD "+sKey+ " spent="+tsStore.td_spent.toString());
		}
	}
	
	synchronized public void exportEntries()
	{
		String sMethod = "exportEntries";
		Set<String> removeSet = new HashSet<String>();
		
		try {
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "STARTED");
			Set<String> keys = dataStore.keySet();
			Iterator<String> itr = keys.iterator();
			while (itr.hasNext()) {
				String sKey = itr.next();
				TimeSensor ts = dataStore.get(sKey);
				TimeVal tv = ts.new TimeVal();
				tv.timeValNow();  // set current time
				
				long iAge = tv.getSeconds() - ts.td_start.getSeconds();
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "key="+sKey+" sender="+ts.getTimeSender()+" age="+iAge);
				if (iAge > _iMinAge) {
					_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "EXPORT="+ts.timeSensorPack());
					int iType = ts.getTimeSensorType();
					String sType = iType==1? "filter": iType==2? "agent": iType==3? "server": "authsp";
					long iSpent = 1000*ts.td_spent.getSeconds()+ts.td_spent.getMicro();
					String sLine = String.format("localhost;;SIAM;SESSION_%s;%d;%s;SERVER;%s;%d;%s;SIAMID;999;%s",
								ts.getTimeSensorId(), ts.getTimeSensorLevel(), sType, ts.td_start.toString().replace(".", ""),
								iSpent, ts.getTimeSensorAppId(), Boolean.toString(ts.isTimeSensorSuccess()));
					appendToFile("export_file.csv", sLine);
					//dataStore.remove(sKey);  // get's us a java.util.ConcurrentModificationException
					removeSet.add(sKey);
				}
			}
			itr = removeSet.iterator();
			while (itr.hasNext()) {
				String sKey = itr.next();
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Remove="+sKey);
				dataStore.remove(sKey);
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
	    	_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, fileName+": append ["+sLine+"]");
			FileOutputStream fileout = new FileOutputStream(fileName, true);
			PrintWriter printer = new PrintWriter(fileout);
			printer.println(sLine);
			printer.close();
			fileout.close();
	    }
		catch (IOException e) {
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "AppendToFile - IOException: " + e.getMessage());
		}
	}

}
