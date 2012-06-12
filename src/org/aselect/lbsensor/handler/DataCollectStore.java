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
import org.aselect.lbsensor.LbSensorSystemLogger;
import org.aselect.lbsensor.TranslateUsi;
import org.aselect.system.utils.TimerSensor;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.TimerSensor.TimeVal;

/**
 * The Class DataCollectStore.
 * 
 * @author bauke
 */
public class DataCollectStore
{
	public static final String MODULE = "DataCollectStore";

	// The class singleton
	private static DataCollectStore _oDataCollectStore;

	protected LbSensorSystemLogger _oLbSensorLogger = LbSensorSystemLogger.getHandle();
	
	private ConcurrentHashMap<String, TimerSensor> dataStore = new ConcurrentHashMap<String, TimerSensor>();
	private ConcurrentHashMap<String, TimerSensor> dataRaw = new ConcurrentHashMap<String, TimerSensor>();
	static int seq = 0;  // to make the dataRaw key unique

	private ConcurrentHashMap<String, TranslateUsi> dataTranslate = new ConcurrentHashMap<String, TranslateUsi>();
	
	private String _myIP = "";
	private int _myPort = 0;
	//private String _sExportFile = "";
	private int _iExportAfter = -1;  // seconds
	private int _iRunExport = -1;  // seconds
	private int _iCollectLevel = 1; // logging level
	private int _iTranslateUsi = 0;
	private long _iLastTranslateCleanup = -1;  // milliseconds

	private static Logger _log4jExport;  // exporting data uses log4j for it's output

	private DataCollectStore()
	{
		_log4jExport = Logger.getLogger("lb_export");
		_iLastTranslateCleanup = System.currentTimeMillis();
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
	 *            the TimerSensor struct
	 */
	synchronized public void addEntry(TimerSensor ts)
	{
		String sMethod = "addEntry";
		String sKey = ts.getTimerSensorId();

		// Look for a level 1 TimerSensorId record
		TimerSensor tsStore = dataStore.get(sKey);
		String sInitialUsi = ts.getTimerSensorRid();
		_oLbSensorLogger.log(Level.FINER, MODULE, sMethod, "Key="+sKey+" Initial="+sInitialUsi);

		if (Utils.hasValue(sInitialUsi)) {
			// Store this translation, will be overwritten if already present
			TranslateUsi tu = new TranslateUsi(sInitialUsi);
			_oLbSensorLogger.log(Level.FINER, MODULE, sMethod, "Change "+sKey+"->"+sInitialUsi);
			dataTranslate.put(sKey, tu);
		}
		
		if (tsStore == null) {  // ID is not present yet
			// Store new entry
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "NEW "+sKey+ " data="+ts.timerSensorPack());
			dataStore.put(sKey, ts);
		}
		else {  // Manipulate contents of tsStore
			if (tsStore.td_start.timeValCompare(ts.td_start) > 0) {  // save lowest start time
				tsStore.td_start = ts.td_start;
			}
			tsStore.timerSensorSpentPlus(ts);
			if (tsStore.td_finish.timeValCompare(ts.td_finish) < 0) {  // save highest finish time
				// ts is the latest, use it's values
				tsStore.td_finish = ts.td_finish;
				tsStore.setTimerSensorSender(ts.getTimerSensorSender());
				tsStore.setTimerSensorSuccess(ts.isTimerSensorSuccess());
			}
			
			if (tsStore.getTimerSensorType() < ts.getTimerSensorType())  // save highest type
				tsStore.setTimerSensorType(ts.getTimerSensorType());

			if (!Utils.hasValue(tsStore.getTimerSensorAppId()))  // grab first app_id
				tsStore.setTimerSensorAppId(ts.getTimerSensorAppId());
			
			// Store updated entry
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "UPD "+sKey+ " data="+tsStore.timerSensorPack());
			dataStore.put(sKey, tsStore);
		}
		
		// And export the detail as a level 2 line
		if (_iTranslateUsi == 0)
			exportSingleEntry("Direct", ts, 2);  // export immediately
		else {
			if (++seq>=100000) seq=1;
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "RAW "+sKey+"."+seq+" data="+ts.timerSensorPack());

			// NOTE: if ts was stored in the dataStore, store a clone in dataRaw
			dataRaw.put(sKey+"."+seq, (tsStore==null)? new TimerSensor(ts): ts);  // store for usi replacement
		}
	}
	
	/**
	 * Export all entries due to the .csv file and cleanup the translation collection
	 */
	public void exportEntries()
	{
		String sMethod = "exportEntries";
		
		exportEntries("Sto", dataStore, 1);
		exportEntries("Raw", dataRaw, 2);
		
		if (_iTranslateUsi == 0)
			return;
		
		// Cleanup usi translation table
		long now = System.currentTimeMillis();
		if (now - _iLastTranslateCleanup > 3000 * _iExportAfter) {
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Cleanup dataTranslate, size="+dataTranslate.size());
			Enumeration<String> eKeys = dataTranslate.keys();
			while (eKeys.hasMoreElements()) {
				String sKey = (String)eKeys.nextElement();
				TranslateUsi tu = dataTranslate.get(sKey);
				if (now - tu.getTransTimeStamp() > 3000 * _iExportAfter) {
					_oLbSensorLogger.log(Level.FINEST, MODULE, sMethod, "Remove key="+sKey+" value="+tu.getTransMain());
					dataTranslate.remove(sKey);
				}
				else
					_oLbSensorLogger.log(Level.FINEST, MODULE, sMethod, "Retain key="+sKey+" value="+tu.getTransMain());
			}
			_iLastTranslateCleanup = now;
		}
	}
	
	/**
	 * Export entries from a single data store.
	 * 
	 * @param pDataStore
	 *            the data store
	 */
	synchronized public void exportEntries(String sQ, ConcurrentHashMap<String, TimerSensor> pDataStore, int level)
	{
		String sMethod = "exportEntries";		
		//LbSensor.getLog4j().info("MainLogger - begin");
		try {
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, sQ+" export_after="+_iExportAfter+" size="+pDataStore.size());
			Enumeration<String> eKeys = pDataStore.keys();
			while (eKeys.hasMoreElements()) {
				String sKey = (String)eKeys.nextElement();

				TimerSensor ts = pDataStore.get(sKey);
				TimeVal tv = ts.new TimeVal();
				tv.timeValNow();  // set current time
				
				long iAge = tv.getSeconds() - ts.td_start.getSeconds();
				//_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "key="+sKey+" sender="+ts.getTimeSender()+" age="+iAge);
				if (iAge > _iExportAfter) {
					exportSingleEntry(sQ, ts, level);
					pDataStore.remove(sKey);  // get's us a java.util.ConcurrentModificationException
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
	 * @param ts - the TimerSensor data
	 * @param exportLevel - the level to be stored in the .csv file
	 */
	private void exportSingleEntry(String sQ, TimerSensor ts, int exportLevel)
	{
		String sMethod = "exportSingleEntry";
		int iType = ts.getTimerSensorType();

		if (exportLevel > _iCollectLevel)
			return;
		_oLbSensorLogger.log(Level.FINER, MODULE, sMethod, sQ+" handle="+ts.timerSensorPack()+" iType="+iType+" expLevel="+exportLevel);

		// type should be at least 1 at this point
		String sType = iType==1? "filter": iType==2? "agent": iType==3? "server":
					iType==4? "authsp": iType==5? "remote": iType==0? "error": iType==-1? "unused": "?:"+Integer.toString(iType);
		long iSpent = 1000*ts.td_spent.getSeconds()+ts.td_spent.getMicro();
		
		// Check for usi translation
		String sId = ts.getTimerSensorId();
		TranslateUsi tu = dataTranslate.get(sId);
		if (tu != null) {
			_oLbSensorLogger.log(Level.FINEST, MODULE, sMethod, "From="+sId+" To="+tu.getTransMain());
			sId = tu.getTransMain();
			tu.refreshTimeStamp();
		}
		
		// Fieldnumbers in doc:        1  2    3  4  5  6      7  8  9 10     11 12 13
		String sLine = String.format("%s;%d;SIAM;%s;%d;%s;SERVER;%s;%d;%s;SIAMID;%s;%s",
					_myIP, _myPort, /*4*/ts.getTimerSensorSender(), /*5*/exportLevel, 
					/*6*/sType, /*8*/ts.td_start.toString().replace(".", ""),
					/*9*/iSpent, ts.getTimerSensorAppId(), /*12*/sId, Boolean.toString(ts.isTimerSensorSuccess()));
		
		// Changed to log4j: appendToFile(_sExportFile, sLine);
		_log4jExport.log(org.apache.log4j.Level.INFO, sLine);  // or info(sLine)
		_oLbSensorLogger.log(Level.FINE, MODULE, sMethod, sQ+" EXPORT=["+sLine+"] ");
	}

	/**
	 * Append a line to a file.
	 * 
	 * @param fileName
	 *            the file name
	 * @param sLine
	 *            the line to be added
	 */
	public void xxxAppendToFile(String fileName, String sLine)
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
	//public void setExportFile(String sExportFile) { _sExportFile = sExportFile; }

	public int getRunExport() { return _iRunExport; }
	public void setRunExport(int iRunExport) { _iRunExport = iRunExport; }

	public int getCollectLevel() { return _iCollectLevel; }
	public void setCollectLevel(int iCollectLevel) { _iCollectLevel = iCollectLevel; }

	public void setTranslateUsi(int iTranslateUsi) { _iTranslateUsi = iTranslateUsi; }
}
