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
package org.aselect.system.storagemanager;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Tools;

public class SendQueue
{
	public static final String MODULE = "SendQueue";

	protected SystemLogger _oSqLogger = null;
	protected ConfigManager _oConfMgr = null;
	protected String _sConfigMainTag = null;
	protected String _sConfigSection = null;
	// Set batch_size to 0 to deactivate
	private int _iBatchSize = -1;  // will keep this value when no <timer_sensor> is configured
	private int _iBatchPeriod = -1;
	
	private ConcurrentLinkedQueue<String> dataStore = new ConcurrentLinkedQueue<String>();

	private static SendQueue _oSendQueue;

	private SendQueue()
	{
	}

	// This is a singleton
	public static SendQueue getHandle()
	{
		if (_oSendQueue == null)
			_oSendQueue = new SendQueue();
		return _oSendQueue;
	}
	
	public void initialize(ConfigManager oConfMgr, SystemLogger oLog, String sConfigMainTag, String sConfigSection)
	throws ASelectException
	{
		String sMethod = "initialize";
		_oConfMgr = oConfMgr;
		_oSqLogger = oLog;
		_sConfigMainTag = sConfigMainTag;
		_sConfigSection = sConfigSection;
		_oSqLogger.log(Level.INFO, MODULE, sMethod, "done batch_size="+_iBatchSize+" batch_period="+_iBatchPeriod);
	}
	
	public void addEntry(String sValue)
	{
		String sMethod = "addEntry";
		
		if (_iBatchSize <= 0)
			return;
		_oSqLogger.log(Level.INFO, MODULE, sMethod, "value="+sValue);
		dataStore.add(sValue);
	}
	
	public void sendEntries()
	{
		String sMethod = "sendEntries";
		int countEntries, countTotal = 0;
		
		if (_iBatchSize <= 0)
			return;
		try {
			_oSqLogger.log(Level.INFO, MODULE, sMethod, "SENDQ { started");
			String sValue = dataStore.poll();  // retrieve and remove
			for (int run = 1; sValue != null; run++) {
				StringBuffer sBuf = new StringBuffer();
				for (countEntries = 0; sValue != null && countEntries < _iBatchSize; countEntries++) {
					sBuf.append("DATA=").append(sValue).append("\r\n");
					sValue = dataStore.poll();
				}
				if (countEntries > 0) {
					long now = System.currentTimeMillis();
			    	reportTimerSensorData(sBuf.toString());
					_oSqLogger.log(Level.FINE, MODULE, sMethod, "mSec="+(System.currentTimeMillis() - now)+" polled="+sValue);
				}
				countTotal += countEntries;
				_oSqLogger.log(Level.INFO, MODULE, sMethod, "run="+run+" count="+countEntries+" total="+countTotal);
				// next run
			}
			_oSqLogger.log(Level.INFO, MODULE, sMethod, "} SENDQ finished");
		}
		catch (Exception e) {
			_oSqLogger.log(Level.WARNING, MODULE, sMethod, "} SENDQ finished: Exception: "+e.getClass()+"="+e.getMessage());
		}
	}

	/**
	 * Report timer sensor data to the url specified in the configuration.
	 * 
	 * @param sData
	 *            the data to be sent
	 */
	private void reportTimerSensorData(String sData)
	{
		String sMethod = "reportTimerSensorData";		
		
		long nowTime = System.currentTimeMillis();
		try {
			Tools.reportDataToSensor(_oConfMgr, _sConfigMainTag/*"aselect" or "agent"*/,
					_sConfigSection/*timer_sensor"*/, "sensor_url", _oSqLogger, sData);
		}
		catch (ASelectException e) {
			_oSqLogger.log(Level.INFO, MODULE, sMethod, "TimerSensor report failed");
		}
		long thenTime = System.currentTimeMillis();
		_oSqLogger.log(Level.FINE, MODULE, sMethod, "Spent local="+(thenTime - nowTime)+" mSec");
	}

	public int getBatchPeriod() {
		return _iBatchPeriod;
	}
	public void setBatchPeriod(int iBatchPeriod) {
		_iBatchPeriod = iBatchPeriod;
	}

	public int getBatchSize() {
		return _iBatchSize;
	}
	public void setBatchSize(int iBatchSize) {
		_iBatchSize = iBatchSize;
	}
}
