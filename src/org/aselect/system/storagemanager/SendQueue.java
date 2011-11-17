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
import org.aselect.system.utils.Utils;

public class SendQueue
{
	public static final String MODULE = "SendQueue";

	protected SystemLogger _oSqLogger = null;
	protected ConfigManager _oConfMgr = null;
	protected String _sConfigMainTag = null;
	protected String _sConfigSection = null;
	private int _iBatchSize = -1;  // will keep this value when no <timer_sensor> is configured
	
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
		Object oConfig = Utils.getSimpleSection(oConfMgr, _oSqLogger, null, _sConfigMainTag, true);
		Object oSensorSection = Utils.getSimpleSection(oConfMgr, _oSqLogger, oConfig, _sConfigSection, false);
		if (oSensorSection == null) {
			_oSqLogger.log(Level.WARNING, MODULE, sMethod, "Section "+_sConfigMainTag+"/"+_sConfigSection+" not found");
			return;
		}
		_iBatchSize = Utils.getSimpleIntParam(oConfMgr, _oSqLogger, oSensorSection, "batch_size", false);
		if (_iBatchSize < 0)
			_iBatchSize = 100;
		_oSqLogger.log(Level.INFO, MODULE, sMethod, "done batch_size="+_iBatchSize);
	}
	
	public void addEntry(String sValue)
	{
		String sMethod = "addEntry";
		
		if (_iBatchSize < 0)
			return;
		_oSqLogger.log(Level.INFO, MODULE, sMethod, "value="+sValue);
		dataStore.add(sValue);
	}
	
	public void sendEntries()
	{
		String sMethod = "sendEntries";
		int countEntries, countTotal = 0;
		
		if (_iBatchSize < 0)
			return;
		try {
			_oSqLogger.log(Level.INFO, MODULE, sMethod, "started");
			String sValue = dataStore.poll();  // retrieve and remove
			for (int run = 1; sValue != null; run++) {
				StringBuffer sBuf = new StringBuffer();
				for (countEntries = 0; sValue != null && countEntries < _iBatchSize; countEntries++) {
					sBuf.append("DATA=").append(sValue).append("\r\n");
				    //Tools.reportTimerSensorData(_oConfMgr, _sConfigMainTag/*"aselect", "timer_section", _oSqLogger, sValue);
					sValue = dataStore.poll();
				}
				if (countEntries > 0) {
					long now = System.currentTimeMillis();
			    	Tools.reportTimerSensorData(_oConfMgr, _sConfigMainTag/*"aselect"*/,
			    					_sConfigSection/*timer_sensor"*/, _oSqLogger, sBuf.toString());
					_oSqLogger.log(Level.FINE, MODULE, sMethod, "mSec="+(System.currentTimeMillis() - now)+" polled="+sValue);
				}
				countTotal += countEntries;
				_oSqLogger.log(Level.INFO, MODULE, sMethod, "run="+run+" count="+countEntries+" total="+countTotal);
				// next run
			}
			_oSqLogger.log(Level.INFO, MODULE, sMethod, "finished");
		}
		catch (Exception e) {
			_oSqLogger.log(Level.WARNING, MODULE, sMethod, "Exception: "+e.getClass()+"="+e.getMessage());
		}
	}
}
