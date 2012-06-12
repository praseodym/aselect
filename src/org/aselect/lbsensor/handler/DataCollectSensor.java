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

import java.io.BufferedWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.TimerSensor;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;

public class DataCollectSensor extends BasicSensorHandler
{
	public final static String MODULE = "DataCollectSensor";

	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.handler.BasicSensorHandler#initialize(java.lang.Object, java.lang.String)
	 */
	@Override
	public void initialize(Object oConfigHandler, String sId)
	throws ASelectException
	{
		String sMethod = "initialize";
		super.initialize(oConfigHandler, sId);
		
		int iExportAfter = _oConfigManager.getSimpleIntParam(oConfigHandler, "export_after", true);  // seconds
		DataCollectStore.getHandle().setExportAfter(iExportAfter);
		int iRunExport = _oConfigManager.getSimpleIntParam(oConfigHandler, "run_export", true);  // seconds
		DataCollectStore.getHandle().setRunExport(iRunExport);
		//String sExportFile = _oConfigManager.getSimpleParam(oConfigHandler, "export_file", true);
		//DataCollectStore.getHandle().setExportFile(sExportFile);
		int iCollectLevel = _oConfigManager.getSimpleIntParam(oConfigHandler, "collect_level", true);  // 1 or 2
		if (iCollectLevel<1)
			iCollectLevel = 1;
		DataCollectStore.getHandle().setCollectLevel(iCollectLevel);
		int iTranslateUsi = _oConfigManager.getSimpleIntParam(oConfigHandler, "translate_usi", true);  // 0 or 1
		DataCollectStore.getHandle().setTranslateUsi(iTranslateUsi);
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "ea="+iExportAfter+" re="+iRunExport);  //+" ef="+sExportFile);
	}

	//
	// Receive data from an external process, takes the form of an HTTP GET request.
	// The GET parameters are: ?request=store&data=<value>
	// The <value>'s will be accumulated.
	
	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.handler.BasicSensorHandler#processLine(java.io.BufferedWriter, java.lang.String, java.lang.String)
	 */
	@Override
	protected void processLine(BufferedWriter oOutWriter, String sLine, String sId)
	throws IOException
	{
		String sMethod = "processLine";
		String sData = null;
		TimerSensor ts = new TimerSensor(_oLbSensorLogger, "");

		//_oLbSensorLogger.log(Level.INFO, MODULE, sMethod,
		//		"LINE ["+sLine.replace("\r\n", "CN").replace("\r", "CR").replace("\n", "NL")+
		//		"], t="+Thread.currentThread().getId());
		// Recognize POST
		int idx = sLine.indexOf("DATA=");
		if (idx >= 0) {
			sData = sLine.substring(idx+5);
			idx = sData.indexOf('\r');
			if (idx >= 0)
				sData = sData.substring(0, idx);
			idx = sData.indexOf('\n');
			if (idx >= 0)
				sData = sData.substring(0, idx);
		}
		// Recognize GET
		else if (sLine.startsWith("GET ")) {
			// GET /?request=store&data=12345 HTTP/1.1
			int i = 4;
			if (sLine.charAt(i) == '/')
				i++;
			if (sLine.charAt(i) == '?')
				i++;

			int h = sLine.lastIndexOf(" HTTP/");
			sLine = sLine.substring(i, h);
			
			HashMap<String, String> hmAttribs = Tools.getUrlAttributes(sLine, _oLbSensorLogger);
			String sReq = hmAttribs.get("request");
			if ("store".equals(sReq))
				sData = hmAttribs.get("data");
		}
		if (Utils.hasValue(sData)) {
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "DATA ["+sData+"]");
			try {
				ts.timerSensorUnPack(sData);
				//_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Add="+ts.getTimerSensorId());
				DataCollectStore hStore = DataCollectStore.getHandle();
				//_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, ts.timerSensorPack());
				hStore.addEntry(ts);
			}
			catch (Exception e) {
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Exception: "+e.getClass()+" :"+e.getMessage());
			}
			oOutWriter.write("HTTP/1.1 200 OK\r\n");
		}
	}

	// Called before processing
	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.handler.BasicSensorHandler#processStart(java.io.BufferedWriter, java.lang.String, java.lang.String)
	 */
	@Override
	protected void processStart(BufferedWriter oOutWriter, String sId)
	throws IOException
	{
		// No Action
	}

	// Called before processing
	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.handler.BasicSensorHandler#processFinish(java.io.BufferedWriter, java.lang.String, java.lang.String)
	 */
	@Override
	protected void processFinish(BufferedWriter oOutWriter, String sId)
	throws IOException
	{
		// No Action
	}

	// Called for each incoming character
	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.handler.BasicSensorHandler#echoCharToStream(java.io.BufferedWriter, char)
	 */
	@Override
	protected void echoCharToStream(BufferedWriter oOutWriter, char c)
		throws IOException
	{
		// No Action
	}
}
