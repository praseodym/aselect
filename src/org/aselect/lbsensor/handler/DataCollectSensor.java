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
import org.aselect.system.utils.TimeSensor;
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
		TimeSensor ts = new TimeSensor(_oLbSensorLogger, "");

		oOutWriter.write(sLine);
		if (sLine.startsWith("GET ")) {
			// GET /?request=store&data=12345 HTTP/1.1
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "["+sLine+"]");
			int i = 4;
			if (sLine.charAt(i) == '/')
				i++;
			if (sLine.charAt(i) == '?')
				i++;

			int h = sLine.lastIndexOf(" HTTP/");
			sLine = sLine.substring(i, h);
			
			HashMap<String, String> hmAttribs = Tools.getUrlAttributes(sLine, _oLbSensorLogger);
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "attrs="+hmAttribs);
			String sReq = hmAttribs.get("request");
			if ("store".equals(sReq)) {
				String sData = hmAttribs.get("data");
				if (Utils.hasValue(sData)) {
					try {
						oOutWriter.write("Data ok");
						ts.timeSensorUnPack(sData);
						DataCollectStore hStore = DataCollectStore.getHandle();
						hStore.addEntry(ts.getTimeSensorId(), ts);
						_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "DATA=" + ts.timeSensorPack());
					}
					catch (Exception e) {
						_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Exception: "+e.getClass()+"="+e.getMessage());
					}
				}
			}
		}
		oOutWriter.write("$\r\n");
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
