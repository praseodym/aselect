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
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;

import org.aselect.lbsensor.*;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;

// TODO: Auto-generated Javadoc
public class HttpSensor extends BasicSensorHandler
{
	public final static String MODULE = "HttpSensor";

	protected long _iPollingInterval = 0;
	protected Timer _pollingTimer;

	private String _sUrl;
	private String _sSignOfLife;

	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.handler.BasicSensorHandler#initialize(java.lang.Object, java.lang.String)
	 */
	@Override
	public void initialize(Object oConfigHandler, String sId)
		throws ASelectException
	{
		String sMethod = "initialize";

		super.initialize(oConfigHandler, sId);

		_iPollingInterval = _oConfigManager.getSimpleIntParam(oConfigHandler, "polling_interval", true);
		_iPollingInterval *= 1000; // milliseconds
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "polling_interval=" + _iPollingInterval);

		_sUrl = _oConfigManager.getSimpleParam(oConfigHandler, "server_url", true);
		_sSignOfLife = _oConfigManager.getSimpleParam(oConfigHandler, "sign_of_life", true);

		HttpPoller poller = new HttpPoller(_sMyId, _sUrl, _sSignOfLife);
		_pollingTimer = new Timer();
		_pollingTimer.schedule(poller, 0, _iPollingInterval);
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "scheduled");
	}

	// Line processing
	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.handler.BasicSensorHandler#processLine(java.io.BufferedWriter, java.lang.String, java.lang.String)
	 */
	@Override
	protected void processLine(BufferedWriter oOutWriter, String sLine, String sId)
		throws IOException
	{
		String sMethod = "processLine";

		// _oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "["+sLine+"]");
		oOutWriter.write(sLine + "$\r\n");
		if (sLine.startsWith("GET ")) {
			// GET /?request=store&data=12345 HTTP/1.1
			int i = 4;
			if (sLine.charAt(i) == '/')
				i++;
			if (sLine.charAt(i) == '?')
				i++;

			int h = sLine.lastIndexOf(" HTTP/");
			sLine = sLine.substring(i, h);
			oOutWriter.write(sId + " GET [" + sLine + "]\r\n");

			HashMap<String, String> hmAttribs = Tools.getUrlAttributes(sLine, _oLbSensorLogger);
			String sReq = hmAttribs.get("request");
			if ("store".equals(sReq)) {
				String sData = hmAttribs.get("data");
				if (sData != null && !"".equals(sData)) {
					oOutWriter.write("DATA [" + sData + "]\r\n");
					try {
						long lValue = Integer.parseInt(sData);
						_myStore.addData(lValue);
						_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Average now: " + _myStore.getAverage());

						// Reset the timer
						_pollingTimer.cancel();

						_pollingTimer = new Timer();
						TimerTask poller = new HttpPoller(_sMyId, _sUrl, _sSignOfLife);
						_pollingTimer.schedule(poller, _iPollingInterval, _iPollingInterval);
					}
					catch (NumberFormatException e) {
						_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Bad data value", e);
					}
				}
			}
		}
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
