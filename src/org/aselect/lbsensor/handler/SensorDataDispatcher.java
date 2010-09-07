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

import org.aselect.lbsensor.LbSensor;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;

public class SensorDataDispatcher extends BasicSensorHandler
{
	public final static String MODULE = "SensorDataDispatcher";
	static final int STATUS_OK = 200;
	static final int STATUS_ONHOLD = 404;
	static final int STATUS_UNAVAILABLE = 503;

	protected String _sStoreHandlerId = null;
	protected int _iAcceptLimit = 0;
	protected int _iDownLimit = 0;

	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.handler.BasicSensorHandler#initialize(java.lang.Object, java.lang.String)
	 */
	@Override
	public void initialize(Object oConfigHandler, String sId)
		throws ASelectException
	{
		String sMethod = "initialize";

		super.initialize(oConfigHandler, sId);

		_iAcceptLimit = _oConfigManager.getSimpleIntParam(oConfigHandler, "accept_limit", false);
		if (_iAcceptLimit < 0)
			_iAcceptLimit = 0; // disables the feature
		_iDownLimit = _oConfigManager.getSimpleIntParam(oConfigHandler, "down_limit", false);
		if (_iDownLimit < 0)
			_iDownLimit = 0; // disables the feature
		_sStoreHandlerId = _oConfigManager.getSimpleParam(oConfigHandler, "store_handler_id", true);
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "accept_limit=" + _iAcceptLimit + " down_limit="
				+ _iDownLimit + " store_handler_id=" + _sStoreHandlerId);
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
		if (sLine.startsWith("GET ")) {
			// GET /?request=retrieve HTTP/1.1
			int i = 4;
			if (sLine.charAt(i) == '/')
				i++;
			if (sLine.charAt(i) == '?')
				i++;

			int h = sLine.lastIndexOf(" HTTP/");
			sLine = sLine.substring(i, h);
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "GET [" + sLine + "]");

			HashMap<String, String> hmAttribs = Tools.getUrlAttributes(sLine, _oLbSensorLogger);
			String sReq = hmAttribs.get("request");
			if (sReq == null || "retrieve".equals(sReq)) {
				// Respond with 200 (OK) 503 (Service Unavailable) 404 (Not found)
				SensorStore myStore = LbSensor.getSensorStore(_sStoreHandlerId);
				if (myStore == null) { // bad config
					_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "No SensorStore found for id="
							+ _sStoreHandlerId);
					return;
				}
				long lAverage = myStore.getAverage();
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "AVG: " + lAverage + " accept=" + _iAcceptLimit
						+ " down=" + _iDownLimit);
				writeHtmlResponse(oOutWriter, lAverage, (lAverage < 0) ? STATUS_UNAVAILABLE
						: (_iDownLimit != 0 && lAverage > _iDownLimit) ? STATUS_UNAVAILABLE
								: (_iAcceptLimit != 0 && lAverage > _iAcceptLimit) ? STATUS_ONHOLD : STATUS_OK);
			}
		}
	}

	/**
	 * Write html response.
	 * 
	 * @param outWriter
	 *            the out writer
	 * @param lAverage
	 *            the l average
	 * @param iCode
	 *            the i code
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	private void writeHtmlResponse(BufferedWriter outWriter, long lAverage, int iCode)
		throws IOException
	{
		String sCode = (iCode == STATUS_OK) ? "OK" : (iCode == STATUS_UNAVAILABLE) ? "Service unavailable"
				: "Not Found";
		String sMsg = (iCode == STATUS_OK) ? "Running" : (iCode == STATUS_UNAVAILABLE) ? "Unavailable" : "Not Found";

		outWriter.write("HTTP/1.1 " + iCode + " " + sCode + "\r\n");
		outWriter.write("Content-Type: text/plain\r\n\r\n");
		outWriter.write(sMsg + ", average=" + lAverage + "\r\n\r\n");
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
