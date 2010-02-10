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

import java.util.logging.Level;

import org.aselect.lbsensor.LbSensorSystemLogger;

public class SensorStore
{
	public final static String MODULE = "SensorStore";

	protected LbSensorSystemLogger _oLbSensorLogger = LbSensorSystemLogger.getHandle();
	private String _sId;
	private boolean _serverIsUp = false;
	private long[] iaCount;
	private long[] iaValues;
	private int iIntervalLength;
	private long lLastNow = -1;

	/**
	 * Instantiates a new sensor store.
	 * 
	 * @param sId
	 *            the s id
	 * @param iIntervals
	 *            the i intervals
	 * @param iLength
	 *            the i length
	 */
	public SensorStore(String sId, int iIntervals, int iLength) {
		_sId = sId;
		iaCount = new long[iIntervals]; // initialized to 0
		iaValues = new long[iIntervals];
		iIntervalLength = iLength;
	}

	/**
	 * Adds the data.
	 * 
	 * @param lValue
	 *            the l value
	 */
	public void addData(long lValue)
	{
		String sMethod = "addData";
		String sAvgList = "";
		long now = System.currentTimeMillis() / 1000; // seconds

		setServerUp(true); // the server is definitely up
		if (now - lLastNow > iIntervalLength) {
			// Shift the data right
			for (int i = iaCount.length - 1; i > 0; i--) {
				iaCount[i] = iaCount[i - 1];
				iaValues[i] = iaValues[i - 1];
			}
			iaCount[0] = 0;
			iaValues[0] = 0;
			lLastNow = now;
		}
		iaValues[0] += lValue;
		iaCount[0]++;

		for (int i = 0; i < iaCount.length; i++) {
			sAvgList += " [" + i + "]" + iaValues[i] + "/" + iaCount[i];
		}
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, _sId + ": new values=" + sAvgList);
	}

	//
	// Change server status: (up / down)
	//
	/**
	 * Sets the server up.
	 * 
	 * @param up
	 *            the new server up
	 */
	public void setServerUp(boolean up)
	{
		_serverIsUp = up;
	}

	//
	// Return: -1 server down,
	// 0 server up but no average yet/any more,
	// >0 server up average available
	//
	/**
	 * Gets the average.
	 * 
	 * @return the average
	 */
	public long getAverage()
	{
		String sMethod = "getAverage";
		String sAvgList = "";
		long lAverage = 0;
		long lCount = 0;
		long lResult;

		for (int i = 0; i < iaCount.length; i++) {
			lAverage += iaValues[i];
			lCount += iaCount[i];
			sAvgList += " [" + i + "]" + iaValues[i] + "/" + iaCount[i];
		}
		lResult = (!_serverIsUp) ? -1 : (lCount == 0) ? 0 : lAverage / lCount;
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, _sId + ": current values=" + sAvgList);
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "up=" + _serverIsUp + " average=" + lAverage + " / cnt="
				+ lCount + " --> " + lResult);
		return lResult;
	}
}
