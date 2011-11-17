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
package org.aselect.lbsensor;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.TimerTask;
import java.util.logging.Level;

import org.aselect.lbsensor.handler.SensorStore;

public class JdbcPoller extends TimerTask
{
	public final static String MODULE = "JdbcPoller";

	protected LbSensorSystemLogger _oLbSensorLogger = LbSensorSystemLogger.getHandle();
	
	private String _sSensorStoreId = null;
	private String _sDriver = null;
	private String _sUrl, _sUser, _sPassword;
	private String _sQuery;

	/**
	 * Instantiates a new jdbc poller.
	 * 
	 * @param sSensorStoreId
	 *            the sensor store id
	 * @param sDriver
	 *            the driver
	 * @param sUrl
	 *            the url
	 * @param sUser
	 *            the user
	 * @param sPassword
	 *            the password
	 * @param sQuery
	 *            the query
	 */
	public JdbcPoller(String sSensorStoreId, String sDriver, String sUrl, String sUser, String sPassword, String sQuery)
	{
		_sDriver = sDriver;
		_sSensorStoreId = sSensorStoreId;
		_sUrl = sUrl;
		_sUser = sUser;
		_sPassword = sPassword;
		_sQuery = sQuery;
	}

	/* (non-Javadoc)
	 * @see java.util.TimerTask#run()
	 */
	@Override
	public void run()
	{
		String sMethod = "run";
		int iCnt = 0;
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "ACTION: " + _sSensorStoreId);

		ResultSet jdbcResult = null;
		Statement jdbcStm = null;
		Connection jdbcConn = null;

		// Poll the data supplier, is it still running?
		SensorStore oSensorStore = LbSensor.getSensorStore(_sSensorStoreId);
		if (oSensorStore == null) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot get SensorStore for: " + _sSensorStoreId);
			return;
		}
		try {
			Class.forName(_sDriver); // Initialize the driver
			long tNow = System.currentTimeMillis();

			jdbcConn = DriverManager.getConnection(_sUrl, _sUser, _sPassword);
			jdbcStm = jdbcConn.createStatement();
			jdbcResult = jdbcStm.executeQuery(_sQuery);
			if (jdbcResult.next()) {
				iCnt++;
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Result=" + jdbcResult.getString(1));
			}
			long tThen = System.currentTimeMillis();
			oSensorStore.setServerUp(iCnt > 0);
			oSensorStore.addData(tThen - tNow);
			if (iCnt == 0)
				_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Server DOWN for " + _sSensorStoreId);
		}
		catch (ClassNotFoundException e) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot initialize driver for " + _sUrl, e);
			oSensorStore.setServerUp(false);
		}
		catch (SQLException e) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot connect to " + _sUrl, e);
			oSensorStore.setServerUp(false);
		}
		finally {
			try {
				if (jdbcResult != null) {
					jdbcResult.close();
					jdbcResult = null;
				}
			}
			catch (SQLException e) {
				_oLbSensorLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resultset.", e);
			}
			try { // If we're using a statement pool, be sure to return the statement to the pool
				if (jdbcStm != null) {
					jdbcStm.close();
					jdbcStm = null;
				}
			}
			catch (SQLException e) {
				_oLbSensorLogger.log(Level.FINE, MODULE, sMethod, "Could not close database statement.", e);
			}
			try { // If we're using a connection pool, be sure to return the connection to the pool
				if (jdbcConn != null) {
					jdbcConn.close();
					jdbcConn = null;
				}
			}
			catch (SQLException e) {
				_oLbSensorLogger.log(Level.FINE, MODULE, sMethod, "Could not close database connection.", e);
			}
		}
	}
}
