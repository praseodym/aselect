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

	public JdbcPoller(String sSensorStoreId, String sDriver, String sUrl, String sUser, String sPassword, String sQuery)
	{
		_sDriver = sDriver;
		_sSensorStoreId = sSensorStoreId;
		_sUrl = sUrl;
		_sUser = sUser;
		_sPassword = sPassword;
		_sQuery = sQuery;
	}
	
	public void run()
	{
		String sMethod = "run";
		int iCnt = 0;
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "ACTION: "+_sSensorStoreId);
		
		// RH, 20090609, sn
		ResultSet jdbcResult = null;
		Statement jdbcStm = null;
		Connection jdbcConn = null;
		// RH, 20090609, sn
		
		// Poll the data supplier, is it still running?
		SensorStore oSensorStore = LbSensor.getSensorStore(_sSensorStoreId);
		if (oSensorStore == null) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot get SensorStore for "+_sSensorStoreId);
			return;
		}
		try {
			Class.forName(_sDriver);  // Initialize the driver
			long tNow = System.currentTimeMillis();
			// RH, 20090609, so
//			Connection jdbcConn = DriverManager.getConnection(_sUrl, _sUser, _sPassword);
//			Statement jdbcStm = jdbcConn.createStatement();
//			ResultSet jdbcResult = jdbcStm.executeQuery(_sQuery);
			// RH, 20090609, eo
			// RH, 20090609, sn
			jdbcConn = DriverManager.getConnection(_sUrl, _sUser, _sPassword);
			jdbcStm = jdbcConn.createStatement();
			jdbcResult = jdbcStm.executeQuery(_sQuery);
			// RH, 20090609, en
			if (jdbcResult.next()) {
				iCnt++;
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Result="+jdbcResult.getString(1));				
			}
			long tThen = System.currentTimeMillis();
			oSensorStore.setServerUp(iCnt > 0);
			oSensorStore.addData(tThen - tNow);
			if (iCnt == 0)
				_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Server DOWN for "+_sSensorStoreId);
		}
		catch (ClassNotFoundException e) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot initialize driver for "+_sUrl, e);				
			oSensorStore.setServerUp(false);			
		}
		catch (SQLException e) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot connect to "+_sUrl, e);				
			oSensorStore.setServerUp(false);			
		}
		// RH, 20090605, sn
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
				_oLbSensorLogger.log(Level.FINE, MODULE, sMethod, "Could not close database statment.", e);
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
		// RH, 20090605, en		
	}
}
