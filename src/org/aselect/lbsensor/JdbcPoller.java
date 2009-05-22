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
		int iCnt = 0, iErr = 0;
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "ACTION: "+_sSensorStoreId);
		
		// Poll the data supplier, is it still running?
		SensorStore oSensorStore = LbSensor.getSensorStore(_sSensorStoreId);
		try {
			Class.forName(_sDriver);  // Initialize the driver
			Connection jdbcConn = DriverManager.getConnection(_sUrl, _sUser, _sPassword);
			Statement jdbcStm = jdbcConn.createStatement();
			ResultSet jdbcResult = jdbcStm.executeQuery(_sQuery);
			if (jdbcResult.next()) {
				iCnt++;
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Result="+jdbcResult.getString(1));				
			}
			oSensorStore.setServerUp(iCnt > 0);
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "cnt="+iCnt+" err="+iErr);				
		}
		catch (ClassNotFoundException e) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot initialize driver for "+_sUrl, e);				
			if (oSensorStore != null)
				oSensorStore.setServerUp(false);			
		}
		catch (SQLException e) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot connect to "+_sUrl, e);				
			if (oSensorStore != null)
				oSensorStore.setServerUp(false);			
		}
	}
}
