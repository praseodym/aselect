package org.aselect.lbsensor.handler;

import java.io.BufferedWriter;
import java.io.IOException;
import java.util.Timer;
import java.util.logging.Level;

import org.aselect.lbsensor.JdbcPoller;
import org.aselect.system.exception.ASelectException;

public class JdbcSensor extends BasicSensorHandler
{
	public final static String MODULE = "HttpSensor";

	protected long _iPollingInterval = 0;
	protected Timer _pollingTimer;

	private String _sDriver, _sUrl, _sUser, _sPassword, _sQuery;
	
	public void initialize(Object oConfigHandler, String sId)
	throws ASelectException
	{
		String sMethod = "initialize";
		
		super.initialize(oConfigHandler, sId);
		
		_iPollingInterval = _oConfigManager.getSimpleIntParam(oConfigHandler, "polling_interval", true);
		_iPollingInterval *= 1000;  // milliseconds

		_sDriver = _oConfigManager.getSimpleParam(oConfigHandler, "jdbc_driver", true);
		_sUrl = _oConfigManager.getSimpleParam(oConfigHandler, "jdbc_url", true);
		_sUser = _oConfigManager.getSimpleParam(oConfigHandler, "username", true);
		_sPassword = _oConfigManager.getSimpleParam(oConfigHandler, "password", true);
		_sQuery = _oConfigManager.getSimpleParam(oConfigHandler, "query", true);
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "polling_interval="+_iPollingInterval);
		
		JdbcPoller poller = new JdbcPoller(_sMyId, _sDriver, _sUrl, _sUser, _sPassword, _sQuery);
		_pollingTimer = new Timer();
		_pollingTimer.schedule(poller, 0, _iPollingInterval);
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "scheduled");
	}

	// Line processing
	protected void processLine(BufferedWriter oOutWriter, String sLine, String sId)
	throws IOException
	{
		// No Action
	}

	// Called for each incoming character
	protected void echoCharToStream(BufferedWriter oOutWriter, char c)
	throws IOException
	{
		// No Action
	}

}
