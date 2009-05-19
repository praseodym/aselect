package org.aselect.lbsensor;

import java.util.TimerTask;
import java.util.logging.Level;

public class DataPoller extends TimerTask
{
	public final static String MODULE = "DataPoller";

	protected LbSensorSystemLogger _oLbSensorLogger = LbSensorSystemLogger.getHandle();
	private String _sUrl;

	public DataPoller(String sUrl)
	{
		_sUrl = sUrl;
	}
	
	public void run()
	{
		String sMethod = "run";
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "ACTION");
		
		// Poll the data supplier, is it still running?
		// Url, port, request
	}
}
