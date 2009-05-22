package org.aselect.lbsensor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.TimerTask;
import java.util.logging.Level;

import org.aselect.lbsensor.handler.SensorStore;

public class HttpPoller extends TimerTask
{
	public final static String MODULE = "HttpPoller";

	protected LbSensorSystemLogger _oLbSensorLogger = LbSensorSystemLogger.getHandle();
	private String _sUrl;
	private String _sSensorStoreId = null;
	private String _sSignOfLife;

	public HttpPoller(String sSensorStoreId, String sUrl, String sSignOfLife)
	{
		_sSensorStoreId = sSensorStoreId;
		_sUrl = sUrl;
		_sSignOfLife = sSignOfLife;
	}
	
	public void run()
	{
		String sMethod = "run";
		String sLine;
		boolean bOk;
		BufferedReader oInReader = null; 
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "ACTION: "+_sSensorStoreId);
		
		// Poll the data supplier, is it still running?
		SensorStore oSensorStore = LbSensor.getSensorStore(_sSensorStoreId);
		try {
			URL serverUrl = new URL(_sUrl);
			URLConnection serverConn = serverUrl.openConnection();
			serverConn.connect();
			serverConn.setReadTimeout(4000);  // timeout for read actions
			InputStream isInput = serverConn.getInputStream();
			
			bOk = false;
			if (isInput != null) {
				oInReader = new BufferedReader(new InputStreamReader(isInput));
				for ( ; (sLine = oInReader.readLine()) != null; ) {
					_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "["+sLine+"]");				
					if (sLine.contains(_sSignOfLife))
						bOk = true;
				}
				oInReader.close();
			}
			oSensorStore.setServerUp(bOk);
			if (!bOk)
				_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Server DOWN for "+_sSensorStoreId);
			
			/*InputStream isError = ((HttpURLConnection)serverConn).getErrorStream();
			if (isError != null) {
				oInReader = new BufferedReader(new InputStreamReader(isError));
				for (iErr = 0; (sLine = oInReader.readLine()) != null; iErr++) {
					_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "{"+sLine+"}");				
				}
				oInReader.close();
			}
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "cnt="+iCnt+" err="+iErr);
			*/				
		}
		catch (MalformedURLException e) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Bad <server_url> value: "+_sUrl, e);				
			oSensorStore.setServerUp(false);			
		}
		catch (IOException e) {  // also catches SocketTimeoutException
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot connect to "+_sUrl, e);				
			oSensorStore.setServerUp(false);			
		}
	}
}
