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
	
	public void initialize(Object oConfigHandler, String sId)
	throws ASelectException
	{
		String sMethod = "initialize";
		
		super.initialize(oConfigHandler, sId);
		
		_iAcceptLimit = _oConfigManager.getSimpleIntParam(oConfigHandler, "accept_limit", true);
		_sStoreHandlerId = _oConfigManager.getSimpleParam(oConfigHandler, "store_handler_id", true);
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "accept_limit="+_iAcceptLimit+" store_handler_id="+_sStoreHandlerId);
	}
	
	// Line processing
	protected void processLine(BufferedWriter oOutWriter, String sLine, String sId)
	throws IOException
	{
		String sMethod = "processLine";
		
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "["+sLine+"]");
		//oOutWriter.write(sLine+"$\r\n");
		if (sLine.startsWith("GET ")) {
			// GET /?request=retrieve HTTP/1.1
			int i = 4;
			if (sLine.charAt(i) == '/') i++;
			if (sLine.charAt(i) == '?') i++;
			
			int h = sLine.lastIndexOf(" HTTP/");
			sLine = sLine.substring(i, h);
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "GET ["+sLine+"]");

			HashMap<String,String> hmAttribs = Tools.getUrlAttributes(sLine, _oLbSensorLogger);
			String sReq = hmAttribs.get("request");
			if ("retrieve".equals(sReq)) {
				// Respond with 200 (OK) 503 (Service Unavailable) 404 (Not found)
				SensorStore myStore = LbSensor.getSensorStore(_sStoreHandlerId);
				if (myStore == null) {  // bad config
					_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "No SensorStore found wit id="+_sStoreHandlerId);
					return;
				}
				long lAverage = myStore.getAverage();
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "AVG: "+lAverage+" limit="+_iAcceptLimit);
				writeHtmlResponse(oOutWriter, lAverage, (lAverage<0)? STATUS_UNAVAILABLE:
							(_iAcceptLimit!=0 && lAverage>_iAcceptLimit)? STATUS_ONHOLD: STATUS_OK);
			}
		}
	}

	private void writeHtmlResponse(BufferedWriter outWriter, long lAverage, int iCode)
	throws IOException
	{
		String sCode = (iCode == STATUS_OK)? "OK": (iCode == STATUS_UNAVAILABLE)? "Service unavailable": "Not Found";
		String sMsg= (iCode == STATUS_OK)? "Running": (iCode == STATUS_UNAVAILABLE)? "Unavailable": "Not Found";
		
		outWriter.write("HTTP/1.1 "+iCode+" "+sCode+"\r\n");
		outWriter.write("Content-Type: text/plain\r\n\r\n");
		outWriter.write(sMsg+", average="+lAverage+"\r\n\r\n");
	}

	// Called for each incoming character
	//
	protected void echoCharToStream(BufferedWriter oOutWriter, char c)
	throws IOException
	{
		// No Action
	}
}
