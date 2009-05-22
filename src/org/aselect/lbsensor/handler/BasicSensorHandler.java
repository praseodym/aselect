package org.aselect.lbsensor.handler;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;

import org.aselect.system.communication.server.Communicator;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.communication.server.IOutputMessage;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.lbsensor.ISensorHandler;
import org.aselect.lbsensor.LbSensorConfigManager;
import org.aselect.lbsensor.LbSensorSystemLogger;

public class BasicSensorHandler implements ISensorHandler
{
	public final static String MODULE = "BasicSensorHandler";

	protected LbSensorConfigManager _oConfigManager = LbSensorConfigManager.getHandle();
	protected LbSensorSystemLogger _oLbSensorLogger = LbSensorSystemLogger.getHandle();
	protected SensorStore _myStore = null;  // Storage to calculate the running average data
	protected String _sMyId = null;
	
	private ServerSocket _oServiceSocket = null;
	private boolean _bActive = true;
	
	public void initialize(Object oConfigHandler, String sId)
	throws ASelectException
	{
		String sMethod = "initialize";
		int iPort = -1;
		int iIntCount, iIntLength;
		
		_sMyId = sId;

		iPort = _oConfigManager.getSimpleIntParam(oConfigHandler, "listen_port", true);
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Port="+iPort);

		// try to allocate the listening ports on localhost.
		try {
			_oServiceSocket = new ServerSocket(iPort, 50, InetAddress.getByName("127.0.0.1"));
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Socket=" + _oServiceSocket +
								" for "+InetAddress.getByName("127.0.0.1"));
		}
		catch (Exception e) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot create serversocket on port "+iPort);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		iIntCount = _oConfigManager.getSimpleIntParam(oConfigHandler, "nr_of_intervals", false);
		if (iIntCount < 0) iIntCount = 8;  // intervals
		iIntLength = _oConfigManager.getSimpleIntParam(oConfigHandler, "interval_length", false);
		if (iIntLength < 0) iIntLength = 30;  // seconds
		_myStore = new SensorStore(_sMyId, iIntCount, iIntLength);
	}
	
	public SensorStore getMyStore()
	{
		return _myStore;
	}
	
	public void run()
	{
		String sMethod = "run";
		StringBuffer sRequestLine = new StringBuffer();
		int n = -1;
		BufferedReader oInReader = null;
		BufferedWriter oOutWriter = null;
		Socket oSocket = null;

		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "["+sRequestLine.toString()+"]");
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, MODULE + " started on port: " + _oServiceSocket.getLocalPort());
		while (_bActive) {
			try {
				long now = System.currentTimeMillis();
				long stamp = now % 1000000;
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Waiting. T=" + now + " "+stamp);
				oSocket = _oServiceSocket.accept();
				int port = oSocket.getPort();
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Accepted T=" + System.currentTimeMillis() + " "+stamp+" port="+port);

				oSocket.setSoTimeout(4000);  // timeout for read actions
				InputStream isInput = oSocket.getInputStream();
		        OutputStream osOutput = oSocket.getOutputStream();
				oInReader = new BufferedReader(new InputStreamReader(isInput));
				oOutWriter = new BufferedWriter(new OutputStreamWriter(osOutput));

				while ((n = oInReader.read()) != -1) {
					char c = (char)n;
					sRequestLine.append(c);
					if (sRequestLine.toString().indexOf("\r\n") >= 0) {
						// We have a complete line
						int len = sRequestLine.length();
						sRequestLine.setLength(len-2);
						try {
							processLine(oOutWriter, sRequestLine.toString(), _sMyId);
						}
						catch (Exception e) {  // continue anyway
						}
						sRequestLine.setLength(0);
					}
					echoCharToStream(oOutWriter, c);
				}
				if (sRequestLine.length() > 0) {
					processLine(oOutWriter, sRequestLine.toString(), _sMyId);
				}
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Ready");
			}
			catch (IOException e) {
				if (!"Read timed out".equals(e.getMessage()))
					_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "I/O exception occurred", e);
				// The last line of a POST request will probably land here
				if (sRequestLine.length() > 0) {
					try {
						processLine(oOutWriter, sRequestLine.toString(), _sMyId);
					}
					catch (IOException e1) {
						_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Exception occurred", e1);
					}
				}
			}
			catch (Exception e) {
				_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Exception occurred", e);
			}
			finally {
				try {
					if (oOutWriter != null)
						oOutWriter.close();  // flushes the output to the client
					if (oSocket != null) {
						oSocket.close();
					}
				}
				catch (Exception e) { }
			}
		}
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, MODULE + " stopped");
	}

	// Allow this thread to be stopped
	public void stopThread()
	{
		_bActive = false;
	}
	
	// default line processing
	protected void processLine(BufferedWriter oOutWriter, String line, String sId)
	throws IOException
	{
		String sMethod = "processLine";
		
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, sId+" ["+line+"]");
	}

	// Override if no echoing is needed
	protected void echoCharToStream(BufferedWriter oOutWriter, char c)
	throws IOException
	{
		oOutWriter.write(c);	
	}
	
	protected void processRequest(Communicator xCommunicator, int port)
	{
		String sMethod = "processRequest";
		IInputMessage oInputMessage = xCommunicator.getInputMessage();
		IOutputMessage oOutputMessage = xCommunicator.getOutputMessage();

		String sRequest = null;
		try {
			sRequest = oInputMessage.getParam("request");
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Request="+sRequest);
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (Exception eX) {
		}
	}
}
