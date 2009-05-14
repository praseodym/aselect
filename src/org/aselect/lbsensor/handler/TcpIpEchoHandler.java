package org.aselect.lbsense.handler;

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
import org.aselect.lbsense.ISenseHandler;
import org.aselect.lbsense.LbSenseConfigManager;
import org.aselect.lbsense.LbSenseSystemLogger;

public class TcpIpEchoHandler implements ISenseHandler
{
	public final static String MODULE = "TcpIpEchoHandler";

	private LbSenseSystemLogger _oLbSenseLogger = LbSenseSystemLogger.getHandle();
	private ServerSocket _oServiceSocket = null;
	boolean _bActive = true;

	public void initialize(Object oConfigHandler)
	throws ASelectException
	{
		String sMethod = "initialize";
		int iPort = -1;
		
		LbSenseConfigManager _oConfigManager = LbSenseConfigManager.getHandle();

		String sServicePort = _oConfigManager.getSimpleParam(oConfigHandler, "serviceport", true);
		_oLbSenseLogger.log(Level.INFO, MODULE, sMethod, "sServicePort="+sServicePort);
		try {
			iPort = Integer.parseInt(sServicePort);
		}
		catch (NumberFormatException e) {
			_oLbSenseLogger.log(Level.WARNING, MODULE, sMethod, "Bad <serviceport> value");
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		// try to allocate the listening ports on localhost.
		try {
			_oServiceSocket = new ServerSocket(iPort, 50, InetAddress.getByName("127.0.0.1"));
			_oLbSenseLogger.log(Level.INFO, MODULE, sMethod, "Socket=" + _oServiceSocket + " for "+InetAddress.getByName("127.0.0.1"));
		}
		catch (Exception e) {
			_oLbSenseLogger.log(Level.WARNING, MODULE, sMethod, "Cannot create serversocket on port "+sServicePort);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}
	
	public void run()
	{
		String sMethod = "run";
		String sRequestLine;
		BufferedReader oInReader = null;
		BufferedWriter oOutWriter = null;
		Socket oSocket = null;

		_oLbSenseLogger.log(Level.INFO, MODULE, sMethod, MODULE+" started on port: " + _oServiceSocket.getLocalPort());
		while (_bActive) {
			try {
				long now = System.currentTimeMillis();
				long stamp = now % 1000000;
				_oLbSenseLogger.log(Level.INFO, MODULE, sMethod, "Waiting  T=" + now + " "+stamp);
				oSocket = _oServiceSocket.accept();
				int port = oSocket.getPort();
				_oLbSenseLogger.log(Level.INFO, MODULE, sMethod, "Accepted T=" + System.currentTimeMillis() + " "+stamp+" port="+port);

				oSocket.setSoTimeout(4000);
				InputStream isInput = oSocket.getInputStream();
		        OutputStream osOutput = oSocket.getOutputStream();
				oInReader = new BufferedReader(new InputStreamReader(isInput));
				oOutWriter = new BufferedWriter(new OutputStreamWriter(osOutput));
				do {
					sRequestLine = oInReader.readLine();
					_oLbSenseLogger.log(Level.INFO, MODULE, sMethod, sRequestLine);
					oOutWriter.write(sRequestLine + "\r\n");
				}
				while (sRequestLine != null && !"".equals(sRequestLine));
				
				_oLbSenseLogger.log(Level.INFO, MODULE, sMethod, "Ready");
			}
			catch (IOException e) {
				_oLbSenseLogger.log(Level.WARNING, MODULE, sMethod, "I/O exception occurred", e);
			}
			catch (Exception e) {
				_oLbSenseLogger.log(Level.WARNING, MODULE, sMethod, "Exception occurred", e);
			}
			finally {
				try {
					if (oOutWriter != null)
						oOutWriter.close();  // flushes the output to the client
					if (oSocket != null) {
						_oLbSenseLogger.log(Level.INFO, MODULE, sMethod, "Close");
						oSocket.close();
					}
				}
				catch (Exception e) { }
			}
		}
		_oLbSenseLogger.log(Level.INFO, MODULE, sMethod, MODULE+" stopped");
	}
	
	void processRequest(Communicator xCommunicator, int port)
	{
		String sMethod = "processRequest";
		IInputMessage oInputMessage = xCommunicator.getInputMessage();
		IOutputMessage oOutputMessage = xCommunicator.getOutputMessage();

		String sRequest = null;
		try {
			sRequest = oInputMessage.getParam("request");
			_oLbSenseLogger.log(Level.INFO, MODULE, sMethod, "Request="+sRequest);
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (Exception eX) {
		}
	}
}
