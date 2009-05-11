package org.aselect.truemonitor;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;

import org.aselect.system.communication.server.Communicator;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.communication.server.IOutputMessage;
import org.aselect.system.error.Errors;

public class TrueMonitorHandler implements Runnable
{
	public final static String MODULE = "TrueMonitorHandler";
	private TrueMonitorSystemLogger _oTrueMonitorSystemLogger;
	private ServerSocket _oServiceSocket;
	private int _iServicePort;
	boolean _bActive = true;
	
	TrueMonitorHandler(ServerSocket oServiceSocket, int iServicePort)
	{
		_oServiceSocket = oServiceSocket;
		_iServicePort = iServicePort;
	}
	
	public void run()
	{
		String sMethod = "run";
		String sRequestLine;
		_oTrueMonitorSystemLogger = TrueMonitorSystemLogger.getHandle();

		_oTrueMonitorSystemLogger.log(Level.INFO, MODULE, sMethod, MODULE+" started on port: " + _iServicePort);
		while (_bActive) {
			try {
				long now = System.currentTimeMillis();
				long stamp = now % 1000000;
				_oTrueMonitorSystemLogger.log(Level.INFO, MODULE, sMethod, "Accept   T=" + now + " "+stamp);
				Socket oSocket = _oServiceSocket.accept();
				int port = oSocket.getPort();
				_oTrueMonitorSystemLogger.log(Level.INFO, MODULE, sMethod, "Accepted T=" + System.currentTimeMillis() + " "+stamp+" port="+port);

				InputStream _isInput = oSocket.getInputStream();
		        OutputStream osOutput = oSocket.getOutputStream();
				BufferedReader oInReader = new BufferedReader(new InputStreamReader(_isInput));
				BufferedWriter oOutWriter = new BufferedWriter(new OutputStreamWriter(osOutput));
				do {
					sRequestLine = oInReader.readLine();
					_oTrueMonitorSystemLogger.log(Level.INFO, MODULE, sMethod, sRequestLine);
					oOutWriter.write(sRequestLine+"\r\n");
				} while(sRequestLine!=null && !"".equals(sRequestLine));
				oOutWriter.close();
				/*
				TCPProtocolRequest oTCPProtocolRequest = new TCPProtocolRequest(oSocket, _oTrueMonitorSystemLogger);
				TCPProtocolResponse oTCPProtocolResponse = new TCPProtocolResponse(oSocket, oTCPProtocolRequest.getProtocolName());
				String sContentType = oTCPProtocolRequest.getProperty("Content-Type");
				if (sContentType == null) sContentType = "";
				String sProtocol = oTCPProtocolRequest.getProtocolName();
				_oTrueMonitorSystemLogger.log(Level.INFO, MODULE, sMethod, "protocol="+sProtocol+" contentType="+sContentType);

				IMessageCreatorInterface oMessageCreator = new RawMessageCreator(_oTrueMonitorSystemLogger);
				// Create Communicator object with the specified messagecreator
				Communicator xCommunicator = new Communicator(oMessageCreator);

				// Initialize the communicator
				if (xCommunicator.init(oTCPProtocolRequest, oTCPProtocolResponse)) {
					// Call processRequest for procesing
					_oTrueMonitorSystemLogger.log(Level.INFO, MODULE, sMethod, "Process  T="+ System.currentTimeMillis());
					processRequest(xCommunicator, port);

					// Send our response
					if (!xCommunicator.send()) {
						_oTrueMonitorSystemLogger.log(Level.WARNING, MODULE, sMethod, "Could not send response");
					}
				}*/
			}
			catch (Exception e) {
				if (_bActive) { // only log if active
					_oTrueMonitorSystemLogger.log(Level.WARNING, MODULE, sMethod, "Exception occurred", e);
				}
			}
		}
		_oTrueMonitorSystemLogger.log(Level.INFO, MODULE, sMethod, MODULE+" stopped");
	}
	
	void processRequest(Communicator xCommunicator, int port)
	{
		String sMethod = "processRequest";
		IInputMessage oInputMessage = xCommunicator.getInputMessage();
		IOutputMessage oOutputMessage = xCommunicator.getOutputMessage();

		String sRequest = null;
		try {
			sRequest = oInputMessage.getParam("request");
			_oTrueMonitorSystemLogger.log(Level.INFO, MODULE, sMethod, "Request="+sRequest);
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (Exception eX) {
		}
	}
}
