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
import java.net.UnknownHostException;
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
	protected SensorStore _myStore = null; // Storage to calculate the running average data
	protected String _sMyId = null;
	protected String _myIP = "";
	protected int _myPort = 0;
	protected String _myHost = "";

	private ServerSocket _oServiceSocket = null;
	private boolean _bActive = true;
	
	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.ISensorHandler#initialize(java.lang.Object, java.lang.String)
	 */
	public void initialize(Object oConfigHandler, String sId)
	throws ASelectException
	{
		String sMethod = "initialize";
		int iPort = -1;
		int iIntCount, iIntLength;

		_sMyId = sId;

		iPort = _oConfigManager.getSimpleIntParam(oConfigHandler, "listen_port", true);
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Port=" + iPort);

		// try to allocate the listening ports on localhost.
		// Bauke, 20090707: Listen on all addresses
		try {
			_oServiceSocket = new ServerSocket(iPort, 50, null/* InetAddress.getByName("localhost") */);
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Socket=" + _oServiceSocket);
		}
		catch (Exception e) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot create serversocket on port " + iPort);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		iIntCount = _oConfigManager.getSimpleIntParam(oConfigHandler, "nr_of_intervals", false);
		if (iIntCount < 0)
			iIntCount = 8; // intervals
		iIntLength = _oConfigManager.getSimpleIntParam(oConfigHandler, "interval_length", false);
		if (iIntLength < 0)
			iIntLength = 30; // seconds
		_myStore = new SensorStore(_sMyId, iIntCount, iIntLength);
		
		try {
			InetAddress ownIP = InetAddress.getLocalHost();
			_myIP = ownIP.getHostAddress();
			_myPort = _oServiceSocket.getLocalPort();
			_myHost = ownIP.getHostName();
			DataCollectStore.getHandle().set_myIP(_myIP);
			DataCollectStore.getHandle().set_myPort(_myPort);
		}
		catch (UnknownHostException e2) {
		}
	}

	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.ISensorHandler#getMyStore()
	 */
	public SensorStore getMyStore()
	{
		return _myStore;
	}

	/* (non-Javadoc)
	 * @see java.lang.Runnable#run()
	 */
	public void run()
	{
		String sMethod = "run";
		StringBuffer sRequestLine = new StringBuffer();
		int n = -1;
		BufferedReader oInReader = null;
		BufferedWriter oOutWriter = null;
		Socket oSocket = null;

		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, MODULE + " ip="+_myIP+" port="	+ _myPort+" host="+_myHost);
		while (_bActive) {
			try {
				long now = System.currentTimeMillis();
				long stamp = now % 1000000;
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Waiting. T=" + now + " " +
						stamp+", t="+Thread.currentThread().getId());
				oSocket = _oServiceSocket.accept();
				int port = oSocket.getPort();
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Accepted T=" + System.currentTimeMillis() +
						" "+stamp + " port="+port);

				oSocket.setSoTimeout(40); // timeout for read actions
				InputStream isInput = oSocket.getInputStream();
				OutputStream osOutput = oSocket.getOutputStream();
				oInReader = new BufferedReader(new InputStreamReader(isInput));
				oOutWriter = new BufferedWriter(new OutputStreamWriter(osOutput));

				sRequestLine.setLength(0);
				processStart(oOutWriter, _sMyId);
				while ((n = oInReader.read()) != -1) {
					char c = (char) n;
					sRequestLine.append(c);
					echoCharToStream(oOutWriter, c);  // default echo behaviour is here
					if (sRequestLine.toString().indexOf("\r\n") >= 0) {
						// We have a complete line
						int len = sRequestLine.length();
						//sRequestLine.setCharAt(len-2, '\0');
						//:sRequestLine.setLength(len-2);
						try {
							processLine(oOutWriter, sRequestLine.substring(0, len-2), _sMyId);
						}
						catch (Exception e) { // continue anyway
						}
						sRequestLine.setLength(0);
					}
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
					processFinish(oOutWriter, _sMyId);
					if (oOutWriter != null)
						oOutWriter.close(); // flushes the output to the client
					if (oSocket != null) {
						oSocket.close();
					}
				}
				catch (Exception e) {
				}
			}
		}
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, MODULE + " stopped");
	}

	// Allow this thread to be stopped
	/**
	 * Stop thread.
	 */
	public void stopThread()
	{
		_bActive = false;
	}

	/**
	 * Process line. This is the default supplied, may be overridden
	 * 
	 * @param oOutWriter
	 *            the o out writer
	 * @param line
	 *            the line
	 * @param sId
	 *            the handler id
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	protected void processLine(BufferedWriter oOutWriter, String line, String sId)
		throws IOException
	{
		String sMethod = "processLine";

		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, sId + " [" + line + "]");
	}

	/**
	 * Called before processing.
	 * 
	 * @param oOutWriter
	 *            the o out writer
	 * @param sId
	 *            the s id
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	protected void processStart(BufferedWriter oOutWriter, String sId)
	throws IOException
	{
		oOutWriter.write("---- Received data:\n\n");  // first \n somehow gets eaten by the browser
	}
	
	/**
	 * Called after processing.
	 * 
	 * @param oOutWriter
	 *            the o out writer
	 * @param sId
	 *            the handler id
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	protected void processFinish(BufferedWriter oOutWriter, String sId)
	throws IOException
	{
		oOutWriter.write("---- End of data\n");
	}

	// Override if no echoing is needed
	/**
	 * Echo char to stream.
	 * 
	 * @param oOutWriter
	 *            the o out writer
	 * @param c
	 *            the c
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	protected void echoCharToStream(BufferedWriter oOutWriter, char c)
		throws IOException
	{
		//if (c=='\r') oOutWriter.write(c+"<R>");
		//else if (c=='\n') oOutWriter.write(c+"<N>");
		//else
		oOutWriter.write(c);
	}

	/**
	 * Process request.
	 * 
	 * @param xCommunicator
	 *            the x communicator
	 * @param port
	 *            the port
	 */
	protected void processRequest(Communicator xCommunicator, int port)
	{
		String sMethod = "processRequest";
		IInputMessage oInputMessage = xCommunicator.getInputMessage();
		IOutputMessage oOutputMessage = xCommunicator.getOutputMessage();

		String sRequest = null;
		try {
			sRequest = oInputMessage.getParam("request");
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Request=" + sRequest);
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (Exception eX) {
		}
	}
}
