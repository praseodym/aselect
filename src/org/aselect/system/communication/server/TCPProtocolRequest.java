/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 */

/* 
 * $Id: TCPProtocolRequest.java,v 1.13 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: TCPProtocolRequest.java,v $
 * Revision 1.13  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.12  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.11  2005/08/30 08:01:36  erwin
 * Fixed bug in TCPProtocolRequest with QueryString
 *
 * Revision 1.10  2005/04/27 07:59:23  martijn
 * bug fixed: NullPointer occurred in some special cases: better error handling in readRequest()
 *
 * Revision 1.9  2005/04/08 12:41:30  martijn
 * fixed todo's
 *
 * Revision 1.8  2005/03/16 13:49:03  tom
 * Added todo
 *
 * Revision 1.7  2005/03/08 09:13:47  erwin
 * Removed ready() because this gave problems.
 *
 * Revision 1.6  2005/03/04 15:52:52  erwin
 * Fixed some errors with reading from the socket.
 *
 * Revision 1.5  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.4  2005/02/14 13:38:36  erwin
 * Applied code style.
 *
 * Revision 1.3  2005/02/14 09:04:46  erwin
 * Applied code style and Javadoc comment.
 *
 * Revision 1.2  2005/02/10 16:10:25  erwin
 * Refactor interface names (added 'I')
 *
 */

package org.aselect.system.communication.server;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.ProtocolException;
import java.net.Socket;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.logging.Level;

import org.aselect.system.logging.SystemLogger;

/**
 * Wrapper to communicate transparent to an incoming Socket request. <br>
 * <br>
 * <b>Description: </b> <br>
 * The <code>TCPProtocolRequest</code> reads headers and other information from an input stream and places this
 * information in a HashMap. The headers can be retrieved by calling the getProperty() method. <br>
 * <br>
 * The <code>TCPProtocolRequest</code> can be used in the <code>Communicator</code> and Message creators. The
 * getProtocolName() method can be used to switch between SOAP12 communication, currently used raw communication, or
 * other protocols that use TCP as a underlying transport protocol. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * Every request should have its own <code>TCPProtocolRequest</code> instance. <br>
 * 
 * @author Alfa & Ariss
 */
public class TCPProtocolRequest implements IProtocolRequest
{
	private static String MODULE = "TCPProtocolRequest";

	/** The request headers */
	private HashMap _htHeaders;

	/** Other request properties */
	private HashMap _htProperties;

	/** Contains the real data. */
	private InputStream _isInput;

	/** The buffer for the input */
	private StringBuffer _sbInputBuffer;

	private SystemLogger _oSystemLogger;

	/**
	 * Create a new instance. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a new wrapper for <code>oRequestSocket</code>. All protocol data (e.g. headers) is extracted from the
	 * socket and buffered. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>oRequestSocket</code> should be connected to a server of some kind. Request data should be available. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The headers are read from the <code>Socket</code> the remaining data (if available) is the actual request data. <br>
	 * 
	 * @param oRequestSocket
	 *            The <CODE>Socket</CODE> with the incoming request.
	 * @param oSystemLogger
	 *            the o system logger
	 * @throws IOException
	 *             If reading from the socket fails.
	 */
	public TCPProtocolRequest(Socket oRequestSocket, SystemLogger oSystemLogger)
	throws IOException {
		_htHeaders = new HashMap();
		_htProperties = new HashMap();
		_sbInputBuffer = new StringBuffer();
		_isInput = oRequestSocket.getInputStream();
		_oSystemLogger = oSystemLogger;
		readRequest(oRequestSocket);
	}

	/**
	 * Retrieve the name of the protocol.
	 * 
	 * @return the protocol name
	 * @see org.aselect.system.communication.server.IProtocolRequest#getProtocolName()
	 */
	public String getProtocolName()
	{
		return (String) _htProperties.get("ProtocolName");
	}

	/**
	 * Retrieve a property of the request.
	 * 
	 * @param sName
	 *            the s name
	 * @return the property
	 * @see org.aselect.system.communication.server.IProtocolRequest#getProperty(java.lang.String)
	 */
	public String getProperty(String sName)
	{
		String sRetVal = null;
		if (sName.equalsIgnoreCase("QueryString")) {
			if (_htProperties.containsKey(sName)) {
				sRetVal = (String) _htProperties.get(sName);
			}
		}
		else {
			if (_htHeaders.containsKey(sName)) {
				sRetVal = (String) _htHeaders.get(sName);
			}
		}
		return sRetVal;
	}

	/**
	 * Retrieve the full local address with port.
	 * 
	 * @return the target
	 * @see org.aselect.system.communication.server.IProtocolRequest#getTarget()
	 */
	public String getTarget()
	{
		return (String) _htProperties.get("Target");
	}

	/**
	 * Get the input stream to the request after stripping the headers. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This class returns a <code>ByteArrayInputStream</code>. The alternative StringBufferInputStream is deprecated: <br>
	 * <i>This class does not properly convert characters into bytes. As of JDK 1.1, the preferred way to create a
	 * stream from a string is via the <code>StringReader</code> class. </i> <br>
	 * Because the <code>StringReader</code> is not an <code>InputStream</code>,<code>ByteArrayInputStream</code> is
	 * used.
	 * 
	 * @return the input stream
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see org.aselect.system.communication.server.IProtocolRequest#getInputStream()
	 * @see java.io.ByteArrayInputStream
	 */
	public InputStream getInputStream()
	throws IOException
	{
		return new ByteArrayInputStream(_sbInputBuffer.toString().getBytes());
	}

	/**
	 * extract request data form the <code>Socket</code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Reads all request data form the <code>Socket</code>. The following steps are performed:
	 * <ul>
	 * <li>Read the first line of the request</li>
	 * <li>Tokenize first line with <code>StringTokenizer</code></li>
	 * <li>"POST" or "GET" available in first token:
	 * <ul>
	 * <li>Read the headers and put them in _htHeaders</li>
	 * <li>Buffer the data part of the message</li>
	 * </ul>
	 * else (data must be a RAW QueryString) :
	 * <ul>
	 * <li>put the querystring in _htProperties</li>
	 * </ul>
	 * </li>
	 * <li>Read target address from the <code>Socket</code></li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * This method should only be called once. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>oSocket</code> should contain data. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All <code>oSocket</code> data has been read. <br>
	 * 
	 * @param oSocket
	 *            The socket from which data is read.
	 * @throws IOException
	 *             If reading from the socket fails.
	 */
	private void readRequest(Socket oSocket)
	throws IOException
	{
		final String sMethod = "TCPProtocolRequest.readRequest()::";
		String sRequestLine = null;
		StringBuffer sbTarget = new StringBuffer();

		// read the first line of the request
		BufferedReader oInReader = new BufferedReader(new InputStreamReader(_isInput));
		sRequestLine = oInReader.readLine();

		// sRequestLine can be null if end of stream is already reached
		if (sRequestLine == null)
			throw new EOFException(sMethod + "End of stream");
		_oSystemLogger.log(Level.INFO, MODULE, sMethod, "RequestLine=" + sRequestLine);

		// put string in tokenizer and switch on white space
		StringTokenizer oTokenizedLine = new StringTokenizer(sRequestLine);
		if (!oTokenizedLine.hasMoreTokens())
			throw new ProtocolException(sMethod + "No content in request");

		String sTmpString = oTokenizedLine.nextToken();

		if (sTmpString.equals("POST")) {
			// message is HTTP so Headers have to be parsed
			if (!oTokenizedLine.hasMoreTokens())
				throw new ProtocolException(sMethod + "No URL in request");

			oTokenizedLine.nextToken(); // skip target page

			if (!oTokenizedLine.hasMoreTokens())
				throw new ProtocolException(sMethod + "No ProtocolName in request");

			_htProperties.put("ProtocolName", oTokenizedLine.nextToken());
			// get protocol name, target must start with http
			sbTarget.append("http:/");

			// read the http headers and put them in _htHeaders
			sRequestLine = oInReader.readLine();
			while (sRequestLine != null && !sRequestLine.equals("")) // while not end of headers
			{
				String[] saHeaderArray = sRequestLine.split(": ");
				if (saHeaderArray.length == 2) {
					_htHeaders.put(saHeaderArray[0], saHeaderArray[1]);
				}
				sRequestLine = oInReader.readLine();
			}

			// buffer the data part of the message.
			// this must be done at this moment,
			// because the inputstream must be buffered
			// before using the xml parser
			sRequestLine = oInReader.readLine();
			while (sRequestLine != null && !sRequestLine.equals("")) {
				_sbInputBuffer.append(sRequestLine);
				sRequestLine = oInReader.readLine();
			}
		}
		else if (sTmpString.equals("GET")) {
			if (!oTokenizedLine.hasMoreTokens())
				throw new ProtocolException(sMethod + "No URL in request");

			String sURL = oTokenizedLine.nextToken();
			String sQuery = null;
			int i = sURL.indexOf("?");
			i++;
			if (i > 0)
				sQuery = sURL.substring(i, sURL.length());

			if (sQuery == null)
				sQuery = "";

			_htProperties.put("QueryString", sQuery);
			_htProperties.put("ProtocolName", "RAW");
		}
		else { // message string must be a RAW QueryString
			// put the querystring in _htProperties
			_htProperties.put("QueryString", sRequestLine);
			_htProperties.put("ProtocolName", "RAW");
		}

		// read target address from socket
		// results with raw request in "/127.0.0.1:1495"
		sbTarget.append(oSocket.getLocalSocketAddress().toString());
		_htProperties.put("Target", sbTarget.toString());
	}

	/**
	 * Get the request data.
	 * 
	 * @return the message
	 * @see org.aselect.system.communication.server.IProtocolRequest#getMessage()
	 */
	public String getMessage()
	{
		return _sbInputBuffer.toString();
	}
}