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
 * $Id: TCPProtocolResponse.java,v 1.8 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: TCPProtocolResponse.java,v $
 * Revision 1.8  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.7  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.6  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.5  2005/02/14 13:38:43  erwin
 * Applied code style.
 *
 * Revision 1.4  2005/02/14 09:07:58  erwin
 * Renamed some internal vairiables.
 *
 * Revision 1.3  2005/02/14 09:05:01  erwin
 * Applied code style and Javadoc comment.
 *
 * Revision 1.2  2005/02/10 16:10:25  erwin
 * Refactor interface names (added 'I')
 *
 */

package org.aselect.system.communication.server;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Iterator;

// TODO: Auto-generated Javadoc
/**
 * Wrapper to add data and headers to an outgoing Socket response. <br>
 * <br>
 * <b>Description: </b> <br>
 * Protocol information (e.g. headers) can be set by calling the <code>setProperty()</code> method. The properties are
 * placed in a <code>HashMap</code>. When the <code>getOutputStream()</code> method is called the headers will first be
 * written to the <code>OutputStream</code> of the socket. <br>
 * <br>
 * The <code>TCPProtocolResponse</code> can also be used in the {@link Communicator}and message creator objects (
 * {@link IMessageCreatorInterface}). <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * Every reponse should have its own <code>TCPProtocolResponse</code> instance. <br>
 * 
 * @author Alfa & Ariss
 */
public class TCPProtocolResponse implements IProtocolResponse
{

	/**
	 * Contain all protocol headers.
	 */
	private HashMap _htHeaders;

	/**
	 * The wrapped socket.
	 */
	private Socket _oSocket;

	/**
	 * The protocol status code.
	 */
	private String _sStatusCode;

	/**
	 * The name of the protocol.
	 */
	private String _sProtocolName;

	/**
	 * Create a new instance. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a new instance with <code>sProtocolName</code> and the given socket. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * <li><code>oResponseSocket</code> should be connected to a server of some kind.</li>
	 * <li><code>sProtocolName</code> should be a valid protocol name e.g. HTTP1/1.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All instance variables are intialized. <br>
	 * 
	 * @param oResponseSocket
	 *            The <CODE>Socket</CODE> with the outgoing response.
	 * @param sProtocolName
	 *            The protocol name that will be contained in the first line (response code) of the outgoing response
	 */
	public TCPProtocolResponse(Socket oResponseSocket, String sProtocolName) {
		_oSocket = oResponseSocket;
		_sProtocolName = sProtocolName;
		_sStatusCode = null;
		_htHeaders = new HashMap();
	}

	/**
	 * Set a property of the response protocol.
	 * 
	 * @param sName
	 *            the s name
	 * @param sValue
	 *            the s value
	 * @see org.aselect.system.communication.server.IProtocolResponse#setProperty(java.lang.String, java.lang.String)
	 */
	public void setProperty(String sName, String sValue)
	{
		if (sName.equalsIgnoreCase("Status")) // HTTP status code is not a
		// header
		{
			// create response statuscode string
			try {
				switch (Integer.parseInt(sValue)) {
				case 200: // ok
				{
					_sStatusCode = _sProtocolName + " 200 OK";
				}
				case 400: // Bad request
				{
					_sStatusCode = _sProtocolName + " 400 Bad Request";
				}
				case 500: // Internal server error
				{
					_sStatusCode = _sProtocolName + " 500 Internal Server Error";
				}
				default: // unknown error
				{
					StringBuffer sb = new StringBuffer(_sProtocolName);
					sb.append(" ").append(sValue);
					_sStatusCode = sb.toString();
				}
				}
			}
			catch (NumberFormatException eNF) {
				// just use text
				StringBuffer sb = new StringBuffer(_sProtocolName);
				sb.append(" ").append(sValue);
				_sStatusCode = sb.toString();
			}
		}
		else
		// a normal header which can be set
		{
			_htHeaders.put(sName, sValue);
		}
	}

	/**
	 * Get the ouput stream to the response message.
	 * 
	 * @return the output stream
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see org.aselect.system.communication.server.IProtocolResponse#getOutputStream()
	 */
	public OutputStream getOutputStream()
		throws IOException
	{
		OutputStream osOutput = _oSocket.getOutputStream();

		if (osOutput != null) {
			if (!_htHeaders.isEmpty()) // HTTP Headers present
			{
				// first send the HTTP headers
				if (_sStatusCode == null) // no status code set yet
				{
					// the default OK response code
					this.setProperty("Status", "200");
				}
				// write response code
				osOutput.write((_sStatusCode + "\r\n").getBytes());

				// write headers
				StringBuffer sbHeader = new StringBuffer();
				Iterator iter = _htHeaders.keySet().iterator();
				while (iter.hasNext()) {
					// create a http header
					String xKey = (String) iter.next();
					sbHeader.append(xKey);
					sbHeader.append(": ");
					sbHeader.append(_htHeaders.get(xKey));
					sbHeader.append("\r\n");

					// write header to outputstream
					osOutput.write(sbHeader.toString().getBytes());
				}
				// write \r\n as the end of the headers
				osOutput.write("\r\n".getBytes());
				// clear headers
				_htHeaders = new HashMap();
			}
		}
		else
		// no ouput stream
		{
			throw new IOException("Can't retrieve OutputStream from Socket.");
		}
		return osOutput;
	}

}