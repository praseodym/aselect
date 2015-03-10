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
package org.aselect.system.communication;

import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;

import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Tools;

/**
 * The Class DataCommunicator contains communication utility methods.
 */
public class DataCommunicator
{
	private static final String MODULE = "DataCommunicator";
	private static final String CONTENT_TYPE = "text/xml; charset=utf-8";
	
/*	Form POST:
    POST / HTTP/1.1
	Host: localhost:1805
	User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:8.0) Gecko/20100101 Firefox/8.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,..*;q=0.8
	Accept-Language: nl,en;q=0.7,en-us;q=0.3
	Accept-Encoding: gzip, deflate
	Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
	DNT: 1
	Connection: keep-alive
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 106

	RelayState=aWRwPWh0dHBzOi8vc2lhbVjdHNlcnZZXJ2ZXI%3D&SAMLRequest=data&language=nl
*/
	/**
	 * Send data using a HTTP POST connection
	 * <br>
	 * <b>Description: </b> <br>
	 * Sends the suplied message to the suplied URL using an <code>HttpURLConnection</code>.<br>
	 * <br>
	 * 
	 * @param sMessage
	 *            A <code>String</code> containing the message that has to be sent.
	 * @param sUrl
	 *            The URL to send the message to.
	 * @return A <CODE>String</CODE> containing the response message.
	 * @throws MalformedURLException
	 *             If suplied URL is invalid.
	 * @throws ASelectCommunicationException
	 *             If communication with the server fails.
	 */
	public static String dataComSend(SystemLogger systemLogger, String sMessage, String sUrl)
	throws MalformedURLException, ASelectCommunicationException
	{
		String sMethod = "send";
		StringBuffer sbBuf = new StringBuffer();
		StringBuffer sbBuffer;
		HttpURLConnection connection = null;
		PrintStream osOutput = null;
		URL url = new URL(sUrl);

		systemLogger.log(Level.INFO, MODULE, sMethod, "Send "+sMessage.length()+" bytes to: "+sUrl);
		try {
			// open HTTP connection to URL
			connection = (HttpURLConnection) url.openConnection();
			// enable sending to connection
			connection.setDoOutput(true);

			// set mime headers
			connection.setRequestProperty("Content-Type", CONTENT_TYPE);
			connection.setRequestProperty("Accept", CONTENT_TYPE);
			// write message to output
			osOutput = new PrintStream(connection.getOutputStream());
			osOutput.println(sMessage);
			osOutput.println("");  // is already <CR><NL> combination

			int xRetCode = connection.getResponseCode();
			switch (xRetCode) { // switch on HTTP response code
			case 200: // ok
				sbBuf = new StringBuffer(Tools.stream2string(connection.getInputStream(), true));
				break;
			case 400: // Bad request
				systemLogger.log(Level.INFO, MODULE, sMethod, "Bad request: "+connection.getHeaderField(0));
				break;
			case 500: // Internal server error
				sbBuffer = new StringBuffer("Internal server error at target host. errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				break;
			default: // unknown error
				sbBuffer = new StringBuffer("Invalid response from target host: \"");
				sbBuffer.append(connection.getHeaderField(0));
				sbBuffer.append(" \". errorcode: ").append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				break;
			}
		}
		catch (java.net.UnknownHostException eUH) {  // target host unknown
			sbBuffer = new StringBuffer("Target host unknown: \"");
			sbBuffer.append(sUrl);
			sbBuffer.append("\" errorcode: ").append(Errors.ERROR_ASELECT_USE_ERROR);
			systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		catch (java.io.IOException eIO) {  // error while connecting,writing or reading
			sbBuffer = new StringBuffer("Could not open connection to host: \"");
			sbBuffer.append(sUrl);
			sbBuffer.append("\" errorcode: ").append(Errors.ERROR_ASELECT_IO);
			systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
		}
		finally {
			systemLogger.log(Level.INFO, MODULE, sMethod, "Close osOutput="+osOutput+" conn="+connection);
			if (osOutput != null)
				osOutput.close();
			if (connection != null)
				connection.disconnect();
		}
		return sbBuf.toString();
	}
}
