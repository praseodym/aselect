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
 * 
 * 14-11-2007 - Changes:
 * - sendStringMessage() method added
 *    
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright Gemeente Den Haag (http://www.denhaag.nl)
 * 
 */

/* 
 * $Id: RawCommunicator.java,v 1.20 2006/05/03 09:37:45 tom Exp $ 
 * 
 * Changelog:
 * $Log: RawCommunicator.java,v $
 * Revision 1.20  2006/05/03 09:37:45  tom
 * Removed Javadoc version
 *
 * Revision 1.19  2006/04/12 13:20:41  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.18.4.2  2006/03/28 10:21:10  leon
 * changed variable name enum to something else because enum is a reserved word in java 5.0
 *
 * Revision 1.18.4.1  2006/02/28 08:57:20  jeroen
 * Bugfix 123:
 *
 * Adapted. Did not encounter additional comparable code in the code base.
 *
 * Revision 1.18  2005/09/08 12:47:12  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.17  2005/03/24 13:24:22  erwin
 * Removed toLowerCase() for parameters.
 *
 * Revision 1.16  2005/03/24 09:32:50  erwin
 * URL encode/decodes all values.
 *
 * Revision 1.15  2005/03/17 15:47:51  erwin
 * Added '&' in array creation. It now supports arrays > 1
 *
 * Revision 1.14  2005/03/16 13:15:33  tom
 * Added new log functionality
 *
 * Revision 1.13  2005/03/11 16:22:08  erwin
 * Improved logging of IO Exception when sending.
 *
 * Revision 1.12  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.11  2005/03/01 16:39:04  erwin
 * Fixed some logging issues
 *
 * Revision 1.10  2005/03/01 15:29:25  erwin
 * Fixed Javadoc warnings
 *
 * Revision 1.9  2005/02/25 15:51:52  erwin
 * 
 * Revision 1.8  2005/02/23 10:04:14  erwin
 * Improved Exception handling.
 *
 * Revision 1.7  2005/02/22 16:18:49  erwin
 * Improved error handling.
 *
 * Revision 1.6  2005/02/21 13:00:31  erwin
 * Now uses the errors.Errors.
 *
 * Revision 1.5  2005/02/10 10:10:49  erwin
 * code format
 *
 * Revision 1.4  2005/02/10 10:01:25  erwin
 * Applied code style and Javadoc comment.
 *
 * Revision 1.3  2005/02/07 14:02:23  erwin
 * Change instance variable names to "_" equivalent
 *
 * Revision 1.2  2005/02/01 16:27:48  erwin
 * Improved code style. Added Javadoc comment.
 *
 */
package org.aselect.system.communication.client.raw;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.system.communication.DataCommunicator;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.logging.SystemLogger;

/**
 * Client communicator which uses CGI messages. <br>
 * <br>
 * <b>Description: </b> <br>
 * The Raw communicator used by the A-Select agent to create, retrieve, and send URL encoded CGI messages. <br>
 * 
 * @author Alfa & Ariss
 */
public class RawCommunicator implements IClientCommunicator
{
	private final String MODULE = "RawCommunicator";

	/** The Logger for this RAWCommunicator */
	private SystemLogger _systemLogger;

	/** "[]" braces UTF-8 encoded. */
	private static final String ENCODED_BRACES = "%5B%5D";

	/**
	 * Creates a new <code>RawCommunicator</code>. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>systemLogger</code> should be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <code>_systemLogger</code> is set with <code> systemLogger</code>. <br>
	 * 
	 * @param systemLogger
	 *            the <code>logger</code> to log system information.
	 */
	public RawCommunicator(SystemLogger systemLogger) {
		_systemLogger = systemLogger;
	}

	/**
	 * Sends a raw api call to the A-Select Server. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Executes the following steps:
	 * <ul>
	 * <li>Create empty return HashMap</li>
	 * <li>Convert paramaters to CGI message string</li>
	 * <li>Send request to A-Select server</li>
	 * <li>Convert response to HashMap</li>
	 * </ul>
	 * <br>
	 * 
	 * @param parameters
	 *            the parameters
	 * @param target
	 *            the target
	 * @return the hash map
	 * @throws ASelectCommunicationException
	 *             If sending fails.
	 * @see org.aselect.system.communication.client.IClientCommunicator#sendMessage(java.util.HashMap, java.lang.String)
	 */
	public HashMap sendMessage(HashMap parameters, String target)
	throws ASelectCommunicationException
	{
		HashMap htReturn = new HashMap();
		try {
			// Convert paramaters to CGI message string.
			String sRequest = hashtable2CGIMessage(parameters);
			// Send request to server
			String sResponse = sendRequestToAnotherServer(target, sRequest);
			// Convert response to HashMap
			if (sResponse != null)
				htReturn = convertCGIMessage(sResponse);
		}
		catch (UnsupportedEncodingException eUE) {
			_systemLogger.log(Level.WARNING, MODULE, "sendMessage", "Could not URL encode/decode one or more values");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return htReturn;
	}

	// Bauke: added
	/* (non-Javadoc)
	 * @see org.aselect.system.communication.client.IClientCommunicator#sendStringMessage(java.lang.String, java.lang.String)
	 */
	public String sendStringMessage(String sMessage, String sTarget)
	throws ASelectCommunicationException
	{
		String sResponse = null;
		String sMethod = "sendStringMessage";

		try {  // Send the message
			sResponse = DataCommunicator.send(_systemLogger, sMessage, sTarget);
		}
		catch (java.net.MalformedURLException eMU) {
			StringBuffer sbBuffer = new StringBuffer("Invalid URL: ");
			sbBuffer.append(eMU.getMessage()).append(" errorcode: ").append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eMU);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, eMU);
		}
		//_systemLogger.log(Level.INFO, MODULE, sMethod, "Response=" + sResponse);
		return sResponse;
	}

	/**
	 * Send the request to the A-Select server. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Executes the following steps:
	 * <ul>
	 * <li>Builds a URL with request parameters</li>
	 * <li>Opens a connection to the server</li>
	 * <li>Recieves response from the server</li>
	 * </ul>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * <li><code>sUrl</code> is a valid URL
	 * <li><code>sParams</code> is a non empty <code>String</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The return <code>String</code> contains the server response. <br>
	 * 
	 * @param sUrl
	 *            The URL of the A-Select server.
	 * @param sParams
	 *            The parameters to be send as CGIMessage.
	 * @return The response from the A-Select server.
	 * @throws ASelectCommunicationException
	 *             If communication with <code>sUrl</code> fails.
	 */
	private String sendRequestToAnotherServer(String sUrl, String sParams)
	throws ASelectCommunicationException
	{
		String sMethod = "sendRequestToAnotherServer";
		String sInputLine = "";
		URL urlSomeServer = null;
		BufferedReader brInput = null;
		StringBuffer sbBuffer = new StringBuffer();

		sbBuffer = new StringBuffer(sUrl).append("?").append(sParams);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "URL=" + sbBuffer.toString());
		try {
			urlSomeServer = new URL(sbBuffer.toString());
			brInput = new BufferedReader(new InputStreamReader(urlSomeServer.openStream()), 16000);
			String s = null;
			while ( (s = brInput.readLine()) != null) {
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Input from the other server=" +s);
				sInputLine += s;
			}
			brInput.close();

			if (sInputLine != null)
				sInputLine = sInputLine.trim();
			return sInputLine;
		}
		catch (MalformedURLException eMU) // Invalid URL
		{
			sbBuffer = new StringBuffer("Invalid URL: \"").append(sUrl);
			sbBuffer.append("\" errorcode: ").append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, eMU);
		}
		catch (IOException eIO) // Error communicating with A-Select Server
		{
			sbBuffer = new StringBuffer("Error communicating with server at: \"").append(sUrl);
			sbBuffer.append("\" errorcode: ").append(Errors.ERROR_ASELECT_IO);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, eIO);
		}
	}

	/**
	 * Convert <code>HashMap</code> to CGI message string. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a CGI syntax message from the key/value pairs in the input <code>HashMap</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The used {@link java.util.HashMap}objects are synchronized. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>htInput</code> should be a HashMap containing valid parameters. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The return <code>String</code> contains the parameters in CGI syntax. <br>
	 * 
	 * @param htInput
	 *            The <code>HashMap</code> to be converted.
	 * @return CGI message containg all parameters in <code>htInput</code>.
	 * @throws UnsupportedEncodingException
	 *             If URL encoding fails.
	 */
	private static String hashtable2CGIMessage(HashMap htInput)
	throws UnsupportedEncodingException
	{
		StringBuffer sbBuffer = new StringBuffer();

		Set keys = htInput.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
			Object oValue = htInput.get(sKey);
			if (oValue instanceof String) {
				sbBuffer.append(sKey);
				sbBuffer.append("=");
				// URL encode value
				String sValue = URLEncoder.encode((String) oValue, "UTF-8");
				sbBuffer.append(sValue);
			}
			else if (oValue instanceof String[]) {
				String[] strArr = (String[]) oValue;
				for (int i = 0; i < strArr.length; i++) {
					sbBuffer.append(sKey).append(ENCODED_BRACES);
					sbBuffer.append("=");
					String sValue = URLEncoder.encode(strArr[i], "UTF-8");
					sbBuffer.append(sValue);
					if (i < strArr.length - 1)
						sbBuffer.append("&");
				}
			}
			// Append extra '&' after every parameter.
			sbBuffer.append("&");
		}
		int len = sbBuffer.length();
		return sbBuffer.substring(0, (len > 0) ? len - 1 : len);
	}

	/**
	 * Convert a CGI message string into a <code>HashMap</code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method will convert a CGI request string ( <code>key=value&key=value</code> etc. ) into a hashtable for much
	 * easier processing. <br>
	 * The <code>HashMap</code> will contain:
	 * <ul>
	 * <li>key = The parameter name</li>
	 * <li>value = The parameter value</li>
	 * </ul>
	 * <i>Note: The key names are all converted to lowercase. </i> <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned {@link java.util.HashMap}is synchronized. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>sMessage</code> must contain a valid CGI message. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The returned <code>HashMap</code> contains all the key/value pairs of the CGI message. <br>
	 * 
	 * @param sMessage
	 *            The CGI message to be converted.
	 * @return A <code>HashMap</code> containing the parameters from the CGI message
	 * @throws UnsupportedEncodingException
	 *             If URL decoding fails.
	 */
	public HashMap convertCGIMessage(String sMessage)
	throws UnsupportedEncodingException
	{
		String sToken, sKey, sValue;
		StringTokenizer sTokenizer = null;
		int iPos;
		HashMap xResponse = new HashMap();
		HashMap tblVectors = new HashMap();

		if (sMessage != null) {
			sTokenizer = new StringTokenizer(sMessage, "&");

			while (sTokenizer.hasMoreElements()) {
				sToken = (String) sTokenizer.nextElement();
				if (!sToken.trim().equals("")) {
					iPos = sToken.indexOf('=');
					if (iPos != -1) {
						sKey = sToken.substring(0, iPos);
						try {
							sValue = sToken.substring(iPos + 1);
						}
						catch (Exception e) {
							sValue = "";
						}
						if (sKey != null && sValue != null) {
							// URL decode
							sValue = URLDecoder.decode(sValue, "UTF-8");
							if (sKey.endsWith(ENCODED_BRACES)) {
								sKey = sKey.substring(0, sKey.lastIndexOf(ENCODED_BRACES));
								Vector vTemp = null;
								if (tblVectors.containsKey(sKey)) {
									vTemp = (Vector) tblVectors.get(sKey);
									vTemp.add(sValue);
								}
								else {
									vTemp = new Vector();
									vTemp.add(sValue);
								}
								tblVectors.put(sKey, vTemp);
							}
							else {
								xResponse.put(sKey, sValue);
							}
						}
					}
				}
			}

			if (!tblVectors.isEmpty()) {
				Set keys = tblVectors.keySet();
				for (Object s : keys) {
					String sArrName = (String) s;
					Vector vTmp = (Vector) tblVectors.get(sArrName);
					String[] arrTemp = new String[vTmp.size()];

					try {
						arrTemp = (String[]) vTmp.toArray(arrTemp);
					}
					catch (Exception e) {
						_systemLogger.log(Level.WARNING, MODULE, "convertCGIMessage",
								"Could not convert Vector to array", e);
					}
					xResponse.put(sArrName, arrTemp);
				}
			}
		}
		return xResponse;
	}
}