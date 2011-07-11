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
 * $Id: RawMessageCreator.java,v 1.14 2006/05/03 09:31:42 martijn Exp $ 
 * 
 * Changelog:
 * $Log: RawMessageCreator.java,v $
 * Revision 1.14  2006/05/03 09:31:42  martijn
 * variable name changed
 *
 * Revision 1.13  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.12  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.11  2005/04/27 13:45:13  martijn
 * fixed bug in convertCGIMessage() this method didn't catch an exception that occurs during decode of a 16k message
 *
 * Revision 1.10  2005/03/24 13:24:22  erwin
 * Removed toLowerCase() for parameters.
 *
 * Revision 1.9  2005/03/24 09:31:22  erwin
 * URL encode/decodes all values.
 *
 * Revision 1.8  2005/03/16 13:29:56  tom
 * Added new log functionality
 *
 * Revision 1.7  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.6  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.5  2005/02/28 12:21:29  erwin
 * Changed some log levels to FINE.
 *
 * Revision 1.4  2005/02/22 16:18:49  erwin
 * Improved error handling.
 *
 * Revision 1.3  2005/02/15 12:20:55  erwin
 * Added additional comment.
 *
 * Revision 1.2  2005/02/10 15:47:45  erwin
 * Applied code style and Javadoc comment.
 *
 *
 */
package org.aselect.system.communication.server.raw;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.system.communication.server.IMessageCreatorInterface;
import org.aselect.system.communication.server.IProtocolRequest;
import org.aselect.system.communication.server.IProtocolResponse;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.logging.SystemLogger;

/**
 * Message creator which uses CGI messages. <br>
 * <br>
 * <b>Description:</b><br>
 * The RAW implementation of <CODE>IMessageCreatorInterface</CODE>. Processes and sends CGI URL encoded API calls. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class RawMessageCreator implements IMessageCreatorInterface
{
	/** "[]" braces UTF-8 encoded. */
	private static final String ENCODED_BRACES = "%5B%5D";

	/** Contains the input parameters. */
	private HashMap _htInputTable;

	/** Contains the output message. */
	private StringBuffer _sbOutputMessage;

	/** The request. */
	private IProtocolRequest _oRequest;

	/** The response. */
	private IProtocolResponse _oResponse;

	/** The logger for system log entries. */
	private SystemLogger _systemLogger;

	private final String MODULE = "RawMessageCreator";
	
	// 20110112, Bauke: Make URL encoding configurable (by application)
	private boolean doUrlEncode = true;

	/**
	 * Has Url Encoding been set?
	 */
	public boolean isDoUrlEncode() {
		return doUrlEncode;
	}

	/**
	 * Change the default setting
	 * 
	 * @param doUrlEncode
	 */
	public void setDoUrlEncode(boolean doUrlEncode) {
		this.doUrlEncode = doUrlEncode;
	}

	/**
	 * Creates a new instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new <code>RawMessageCreator</code>. Sets the logger. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * For every request a instance of <code>RawMessageCreator</code> should be created. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>systemLogger</code> should be initialized. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The system logger is set.
	 * 
	 * @param systemLogger
	 *            The logger that should be used for system log entries.
	 */
	public RawMessageCreator(SystemLogger systemLogger)
	{
		_sbOutputMessage = null;
		_systemLogger = systemLogger;
	}

	/**
	 * Initializes the RawMessageCreator. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Initializes the <code>RawMessageCreator</code>:
	 * <ul>
	 * <li>Get query string from request.</li>
	 * <li>Parse query string to input message.</li>
	 * <li>Create new output message.</li>
	 * </ul>
	 * <br>
	 * This method should be the first that is called. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * Initialize should be performed once. <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>oRequest</code> should contain a valid request.</li>
	 * <li><code>oResponse</code> should contain a valid response.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The input message is parsed and a empty response message is ready. <br>
	 * 
	 * @param oRequest
	 *            the request
	 * @param oResponse
	 *            the response
	 * @return true, if inits the
	 * @throws ASelectCommunicationException
	 *             the select communication exception
	 * @see org.aselect.system.communication.server.IMessageCreatorInterface#init(org.aselect.system.communication.server.IProtocolRequest,
	 *      org.aselect.system.communication.server.IProtocolResponse)
	 */
	public boolean init(IProtocolRequest oRequest, IProtocolResponse oResponse)
		throws ASelectCommunicationException
	{
		_oRequest = oRequest;
		_oResponse = oResponse;
		String sMethod = "init()";
		boolean bRetVal = false;

		String sQueryString = _oRequest.getProperty("QueryString");
		if (sQueryString != null) {
			// parse string to _htInputTable
			_htInputTable = new HashMap();
			try {
				_htInputTable = convertCGIMessage(sQueryString);
			}
			catch (ASelectCommunicationException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Can't convert QueryString to HashMap", e);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, e);
			}

			if (!_htInputTable.isEmpty()) {
				_sbOutputMessage = new StringBuffer();
				bRetVal = true;
			}
			else { // query string couldn't be converted
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Can't convert QueryString to HashMap, empty input message.");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
			}
		}
		else { // no query string given
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request, no QueryString");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		return bRetVal;
	}

	/**
	 * get a parameter from a CGI query string message.
	 * 
	 * @param sName
	 *            the s name
	 * @return the param
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 * @see org.aselect.system.communication.server.IInputMessage#getParam(java.lang.String)
	 */
	public String getParam(String sName)
		throws ASelectCommunicationException
	{
		String sMethod = "getParam()";
		StringBuffer sbBuffer = null;
		String sRetVal = null;
		// _systemLogger.log(Level.INFO, MODULE, sMethod, "param:"+sName);
		if (sName != null) {
			if (_htInputTable.containsKey(sName)) // check if name exists
			{
				sRetVal = (String) _htInputTable.get(sName);
			}
			else { // name does not exist in request message
				sbBuffer = new StringBuffer("Can't find parameter name: ");
				sbBuffer.append(sName);
				_systemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
			}
		}
		else { // no name given as parameter
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter name supplied");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		return sRetVal;
	}

	/**
	 * get an array parameter from a CGI query string message.
	 * 
	 * @param sName
	 *            the s name
	 * @return the array
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 * @see org.aselect.system.communication.server.IInputMessage#getArray(java.lang.String)
	 */
	public String[] getArray(String sName)
		throws ASelectCommunicationException
	{
		String sMethod = "getArray()";
		StringBuffer sbBuffer = null;
		String[] saRetVal = null;

		if (sName != null) {
			if (_htInputTable.containsKey(sName)) { // check if name exists
				try {
					saRetVal = (String[]) _htInputTable.get(sName);
				}
				catch (Exception e) {
					sbBuffer = new StringBuffer("Could not cast to String array: \"");
					sbBuffer.append(e.getMessage());
					sbBuffer.append("\" Parameter name: ");
					sbBuffer.append(sName).append(ENCODED_BRACES);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), e);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
				}

			}
			else { // name does not exist in request message
				sbBuffer = new StringBuffer("Can't find parameter: ");
				sbBuffer.append(sName).append(ENCODED_BRACES);
				_systemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
			}
		}
		else { // no name given as parameter
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter name supplied.");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		return saRetVal;
	}

	// 20090310, Bauke: Added to support applications using the DigiD protocol to connect to the server
	// That protocol does not URL encode it's parameters
	/* (non-Javadoc)
	 * @see org.aselect.system.communication.server.IOutputMessage#setParam(java.lang.String, java.lang.String)
	 */
	public boolean setParam(String sName, String sValue)
		throws ASelectCommunicationException
	{
		return setParam(sName, sValue, isDoUrlEncode());  // 20110112: Formerly: true);
	}

	/**
	 * set a parameter as a CGI query string message.
	 * 
	 * @param sName
	 *            the s name
	 * @param sValue
	 *            the s value
	 * @param doUrlEncode
	 *            the do url encode
	 * @return true, if sets the param
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 * @see org.aselect.system.communication.server.IOutputMessage#setParam(java.lang.String, java.lang.String)
	 */
	public boolean setParam(String sName, String sValue, boolean doUrlEncode)
		throws ASelectCommunicationException
	{
		String sMethod = "setParam";
		StringBuffer sbBuffer = null;

		_systemLogger.log(Level.FINE, MODULE, sMethod, "param="+sName +" value="+sValue +" encode="+doUrlEncode);
		boolean bRetValue = false;
		if (sName != null && sValue != null) // name and value may not be empty
		{
			try {
				if (doUrlEncode) {
					sValue = URLEncoder.encode(sValue, "UTF-8");
				}
			}
			catch (UnsupportedEncodingException eUE) {
				sbBuffer = new StringBuffer("Could not URL encode parameter '");
				sbBuffer.append(sName);
				sbBuffer.append("' with value '");
				sbBuffer.append(sName).append("'");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eUE);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			if (_sbOutputMessage == null)
				_sbOutputMessage = new StringBuffer("");
			if (_sbOutputMessage.indexOf(sName + "=") == -1) { // if not already contains the parameter
				if (_sbOutputMessage.length() > 0) {
					_sbOutputMessage.append("&" + sName + "=" + sValue);
				}
				else {
					_sbOutputMessage.append(sName + "=" + sValue);
				}
				bRetValue = true;
			}
			else {
				sbBuffer = new StringBuffer("Parameter ");
				sbBuffer.append(sName);
				sbBuffer.append(" already exists in output message");
				_systemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
			}
		}
		else { // no parameter given
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to set empty parameter");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		return bRetValue;
	}

	/**
	 * set an array parameter as a CGI query string message.
	 * 
	 * @param sName
	 *            the s name
	 * @param saValue
	 *            the sa value
	 * @return true, if sets the param
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 * @see org.aselect.system.communication.server.IOutputMessage#setParam(java.lang.String, java.lang.String[])
	 */
	public boolean setParam(String sName, String[] saValue)
		throws ASelectCommunicationException
	{
		String sMethod = "setParam()";
		StringBuffer sbBuffer = null;

		boolean bRetValue = false;
		if (sName != null && saValue != null) // name and value may not be empty
		{
			if (_sbOutputMessage.indexOf(sName + ENCODED_BRACES + "=") == -1) {
				// if not already contains the parameter
				if (_sbOutputMessage.length() > 0) {
					_sbOutputMessage.append("&");
				}
				try {
					_sbOutputMessage.append(convertArray(sName, saValue));
				}
				catch (UnsupportedEncodingException eUE) {
					sbBuffer = new StringBuffer("Could not URL encode array parameter '");
					sbBuffer.append(sName);
					sbBuffer.append("'");
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eUE);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}
				bRetValue = true;
			}
			else {
				sbBuffer = new StringBuffer("Parameter ");
				sbBuffer.append(sName);
				sbBuffer.append("[] already exists in output message");
				_systemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
			}
		}
		else { // no parameter given
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to set empty parameter.");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		return bRetValue;
	}

	/**
	 * Convert a CGI string. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method will convert a string of <code>key=value&key=value</code> etc. tuples (aka a CGI request string) into
	 * a hashtable for much easier processing. This method supports CGI array parameters. <br>
	 * <br>
	 * <i>Note: The key names are all converted to lowercase.</i> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * The used <code>HashMap</code> is threadsafe. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sMessage</code> should be a valid request string. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sMessage
	 *            A CGI request string.
	 * @return The name/value pairs of the request in a <code>HashMap</code>.
	 * @throws ASelectCommunicationException
	 *             if decoding of value fails or internal error occurs.
	 */
	public HashMap convertCGIMessage(String sMessage)
		throws ASelectCommunicationException
	{
		String sMethod = "convertCGIMessage()";
		HashMap htResponse = new HashMap();
		String sToken, sKey, sValue;
		StringTokenizer oTokenizer = null;
		int iPos;
		HashMap htVectors = new HashMap();

		try {
			if (sMessage != null) {
				oTokenizer = new StringTokenizer(sMessage, "&");
				while (oTokenizer.hasMoreElements()) {
					sToken = (String) oTokenizer.nextElement();
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
									if (htVectors.containsKey(sKey))
										vTemp = (Vector) htVectors.get(sKey);
									else
										vTemp = new Vector();
									vTemp.add(sValue);
									htVectors.put(sKey, vTemp);
								}
								else {
									htResponse.put(sKey, sValue);
								}
							}
						}
					}
				}

				if (!htVectors.isEmpty()) {
					Set keys = htVectors.keySet();
					for (Object s : keys) {
						String strArrName = (String) s;
						// Enumeration enumVectors = htVectors.keys();
						// while (enumVectors.hasMoreElements())
						// {
						// String strArrName = (String) enumVectors.nextElement();
						Vector vTmp = (Vector) htVectors.get(strArrName);
						String[] arrTemp = new String[vTmp.size()];
						arrTemp = (String[]) vTmp.toArray(arrTemp);
						htResponse.put(strArrName, arrTemp);
					}
				}
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception during converting the CGI message", e);

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return htResponse;
	}

	/**
	 * Send the repsonse as a CGI URL encoded query string.
	 * 
	 * @return true, if send
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 * @see org.aselect.system.communication.server.IOutputMessage#send()
	 */
	public boolean send()
		throws ASelectCommunicationException
	{
		String sMethod = "send()";
		boolean bRetVal = false;
		// parse xOutputTable to URL string
		// String xOutput = convertHashtable(xOutputTable);
		if (_sbOutputMessage != null) {
			// send message to ouputStream
			bRetVal = sendMessage(_sbOutputMessage.toString());
		}
		else { // couldn't convert ouput table to response string
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Supplied message is empty");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		// erase hashtables
		_htInputTable = null;
		_sbOutputMessage = null;

		return bRetVal;
	}

	/**
	 * Send the output message. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Sending the output message as <CODE>String</CODE> to the <CODE>OuputStream</CODE>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * This method should only be called once. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * This instance is initialised. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The ouput message is sent. <br>
	 * 
	 * @param sMsg
	 *            The ouput message as <CODE>String</CODE>.
	 * @return false if response message could not be sent, otherwise false.
	 * @throws ASelectCommunicationException
	 *             If communication fails.
	 */
	private boolean sendMessage(String sMsg)
		throws ASelectCommunicationException
	{
		String sMethod = "sendMessage()";
		boolean bRetVal = false;
		try {
			OutputStream oStream = _oResponse.getOutputStream();
			oStream.write(sMsg.getBytes());
			oStream.close();
			bRetVal = true;
		}
		catch (IOException eIO) // couldn't write response to requester
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error sending message", eIO);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
		}
		return bRetVal;
	}

	/**
	 * Convert an string array to an array paremeter. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Convert all given values to an CGI array parameter with the given name. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>sName</code> should be a valid parameter name.</li>
	 * <li><code>saValues</code> should contain valid paremete values.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sName
	 *            The array paremeter name.
	 * @param saValues
	 *            The array parameter values.
	 * @return A StringBuffer containing the CGI string array parameter.
	 * @throws UnsupportedEncodingException
	 *             If encoding of value fails.
	 */
	private StringBuffer convertArray(String sName, String[] saValues)
		throws UnsupportedEncodingException
	{
		StringBuffer sbBuffer = new StringBuffer();
		for (int i = 0; i < saValues.length; i++) {
			if (i > 0) {
				sbBuffer.append("&");
			}
			String sValue = URLEncoder.encode(saValues[i], "UTF-8");
			sbBuffer.append(sName).append(ENCODED_BRACES).append("=").append(sValue);
		}
		return sbBuffer;
	}

}