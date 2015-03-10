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
 * $Id: SOAP11Communicator.java,v 1.19 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: SOAP11Communicator.java,v $
 * Revision 1.19  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.18  2006/04/12 13:20:41  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.17.4.1  2006/02/28 09:04:08  jeroen
 * Bugfix for 136:
 *
 * SOAP11Communicator -> send
 * Added SOAPAction to the request property with value the aselect url
 *
 * Revision 1.17  2005/09/08 12:47:12  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.16  2005/03/24 09:33:14  erwin
 * Added normalization of values.
 *
 * Revision 1.15  2005/03/16 13:15:39  tom
 * Added new log functionality
 *
 * Revision 1.14  2005/03/16 12:55:45  tom
 * Added new log functionality
 *
 * Revision 1.13  2005/03/16 11:41:48  tom
 * Fixed Javadoc comment
 *
 * Revision 1.12  2005/03/11 15:35:38  erwin
 * Improved logging of IO Exception when sending.
 *
 * Revision 1.11  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.10  2005/03/08 09:11:59  erwin
 * Added a \r\n\r\n after message.
 *
 * Revision 1.9  2005/03/04 15:50:13  erwin
 * Renamed Content-type -> Content-Type
 *
 * Revision 1.8  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.7  2005/02/22 16:18:49  erwin
 * Improved error handling.
 *
 * Revision 1.6  2005/02/10 15:46:18  erwin
 * minor comment change.
 *
 * Revision 1.5  2005/02/10 10:10:49  erwin
 * code format
 *
 * Revision 1.4  2005/02/10 10:01:25  erwin
 * Applied code style and Javadoc comment.
 *
 * Revision 1.3  2005/02/07 16:26:47  erwin
 * Improved Javadoc comment
 *
 * Revision 1.2  2005/02/07 15:19:17  erwin
 * Refactor ClientCommunicator to IClientCommunicator.
 *
 */

package org.aselect.system.communication.client.soap11;

import java.io.PrintStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.logging.Level;

import org.apache.xerces.dom.DocumentImpl;
import org.apache.xerces.parsers.DOMParser;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Tools;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;


/**
 * Client communicator which uses SOAP 1.1 over HTTP. <br>
 * <br>
 * <b>Description: </b> <br>
 * The SOAP communicator is used to create, retrieve, and send SOAP 1.1 messages. <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - sendStringMessage() method added
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl)
 */
public class SOAP11Communicator implements IClientCommunicator
{
	/** The MIME content type for SOAP 1.1. */
	private static final String CONTENT_TYPE = "text/xml; charset=utf-8";

	/** SOAP 1.1 URI. */
	private static final String URI_SOAP11_ENV = "http://www.w3.org/2001/12/soap-envelope";

	/** SOAP 1.1 Encoding URI. */
	private static final String URI_SOAP11_ENC = "http://www.w3.org/2001/12/soap-encoding";

	/** A-Select RPC-BODY URI extension. */
	private static final String URI_ASELECT_ENV = "";// "/schemas/"

	/** The method name that is used in the SOAP RPC body. */
	private String _sCallMethod;

	/** The logger for system log entries. */
	private SystemLogger _systemLogger;

	private final String MODULE = "SOAP11Communicator";

	/**
	 * Creates a new <code>SOAP11Communicator</code>. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>requestMethod</code> may not be null.</li>
	 * <li><code>systemLogger</code> should be initialized.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <ul>
	 * <li>The systemlogger is set with <code> systemLogger</code>.</li>
	 * <li><The call method is set with <code> sCallMethod</code>.</li>
	 * </ul>
	 * 
	 * @param sCallMethod
	 *            The method name that is used in the SOAP message.
	 * @param systemLogger
	 *            The <code>Logger</code> to log system log entries.
	 */
	public SOAP11Communicator(String sCallMethod, SystemLogger systemLogger) {
		_sCallMethod = sCallMethod;
		_systemLogger = systemLogger;
	}

	/**
	 * Creates a SOAP message of the given parameters and sends it to the given url. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Executes the following steps:
	 * <ul>
	 * <li>Builds a SOAP 1.1 request message</li>
	 * <li>Send the message to the server</li>
	 * <li>Recieves SOAP response message from the server</li>
	 * <li>Parse the repsonse and return the parameters it contains</li>
	 * </ul>
	 * 
	 * @param htParameters
	 *            the ht parameters
	 * @param sUrl
	 *            the s url
	 * @return the hash map
	 * @throws ASelectCommunicationException
	 *             If suplied URL is invalid.
	 * @see org.aselect.system.communication.client.IClientCommunicator#sendMessage(java.util.HashMap, java.lang.String)
	 */
	public HashMap sendMessage(HashMap htParameters, String sUrl)
	throws ASelectCommunicationException
	{
		String sMethod = "sendMessage";
		HashMap htResult = new HashMap();
		String sMessage = null;
		String sResponse = null;
		Element elBody = null;

		// Create a new message
		sMessage = createMessage(htParameters, sUrl);
		try {
			// Send the message
			sResponse = sendTheSoapMessage(sMessage, sUrl);
		}
		catch (java.net.MalformedURLException eMU)
		// exception if URL is malformed
		{
			StringBuffer sbBuffer = new StringBuffer("Invalid URL: ");
			sbBuffer.append(eMU.getMessage());
			sbBuffer.append(" errorcode: ");
			sbBuffer.append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eMU);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, eMU);
		}
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Response=" + sResponse);

		// Parse and return response
		elBody = this.parse(sResponse);
		htResult = this.xmlBody2Hashtable(elBody, sUrl);

		return htResult;
	}

	// Bauke: added
	/* (non-Javadoc)
	 * @see org.aselect.system.communication.client.IClientCommunicator#sendStringMessage(java.lang.String, java.lang.String)
	 */
	public String sendStringMessage(String soapMessage, String sTarget)
	throws ASelectCommunicationException
	{
		String sResponse = null;
		String sMethod = "sendStringMessage";

		// Create a new message
		StringBuffer sbMessage = new StringBuffer();
		sbMessage.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		sbMessage.append("<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n");
		sbMessage.append("<soap:Header/><soap:Body>\n");
		sbMessage.append(soapMessage);
		sbMessage.append("\n</soap:Body></soap:Envelope>");
		try {
			// Send the message
			sResponse = sendTheSoapMessage(sbMessage.toString(), sTarget);
		}
		catch (java.net.MalformedURLException eMU) {
			StringBuffer sbBuffer = new StringBuffer("Invalid URL: ");
			sbBuffer.append(eMU.getMessage());
			sbBuffer.append(" errorcode: ");
			sbBuffer.append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eMU);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, eMU);
		}
		// int len = sResponse.length();
		// _systemLogger.log(Level.INFO, MODULE, sMethod, "Response="+sResponse.substring(0, (len<40)?len:40));
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Response=" + sResponse);
		return sResponse;
	}

	/**
	 * Creates an SOAP message as <code>String</code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a correct SOAP 1.1 message containing the given parameters. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The used {@link java.util.HashMap}is synchronized. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>htParameters</code> must contain valid parameter name/valuepairs.</li>
	 * <li><code>sTargetUrl</code> must be a valid URL.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param htParameters
	 *            A <CODE>HashMap</CODE> containing the paramaters to add to the SOAP message.
	 * @param sTargetUrl
	 *            The URL of the server.
	 * @return <CODE>String</CODE> containing the created SOAP message
	 */
	public String createMessage(HashMap htParameters, String sTargetUrl)
	{
		String sMethod = "createMessage";
		StringBuffer sbMessage = new StringBuffer();
		if (htParameters != null || !sTargetUrl.equals(""))
		// Params and target url may not be empty to create a message
		{
			// create SOAP message in String format
			sbMessage.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
			sbMessage.append("<env:Envelope xmlns:env=\"").append(URI_SOAP11_ENV).append("\" env:encodingStyle=\"")
					.append(URI_SOAP11_ENC).append("\">\n");
			sbMessage.append("\t<env:Body>\n");
			sbMessage.append("\t\t<m:").append(_sCallMethod).append(" xmlns:m=\"").append(sTargetUrl);
			sbMessage.append(URI_ASELECT_ENV).append("\">\n");

			Iterator iter = htParameters.keySet().iterator();
			String sKey = null;
			while (iter.hasNext()) {
				sKey = (String) iter.next();
				Object objValue = htParameters.get(sKey);
				if (objValue instanceof String) {
					// Add params to message in SOAP-RPC format
					sbMessage.append("\t\t\t<m:").append(sKey).append(">");
					sbMessage.append(normalize((String) objValue));
					sbMessage.append("</m:").append(sKey).append(">\n");
				}
				else if (objValue instanceof String[]) {
					String[] strArr = (String[]) objValue;
					// Add params to message in SOAP-RPC format
					sbMessage.append("\t\t\t<m:").append(sKey).append(" m:arrayType=\"xsd:string[").append(
							strArr.length).append("]\" >\n");
					for (int i = 0; i < strArr.length; i++) {
						sbMessage.append("\t\t\t\t<m:item>");
						sbMessage.append(normalize(strArr[i]));
						sbMessage.append("</m:item>\n");
					}
					sbMessage.append("\t\t\t</m:").append(sKey).append(">\n");
				}
				else {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Unknown object found in HashMap");
				}
			}

			// close tags
			sbMessage.append("\t\t</m:").append(_sCallMethod).append(">\n");
			sbMessage.append("\t</env:Body>\n");
			sbMessage.append("</env:Envelope>");
		}
		return sbMessage.toString();
	}

	/**
	 * Sends a SOAP message to a SOAP server. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Sends the suplied SOAP message to the suplied URL using an <code>HttpURLConnection</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li>
	 * <code>sMessage</code> should contain a valid SOAP 1.1 message.</li>
	 * <li><code>sUrl</code> should be a valid URL.</li>
	 * </ul>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param sMessage
	 *            A <code>String</code> containing the SOAP message that has to be sent.
	 * @param sUrl
	 *            The URL to send the message to.
	 * @return A <CODE>String</CODE> containing the response SOAP message.
	 * @throws java.net.MalformedURLException
	 *             If suplied URL is invalid.
	 * @throws ASelectCommunicationException
	 *             If communication with the server fails.
	 * @throws MalformedURLException
	 *             the malformed url exception
	 */
	private String sendTheSoapMessage(String sMessage, String sUrl)
	throws java.net.MalformedURLException, ASelectCommunicationException
	{
		StringBuffer sb = new StringBuffer();
		String sMethod = "send";
		URL url = null;
		HttpURLConnection connection = null;

		// http://[target address]/[schema target]
		url = new URL(sUrl);

		try {
			// open HTTP connection to URL
			connection = (HttpURLConnection) url.openConnection();
			// enable sending to connection
			connection.setDoOutput(true);

			// set mime headers
			connection.setRequestProperty("Content-Type", CONTENT_TYPE);
			connection.setRequestProperty("Accept", CONTENT_TYPE);

			StringBuffer sbSOAPAction = new StringBuffer("\"");
			sbSOAPAction.append(sUrl).append("\"");
			connection.setRequestProperty("SOAPAction", sbSOAPAction.toString());

			// write message to output
			PrintStream osOutput = new PrintStream(connection.getOutputStream());
			osOutput.println(sMessage);
			osOutput.println("\r\n\r\n");
			osOutput.close();

			// RH, 20080717, so
			// int xRead = 0;
			// byte[] ba = new byte[512];
			// DataInputStream isInput = null;
			// RH, 20080717, eo

			int iRetCode = connection.getResponseCode();
			switch (iRetCode) { // switch on HTTP response code
			case 200: // ok
			{
				/*
				 * // RH, 20080717, so isInput = new DataInputStream(connection.getInputStream()); //Retrieve message as
				 * bytes and put them in a string while ((xRead = isInput.read(ba)) != -1) { //append to stringbuffer
				 * sb.append(new String(ba, 0, xRead)); // clear the buffer Arrays.fill(ba, (byte)0); } //close the
				 * stream isInput.close();
				 */// RH, 20080717, eo
				sb = new StringBuffer(Tools.stream2string(connection.getInputStream(), true)); // RH, 20080717, n
				break;
			}
			case 500: // Internal server error
			{
				StringBuffer sbBuffer = new StringBuffer("Internal server error at target host. errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				break;
			}
			default: // unknown error
			{
				StringBuffer sbBuffer = new StringBuffer("Invalid response from target host: \"");
				sbBuffer.append(connection.getHeaderField(0));
				sbBuffer.append(" \". errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				break;
			}
			}

		}
		catch (java.net.UnknownHostException eUH)// target host unknown
		{
			StringBuffer sbBuffer = new StringBuffer("Target host unknown: \"");
			sbBuffer.append(sUrl);
			sbBuffer.append("\" errorcode: ");
			sbBuffer.append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eUH);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, eUH);
		}
		catch (java.io.IOException eIO)
		// error while connecting,writing or reading
		{
			StringBuffer sbBuffer = new StringBuffer("Could not open connection with host: \"");
			sbBuffer.append(sUrl);
			sbBuffer.append("\" errorcode: ");
			sbBuffer.append(Errors.ERROR_ASELECT_IO);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eIO);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, eIO);
		}
		return sb.toString();
	}

	/**
	 * Parses a message to a XML <code>Element</code> object. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Uses a <code>DOMParser</code> to parse the supplied message. Extracts the SOAP body from the parsed message. All
	 * parse and I/O errors are converted to <code>ASelectCommunicationException</code> exceptions. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * Xerces XML object are not thread safe, this methods creates its own <code>DOMParser</code> and is therefore
	 * threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>sMessage</code> should contain a valid SOAP 1.1 message. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param sMessage
	 *            A <CODE>String</CODE> with the SOAP message that has to be parsed.
	 * @return An <CODE>Element</CODE> containing the parsed SOAP message body.
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 * @see org.apache.xerces.parsers.DOMParser#parse(org.xml.sax.InputSource)
	 */
	private Element parse(String sMessage)
	throws ASelectCommunicationException
	{
		Element elBody = null;
		String sMethod = "parse";
		if (!sMessage.equals("")) {
			try {
				// create new DOM parser
				DOMParser parser = new DOMParser();
				// set error handler to default empty handler
				parser.setErrorHandler(new DefaultHandler());
				// parse message as String to DOM object

				_systemLogger.log(Level.FINEST, MODULE, sMethod, "PARSE " + sMessage);
				parser.parse(new InputSource(new StringReader(sMessage)));
				// get root XML tag
				DocumentImpl doc = (DocumentImpl) parser.getDocument();
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "doc=" + doc);
				// get body element
				NodeList nlNodes = doc.getDocumentElement().getElementsByTagNameNS(URI_SOAP11_ENV, "Body");

				if (nlNodes.getLength() == 0) { // Bauke: additional try
					nlNodes = doc.getDocumentElement().getElementsByTagNameNS(
							"http://schemas.xmlsoap.org/soap/envelope/", "soap:Body");
				}
				if (nlNodes.getLength() == 1) {
					Node nBody = nlNodes.item(0);
					if (nBody instanceof Element)
					// if node = element then it's the Body element
					{
						elBody = (Element) nBody;
					}
				}
			}
			catch (org.xml.sax.SAXException eSaxE)
			// error while parsing
			{
				StringBuffer sbBuffer = new StringBuffer("Error during parsing: ");
				sbBuffer.append(eSaxE.getMessage());
				sbBuffer.append(" errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_PARSE_ERROR);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eSaxE);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_PARSE_ERROR, eSaxE);
			}
			catch (java.io.IOException eIO)
			// error reading Message String from inputstream
			{
				StringBuffer sbBuffer = new StringBuffer("Error reading message from inputstream: ");
				sbBuffer.append(eIO.getMessage());
				sbBuffer.append(" errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_IO);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eIO);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, eIO);
			}
		}
		return elBody;
	}

	/**
	 * Converts the xml body to a HashMap object. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Converts the xml body <code>Element</code> to a HashMap object. <br>
	 * <br>
	 * <b>Concurrency issues: </b>
	 * <ul>
	 * <li><code>elBody</code> is not threadsafe and this method should be called sequential when using the same
	 * <code>elBody</code> object.</li>
	 * <li>The returned <code>HashMap</code> is threadsafe.</li>
	 * </ul>
	 * <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>elBody</code> should be a constructed SOAP Body.</li>
	 * <li><code>sURI</code> should be a valid URL</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param elBody
	 *            an DOM <code>Element</code> containing the body of the SOAP message
	 * @param sURI
	 *            the Namespace URI of the body.
	 * @return An <CODE>HashMap</CODE> containing the response params.
	 * @throws ASelectCommunicationException
	 *             If conversion fails.
	 */
	private HashMap xmlBody2Hashtable(Element elBody, String sURI)
	throws ASelectCommunicationException
	{
		String sMethod = "xmlBody2Hashtable";
		HashMap htReturn = new HashMap();
		if (elBody != null) {
			String sKey = null;
			String sValue = null;
			NodeList nlTemp = null;
			NodeList nl = null;
			nl = elBody.getElementsByTagNameNS(new StringBuffer(sURI).append(URI_ASELECT_ENV).toString(),
					new StringBuffer(_sCallMethod).append("Response").toString());
			if (nl.getLength() == 1) // There may only be one Response tag
			{
				// get all child nodes of the first element from nodelist
				nl = nl.item(0).getChildNodes();
				// for every param do
				for (int i = 0; i < nl.getLength(); i++) {
					// get param and check if it has childs
					if (nl.item(i).hasChildNodes()) {
						nlTemp = nl.item(i).getChildNodes();
						// it may only have one child node and it must be a
						// TEXT_NODE
						if (nlTemp.getLength() == 1) {// it must be a TEXT_NODE
							if (nlTemp.item(0).getNodeType() == Node.TEXT_NODE) {
								// localname = tagname without namespace prefix
								sKey = nl.item(i).getLocalName();
								// get value of text node
								sValue = nlTemp.item(0).getNodeValue();
								// add to HashMap
								htReturn.put(sKey, sValue);
							}
						}
						else {
							if (nl.item(i).getNodeType() == Node.ELEMENT_NODE) {
								Element curElement = (Element) nl.item(i);
								String[] aString = resolveArray(curElement, nlTemp);

								// localname = tagname without namespace prefix
								sKey = curElement.getLocalName();

								// add to HashMap
								htReturn.put(sKey, aString);
							}
						}
					}
				}
			}
			else {
				// SOAP RPC body = invalid
				// -> namespace can be invalid, more response tags or no
				// response tag
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Invalid SOAP-RPC body");
			}
		}
		return htReturn;
	}

	/**
	 * resolve an array from a SOAP message. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Get all values form the suplied element and convert these to a <code>String</code> array. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * <code>elRoot</code> and <code>nlChildElements</code> are not threadsafe and this method should be called
	 * sequential when using the same instances of these objects. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>elRoot</code> Should be a valid XML <code>Element</code>.</li>
	 * <li><code>nlChildElements</code> Should contain aray parameters.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param elRoot
	 *            The root <code>element</code>.
	 * @param nlChildElements
	 *            The array parameters (child elements of <code>elRoot</code>).
	 * @return The parameter values in the array.
	 * @throws ASelectCommunicationException
	 *             If the "arraySize" is malformed.
	 */
	private String[] resolveArray(Element elRoot, NodeList nlChildElements)
	throws ASelectCommunicationException
	{
		String sMethod = "resolveArray";
		String[] sa = null;
		String sAttr = elRoot.getAttribute("m:arrayType");
		String s = (String) sAttr.subSequence(sAttr.lastIndexOf("[") + 1, sAttr.lastIndexOf("]"));
		try {
			int iArrayMax = new Integer(s).intValue();
			int aArrayIndex = 0;
			sa = new String[iArrayMax];
			for (int i = 0; i < nlChildElements.getLength(); i++) {
				if (nlChildElements.item(i).getNodeType() == Node.ELEMENT_NODE) {
					Node tmpNode = nlChildElements.item(i).getFirstChild();
					if (tmpNode.getNodeType() == Node.TEXT_NODE) {
						// get value of text node
						if (aArrayIndex < iArrayMax)
							sa[aArrayIndex++] = tmpNode.getNodeValue();
					}
				}
			}
		}
		catch (NumberFormatException eNumberFormat) {
			StringBuffer sbBuffer = new StringBuffer("Error during resolving array (invalid 'arraySize'): ");
			sbBuffer.append(eNumberFormat.getMessage());
			sbBuffer.append(" errorcode: ");
			sbBuffer.append(Errors.ERROR_ASELECT_PARSE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eNumberFormat);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_PARSE_ERROR, eNumberFormat);
		}
		return sa;
	}

	/**
	 * Normalizes the given string. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Converts special XML characters (&lt;, &gt;, &amp;, and &quot;). <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>s != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param s
	 *            The <code>String</code> to be normalized.
	 * @return The normalized <code>String</code>.
	 */
	private String normalize(String s)
	{
		// RM_65_01
		StringBuffer sb = new StringBuffer();

		for (int i = 0; i < s.length(); i++) {
			char ch = s.charAt(i);
			switch (ch) {
			case '<': {
				sb.append("&lt;");
				break;
			}
			case '>': {
				sb.append("&gt;");
				break;
			}
			case '&': {
				sb.append("&amp;");
				break;
			}
			case '"': {
				sb.append("&quot;");
				break;
			}
			default: {
				sb.append(ch);
			}
			}
		}

		return sb.toString();
	}
}