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
 * $Id: SOAP12MessageCreator.java,v 1.13 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: SOAP12MessageCreator.java,v $
 * Revision 1.13  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.12  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.11  2005/04/28 07:55:45  erwin
 * Fixed problem with StringBuffer in logging.
 *
 * Revision 1.10  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.9  2005/03/21 10:22:41  erwin
 * Replaced several invalid log method names (SOAP11 -> SOAP12)
 *
 * Revision 1.8  2005/03/10 14:19:59  erwin
 * Fixed log level in init() method.
 *
 * Revision 1.7  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.6  2005/02/28 12:21:30  erwin
 * Changed some log levels to FINE.
 *
 * Revision 1.5  2005/02/23 10:04:14  erwin
 * Improved Exception handling.
 *
 * Revision 1.4  2005/02/22 16:18:50  erwin
 * Improved error handling.
 *
 * Revision 1.3  2005/02/15 10:57:37  erwin
 * Applied code style and added Javadoc.
 *
 *
 */

package org.aselect.system.communication.server.soap12;

import java.io.IOException;
import java.util.logging.Level;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xerces.dom.DocumentImpl;
import org.apache.xml.serialize.LineSeparator;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.aselect.system.communication.server.IMessageCreatorInterface;
import org.aselect.system.communication.server.IProtocolRequest;
import org.aselect.system.communication.server.IProtocolResponse;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.logging.SystemLogger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

// TODO: Auto-generated Javadoc
/**
 * Message creator which uses SOAP 1.2 messages. <br>
 * <br>
 * <b>Description: </b> <br>
 * A SOAP 1.2 implementation of the <code>IMessageCreatorInterface</code>. <br>
 * <br>
 * The <code>SOAP12MessageCreator</code> parses the request message to an XML DOM object and validates it manually
 * against the SOAP 1.2 XML Schema. If the request cannott be parsed, a SOAP Fault message will be sent directly. The
 * XML DOM object containing the request message is used as a buffer; the object will be removed if the response message
 * is sent. <br>
 * <br>
 * The parameters for the response message will be buffered in a XML Document object. This object will be serialized to
 * a valid SOAP 1.2 response message when the <code>send()</code> method is called. <br>
 * <br>
 * This implementation uses the Xerces XML parser and DOM objects implementation (xercesImpl.jar and xml-apis.jar).
 * <i>For more info about Xerces see: <a href='http://xml.apache.org/xerces-j/' target='_new'> Xerces Java Parser
 * documentation </a> </i> <br>
 * <br>
 * <i>Note: The SOAP request is not validated to the full W3C SOAP 1.2 XML Schema, but only checked if the information
 * can be retrieved from the message in the way that the XML schema describes. Full schema validation can be turned on
 * by uncomment some code in <code>createInputMessage()</code> method, but slows down the parsing extremely. </i> <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * The used Xerces implemenations are non threadsafe and therefore every SOAP request requires its own
 * <code>SOAP12MessageCreator</code>. <br>
 * 
 * @author Alfa & Ariss
 */
public class SOAP12MessageCreator implements IMessageCreatorInterface
{
	/** name of this module, used for logging */
	private static final String MODULE = "SOAP12MessageCreator";

	/** The logger for system log entries. */
	private SystemLogger _systemLogger;

	/* Input message buffers */
	/** The complete input message */
	private Document _oInputMessage;

	/** The input message its body. */
	private Element _elInputBody;

	/** The input message its RPC body. */
	private Element _elInputRPCBody;

	/* Output message buffers */
	/** The complete output message */
	private Document _oOutputMessage;

	/** The output SOAP header. */
	private Element _elOutputHeader;

	/** The output message its body */
	private Element _elOutputBody;

	/** The output message its RPC body. */
	private Element _elOutputRPCBody;

	/* SOAP variabeles */
	/** The method environment URI. */
	private String _sMethodEnv;

	/** The method name. */
	private String _sMethodName;

	/* protocol buffers */
	/** The request protocol information */
	private IProtocolRequest _oRequest;

	/** The response protocol information */
	private IProtocolResponse _oResponse;

	/**
	 * Creates a new instance. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a new <code>SOAP12MessageCreator</code> with the given values. All other instance variables are
	 * initalized with default values. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>sMethodEnv</code> should be a valid URI.</li>
	 * <li>
	 * <code>sMethodName</code> should be a non empty <code>String</code>.</li>
	 * <li><code>systemLogger</code> should be initialized.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All instance variables are initialized. <br>
	 * 
	 * @param sMethodEnv
	 *            The SOAP-RPC namespace URI.
	 * @param sMethodName
	 *            The SOAP-RPC method name.
	 * @param systemLogger
	 *            The logger that is used to log system entries.
	 */
	public SOAP12MessageCreator(String sMethodEnv, String sMethodName, SystemLogger systemLogger) {
		_sMethodEnv = sMethodEnv;
		_sMethodName = sMethodName;
		_oInputMessage = null;
		_elInputBody = null;
		_elInputRPCBody = null;

		_oOutputMessage = null;
		_elOutputHeader = null;
		_elOutputBody = null;
		_elOutputRPCBody = null;

		_systemLogger = systemLogger;
	}

	/**
	 * Initializes the <code>SOAP12MessageCreator</code>. <br>
	 * <br>
	 * <i>note: A Fault message will be send imediately to the sender </i> <br>
	 * 
	 * @param oRequest
	 *            the o request
	 * @param oResponse
	 *            the o response
	 * @return true, if inits the
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 * @see org.aselect.system.communication.server.IMessageCreatorInterface#init(org.aselect.system.communication.server.IProtocolRequest,
	 *      org.aselect.system.communication.server.IProtocolResponse)
	 */
	public boolean init(IProtocolRequest oRequest, IProtocolResponse oResponse)
		throws ASelectCommunicationException
	{
		String sMethod = "init()";

		// set class variabeles
		_oRequest = oRequest;
		_oResponse = oResponse;

		// create standard output message
		createOutputMessage();

		// Parse input Message
		try {
			createInputMessage();
		}
		catch (ASOAPException eAS) // SOAP Fault handling
		{
			int iCode = eAS.getCode();
			String sReason = eAS.getReason();
			String sDetail = eAS.getMessage();
			String sCodeString = "";
			switch (iCode) {
			case ASOAPException.VERSION_MISMATCH: // version mismatch
			{
				sCodeString = SOAPConstants.ERR_VERSION_MISMATCH;
				_oResponse.setProperty("Status", "" + SOAPConstants.STATUS_VERSION_MISMATCH);
				createFault(sCodeString, sReason, sDetail);
				break;
			}
			case ASOAPException.MUST_UNDERSTAND: // Must understand
			{
				sCodeString = SOAPConstants.ERR_MUST_UNDERSTAND;
				_oResponse.setProperty("Status", "" + SOAPConstants.STATUS_MUST_UNDERSTAND);
				createFault(sCodeString, sReason, sDetail);
				break;
			}
			case ASOAPException.DATA_ENCODING_UNKNOWN: // Unknown data
				// encoding
			{
				sCodeString = SOAPConstants.ERR_DATA_ENCODING_UNKNOWN;
				_oResponse.setProperty("Status", "" + SOAPConstants.STATUS_DATA_ENCODING_UNKNOWN);
				createFault(sCodeString, sReason, sDetail);
				break;
			}
			case ASOAPException.SOAP_11: // Received SOAP 1.1 message
			{
				sCodeString = SOAPConstants.ERR_VERSION_MISMATCH;
				_oResponse.setProperty("Status", "" + SOAPConstants.STATUS_VERSION_MISMATCH);
				createSOAP11UpdateFault(sCodeString, sReason);
				break;
			}
			case ASOAPException.SENDER: // Bad request received
			{
				sCodeString = SOAPConstants.ERR_CLIENT;
				_oResponse.setProperty("Status", "" + SOAPConstants.STATUS_CLIENT);
				createFault(sCodeString, sReason, sDetail);
				break;
			}
			case ASOAPException.RECEIVER: // Internal Server error
			{
				sCodeString = SOAPConstants.ERR_SERVER;
				_oResponse.setProperty("Status", "" + SOAPConstants.STATUS_SERVER);
				createFault(sCodeString, sReason, sDetail);
				break;
			}
			default: // Server error
			{
				sCodeString = SOAPConstants.ERR_SERVER;
				_oResponse.setProperty("Status", "" + SOAPConstants.STATUS_SERVER);
				createFault(sCodeString, sReason, sDetail);
				break;
			}
			}
			// a Fault message will be send imediately to the sender
			send();
			// reset inputMessage
			_oInputMessage = null;

			// log error
			StringBuffer sbBuffer = new StringBuffer("Could not parse inputmessage. errorcode: ");
			sbBuffer.append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			// log additional info
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Received SOAP inputmessage:\n" + _oRequest.getMessage());

			_systemLogger.log(Level.WARNING, MODULE, sMethod, "SOAP fault sent: " + sCodeString + ", " + sReason + ", "
					+ sDetail);

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		return true;
	}

	/**
	 * Returns a Parameter from the input message.
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
		// _systemLogger.log(Level.INFO, MODULE, sMethod, "param:"+sName);
		if (_oInputMessage == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No input message available, cause: "
					+ Errors.ERROR_ASELECT_USE_ERROR);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}

		// get parameters with [name] from RPC SOAP body
		NodeList nlParams = _elInputRPCBody.getElementsByTagNameNS(_sMethodEnv, sName);
		String sValue = "";
		if (nlParams.getLength() == 1) // exactly 1 param found with this name
		{
			// get all text nodes
			Element elParam = (Element) nlParams.item(0);
			NodeList xValues = elParam.getChildNodes();
			for (int c = 0; c < xValues.getLength(); c++) {
				Node nValue = xValues.item(c);
				if (nValue.getNodeType() == Node.TEXT_NODE) {
					Text oText = (Text) nValue;
					String sAdd = oText.getData();
					if (!sAdd.equals(""))
						sValue += sAdd;
				}
				else
				// not a TextNode inside parameter
				{
					StringBuffer sb = new StringBuffer("Invalid parameter in input message: ");
					sb.append(nValue.getNodeName());
					sb.append(",cause: ");
					sb.append(Errors.ERROR_ASELECT_USE_ERROR);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sb.toString());
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
				}
			}
		}
		else
		// no Param found or more then one
		{
			StringBuffer sb = new StringBuffer();
			sb.append(nlParams.getLength());
			sb.append(" number of parameters in input message with name ");
			sb.append(sName);
			sb.append(",cause: ");
			sb.append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.FINE, MODULE, sMethod, sb.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		return sValue.trim();
	}

	/**
	 * Returns a array Parameter from the input message.
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
		if (_elInputRPCBody == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No input message available, cause: "
					+ Errors.ERROR_ASELECT_USE_ERROR);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}

		String[] sa = null;
		// get parameters with [name] from RPC SOAP body
		NodeList nlParams = _elInputRPCBody.getElementsByTagNameNS(_sMethodEnv, sName);
		if (nlParams.getLength() == 1) // exactly 1 param found with this name
		{
			// resolve the array from the first occurence of the param tag
			sa = resolveArray((Element) nlParams.item(0));
		}
		else {
			StringBuffer sb = new StringBuffer("SOAP Message contains multiple params with the same name: ");
			sb.append(sName);
			sb.append(",cause: ");
			sb.append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sb.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		return sa;
	}

	// 20090310, Bauke: Added to support applications using the DigiD protocol to connect to the server
	// That protocol does not URL encode it's parameters
	/* (non-Javadoc)
	 * @see org.aselect.system.communication.server.IOutputMessage#setParam(java.lang.String, java.lang.String, boolean)
	 */
	public boolean setParam(String sName, String sValue, boolean doUrlEncode)
		throws ASelectCommunicationException
	{
		return setParam(sName, sValue);
	}

	/**
	 * Sets a parameter in the SOAP output message.
	 * 
	 * @param sName
	 *            the s name
	 * @param sValue
	 *            the s value
	 * @return true, if sets the param
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 * @see org.aselect.system.communication.server.IOutputMessage#setParam(java.lang.String, java.lang.String)
	 */
	public boolean setParam(String sName, String sValue)
		throws ASelectCommunicationException
	{
		String sMethod = "setParam()";
		if (_oOutputMessage == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No output message available, cause: "
					+ Errors.ERROR_ASELECT_USE_ERROR);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}

		if (_elOutputRPCBody == null) { // No RPC content yet
			// create RPC content
			_elOutputRPCBody = createRPCBody();
			// add RPC content
			_elOutputBody.appendChild(_elOutputRPCBody);
		}

		// create parameter value
		Text oParamValue = _oOutputMessage.createTextNode(sValue);

		NodeList nlParams = _elOutputRPCBody.getElementsByTagNameNS(_sMethodEnv, sName);
		if (nlParams.getLength() != 1) // not a parameter with this name yet
		{
			// create parameter name
			Element xParamName = null;
			xParamName = _oOutputMessage.createElementNS(_sMethodEnv, SOAPConstants.NS_PREFIX_RPC + ":" + sName);

			// add value and name to message
			xParamName.appendChild(oParamValue);
			_elOutputRPCBody.appendChild(xParamName);
		}
		else
		// update paramater with new value
		{
			Element xParamName = (Element) nlParams.item(0);
			Node xOldValue = xParamName.getFirstChild();
			xParamName.replaceChild(oParamValue, xOldValue);
		}
		return true;
	}

	/**
	 * Sets an array parameter in the SOAP output message.
	 * 
	 * @param sName
	 *            the s name
	 * @param saValues
	 *            the sa values
	 * @return true, if sets the param
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 * @see org.aselect.system.communication.server.IOutputMessage#setParam(java.lang.String, java.lang.String[])
	 */
	public boolean setParam(String sName, String[] saValues)
		throws ASelectCommunicationException
	{
		String sMethod = "setParam()";
		if (_oOutputMessage == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No output message available, cause: "
					+ Errors.ERROR_ASELECT_USE_ERROR);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}

		// convert array to xml tags
		Element eTemp = arrayToXML(sName, saValues);

		NodeList nlParams = _elOutputRPCBody.getElementsByTagNameNS(SOAPConstants.URI_SOAP12_ENC, sName);
		if (nlParams.getLength() != 1)// new tag
		{
			// append to outputRPCBody
			_elOutputRPCBody.appendChild(eTemp);
		}
		else
		// existing tag
		{
			// replace existing tag with new tag
			_elOutputRPCBody.replaceChild(eTemp, nlParams.item(0));
		}
		return true;
	}

	/**
	 * Sends the output message. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Performs the following steps:
	 * <ul>
	 * <li>creates an output format which uses new lines and tabs</li>
	 * <li>Uses a {@link org.apache.xml.serialize.XMLSerializer }to serialize the message.</li>
	 * <li>reset output and input message</li>
	 * </ul>
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
		if (_oOutputMessage == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Message is already sent, there is no output message, cause: " + Errors.ERROR_ASELECT_USE_ERROR);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		try {
			// create output format which uses new lines and tabs
			OutputFormat oFormat = new OutputFormat(_oOutputMessage);
			oFormat.setLineSeparator(LineSeparator.Web);
			oFormat.setIndenting(true);
			oFormat.setLineWidth(80);
			// Create serializer
			XMLSerializer oSerializer = new XMLSerializer(_oResponse.getOutputStream(), oFormat);
			oSerializer.setNamespaces(true);
			// serialize outputmessage to outputstream
			oSerializer.serialize(_oOutputMessage.getDocumentElement());

			_oOutputMessage = null;
			_elOutputBody = null;
			_elOutputRPCBody = null;
			_elOutputHeader = null;
			return true;
		}

		catch (IOException eIO) // I/O error while serializing, should not
		// occur
		{
			StringBuffer sbBuffer = new StringBuffer("DOM object could not be serialized: ");
			sbBuffer.append(eIO.getMessage());
			sbBuffer.append(", cause: ");
			sbBuffer.append(Errors.ERROR_ASELECT_IO);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eIO);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
		}
	}

	/**
	 * Creates an input message from the input. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method parses the request data and creates an XML <code>Document</code> containing all parameters in the
	 * SOAP 1.2 message. <br>
	 * <br>
	 * Parse and validation errors are logged and an <code>ASOAPException</code> is thrown. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>Document</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * This method should be called in the initializing stage of the <code>SOAP12MessageCreator</code>. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <ul>
	 * <li>
	 * <code>_oInputMessage</code> contains a valid SOAP request message.</li>
	 * <li>The input message instance variables contain input message XML data.</li>
	 * </ul>
	 * 
	 * @throws ASOAPException
	 *             If parsing or validation fails.
	 */
	private void createInputMessage()
		throws ASOAPException
	{
		try {
			// create DocumentBuilderFactory to parse SOAP message.
			DocumentBuilderFactory oDbf = DocumentBuilderFactory.newInstance();
			oDbf.setNamespaceAware(true);

			// SOAP 1.2 SCHEMA VALIDATING default disabled because of
			// performance issues
			/*
			 * xDbf.setValidating(true); xDbf.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage",
			 * "http://www.w3.org/2001/XMLSchema");
			 * xDbf.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource",
			 * "http://www.w3.org/2003/05/soap-envelope");
			 */

			// Create parse
			DocumentBuilder oParser = oDbf.newDocumentBuilder();
			// set SOAP12 error handler which throws all errors.
			oParser.setErrorHandler(new SOAP12ErrorHandler());
			// parse
			_oInputMessage = oParser.parse(_oRequest.getInputStream());
		}
		catch (org.xml.sax.SAXParseException eSP) // Invalid XML
		{
			throw new ASOAPException(ASOAPException.SENDER, "Bad request", eSP.getMessage());
		}
		catch (org.xml.sax.SAXException eS) // Invalid XML
		{
			throw new ASOAPException(ASOAPException.SENDER, "Bad request", eS.getMessage());
		}
		catch (java.io.IOException eIO) // Invalid inputstream (i/o error)
		{
			throw new ASOAPException(ASOAPException.RECEIVER, "Internal server error", eIO.getMessage());

		}
		catch (ParserConfigurationException xPCE) {
			throw new ASOAPException(ASOAPException.RECEIVER, "Internal server error", xPCE.getMessage());
		}

		// check namespace
		Element elRoot = _oInputMessage.getDocumentElement();
		String sSchema = elRoot.getNamespaceURI();
		if (sSchema.equals(SOAPConstants.URI_SOAP12_ENV)) // SOAP1.2 -> ok?
		{
			// check envelope
			if (!validEnvelope(elRoot)) {
				String sDetail = null; // no detail for VerionMismatch
				throw new ASOAPException(ASOAPException.VERSION_MISMATCH, "Version Mismatch", sDetail);
			}

			// check body
			_elInputBody = getChildElement(elRoot, SOAPConstants.ELEM_BODY, SOAPConstants.URI_SOAP12_ENV);
			if (_elInputBody == null) {
				throw new ASOAPException(ASOAPException.SENDER, "Bad request",
						"SOAP message must contain mandatory Body element.");
			}

			// check rpc body
			_elInputRPCBody = getChildElement(_elInputBody, _sMethodName, _sMethodEnv);
			if (_elInputRPCBody == null) {
				throw new ASOAPException(ASOAPException.SENDER, "Bad request",
						"Unsupported request received, invalid RPC body.");
			}
			// check encoding
			if (!validEncoding(_elInputRPCBody)) {
				throw new ASOAPException(ASOAPException.DATA_ENCODING_UNKNOWN, "Internal server error",
						"Unsupported data encoding received.");
			}

		}

		else if (sSchema.equals(SOAPConstants.URI_SOAP11_ENV)) // SOAP1.1 ->
		// error
		{
			String sDetail = null; // no detail for VerionMismatch
			throw new ASOAPException(ASOAPException.SOAP_11, "Version Mismatch", sDetail);
		}

		else
		// NON SOAP -> error
		{
			String sDetail = null; // no detail for VerionMismatch
			throw new ASOAPException(ASOAPException.VERSION_MISMATCH, "Version Mismatch", sDetail);
		}
	}

	/**
	 * creates an empty SOAP output message. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a new <code>Document</code> with a empty RPC body. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>Document</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * This method should be called in the initializing stage of the <code>SOAP12MessageCreator</code>. <br>
	 * <br>
	 * <b>Postconditions: </b>
	 * <ul>
	 * <li>
	 * <code>_oOuputMessage</code> contains a valid SOAP response message.</li>
	 * <li>The output message instance variables contain output message XML data.</li>
	 * </ul>
	 */
	private void createOutputMessage()
	{
		// set Content type of response
		_oResponse.setProperty("Content-Type", SOAPConstants.CONTENT_TYPE);
		// Create IOutputMessage
		_oOutputMessage = new DocumentImpl();

		// create envelope
		Element elEnvelope = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_ENVELOPE);

		// can't be created with setAttributeNS, because
		// parser can't define two extra (xsi and xsd) namespaces for xmlns
		// if parsing against soap schema this is valid soap 12
		elEnvelope.setAttribute(SOAPConstants.NS_PREFIX_XMLNS + ":" + SOAPConstants.NS_PREFIX_XSI,
				SOAPConstants.URI_XML_XSI);

		elEnvelope.setAttribute(SOAPConstants.NS_PREFIX_XMLNS + ":" + SOAPConstants.NS_PREFIX_XSD,
				SOAPConstants.URI_XML_XSD);

		// add envelope
		_oOutputMessage.appendChild(elEnvelope);

		// create Body
		_elOutputBody = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV, SOAPConstants.NS_PREFIX_SOAP_ENV
				+ ":" + SOAPConstants.ELEM_BODY);
		// add body
		elEnvelope.appendChild(_elOutputBody);
	}

	/**
	 * Creates the RPC Body element for the ouput message. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a new <code>Element</code> with a default RPC body. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>Element</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @return A new <code>Element</code> containing XML RPC body data.
	 */
	private Element createRPCBody()
	{
		// create RPC body element with namespace
		Element elRPC = _oOutputMessage.createElementNS(_sMethodEnv, SOAPConstants.NS_PREFIX_RPC + ":" + _sMethodName
				+ "Response");

		elRPC.setAttributeNS(SOAPConstants.URI_SOAP12_ENV, SOAPConstants.NS_PREFIX_SOAP_ENV + ":"
				+ SOAPConstants.ATTR_ENCODING_STYLE, SOAPConstants.URI_SOAP12_ENC);

		return elRPC;
	}

	/**
	 * Create a SOAP 1.2 Fault in the ouput message. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a SOAP 1.2 fault tag in the output message. <br>
	 * <br>
	 * <i>For more info see: <a href='http://www.w3.org/TR/2003/REC-soap12-part0-20030624/#L11549' target='_new'>SOAP
	 * fault handling </a> </i> <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The created <code>Element</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li>
	 * <code>sFaultString</code> should be a valid SOAP 1.1 fault code.</li>
	 * <li>
	 * <code>sReasonString</code> should be a valid SOAP 1.1 fault reason.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <code>_elOutputBody</code> contains a SOAP fault. <br>
	 * 
	 * @param sFaultString
	 *            The SOAP fault code as <code>String</code>.
	 * @param sReasonString
	 *            The SOAP fault reason contents.
	 * @param sDetailString
	 *            The SOAP fault detail contents.
	 */
	private void createFault(String sFaultString, String sReasonString, String sDetailString)
	{
		// get Envelope
		Element elEnvelope = _oOutputMessage.getDocumentElement();

		// check if message has allready some parameters
		if (_elOutputRPCBody != null) {
			// remove parameter content
			_elOutputBody.removeChild(_elOutputRPCBody);
		}

		// create Fault
		Element elFault = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_FAULT);
		// add fault
		_elOutputBody.appendChild(elFault);

		// create Code
		Element elCode = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV, SOAPConstants.NS_PREFIX_SOAP_ENV
				+ ":" + SOAPConstants.ELEM_FAULT_CODE);
		// add Code
		elFault.appendChild(elCode);

		// Create Code value
		Element elValue = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_FAULT_CODE_VALUE);
		// add text to value
		Text oValueText = _oOutputMessage.createTextNode(SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + sFaultString);
		elValue.appendChild(oValueText);

		// add Value to code
		elCode.appendChild(elValue);

		// Create reason
		Element elReason = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_FAULT_REASON);
		// add reason
		elFault.appendChild(elReason);

		// create reason contents
		Element elReasonContent = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":Text");
		elReasonContent.setAttribute("xml:lang", SOAPConstants.XML_LANG);
		Text oReasonText = _oOutputMessage.createTextNode(sReasonString);
		elReasonContent.appendChild(oReasonText);

		// add reason contents
		elReason.appendChild(elReasonContent);

		// create detail if applicable
		if (sDetailString != null) {
			// create deatil
			Element elDetail = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV,
					SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_FAULT_DETAIL);
			// add detail
			elFault.appendChild(elDetail);

			// add text to detail
			Text oDetailText = _oOutputMessage.createTextNode(sDetailString);
			elDetail.appendChild(oDetailText);

		}

		// create update header if applicable
		if (sFaultString.equals(SOAPConstants.ERR_VERSION_MISMATCH)) {
			// check if header exsists
			if (_elOutputHeader == null) {
				// create header
				_elOutputHeader = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV,
						SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_HEADER);
				// add header
				elEnvelope.insertBefore(_elOutputHeader, _elOutputBody);
			}

			// create update header
			Element elUpdate = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV,
					SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_UPGRADE);
			// add update header
			_elOutputHeader.appendChild(elUpdate);

			// create supported envelope element
			Element elSupported = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP12_ENV,
					SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_SUPPORTEDENVELOPE);
			// add attributes
			elSupported.setAttribute("qname", "ns1:Envelope");
			elSupported.setAttribute("xmlns:ns1", SOAPConstants.URI_SOAP12_ENV);
			// add supported envelope header
			elUpdate.appendChild(elSupported);
		}
	}

	/**
	 * Creates a SOAP1.1 not supported fault message. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a new SOAP 1.1 not supported fault in the output message. This message is returned if a SOAP 1.1 node has
	 * sent a request to this SOAP 1.2 server and therefore a SOAP 1.1 message is created. <br>
	 * <br>
	 * <i>For more info see: <a href='http://www.w3.org/TR/2003/REC-soap12-part0-20030624/#L11549' target='_new'>SOAP
	 * fault handling </a> </i> <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The created <code>Element</code> is not threadsafe. <br>
	 * <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li>
	 * <code>sFaultString</code> should be a valid SOAP 1.1 fault code.</li>
	 * <li>
	 * <code>sReasonString</code> should be a valid SOAP 1.1 fault reason.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <code>_oOutputMessage</code> contains a SOAP 1.1 Fault. <br>
	 * 
	 * @param sFaultString
	 *            The SOAP fault code as <code>String</code>.
	 * @param sReasonString
	 *            The SOAP fault reason contents.
	 */
	private void createSOAP11UpdateFault(String sFaultString, String sReasonString)
	{
		// set SOAP 1.1 content type.
		_oResponse.setProperty("Content-Type", "" + SOAPConstants.CONTENT_TYPE_11);

		// Create IOutputMessage
		_oOutputMessage = new DocumentImpl();

		// create envelope
		Element elEnvelope = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP11_ENV,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_ENVELOPE);
		// add envelope
		_oOutputMessage.appendChild(elEnvelope);

		// create Header
		_elOutputHeader = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP11_ENV,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_HEADER);
		// add header
		elEnvelope.appendChild(_elOutputHeader);

		// create update header
		Element elUpdate = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP11_ENV,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_UPGRADE);
		// add update header
		_elOutputHeader.appendChild(elUpdate);

		// create supported envelope element
		Element elSupported = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP11_ENV,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_SUPPORTEDENVELOPE);
		// add attributes
		elSupported.setAttribute("qname", "ns1:Envelope");
		elSupported.setAttribute("xmlns:ns1", SOAPConstants.URI_SOAP12_ENV);
		// add supported envelope header
		elUpdate.appendChild(elSupported);

		// create Body
		_elOutputBody = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP11_ENV, SOAPConstants.NS_PREFIX_SOAP_ENV
				+ ":" + SOAPConstants.ELEM_BODY);
		// add body
		elEnvelope.appendChild(_elOutputBody);

		// create Fault
		Element elFault = _oOutputMessage.createElementNS(SOAPConstants.URI_SOAP11_ENV,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + SOAPConstants.ELEM_FAULT);
		// add fault
		_elOutputBody.appendChild(elFault);

		// create Code
		Element elCode = _oOutputMessage.createElement("faultcode");
		Text oCodeText = _oOutputMessage.createTextNode(SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + sFaultString);
		elCode.appendChild(oCodeText);
		// add Code
		elFault.appendChild(elCode);

		// create faultString
		Element elFaultStringElement = _oOutputMessage.createElement("faultstring");
		Text oFaultStringText = _oOutputMessage.createTextNode(sReasonString);
		elFaultStringElement.appendChild(oFaultStringText);

		// add FaultString
		elFault.appendChild(elFaultStringElement);
	}

	/**
	 * Checks if the envelope is a valid SOAP 1.2 envelope. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Checks the local name of the received SOAP envelope. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>elEnvelope != null</code> <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param elEnvelope
	 *            The SOAP Envelope.
	 * @return true if The given Envelope is valid, otherwise false.
	 */
	private boolean validEnvelope(Element elEnvelope)
	{
		// get envelope tage name
		String xEnvelopeName = elEnvelope.getLocalName();
		if (!xEnvelopeName.equals(SOAPConstants.ELEM_ENVELOPE)) // invalid
		// envelop
		{
			return false;
		}
		return true;
	}

	/**
	 * Check received encoding schema. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Checks if the message body (RPC) contains the correct encoding schema. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>elRPCBody != null</code> <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param elRPCBody
	 *            The SOAP-RPC body that should contain the encoding attribute.
	 * @return true if encoding attribute is correct, otherwise false.
	 */
	private boolean validEncoding(Element elRPCBody)
	{
		String xEncoding = elRPCBody.getAttributeNS(SOAPConstants.URI_SOAP12_ENV, SOAPConstants.ATTR_ENCODING_STYLE);
		if (xEncoding.equals(SOAPConstants.URI_SOAP12_ENC)) {
			return true;
		}
		return false;
	}

	/**
	 * Retrieve an XML child element. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Get the child element with the given tag name and namespace from the given parent. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>Element</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>elParent</code> should be a valid XML element.</li>
	 * <li><code>sTagname</code> should be a valid XML tag name.</li>
	 * <li><code>sNamespaceURI</code> should a valid URI.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param elParent
	 *            The parenet <code>Element</code>.
	 * @param sTagname
	 *            The XML tag name.
	 * @param sNamespaceURI
	 *            The XML namespace XML.
	 * @return The element if found, otherwise null.
	 */
	private Element getChildElement(Element elParent, String sTagname, String sNamespaceURI)
	{
		NodeList nlChilds = elParent.getElementsByTagNameNS(sNamespaceURI, sTagname);
		if (nlChilds.getLength() == 1) {
			return (Element) nlChilds.item(0);
		}
		return null;
	}

	/**
	 * Convert a array parameter to a <code>String</code> array. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Converts the XML parameter data to an array of strings. <br>
	 * <br>
	 * Performs the following steps:
	 * <ul>
	 * <li>Parse "itemType"</li>
	 * <li>Get number of parameter values</li>
	 * <li>Get the array item tags defined inside the array tag</li>
	 * <li>For all child elements:
	 * <ul>
	 * <li>
	 * <code>if node type == ELEMENT_NODE</code> retrieve value of text node</li>
	 * <li>Add value to return array</li>
	 * </ul>
	 * </li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * <code>elParam</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>elParam</code> should contain an array parameter. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param elParam
	 *            The <code>Element</code> contaning the parameter as XML data.
	 * @return An array of parameter values.
	 * @throws ASelectCommunicationException
	 *             If resolving fails.
	 */
	private String[] resolveArray(Element elParam)
		throws ASelectCommunicationException
	{
		String[] sa = null;
		String sArraySize = null;
		String sMethod = "resolveArray()";

		String strItemType = elParam.getAttributeNS(SOAPConstants.URI_SOAP12_ENC, "itemType");
		if (strItemType.equalsIgnoreCase("xsd:string")) {
			sArraySize = elParam.getAttributeNS(SOAPConstants.URI_SOAP12_ENC, "arraySize");
			try {
				int iArrayMax = new Integer(sArraySize).intValue();
				int iArrayIndex = 0;
				sa = new String[iArrayMax];
				NodeList nlArrayItems = elParam.getChildNodes();
				for (int i = 0; i < nlArrayItems.getLength(); i++) {
					if (nlArrayItems.item(i).getNodeType() == Node.ELEMENT_NODE) {
						Node nTemp = nlArrayItems.item(i).getFirstChild();
						if (nTemp.getNodeType() == Node.TEXT_NODE) {
							// get value of text node
							if (iArrayIndex < iArrayMax) {
								sa[iArrayIndex++] = nTemp.getNodeValue();
							}
						}
					}
				}
			}
			catch (NumberFormatException eNF) {
				StringBuffer sbBuffer = new StringBuffer("Error during resolving array (invalid 'arraySize'): ");
				sbBuffer.append(eNF.getMessage());
				sbBuffer.append(", cause: ");
				sbBuffer.append(Errors.ERROR_ASELECT_PARSE_ERROR);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eNF);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_PARSE_ERROR);
			}
		}

		if (sa == null) {
			StringBuffer sbBuffer = new StringBuffer("Could not resolve array. Resolved array length: ");
			sbBuffer.append(sArraySize);
			sbBuffer.append(", cause: ");
			sbBuffer.append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		return sa;
	}

	/**
	 * Convert array to xml tags. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Converts the strings in the array into a parameter with the given name as XML <code>Element</code>. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>Element</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>sTagName</code> should be valid XML tagname.</li>
	 * <li><code>sa</code> should contain one or more valid tag values</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param sTagName
	 *            The tagname of the array parameter.
	 * @param sa
	 *            the array parameter values.
	 * @return An XML object containg the created array parameter.
	 */
	private Element arrayToXML(String sTagName, String[] sa)
	{
		Element elResult = _oOutputMessage.createElementNS(_sMethodEnv, SOAPConstants.NS_PREFIX_RPC + ":" + sTagName);

		elResult.setAttributeNS(SOAPConstants.URI_SOAP12_ENC, SOAPConstants.NS_PREFIX_SOAP_ENC + ":itemType",
				"xsd:string");

		elResult.setAttributeNS(SOAPConstants.URI_SOAP12_ENC, SOAPConstants.NS_PREFIX_SOAP_ENC + ":arraySize", ""
				+ sa.length);

		// create item tags for every array item
		for (int i = 0; i < sa.length; i++) {
			// create item tag (ELEMENT_NODE)
			// can't be created with createElementNS, because parser can't find
			// the already defined xsi and xsd
			Element elTemp = _oOutputMessage.createElement(SOAPConstants.NS_PREFIX_RPC + ":item");
			// can't be created with setAttributeNS, because parser can't find
			// the already defined xsi and xsd
			elTemp.setAttribute(SOAPConstants.NS_PREFIX_XSI + ":type", "xsd:string");

			// create value tag (TEXT_NODE)
			Text oTextNode = _oOutputMessage.createTextNode(sa[i]);
			elTemp.appendChild(oTextNode);
			elResult.appendChild(elTemp);
		}

		return elResult;
	}
}