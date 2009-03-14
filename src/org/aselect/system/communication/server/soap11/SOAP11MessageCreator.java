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
 * $Id: SOAP11MessageCreator.java,v 1.14 2006/05/03 09:30:33 tom Exp $ 
 * Changelog:
 * $Log: SOAP11MessageCreator.java,v $
 * Revision 1.14  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.13  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.12  2005/04/28 07:55:45  erwin
 * Fixed problem with StringBuffer in logging.
 *
 * Revision 1.11  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.10  2005/03/10 14:19:59  erwin
 * Fixed log level in init() method.
 *
 * Revision 1.9  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.8  2005/03/01 13:11:33  erwin
 * removed F. comment  -> fixme
 *
 * Revision 1.7  2005/03/01 13:04:19  erwin
 * Removed fixme
 *
 * Revision 1.6  2005/02/28 12:21:30  erwin
 * Changed some log levels to FINE.
 *
 * Revision 1.5  2005/02/22 16:18:49  erwin
 * Improved error handling.
 *
 * Revision 1.4  2005/02/15 10:56:23  erwin
 * Applied code format.
 *
 * Revision 1.3  2005/02/14 13:54:30  erwin
 * Applied code style and added Javadoc.
 *
 */

package org.aselect.system.communication.server.soap11;

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
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

/**
 * Message creator which uses SOAP 1.1 messages. 
 * <br><br>
 * <b>Description: </b> <br>
 * A SOAP 1.1 implementation of the <code>IMessageCreatorInterface</code>.
 * <br>
 * <br>
 * The <code>SOAP11MessageCreator</code> parses the request message to an XML
 * DOM object and validates it manually against the SOAP 1.1 XML Schema. If the
 * request cannot be parsed, a SOAP Fault message will be sent directly. The XML
 * DOM object containing the request message is used as a buffer; the object
 * will be removed if the response message is sent. <br>
 * <br>
 * The parameters for the response message will be buffered in a XML Document
 * object. This object will be serialized to a valid SOAP 1.1 response message
 * when the <code>send()</code> method is called. <br>
 * <br>
 * This implementation uses the Xerces XML parser and DOM objects implementation
 * (xercesImpl.jar and xml-apis.jar). <i>For more info about Xerces see: <a
 * href='http://xml.apache.org/xerces-j/' target='_new'> Xerces Java Parser
 * documentation </a> </i> 
 * <br><br>
 * <i>Note: The SOAP request is not validated to the full W3C SOAP 1.1 XML
 * Schema, but only checked if the information can be retrieved from the message
 * in the way that the XML schema describes. Full schema validation can be
 * turned on by uncomment some code in <code>createInputMessage()</code>
 * method, but slows down the parsing extremely. </i> 
 * <br><br>
 * <b>Concurrency issues: </b> 
 * <br>
 * The used Xerces implemenations are non threadsafe and therefore every SOAP
 * request requires its own <code>SOAP11MessageCreator</code>.<br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class SOAP11MessageCreator implements IMessageCreatorInterface
{
	/** name of this module, used for logging */
	private static final String MODULE = "SOAP11MessageCreator";

	/** The logger for system log entries. */
	private SystemLogger _systemLogger;

	/* Input message buffers */
	/** The complete input message. */
	private Document _oInputMessage;

	/** The input message its body. */
	private Element _elInputBody;

	/** The input message its RPC body. */
	private Element _elInputRPCBody;

	/* Output message buffers */
	/** The complete output message */
	private Document _oOutputMessage;

	/** The output message its body. */
	private Element _elOutputBody;

	/** The output message its RPC body. */
	private Element _elOutputRPCBody;

	/* protocol buffers */
	/** The request protocol information */
	private IProtocolRequest _oRequest;

	/** The response protocol information */
	private IProtocolResponse _oResponse;

	/* SOAP variables */
	/** SOAP 1.1 URI. */
	private String _sInputMessageSchema;

	/** SOAP 1.1 RPC method URI */
	private String _sMethodEnv;

	/** SOAP 1.1 RPC method name. */
	private String _sMethodName;

	/**
	 * Creates a new instance. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * Creates a new <code>SOAP11MessageCreator</code> with the given values.
	 * All other instance variables are initalized with default values. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>-<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * <li><code>sMethodEnv</code> should be a valid URI.</li>
	 * <li><code>sMethodName</code> should be a non empty <code>String</code>.
	 * </li>
	 * <li><code>systemLogger</code> should be initialized.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All instance variables are initialized. <br>
	 * 
	 * @param sMethodEnv
	 *            The method environment URI for the RPC body.
	 * @param sMethodName
	 *            the method name for the RPC body.
	 * @param systemLogger
	 *            The logger that is used to log system entries.
	 */
	public SOAP11MessageCreator(String sMethodEnv, String sMethodName, SystemLogger systemLogger)
	{
		_sMethodEnv = sMethodEnv;
		_sMethodName = sMethodName;

		_systemLogger = systemLogger;
		_oInputMessage = null;
		_elInputBody = null;
		_elInputRPCBody = null;
		_sInputMessageSchema = SOAPConstants.URI_SOAP11_ENV;

		_oOutputMessage = null;
		_elOutputBody = null;
		_elOutputRPCBody = null;
	}

	/**
	 * Initializes the <code>SOAP11MessageCreator</code>.
	 * <br><br>
	 * <i>note: A Fault message will be send imediately to the sender</i>
	 * <br>
	 * 
	 * @see org.aselect.system.communication.server.IMessageCreatorInterface#init(org.aselect.system.communication.server.IProtocolRequest,
	 *      org.aselect.system.communication.server.IProtocolResponse)
	 */
	public boolean init(IProtocolRequest oRequest, IProtocolResponse oResponse)
		throws ASelectCommunicationException
	{

		StringBuffer sbBuffer = null;
		String sMethod = "init()";

		//set class variabeles
		_oRequest = oRequest;
		_oResponse = oResponse;

		//Parse input Message
		try {
			_oInputMessage = createInputMessage();
		}
		catch (ASOAPException eAS) //SOAP Fault handling
		{
			int iCode = eAS.getCode();
			String sReason = eAS.getReason();
			String sDetail = eAS.getMessage();
			String sCodeString = "";
			switch (iCode) {
			case ASOAPException.VERSION_MISMATCH: //version mismatch
			{
				sCodeString = SOAPConstants.ERR_VERSION_MISMATCH;
				break;
			}
			case ASOAPException.MUST_UNDERSTAND: //Must understand
			{
				sCodeString = SOAPConstants.ERR_MUST_UNDERSTAND;
				break;
			}
			case ASOAPException.CLIENT: //Bad request received
			{
				sCodeString = SOAPConstants.ERR_CLIENT;
				break;
			}
			case ASOAPException.SERVER: //Internal Server error
			{
				sCodeString = SOAPConstants.ERR_SERVER;
				break;
			}
			default: //Server error
			{
				sCodeString = SOAPConstants.ERR_SERVER;
				break;
			}
			}
			//log error
			sbBuffer = new StringBuffer("Could not parse inputmessage, cause: ");
			sbBuffer.append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			//log additional info
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Received SOAP inputmessage:\n" + _oRequest.getMessage());

			//set HTTP response code
			oResponse.setProperty("Status", "" + SOAPConstants.ERR_RESPONSECODE);
			//create default output message
			_oOutputMessage = createOutputMessage();
			//if error, then create fault tag and append it to the body
			_elOutputBody.appendChild(createFault(sCodeString, sReason, sDetail));
			//a Fault message will be send imediately to the sender
			send();

			_systemLogger.log(Level.WARNING, MODULE, sMethod, "SOAP fault sent: " + sCodeString + ", " + sReason + ", "
					+ sDetail);

			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		//create default output message
		_oOutputMessage = createOutputMessage();

		//the fault tag cannot be created anymore, so outputRPCBody must be
		// added.
		//create and add RPC body element with namespace
		_elOutputRPCBody = _oOutputMessage.createElementNS(_sMethodEnv, SOAPConstants.NS_PREFIX_RPC + ":"
				+ _sMethodName + "Response");
		_elOutputBody.appendChild(_elOutputRPCBody);
		return true;
	}

	/**
	 * Returns a Parameter from the input SOAP message.
	 * 
	 * @see org.aselect.system.communication.server.IInputMessage#getParam(java.lang.String)
	 */
	public String getParam(String sName)
		throws ASelectCommunicationException
	{
		String sMethod = "getParam()";
		//_systemLogger.log(Level.INFO, MODULE, sMethod, "param:"+sName);
		if (_oInputMessage == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No input message available, cause: "
					+ Errors.ERROR_ASELECT_USE_ERROR);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}

		// get parameters with [name] from RPC SOAP body
		NodeList nlParams = _elInputRPCBody.getElementsByTagNameNS(_sMethodEnv, sName);
		String sValue = "";
		if (nlParams.getLength() == 1) //exactly 1 param found with this name
		{
			//get all text nodes
			Element elParam = (Element) nlParams.item(0);
			NodeList nlValues = elParam.getChildNodes();
			for (int c = 0; c < nlValues.getLength(); c++) {
				Node nValue = nlValues.item(c);
				if (nValue.getNodeType() == Node.TEXT_NODE) {
					Text oText = (Text) nValue;
					String sAdd = oText.getData();
					if (!sAdd.equals(""))
						sValue += sAdd;
				}
				else
				//not a TextNode inside parameter
				{
					StringBuffer sb = new StringBuffer("Invalid parameter in input message: ");
					sb.append(nValue.getNodeName());
					sb.append(", cause: ");
					sb.append(Errors.ERROR_ASELECT_USE_ERROR);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sb.toString());
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
				}
			}
		}
		else
		//no Param found or more then one
		{
			StringBuffer sb = new StringBuffer();
			sb.append(nlParams.getLength());
			sb.append(" number of parameters in input message with name ");
			sb.append(sName);
			sb.append(", cause: ");
			sb.append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.FINE, MODULE, sMethod, sb.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		return sValue.trim();
	}

	/**
	 * Get array Parameter values from this SOAP 1.1 message.
	 * 
	 * @see org.aselect.system.communication.server.IInputMessage#getArray(java.lang.String)
	 */
	public String[] getArray(String sName)
		throws ASelectCommunicationException
	{
		String sMethod = "getArray()";
		if (_oInputMessage == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No input message available, cause: "
					+ Errors.ERROR_ASELECT_USE_ERROR);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}

		String[] sa = null;
		//get parameters with [name] from RPC SOAP body
		NodeList nlParams = _elInputRPCBody.getElementsByTagNameNS(_sMethodEnv, sName);
		if (nlParams.getLength() == 1) //exactly 1 param found with this name
		{
			//resolve the array from the first occurence of the param tag
			sa = resolveArray((Element) nlParams.item(0));
		}
		else {
			StringBuffer sb = new StringBuffer("SOAP Message contains multiple params with the same name: ");
			sb.append(sName);
			sb.append(", cause: ");
			sb.append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.FINE, MODULE, sMethod, sb.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		return sa;
	}
	
	// 20090310, Bauke: Added to support applications using the DigiD protocol to connect to the server
	// That protocol does not URL encode it's parameters
	public boolean setParam(String sName, String sValue, boolean doUrlEncode)
	throws ASelectCommunicationException
	{
		return setParam(sName, sValue);
	}

	/**
	 * Sets a parameter in the SOAP output message. 
	 * 
	 * @see org.aselect.system.communication.server.IOutputMessage#setParam(java.lang.String,
	 *      java.lang.String)
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

		//create parameter value
		Text xParamValue = _oOutputMessage.createTextNode(sValue);

		NodeList xParams = _elOutputRPCBody.getElementsByTagNameNS(_sMethodEnv, sName);
		if (xParams.getLength() != 1) //not a parameter with this name yet
		{
			//create parameter name
			Element xParamName = _oOutputMessage
					.createElementNS(_sMethodEnv, SOAPConstants.NS_PREFIX_RPC + ":" + sName);
			//add value and name to message
			xParamName.appendChild(xParamValue);
			_elOutputRPCBody.appendChild(xParamName);
		}
		else { //update paramater with new value
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Updating parameter: " + sName);
			Element xParamName = (Element) xParams.item(0);
			Node xOldValue = xParamName.getFirstChild();
			xParamName.replaceChild(xParamValue, xOldValue);
		}
		return true;
	}

	/**
	 * Sets an array parameter in the SOAP output message. 
	 * 
	 * @see org.aselect.system.communication.server.IOutputMessage#setParam(java.lang.String,
	 *      java.lang.String[])
	 */
	public boolean setParam(String sName, String[] saValue)
		throws ASelectCommunicationException
	{
		String sMethod = "setParam()";
		if (_oOutputMessage == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No output message available, cause: "
					+ Errors.ERROR_ASELECT_USE_ERROR);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}

		//convert array to xml tags
		Element tmpElement = arrayToXML(sName, saValue);

		NodeList xParams = _elOutputRPCBody.getElementsByTagNameNS(SOAPConstants.URI_SOAP11_ENC, sName);
		if (xParams.getLength() != 1)//new tag
		{
			//append to outputRPCBody
			_elOutputRPCBody.appendChild(tmpElement);
		}
		else
		//existing tag
		{
			//replace existing tag with new tag
			_elOutputRPCBody.replaceChild(tmpElement, xParams.item(0));
		}
		return true;
	}

	/**
	 * Sends the output message. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * Performs the following steps:
	 * <ul>
	 * <li>creates an output format which uses new lines and tabs</li>
	 * <li>Uses a {@link org.apache.xml.serialize.XMLSerializer }to serialize
	 * the message.</li>
	 * <li>reset output and input message</li>
	 * </ul>
	 * 
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
			//create output format which uses new lines and tabs
			OutputFormat oFormat = new OutputFormat(_oOutputMessage);
			oFormat.setLineSeparator(LineSeparator.Web);
			oFormat.setIndenting(true);
			oFormat.setLineWidth(80);
			//Create serializer
			XMLSerializer oSerializer = new XMLSerializer(_oResponse.getOutputStream(), oFormat);
			oSerializer.setNamespaces(true);
			//serialize outputmessage to outputstream
			oSerializer.serialize(_oOutputMessage.getDocumentElement());

			//clear output and input message
			_oOutputMessage = null;
			_elOutputBody = null;
			_elOutputRPCBody = null;
			//_elOutputHeader = null;
			_oInputMessage = null;

			return true;
		}
		catch (IOException eIO)
		//I/O error while serializing, should not occur
		{
			StringBuffer sbBuffer = new StringBuffer("DOM object could not be serialized: ");
			sbBuffer.append(eIO.getMessage());
			sbBuffer.append(", cause: ");
			sbBuffer.append(Errors.ERROR_ASELECT_IO);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eIO);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, eIO);
		}
	}

	/*
	 * Private creation helper methods
	 */

	/**
	 * Convert array to xml tags. 
	 * <br><br>
	 * <b>Description: </b> 
	 * <br>
	 * Converts the strings in the array into a parameter with the given name as
	 * XML <code>Element</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>Element</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * <li><code>sTagName</code> should be valid XML tagname.</li>
	 * <li><code>sa</code> should contain one or more valid tag values</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @param sTagName
	 *            The tagname of the array parameter.
	 * @param sa
	 *            the array parameter values.
	 * @return An XML object containg the created array parameter.
	 */
	private Element arrayToXML(String sTagName, String[] sa)
	{
		Element resultElement = _oOutputMessage.createElementNS(_sMethodEnv, SOAPConstants.NS_PREFIX_RPC + ":"
				+ sTagName);

		resultElement.setAttributeNS(_sMethodEnv, "arrayType", "xsd:string[" + sa.length + "]");

		//create item tags for every array item
		for (int i = 0; i < sa.length; i++) {
			//create item tag (ELEMENT_NODE)
			Element tmpElement = _oOutputMessage.createElementNS(_sMethodEnv, SOAPConstants.NS_PREFIX_RPC + ":item");
			//create value tag (TEXT_NODE)
			Text tmpTextNode = _oOutputMessage.createTextNode(sa[i]);
			tmpElement.appendChild(tmpTextNode);
			resultElement.appendChild(tmpElement);
		}

		return resultElement;
	}

	/**
	 * Convert a array parameter to a <code>String</code> array. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * Converts the XML parameter data to an array of strings. <br>
	 * Performs the following steps:
	 * <ul>
	 * 	<li>Parse "arrayType"</li>
	 * 	<li>Get number of parameter values</li>
	 * 	<li>Get the array item tags defined inside the array tag</li>
	 * 	<li>For all child elements:
	 * 		<ul>
	 * 			<li><code>if node type == ELEMENT_NODE</code> retrieve value of text
	 * 			node</li>
	 * 			<li>Add value to return array</li>
	 * 		</ul>
	 * 	</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * <code>elParam</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>elParam</code> should contain an array parameter. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @param elParam
	 *            The <code>Element</code> contaning the parameter as XML
	 *            data.
	 * @return An array of parameter values.
	 * @throws ASelectCommunicationException
	 *             If resolving fails.
	 */
	private String[] resolveArray(Element elParam)
		throws ASelectCommunicationException
	{
		String sMethod = "resolveArray()";
		String[] saReturn = null;
		String sArrayLength = null;

		//parse array type
		NamedNodeMap oNodes = elParam.getAttributes();
		for (int attrI = 0; attrI < oNodes.getLength(); attrI++) {
			Node nAttr = oNodes.item(0);
			if (nAttr.getLocalName().equalsIgnoreCase("arrayType")) {
				sArrayLength = (String) nAttr.getNodeValue().subSequence(nAttr.getNodeValue().lastIndexOf("[") + 1,
						nAttr.getNodeValue().lastIndexOf("]"));
			}
		}
		try {
			int iArrayMax = new Integer(sArrayLength).intValue();
			int iArrayIndex = 0;
			saReturn = new String[iArrayMax];

			//get the array item tags defined inside the array tag
			NodeList nlItems = elParam.getChildNodes();
			for (int i = 0; i < nlItems.getLength(); i++) {
				//check if node type == ELEMENT_NODE
				if (nlItems.item(i).getNodeType() == Node.ELEMENT_NODE) {
					Node tmpNode = nlItems.item(i).getFirstChild();
					if (tmpNode.getNodeType() == Node.TEXT_NODE) {
						//get value of text node
						if (iArrayIndex < iArrayMax)
							saReturn[iArrayIndex++] = tmpNode.getNodeValue();
					}
				}
			}
			if (saReturn == null) {
				StringBuffer sbBuffer = new StringBuffer("Could not resolve array. Resolved array length: ");
				sbBuffer.append(sArrayLength);
				sbBuffer.append(", cause: ");
				sbBuffer.append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
		}
		catch (NumberFormatException eNF) {

			StringBuffer sbBuffer = new StringBuffer("Error during resolving array (invalid 'arraySize'): ");
			sbBuffer.append(eNF.getMessage());
			sbBuffer.append(", cause: ");
			sbBuffer.append(Errors.ERROR_ASELECT_PARSE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eNF);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_PARSE_ERROR, eNF);
		}

		return saReturn;
	}

	/**
	 * Creates an input message from the input. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * This method parses the request data and creates an XML
	 * <code>Document</code> containing all parameters in the SOAP 1.1
	 * message. <br>
	 * <br>
	 * Parse and validation errors are logged and an <code>ASOAPException</code>
	 * is thrown. <b>Concurrency issues: </b> <br>
	 * The returned <code>Document</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * This method should be called in the initializing stage of the
	 * <code>SOAP11MessageCreator</code>.<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The input message instance variables contain input message XML data. <br>
	 * <br>
	 * <i>note: _oInputMessage is not set </i> <br>
	 * 
	 * @return The parsed and validated input message.
	 * @throws ASOAPException
	 *             If parsing or validation fails.
	 */
	private Document createInputMessage()
		throws ASOAPException
	{
		String sMethod = "createInputMessage()";
		Document oInputMessage = null;
		try {
			//create DocumentBuilderFactory to parse SOAP message.
			DocumentBuilderFactory oDbf = DocumentBuilderFactory.newInstance();
			oDbf.setNamespaceAware(true);

			//SOAP 1.1 SCHEMA VALIDATING default disabled because of
			// performance issues
			//			xDbf.setValidating(true);
			//			xDbf.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage",
			//							 "http://www.w3.org/2001/XMLSchema");
			//			xDbf.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource",
			//							 System.getProperty("user.dir") +
			//							 File.separator +
			//							 "soap-envelope.xsd");

			//Create parser
			DocumentBuilder oParser = oDbf.newDocumentBuilder();
			//set SOAP12 error handler which throws all errors.
			oParser.setErrorHandler(new SOAP11ErrorHandler());
			//parse
			oInputMessage = oParser.parse(_oRequest.getInputStream());
		}
		catch (org.xml.sax.SAXParseException xSPE) //Invalid XML
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Bad request, could not parse request.", xSPE);
			throw new ASOAPException(ASOAPException.CLIENT, "Bad request", xSPE.getMessage());
		}
		catch (org.xml.sax.SAXException xSE) //Invalid XML
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Bad request, could not parse request.", xSE);
			throw new ASOAPException(ASOAPException.CLIENT, "Bad request", xSE.getMessage());
		}
		catch (java.io.IOException xIOE) //Invalid inputstream (i/o error)
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Internal server error, could not open soap request.",
					xIOE);
			throw new ASOAPException(ASOAPException.SERVER, "Internal server error", xIOE.getMessage());
		}
		catch (ParserConfigurationException xPCE) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal server error", xPCE);
			throw new ASOAPException(ASOAPException.SERVER, "Internal server error", xPCE.getMessage());
		}

		//retrieve root element
		Element elRoot = oInputMessage.getDocumentElement();

		//check envelope tag name
		String xEnvelopeName = elRoot.getLocalName();
		if (!xEnvelopeName.equals(SOAPConstants.ELEM_ENVELOPE)) //invalid
		// envelop
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Version Mismatch, invalid envelope tag name.");
			String xDetail = null; //no detail for VerionMismatch
			throw new ASOAPException(ASOAPException.VERSION_MISMATCH, "Version Mismatch", xDetail);
		}
		//validate Body tag
		String nameSpace = elRoot.getNamespaceURI();
		if (nameSpace != null) //if encoding schema is specified, then use it.
		{
			_sInputMessageSchema = nameSpace;
			_elInputBody = getChildElementNS(elRoot, SOAPConstants.ELEM_BODY, _sInputMessageSchema);
		}
		else
		//no namespace is used
		{
			_elInputBody = getChildElement(elRoot, SOAPConstants.ELEM_BODY);
		}
		if (_elInputBody == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Bad request, No Body element found.");
			throw new ASOAPException(ASOAPException.CLIENT, "Bad request",
					"SOAP message must contain mandatory Body element.");
		}
		//retrieve RPCBody
		_elInputRPCBody = getChildElementNS(_elInputBody, _sMethodName, _sMethodEnv);
		if (_elInputRPCBody == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Bad request, No correct RPC Body found while looking for: "
					+ _sMethodName);
			throw new ASOAPException(ASOAPException.CLIENT, "Bad request",
					"Unsupported request received, invalid RPC body.");
		}
		return oInputMessage;
	}

	/**
	 * creates an empty SOAP output message. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * Creates a new <code>Document</code> with a empty RPC body. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>Document</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * This method should be called in the initializing stage of the
	 * <code>SOAP11MessageCreator</code>.<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <code>_elOutputBody</code> contains an empty SOAP body. <br>
	 * 
	 * @return An empty SOAP response message.
	 */
	private Document createOutputMessage()
	{
		//set Content type of response
		_oResponse.setProperty("Content-Type", SOAPConstants.CONTENT_TYPE);
		//Create IOutputMessage
		Document oOutputMessage = new DocumentImpl();
		//create envelope
		Element elEnvelope = oOutputMessage.createElementNS(_sInputMessageSchema, SOAPConstants.NS_PREFIX_SOAP_ENV
				+ ":" + SOAPConstants.ELEM_ENVELOPE);

		elEnvelope.setAttributeNS(_sInputMessageSchema, SOAPConstants.NS_PREFIX_SOAP_ENV + ":"
				+ SOAPConstants.ATTR_ENCODING_STYLE, SOAPConstants.URI_SOAP11_ENC);

		//add envelope
		oOutputMessage.appendChild(elEnvelope);
		//create Body
		_elOutputBody = oOutputMessage.createElementNS(_sInputMessageSchema, SOAPConstants.NS_PREFIX_SOAP_ENV + ":"
				+ SOAPConstants.ELEM_BODY);
		//add body
		elEnvelope.appendChild(_elOutputBody);

		return oOutputMessage;
	}

	/**
	 * Create a SOAP 1.1 Fault in the ouput message. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * Creates a SOAP 1.1 fault tag in the output message. <br>
	 * <br>
	 * <i>For more info see: <a
	 * href='http://www.w3.org/TR/2003/REC-soap12-part0-20030624/#L11549'
	 * target='_new'>SOAP fault handling </a> </i> <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * the returned <code>Element</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * 	<li><code>sFaultString</code> should be a valid SOAP 1.1 fault code.
	 * 	<li><code>sReasonString</code> should be a valid SOAP 1.1 fault
	 * 		reason.
	 * 	<li><code>sDetailString</code> should contain additional information.
	 * </ul>
	 * <br>
	 * <br>
	 * <b>Postconditions: </b> 
	 * <br>-<br>
	 * 
	 * @param sFaultString
	 *            The SOAP fault code as <code>String</code>.
	 * @param sReasonString
	 *            The SOAP fault reason contents.
	 * @param sDetailString
	 *            The SOAP fault detail contents.
	 * @return The created Fault.
	 */
	private Element createFault(String sFaultString, String sReasonString, String sDetailString)
	{
		//create Fault
		Element elFault = _oOutputMessage.createElementNS(_sInputMessageSchema, SOAPConstants.NS_PREFIX_SOAP_ENV + ":"
				+ SOAPConstants.ELEM_FAULT);

		//create Code
		Element elCode = _oOutputMessage.createElementNS(_sInputMessageSchema, SOAPConstants.NS_PREFIX_SOAP_ENV + ":"
				+ SOAPConstants.ELEM_FAULT_CODE);
		//add Code
		elFault.appendChild(elCode);

		//Create Code value
		Element elValue = _oOutputMessage.createElementNS(_sInputMessageSchema, SOAPConstants.NS_PREFIX_SOAP_ENV + ":"
				+ SOAPConstants.ELEM_FAULT_CODE_VALUE);
		//add text to value
		Text oValueText = _oOutputMessage.createTextNode(SOAPConstants.NS_PREFIX_SOAP_ENV + ":" + sFaultString);
		elValue.appendChild(oValueText);

		//add Value to code
		elCode.appendChild(elValue);

		//Create reason
		Element elReason = _oOutputMessage.createElementNS(_sInputMessageSchema, SOAPConstants.NS_PREFIX_SOAP_ENV + ":"
				+ SOAPConstants.ELEM_FAULT_REASON);
		//add reason
		elFault.appendChild(elReason);

		//create reason contents
		Element elReasonContent = _oOutputMessage.createElementNS(_sInputMessageSchema,
				SOAPConstants.NS_PREFIX_SOAP_ENV + ":Text");
		elReasonContent.setAttribute("xml:lang", SOAPConstants.XML_LANG);
		Text oReasonText = _oOutputMessage.createTextNode(sReasonString);
		elReasonContent.appendChild(oReasonText);

		//add reason contents
		elReason.appendChild(elReasonContent);

		//create detail if applicable
		if (sDetailString != null) {
			//create deatil
			Element elDetail = _oOutputMessage.createElementNS(_sInputMessageSchema, SOAPConstants.NS_PREFIX_SOAP_ENV
					+ ":" + SOAPConstants.ELEM_FAULT_DETAIL);
			//add detail
			elFault.appendChild(elDetail);

			//add text to detail
			Text oDetailText = _oOutputMessage.createTextNode(sDetailString);
			elDetail.appendChild(oDetailText);
		}
		return elFault;
	}

	/**
	 * Get XML child element. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * Get the child element with the given tagname from <code>elParent</code>.
	 * <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>Element</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * <li><code>elParent</code> should be a valid XML DOM
	 * <code>Element</code>.</li>
	 * <li><code>sTagname</code> should be a vaild tag name.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> 
	 * <br>-<br>
	 * 
	 * @param elParent
	 *            The root element from which the child element is extracted.
	 * @param sTagname
	 *            The tag name of the child element.
	 * @return The <code>Element</code> if found, otherwise <code>null</code>.
	 */
	private Element getChildElement(Element elParent, String sTagname)
	{
		NodeList xList = elParent.getElementsByTagName(sTagname);
		if (xList.getLength() == 1) {
			return (Element) xList.item(0);
		}
		return null;
	}

	/**
	 * Get XML child element with namespace. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * Get the child element with the given tagname and namespace URI from
	 * <code>elParent</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>Element</code> is not threadsafe. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * 	<li><code>elParent</code> should be a valid XML DOM
	 * 		<code>Element</code>.</li>
	 * 	<li><code>sTagname</code> should be a vaild tag name.</li>
	 * 	<li><code>sNamespaceURI</code> should contain a valid URI.</li>
	 * </ul>
	 * <br>
	 * <br>
	 * <b>Postconditions: </b> <br>-<br>
	 * 
	 * @param elParent
	 *            The root element from which the child element is extracted.
	 * @param sTagname
	 *            The tag name of the child element.
	 * @param sNamespaceURI
	 *            The namespace URI of the child element.
	 * @return The <code>Element</code> if found, otherwise <code>null</code>.
	 */
	private Element getChildElementNS(Element elParent, String sTagname, String sNamespaceURI)
	{
		NodeList nlChilds = elParent.getElementsByTagNameNS(sNamespaceURI, sTagname);
		if (nlChilds.getLength() == 1) {
			return (Element) nlChilds.item(0);
		}
		return null;
	}

}