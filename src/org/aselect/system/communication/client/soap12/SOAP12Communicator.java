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
 * $Id: SOAP12Communicator.java,v 1.16 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: SOAP12Communicator.java,v $
 * Revision 1.16  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.15  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.14  2005/03/24 09:33:22  erwin
 * Added normalization of values.
 *
 * Revision 1.13  2005/03/17 11:34:09  erwin
 * MODULE changed to "SOAP12Communicator".
 *
 * Revision 1.12  2005/03/16 13:15:44  tom
 * *** empty log message ***
 *
 * Revision 1.11  2005/03/16 11:41:54  tom
 * Fixed Javadoc comment
 *
 * Revision 1.10  2005/03/11 15:35:38  erwin
 * Improved logging of IO Exception when sending.
 *
 * Revision 1.9  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.8  2005/03/08 09:11:59  erwin
 * Added a \r\n\r\n after message. removed TODo.
 *
 * Revision 1.7  2005/03/04 15:50:27  erwin
 * Renamed Content-type -> Content-Type
 *
 * Revision 1.6  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.5  2005/02/22 16:18:50  erwin
 * Improved error handling.
 *
 * Revision 1.4  2005/02/10 10:10:49  erwin
 * code format
 *
 * Revision 1.3  2005/02/10 10:01:25  erwin
 * Applied code style and Javadoc comment.
 *
 *
 */

package org.aselect.system.communication.client.soap12;

import java.io.DataInputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.logging.Level;

import org.apache.xerces.dom.DocumentImpl;
import org.apache.xerces.parsers.DOMParser;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.server.soap12.SOAPConstants;
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
 * Client communicator which uses SOAP 1.2 over HTTP. 
 * <br><br>
 * <b>Description: </b> <br>
 * The SOAP communicator is used to create, retrieve, and
 * send SOAP 1.2 messages. <br>
 * 
 * @author Alfa & Ariss
 * 
 * 
 * 14-11-2007 - Changes:
 * - sendStringMessage() method added
 *    
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright Gemeente Den Haag (http://www.denhaag.nl)
 * 
 */
public class SOAP12Communicator implements IClientCommunicator
{
    /** The MIME content type for SOAP 1.2. */
    private static final String CONTENT_TYPE    = "application/soap+xml; charset=utf-8";

    /** SOAP 1.2 URI. */
    private static final String URI_SOAP12_ENV  = "http://www.w3.org/2003/05/soap-envelope";

    /** SOAP 1.2 Encoding URI. */
    private static final String URI_SOAP12_ENC  = "http://www.w3.org/2003/05/soap-encoding";

    /** A-Select SOAP Extension URI. */
    private static final String URI_ASELECT_ENV = ""; //"/schemas/"

    /** The method name that is used in the SOAP RPC body. */
    private String              _sCallMethod;

    /** The logger for system log entries. */
    private SystemLogger        _systemLogger;

    private final String		MODULE = "SOAP12Communicator";
    
    /**
     * Creates a new <code>SOAP12Communicator</code>.
     * <br><br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>sCallMethod</code> may not be null.</li>
     * <li><code>systemLogger</code> should be initialized.</li>
     * </ul>
     * <br>
     * <b>Postconditions: </b> <br>
     * <ul>
     * <li><code>_systemLogger</code> is set with <code> systemLogger</code>.
     * </li>
     * <li><code>_sCallMethod</code> is set with <code> sCallMethod</code>.
     * </li>
     * </ul>
     * 
     * @param sCallMethod
     *            The method name that is used in the SOAP message.
     * @param systemLogger
     *            The <code>Logger</code> to log system log entries.
     */
    public SOAP12Communicator (String sCallMethod, SystemLogger systemLogger)
    {
        _sCallMethod = sCallMethod;
        _systemLogger = systemLogger;
    }

    /**
     * Creates a SOAP message of the given parameters and sends it to the given
     * url. 
     * <br><br>
     * <b>Description: </b> <br>
     * Executes the following steps:
     * <ul>
     * <li>Builds a SOAP 1.2 request message</li>
     * <li>Send the message to the server</li>
     * <li>Recieves SOAP response message from the server</li>
     * <li>Parse the repsonse and return the parameters it contains</li>
     * </ul>
     * 
     * @throws ASelectCommunicationException
     *             If suplied URL is invalid.
     * @see org.aselect.system.communication.client.IClientCommunicator#sendMessage(
     * java.util.Hashtable,java.lang.String)
     */
    public Hashtable sendMessage(Hashtable htParameters, String sTarget)
        throws ASelectCommunicationException
    {
        Hashtable htResult = new Hashtable();
        String sMessage = null;
        String sResponse = null;
        Element elBody = null;
        String sMethod = "sendMessage()";
        
        //Create a new message
        sMessage = createMessage(htParameters, sTarget);
        try
        {
            //Send the message
            sResponse = send(sMessage, sTarget);
        }
        catch (java.net.MalformedURLException eMU)
        //exception if URL is malformed
        {                  
            StringBuffer sbBuffer = new StringBuffer("Invalid URL: ");
            sbBuffer.append(eMU.getMessage());
            sbBuffer.append(" errorcode: ");
            sbBuffer.append(Errors.ERROR_ASELECT_USE_ERROR);
            _systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eMU);
            throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, eMU);
        }
        _systemLogger.log(Level.INFO, MODULE, sMethod, "Response="+sResponse);

        //Parse and return response
        elBody = this.parse(sResponse);
        htResult = this.xmlBody2Hashtable(elBody, sTarget);
        return htResult;
    }
    
    // Bauke: added
    public String sendStringMessage(String soapMessage, String sTarget)
    throws ASelectCommunicationException
    {
        Hashtable htResult = new Hashtable();
        String sMessage = null;
        String sResponse = null;
        Element elBody = null;
        String sMethod = "sendStringMessage()";
        
        //Create a new message
        StringBuffer sbMessage = new StringBuffer();
        sbMessage.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sbMessage.append("<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">\n");
        sbMessage.append("<SOAP-ENV:Header/><SOAP-ENV:Body>\n");
        sbMessage.append(soapMessage);
        sbMessage.append("\n</SOAP-ENV:Body></SOAP-ENV:Envelope>");
        try {
            //Send the message
            sResponse = send(sbMessage.toString(), sTarget);
        }
        catch (java.net.MalformedURLException eMU) {                  
            StringBuffer sbBuffer = new StringBuffer("Invalid URL: ");
            sbBuffer.append(eMU.getMessage());
            sbBuffer.append(" errorcode: ");
            sbBuffer.append(Errors.ERROR_ASELECT_USE_ERROR);
            _systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eMU);
            throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, eMU);
        }
//        int len = sResponse.length();
//        _systemLogger.log(Level.INFO, MODULE, sMethod, "Response="+sResponse.substring(0, (len<40)?len:40));
        _systemLogger.log(Level.INFO, MODULE, sMethod, "Response="+sResponse);
        return sResponse;
    }

    /**
     * Creates an SOAP message as <code>String</code>.
     * <br><br>
     * <b>Description: </b> <br>
     * Creates a correct SOAP 1.2 message containing the given parameters. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * The used {@link java.util.Hashtable}is synchronized. <br>
     * <br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>htParameters</code> must contain valid parameter
     * name/valuepairs.</li>
     * <li><code>sTargetUrl</code> must be a valid URL.</li>
     * </ul>
     * <br>
     * <b>Postconditions: </b> <br>-<br>
     * 
     * @param htParameters
     *            A <CODE>Hashtable</CODE> containing the paramaters to add to
     *            the SOAP message.
     * @param sTargetUrl
     *            The URL of the server.
     * @return <CODE>String</CODE> containing the created SOAP message
     */
    private String createMessage(Hashtable htParameters, String sTargetUrl)
    {
        String sMethod = "createMessage";
        StringBuffer sbMessage = new StringBuffer();
        if (htParameters != null || !sTargetUrl.equals(""))
        //Params and target url may not be empty to create a message
        {
            //create SOAP message in String format
            sbMessage.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            sbMessage.append("<env:Envelope xmlns:env=\"").append(
                URI_SOAP12_ENV).append("\" ");
            sbMessage.append("xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" ");
            sbMessage
                .append("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n");
            sbMessage.append("\t<env:Body>\n");
            sbMessage.append("\t\t<m:").append(_sCallMethod).append(
                " xmlns:m=\"").append(sTargetUrl);
            sbMessage.append(URI_ASELECT_ENV);
            sbMessage.append("\" env:encodingStyle=\"");
            sbMessage.append(URI_SOAP12_ENC);
            sbMessage.append("\">\n");

            Iterator iter = htParameters.keySet().iterator();
            String sKey = null;
            while (iter.hasNext())
            {
                sKey = (String)iter.next();
                Object oValue = htParameters.get(sKey);
                if (oValue instanceof String)
                {
                    //Add params to message in SOAP-RPC format
                    sbMessage.append("\t\t\t<m:").append(sKey).append(">");
                    sbMessage.append(normalize((String)oValue));
                    sbMessage.append("</m:").append(sKey).append(">\n");
                }
                else if (oValue instanceof String[])
                {
                    String[] asAtributes = (String[])oValue;
                    //Add params to message in SOAP-RPC format
                    sbMessage.append("\t\t\t<m:").append(sKey);
                    sbMessage
                        .append(" enc:itemType=\"xsd:string\" enc:arraySize=\"");
                    sbMessage.append(asAtributes.length).append(
                        "\" xmlns:enc=\"").append(URI_SOAP12_ENC).append(
                        "\">\n");
                    for (int i = 0; i < asAtributes.length; i++)
                    {
                        sbMessage.append(
                            "\t\t\t\t<m:item xsi:type=\"xsd:string\">");
                        sbMessage.append(normalize(asAtributes[i]));
                        sbMessage.append("</m:item>\n");
                    }
                    sbMessage.append("\t\t\t</m:").append(sKey).append(">\n");
                }
                else
                {
                    _systemLogger.log(Level.INFO, MODULE, sMethod,
                        "Unknown object found in Hashtable");
                }
            }

            //close tags
            sbMessage.append("\t\t</m:").append(_sCallMethod).append(">\n");
            sbMessage.append("\t</env:Body>\n");
            sbMessage.append("</env:Envelope>");
        }
        return sbMessage.toString();
    }

    /**
     * Sends a SOAP message to a SOAP server. 
     * <br><br>
     * <b>Description: </b> <br>
     * Sends the suplied SOAP message to the suplied URL using an
     * <code>HttpURLConnection</code>.<br>
     * <br>
     * <b>Concurrency issues: </b> <br>-<br>
     * <br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>sMessage</code> should contain a valid SOAP 1.1 message.
     * </li>
     * <li><code>sUrl</code> should be a valid URL.</li>
     * </ul>
     * <b>Postconditions: </b> <br>-<br>
     * 
     * @param sMessage
     *            A <code>String</code> containing the SOAP message that has
     *            to be sent.
     * @param sUrl
     *            The URL to send the message to.
     * @return A <CODE>String</CODE> containing the response SOAP message.
     * @throws java.net.MalformedURLException
     *             If suplied URL is invalid.
     * @throws ASelectCommunicationException
     *             If communication with the server fails.
     */
    private String send(String sMessage, String sUrl)
        throws java.net.MalformedURLException, ASelectCommunicationException
    {
        StringBuffer sbBuf = new StringBuffer();
        String sMethod = "send()";
        URL url = null;
        HttpURLConnection connection = null;

        //http://[target address]/[schema target]
        url = new URL(sUrl);

        try
        {
            //open HTTP connection to URL
            connection = (HttpURLConnection)url.openConnection();
            //enable sending to connection
            connection.setDoOutput(true);

            //set mime headers
            connection.setRequestProperty("Content-Type", CONTENT_TYPE);
            connection.setRequestProperty("Accept", CONTENT_TYPE);
            //write message to output
            PrintStream osOutput = new PrintStream(connection.getOutputStream());
            osOutput.println(sMessage);
            osOutput.println("\r\n\r\n");
            osOutput.close();

            // RH, 20080717, so
//            int iRead = 0;
//            byte[] ba = new byte[512];
//            DataInputStream isInput = null;
            // RH, 20080717, eo

            int xRetCode = connection.getResponseCode();
            switch (xRetCode)
            { //switch on HTTP response code
                case 200: //ok
                {
                	/*             // RH, 20080717, so
                    isInput = new DataInputStream(connection.getInputStream());
                    //Retrieve message as bytes and put them in a string
                    while ((iRead = isInput.read(ba)) != -1)
                    {
                        //append to stringbuffer
                        sbBuf.append(new String(ba, 0, iRead));
                        // clear the buffer
                        Arrays.fill(ba, (byte)0);
                    }
                    //close the stream
                    isInput.close();
                    */             // RH, 20080717, eo
                    sbBuf = new StringBuffer(Tools.stream2string(connection.getInputStream(), true));  // RH, 20080717, n

                    break;
                }
                case 400: //Bad request
                {
                    _systemLogger.log(Level.INFO, MODULE, sMethod, connection.getHeaderField(0));
                    break;
                }
                case 500: //Internal server error
                {
                    StringBuffer sbBuffer = new StringBuffer("Internal server error at target host. errorcode: ");
                    sbBuffer.append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
                    break;
                }
                default: //unknown error
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
        //error while connecting,writing or reading
        {
            StringBuffer sbBuffer = new StringBuffer("Could not open connection with host: \"");
            sbBuffer.append(sUrl);
            sbBuffer.append("\" errorcode: ");
            sbBuffer.append(Errors.ERROR_ASELECT_IO);
            _systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eIO);
            throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, eIO);     
        }
        return sbBuf.toString();
    }

    /**
     * Parses a message to a XML <code>Element</code> object. 
     * <br><br>
     * <b>Description: </b> <br>
     * Uses a <code>DOMParser</code> to parse the supplied message. Extracts
     * the SOAP body from the parsed message. All parse and I/O errors are
     * converted to <code>ASelectCommunicationException</code> exceptions.
     * <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * Xerces XML object are not thread safe, this methods creates its own
     * <code>DOMParser</code> and is therefore threadsafe. <br>
     * <br>
     * <b>Preconditions: </b> <br>
     * <code>sMessage</code> should contain a valid SOAP 1.2 message. <br>
     * <br>
     * <b>Postconditions: </b> <br>-<br>
     * 
     * @param sMessage
     *            A <CODE>String</CODE> with the SOAP message that has to be
     *            parsed.
     * @return An <CODE>Element</CODE> containing the parsed SOAP message
     *         body.
     * @throws ASelectCommunicationException
     * @see org.apache.xerces.parsers.DOMParser#parse(org.xml.sax.InputSource)
     */
    private Element parse(String sMessage) throws ASelectCommunicationException
    {
        Element elBody = null;
        String sMethod = "parse()";
        if (!sMessage.equals(""))
        {
            try
            {
                //create new DOM parser
                DOMParser oParser = new DOMParser();
                //set error handler to default empty handler
                oParser.setErrorHandler(new DefaultHandler());
                //parse message as String to DOM object
                oParser.parse(new InputSource(new StringReader(sMessage)));
                //get root XML tag
                DocumentImpl oDoc = (DocumentImpl)oParser.getDocument();
                //get body element
                NodeList nlNodes = oDoc.getDocumentElement()
                    .getElementsByTagNameNS(URI_SOAP12_ENV, "Body");

                if (nlNodes.getLength() == 0) {  // Bauke: additional try
                    nlNodes = oDoc.getDocumentElement().getElementsByTagNameNS(
                    	"http://schemas.xmlsoap.org/soap/envelope/", "soap:Body");
                }
                if (nlNodes.getLength() == 1)
                {
                    Node nNode = nlNodes.item(0);
                    if (nNode instanceof Element)
                    //if node = element then it's the Body element
                    {
                        elBody = (Element)nNode;
                    }
                }
            }
            catch (org.xml.sax.SAXException eSax) //error while parsing
            {
                StringBuffer sbBuffer = new StringBuffer("Error during parsing: ");
                sbBuffer.append(eSax.getMessage());
                sbBuffer.append(" errorcode: ");
                sbBuffer.append(Errors.ERROR_ASELECT_PARSE_ERROR);
                _systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eSax);
                throw new ASelectCommunicationException(Errors.ERROR_ASELECT_PARSE_ERROR, eSax); 
            }
            catch (java.io.IOException eIO)
            //error reading Message String to inputstream
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
     * Converts the xml body to a Hashtable object. 
     * <br><br>
     * <b>Description: </b> <br>
     * Converts the xml body <code>Element</code> to a Hashtable object. <br>
     * <br>
     * <b>Concurrency issues: </b>
     * <ul>
     * <li><code>elBody</code> is not threadsafe and this method should be
     * called sequential when using the same <code>elBody</code> object.</li>
     * <li>The returned <code>Hashtable</code> is threadsafe.</li>
     * </ul>
     * <br>
     * <br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>elBody</code> should be a constructed SOAP Body.</li>
     * <li><code>sURI</code> should be a valid URL</li>
     * </ul>
     * <br>
     * <b>Postconditions: </b> <br>-<br>
     * 
     * @param elBody
     *            an DOM <code>Element</code> containing the body of the SOAP
     *            message
     * @param sURI
     *            the Namespace URI of the body.
     * @return An <CODE>Hashtable</CODE> containing the response params.
     * @throws ASelectCommunicationException
     *             If conversion fails.
     */
    private Hashtable xmlBody2Hashtable(Element elBody, String sURI)
        throws ASelectCommunicationException
    {
        String sMethod = "xmlBody2Hashtable";
        Hashtable htReturn = new Hashtable();
        if (elBody != null)
        {
            String sKey = null;
            String sValue = null;
            NodeList nlTemp = null;
            NodeList nlNodes = null;
            nlNodes = elBody.getElementsByTagNameNS(sURI + URI_ASELECT_ENV,
                _sCallMethod + "Response");
            if (nlNodes.getLength() == 1) //There may only be one Response tag
            {
                //get all child nodes of the first element from nodelist
                nlNodes = nlNodes.item(0).getChildNodes();
                //for every param do
                for (int xI = 0; xI < nlNodes.getLength(); xI++)
                {
                    //get param and check if it has childs
                    if (nlNodes.item(xI).hasChildNodes())
                    {
                        nlTemp = nlNodes.item(xI).getChildNodes();
                        //it may only have one child node and it must be a
                        // TEXT_NODE
                        if (nlTemp.getLength() == 1)
                        {
                            if (nlTemp.item(0).getNodeType() == Node.TEXT_NODE)
                            {
                                //localname = tagname without namespace prefix
                                sKey = nlNodes.item(xI).getLocalName();
                                //get value of text node
                                sValue = nlTemp.item(0).getNodeValue();
                                //add to Hashtable
                                htReturn.put(sKey, sValue);
                            }
                        }
                        else
                        {
                            if (nlNodes.item(xI).getNodeType() == Node.ELEMENT_NODE)
                            {
                                Element elCurrent = (Element)nlNodes.item(xI);
                                String[] sa = resolveArray(elCurrent, nlTemp);

                                //localname = tagname without namespace prefix
                                sKey = elCurrent.getLocalName();

                                //add to Hashtable
                                htReturn.put(sKey, sa);
                            }
                        }
                    }
                }
            }
            else
            {
                //SOAP RPC body = invalid
                //-> namespace can be invalid, more response tags or no
                // response tag
                _systemLogger.log(Level.INFO, MODULE, sMethod, "Invalid SOAP-RPC body");
            }
        }
        return htReturn;
    }

    /**
     * resolve an array from a SOAP message. 
     * <br><br>
     * <b>Description: </b> <br>
     * Get all values form the suplied element and convert these to a
     * <code>String</code> array. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * <code>elRoot</code> and <code>nlChildElements</code> are not
     * threadsafe and this method should be called sequential when using the
     * same instances of these objects. <br>
     * <br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>elRoot</code> Should be a valid XML <code>Element</code>.
     * </li>
     * <li><code>nlChildElements</code> Should contain aray parameters.</li>
     * </ul>
     * <br>
     * <b>Postconditions: </b> <br>-<br>
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
        String[] sa = null;
        String sMethod = "resolveArray()";
        String sItemType = elRoot.getAttributeNS(SOAPConstants.URI_SOAP12_ENC,
            "itemType");
        if (sItemType.equalsIgnoreCase("xsd:string"))
        {
            String sSize = elRoot.getAttributeNS(URI_SOAP12_ENC, "arraySize");
            try
            {
                int iArrayMax = new Integer(sSize).intValue();
                int iArrayIndex = 0;
                sa = new String[iArrayMax];
                for (int i = 0; i < nlChildElements.getLength(); i++)
                {
                    if (nlChildElements.item(i).getNodeType() == Node.ELEMENT_NODE)
                    {
                        Node nTemp = nlChildElements.item(i).getFirstChild();
                        if (nTemp.getNodeType() == Node.TEXT_NODE)
                        {
                            //get value of text node
                            if (iArrayIndex < iArrayMax)
                                sa[iArrayIndex++] = nTemp.getNodeValue();
                        }
                    }
                }
            }
            catch (NumberFormatException eNF)
            {
                StringBuffer sbBuffer = new StringBuffer("Error during resolving array (invalid 'arraySize'): ");
                sbBuffer.append(eNF.getMessage());
                sbBuffer.append(" errorcode: ");
                sbBuffer.append(Errors.ERROR_ASELECT_PARSE_ERROR);
                _systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eNF);
                throw new ASelectCommunicationException(Errors.ERROR_ASELECT_PARSE_ERROR, eNF);                              
            }

        }
        return sa;
    }
    
    /** 
     * Normalizes the given string. 
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Converts special XML characters (&lt;, &gt;, &amp;, and &quot;).
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <code>s != null</code>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param s The <code>String</code> to be normalized.
     * @return The normalized <code>String</code>.
     * 
     */
    private String normalize(String s)
    {
        //TODO Move this redundant method (Erwin)
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < s.length(); i++)
        {
            char ch = s.charAt(i);
            switch (ch)
            {
                case '<':
                {
                    sb.append("&lt;");
                    break;
                }
                case '>':
                {
                    sb.append("&gt;");
                    break;
                }
                case '&':
                {
                    sb.append("&amp;");
                    break;
                }
                case '"':
                {
                    sb.append("&quot;");
                    break;
                }                
                default:
                {
                    sb.append(ch);
                }
            }
        }

        return sb.toString();
    }

}