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
 * @author Bauke Hiemstra - www.anoigo.nl
 * 
 * Version 1.0 - 14-11-2007
 */
package org.aselect.system.utils;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.w3c.dom.*;

//
//
public class Tools
{
    final static String MODULE = "Tools";
    protected final static String DEFAULT_CHARSET = "UTF8";

	
    // Bauke: added
	// if 'getContent' extract the content within the tags, otherwise extract with tags included
	// <searchFor xxx      >contents              </searchFor>
	// ^begin               ^cntBegin             ^cntEnd     ^end
    public static String extractFromXml(String message, String searchFor, boolean getContent)
    {
        String sMethod = "extractFromXml()";
        int begin = message.indexOf("<" + searchFor + ">");
        if (begin < 0) {
        	begin = message.indexOf("<" + searchFor + " ");
        }
        if (begin < 0) {
        	//_systemLogger.log(Level.INFO,MODULE,sMethod, "extractFromXml; No begin: " + searchFor);
            return null;
        }
        int cntBegin = begin + searchFor.length() + 1;
        cntBegin = message.indexOf(">", cntBegin);
        if (cntBegin < 0) return null;
        cntBegin++;
        int cntEnd = message.indexOf("</" + searchFor + ">", cntBegin);
        if (cntEnd < 0) {
        	//_systemLogger.log(Level.INFO,MODULE,sMethod,"extractFromXml; No end: " + searchFor);
            return null;
        }
        int end = cntEnd + 3 + searchFor.length();
    	//_systemLogger.log(Level.INFO,MODULE,sMethod,"begin="+begin+" end="+end+" cntBegin="+cntBegin+"cntEnd="+cntEnd);
        String result;
        if (getContent)
        	result = message.substring(cntBegin, cntEnd);
        else
        	result = message.substring(begin, end);
        //_systemLogger.log(Level.INFO,MODULE,sMethod,"extractFromXml: " + searchFor + "->" + result);
        return result;
    }
    
    // Bauke: added
    public static String clipString(String text, int max, boolean dots)
    {
    	int len = text.length();
    	return (len<=max)? text: (text.substring(0, max)+((dots)? "...": ""));
    }

    // Bauke: added
	public static String samlCurrentTime()
	{
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		return df.format(new Date());
	}
    // Bauke: added
	public static String getTimestamp()
	{
		SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		return df.format(new Date());
	}

	// Bauke: added
	public static String htmlEncode(String sText)
	{
		StringTokenizer tokenizer = new StringTokenizer(sText, "<>\"'", true);
		int tokenCount = tokenizer.countTokens();

		StringBuffer buffer = new StringBuffer(sText.length() + tokenCount * 6);
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken();
			if (token.length() == 1) {
				switch (token.charAt(0)) {
				case '<': buffer.append("&lt;"); break;
				case '>': buffer.append("&gt;"); break;
				case '"': buffer.append("&quot;"); break;
				case '\'': buffer.append("#39;"); break;
				default: buffer.append(token);
				}
			}
			else {
				buffer.append(token);
			}
		}
		return buffer.toString();
	}

    public static void addAttributeToElement(Node baseNode, ASelectSystemLogger logger,
    		String sName, String sAttr, String sValue)
    {
    	String sMethod = "changeNode";
        logger.log(Level.INFO, MODULE, sMethod, "NAME="+baseNode.getLocalName()+" sName="+sName+" sAttr="+sAttr+" sValue="+sValue);
        if (baseNode.getLocalName().equals(sName)) {
            logger.log(Level.INFO, MODULE, sMethod, "ADDATTR sAttr="+sAttr+" sValue="+sValue);
            ((Element)baseNode).setAttribute(sAttr, sValue);
        	return;  // ready
        }
        // Obtain a NodeList of nodes in an Element node.
        NodeList nodeList = baseNode.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            // Retrieve Element Nodes
            if (node.getNodeType() == Node.ELEMENT_NODE) {
            	Element element = (Element) node;
                if (element.getLocalName().equals(sName)) {
                    logger.log(Level.INFO, MODULE, sMethod, "ADDATTR sAttr="+sAttr+" sValue="+sValue);
                	element.setAttribute(sAttr, sValue);
                	return;  // ready
                }
            	addAttributeToElement(element, logger, sName, sAttr, sValue);
            }
        }
    }

    // debugging use:
    public static void visitNode(Element previousNode, Element visitNode, ASelectSystemLogger logger)
    {
    	String sMethod = "visitNode";
        if (previousNode != null) {
        	logger.log(Level.INFO, MODULE, sMethod, "Element " + previousNode.getTagName()
                    + " has element:");
        }
        logger.log(Level.INFO, MODULE, sMethod, "Element Name: " + visitNode.getTagName() + " | " +
        				visitNode.getLocalName() + " | "+visitNode.getNamespaceURI());
        if (visitNode.hasAttributes()) {
        	logger.log(Level.INFO, MODULE, sMethod, "Element " + visitNode.getTagName()
                    + " has attributes: ");
            NamedNodeMap attributes = visitNode.getAttributes();

            for (int j = 0; j < attributes.getLength(); j++) {
                Attr attribute = (Attr) (attributes.item(j));
                logger.log(Level.INFO, MODULE, sMethod, "Attribute:" + attribute.getName()
                        + " with value " + attribute.getValue());
            }
        }
        // Obtain a NodeList of nodes in an Element node.

        NodeList nodeList = visitNode.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            // Retrieve Element Nodes
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;
                visitNode(visitNode, element, logger);
            } else if (node.getNodeType() == Node.TEXT_NODE) {
                String str = node.getNodeValue().trim();
                if (str.length() > 0) {
                	logger.log(Level.INFO, MODULE, sMethod, "Element Text: " + str);

                }
            }
        }
    }

	/**
		 * Read bytes from inputstream till empty and convert to string.
		 * based on supplied charset encoding
		 * Inputstream is NOT closed at return.
		 * 
		 * @param is
		 *            The inputstream to read from.
		 * @param enc
		 *            The character encoding to use in conversion.
		 * @param doClose
		 *            Should the underlying inputstream be closed. <true|false>
		 *         
		 * @return String containing the data from the inputstream
		 * @throws IOException 
	
		 * @category utility method
		 * 
		 * @see http://java.sun.com/j2se/1.5.0/docs/guide/intl/encoding.doc.html
		 * 
		 */
	
		public static String stream2string(InputStream is, String enc, boolean doClose) throws IOException {
			
			int xRead = 0;
			byte[] ba = new byte[512];
			DataInputStream isInput = new DataInputStream(new BufferedInputStream(is));
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			// Retrieve message as bytes and put them in a string
			while ((xRead = isInput.read(ba)) != -1) {
				bos.write(ba, 0, xRead);
				// clear the buffer
	//			Arrays.fill(ba, (byte) 0); /// Why? Just to be sure?
			} 
			return (bos.toString(enc));  // RH, 20080714, n
		}

	public static String stream2string(InputStream is, boolean close) throws IOException {
		return stream2string(is, DEFAULT_CHARSET, close);
	}

	public static String stream2string(InputStream is, String enc) throws IOException {
		return stream2string(is, enc, true);
	}
	
	public static String stream2string(InputStream is) throws IOException {
		return stream2string(is, DEFAULT_CHARSET, true);
	}

}
