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
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.logging.Level;

import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.communication.client.soap11.SOAP11Communicator;
import org.aselect.system.communication.client.soap12.SOAP12Communicator;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.storagemanager.SendQueue;
import org.w3c.dom.*;

//
public class Tools
{
	final static String MODULE = "Tools";
	protected final static String DEFAULT_CHARSET = "UTF8";

	// Bauke: added
	// if 'getContent' extract the content within the tags, otherwise extract with tags included
	// <searchFor xxx >contents </searchFor>
	// ^begin ^cntBegin ^cntEnd ^end
	/**
	 * Extract from xml.
	 * 
	 * @param message
	 *            the message
	 * @param searchFor
	 *            the search for
	 * @param getContent
	 *            the get content
	 * @return the string
	 */
	public static String extractFromXml(String message, String searchFor, boolean getContent)
	{
		String sMethod = "extractFromXml()";
		int begin = message.indexOf("<" + searchFor + ">");
		if (begin < 0) {
			begin = message.indexOf("<" + searchFor + " ");
		}
		if (begin < 0) {
			// _systemLogger.log(Level.INFO,MODULE,sMethod, "extractFromXml; No begin: " + searchFor);
			return null;
		}
		int cntBegin = begin + searchFor.length() + 1;
		cntBegin = message.indexOf(">", cntBegin);
		if (cntBegin < 0)
			return null;
		cntBegin++;
		int cntEnd = message.indexOf("</" + searchFor + ">", cntBegin);
		if (cntEnd < 0) {
			// _systemLogger.log(Level.INFO,MODULE,sMethod,"extractFromXml; No end: " + searchFor);
			return null;
		}
		int end = cntEnd + 3 + searchFor.length();
		// _systemLogger.log(Level.INFO,MODULE,sMethod,"begin="+begin+" end="+end+" cntBegin="+cntBegin+"cntEnd="+cntEnd);
		String result;
		if (getContent)
			result = message.substring(cntBegin, cntEnd);
		else
			result = message.substring(begin, end);
		// _systemLogger.log(Level.INFO,MODULE,sMethod,"extractFromXml: " + searchFor + "->" + result);
		return result;
	}

	// Bauke: added
	/**
	 * Clip string.
	 * 
	 * @param text
	 *            the text
	 * @param max
	 *            the max
	 * @param dots
	 *            the dots
	 * @return the string
	 */
	public static String clipString(String text, int max, boolean dots)
	{
		int len = text.length();
		return (len <= max) ? text : (text.substring(0, max) + ((dots) ? "..." : ""));
	}

	// Bauke: added
	/**
	 * Saml current time.
	 * 
	 * @return the string
	 */
	public static String samlCurrentTime()
	{
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		return df.format(new Date());
	}

	// Bauke: added
	/**
	 * Gets the timestamp.
	 * 
	 * @return the timestamp
	 */
	public static String getTimestamp()
	{
		SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		return df.format(new Date());
	}

	private static int usiRotate = 0;

	/**
	 * Generate unique sensor id. For use with LbSensor.
	 * The format matches the filter version.
	 * 
	 * @return the unique id
	 */
	public static String generateUniqueSensorId()
	{
		// Result: 11618456.720181001
		final String sZeroes = "000000000";

		usiRotate++;
		if (usiRotate>999) usiRotate = 1;
		
		Long nano = System.nanoTime();
		String sNano = Long.toString(nano);
		int len = sNano.length();
		if (len < 9) {  // will likely never happen
			sNano = sZeroes.substring(len)+sNano;
			len = sNano.length();
		}
		StringBuffer sbResult = new StringBuffer(sNano.substring(0, len-9));
		sbResult.append(".").append(sNano.substring(len-9, len-3));
		sbResult.append(String.format("%03d", usiRotate));

		return sbResult.toString();
	}

	// Bauke: added
	/**
	 * Html encode.
	 * 
	 * @param sText
	 *            the s text
	 * @return the string
	 */
	public static String htmlEncode(String sText)
	{
		StringTokenizer tokenizer = new StringTokenizer(sText, "<>\"'", true);
		int tokenCount = tokenizer.countTokens();

		StringBuffer buffer = new StringBuffer(sText.length() + tokenCount * 6);
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken();
			if (token.length() == 1) {
				switch (token.charAt(0)) {
				case '<':
					buffer.append("&lt;");
					break;
				case '>':
					buffer.append("&gt;");
					break;
				case '"':
					buffer.append("&quot;");
					break;
				case '\'':
					buffer.append("#39;");
					break;
				default:
					buffer.append(token);
				}
			}
			else {
				buffer.append(token);
			}
		}
		return buffer.toString();
	}

	/**
	 * Adds the attribute to element.
	 * 
	 * @param baseNode
	 *            the base node
	 * @param logger
	 *            the logger
	 * @param sName
	 *            the s name
	 * @param sAttr
	 *            the s attr
	 * @param sValue
	 *            the s value
	 */
	public static void addAttributeToElement(Node baseNode, SystemLogger logger, String sName, String sAttr,
			String sValue)
	{
		String sMethod = "changeNode";
		logger.log(Level.INFO, MODULE, sMethod, "NAME=" + baseNode.getLocalName() + " sName=" + sName + " sAttr="
				+ sAttr + " sValue=" + sValue);
		if (baseNode.getLocalName().equals(sName)) {
			logger.log(Level.INFO, MODULE, sMethod, "ADDATTR sAttr=" + sAttr + " sValue=" + sValue);
			((Element) baseNode).setAttribute(sAttr, sValue);
			return; // ready
		}
		// Obtain a NodeList of nodes in an Element node.
		NodeList nodeList = baseNode.getChildNodes();
		for (int i = 0; i < nodeList.getLength(); i++) {
			Node node = nodeList.item(i);
			// Retrieve Element Nodes
			if (node.getNodeType() == Node.ELEMENT_NODE) {
				Element element = (Element) node;
				if (element.getLocalName().equals(sName)) {
					logger.log(Level.INFO, MODULE, sMethod, "ADDATTR sAttr=" + sAttr + " sValue=" + sValue);
					element.setAttribute(sAttr, sValue);
					return; // ready
				}
				addAttributeToElement(element, logger, sName, sAttr, sValue);
			}
		}
	}

	// debugging use:
	/**
	 * Visit node.
	 * 
	 * @param previousNode
	 *            the previous node
	 * @param visitNode
	 *            the visit node
	 * @param logger
	 *            the logger
	 */
	public static void visitNode(Element previousNode, Element visitNode, SystemLogger logger)
	{
		String sMethod = "visitNode";
		if (previousNode != null) {
			logger.log(Level.INFO, MODULE, sMethod, "Element " + previousNode.getTagName() + " has element:");
		}
		logger.log(Level.INFO, MODULE, sMethod, "Element Name: " + visitNode.getTagName() + " | "
				+ visitNode.getLocalName() + " | " + visitNode.getNamespaceURI());
		if (visitNode.hasAttributes()) {
			logger.log(Level.INFO, MODULE, sMethod, "Element " + visitNode.getTagName() + " has attributes: ");
			NamedNodeMap attributes = visitNode.getAttributes();

			for (int j = 0; j < attributes.getLength(); j++) {
				Attr attribute = (Attr) (attributes.item(j));
				logger.log(Level.INFO, MODULE, sMethod, "Attribute:" + attribute.getName() + " with value "
						+ attribute.getValue());
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
			}
			else if (node.getNodeType() == Node.TEXT_NODE) {
				String str = node.getNodeValue().trim();
				if (str.length() > 0) {
					logger.log(Level.INFO, MODULE, sMethod, "Element Text: " + str);

				}
			}
		}
	}

	/**
	 * Read bytes from inputstream till empty and convert to string. based on supplied charset encoding Inputstream is
	 * NOT closed at return.
	 * 
	 * @param is
	 *            The inputstream to read from.
	 * @param enc
	 *            The character encoding to use in conversion.
	 * @param doClose
	 *            Should the underlying inputstream be closed. <true|false>
	 * @return String containing the data from the inputstream
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @category utility method
	 * @see http://java.sun.com/j2se/1.5.0/docs/guide/intl/encoding.doc.html
	 */

	public static String stream2string(InputStream is, String enc, boolean doClose)
	throws IOException
	{

		int xRead = 0;
		byte[] ba = new byte[512];
		DataInputStream isInput = new DataInputStream(new BufferedInputStream(is));
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		// Retrieve message as bytes and put them in a string
		while ((xRead = isInput.read(ba)) != -1) {
			bos.write(ba, 0, xRead);
			// clear the buffer
			// Arrays.fill(ba, (byte) 0); /// Why? Just to be sure?
		}
		return (bos.toString(enc)); // RH, 20080714, n
	}

	/**
	 * Stream2string.
	 * 
	 * @param is
	 *            the is
	 * @param close
	 *            the close
	 * @return the string
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String stream2string(InputStream is, boolean close)
	throws IOException
	{
		return stream2string(is, DEFAULT_CHARSET, close);
	}

	/**
	 * Stream2string.
	 * 
	 * @param is
	 *            the is
	 * @param enc
	 *            the enc
	 * @return the string
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String stream2string(InputStream is, String enc)
	throws IOException
	{
		return stream2string(is, enc, true);
	}

	/**
	 * Stream2string.
	 * 
	 * @param is
	 *            the is
	 * @return the string
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String stream2string(InputStream is)
	throws IOException
	{
		return stream2string(is, DEFAULT_CHARSET, true);
	}

	/**
	 * Inits the client communicator.
	 * 
	 * @param oCfgMgr
	 *            the o cfg mgr
	 * @param oSysLog
	 *            the o sys log
	 * @param oConfig
	 *            the o config
	 * @return the i client communicator
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static IClientCommunicator initClientCommunicator(ConfigManager oCfgMgr, SystemLogger oSysLog, Object oConfig)
	throws ASelectException
	{
		String sClientCommunicator = Utils.getSimpleParam(oCfgMgr, oSysLog, oConfig, "clientcommunicator", false);
		oSysLog.log(Level.FINE, MODULE, "initClientCommunicator", "communicator="+sClientCommunicator);
		
		if (sClientCommunicator == null || sClientCommunicator.equalsIgnoreCase("raw")) {
			return new RawCommunicator(oSysLog);
		}
		else if (sClientCommunicator.equalsIgnoreCase("soap11")) {
			return new SOAP11Communicator("ASelect", oSysLog);
		}
		else if (sClientCommunicator.equalsIgnoreCase("soap12")) {
			return new SOAP12Communicator("ASelect", oSysLog);
		}
		oSysLog.log(Level.WARNING, MODULE, "initClientCommunicator", "Invalid 'clientcommunicator' value");
		throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
	}

	/**
	 * Initialize sensor data.
	 * 
	 * @param oConfMgr
	 *            the conf mgr
	 * @param oSysLog
	 *            the system log
	 * @param htSessionContext
	 *            the session context
	 */
	public static void initializeSensorData(ConfigManager oConfMgr, SystemLogger oSysLog, HashMap<String, String> htSessionContext)
	{
		String sMethod = "initializeSensorData";
		long now = System.currentTimeMillis();

		if (!oConfMgr.isLbSensorConfigured() && !oConfMgr.isTimerSensorConfigured())
			return;
		if (htSessionContext == null) {
			oSysLog.log(Level.INFO, MODULE, sMethod, "NO SESSION");
			return;
		}
		oSysLog.log(Level.INFO, MODULE, sMethod, "init now=" + now);
		htSessionContext.put("first_contact", Long.toString(now)); // milliseconds
		htSessionContext.put("time_user", "0"); // milliseconds
		Utils.setSessionStatus(htSessionContext, "upd", oSysLog);
	}

	/**
	 * Pause sensor data.
	 * 
	 * @param oConfMgr
	 *            the conf mgr
	 * @param oSysLog
	 *            the system log
	 * @param htSessionContext
	 *            the session context
	 */
	public static void pauseSensorData(ConfigManager oConfMgr, SystemLogger oSysLog, HashMap<String, String> htSessionContext)
	{
		String sMethod = "pauseSensorData";

		if (!oConfMgr.isLbSensorConfigured() && !oConfMgr.isTimerSensorConfigured())
			return;
		if (htSessionContext == null) {
			oSysLog.log(Level.INFO, MODULE, sMethod, "NO SESSION");
			return;
		}
		long now = System.currentTimeMillis();
		String sPause = htSessionContext.get("pause_contact"); // seconds
		oSysLog.log(Level.INFO, MODULE, sMethod, "pause now=" + now + ((sPause==null)?"": ", LBE already paused at="+sPause));
		// 20120215, Bauke: only replace if no old value
		if (sPause == null) {
			htSessionContext.put("pause_contact", Long.toString(now)); // seconds
			Utils.setSessionStatus(htSessionContext, "upd", oSysLog);
		}
	}

	/**
	 * Resume sensor data.
	 * 
	 * @param oConfMgr
	 *            the conf mgr
	 * @param oSysLog
	 *            the system log
	 * @param htSessionContext
	 *            the session context
	 */
	public static void resumeSensorData(ConfigManager oConfMgr, SystemLogger oSysLog, HashMap<String, String> htSessionContext)
	{
		String sMethod = "resumeSensorData";

		if (!oConfMgr.isLbSensorConfigured() && !oConfMgr.isTimerSensorConfigured())
			return;
		if (htSessionContext == null) {
			oSysLog.log(Level.INFO, MODULE, sMethod, "NO SESSION");
			return;
		}
		long now = System.currentTimeMillis();
		oSysLog.log(Level.INFO, MODULE, sMethod, "resume now=" + now);
		String sPause = htSessionContext.get("pause_contact"); // seconds
		String sUserSpent = htSessionContext.get("time_user"); // seconds
		if (sPause == null) {
			oSysLog.log(Level.INFO, MODULE, sMethod,  "user="+sUserSpent + ", LBE cannot resume, not paused");
		}
		else {
			try {
				long lPause = Long.parseLong(sPause);
				long lUserSpent = (sUserSpent != null) ? Long.parseLong(sUserSpent) : 0;
				long lPaused = now - lPause;
				long lSpentNew = lUserSpent + lPaused;
				oSysLog.log(Level.INFO, MODULE, sMethod, "user=" + lUserSpent + "->" + lSpentNew + " paused="+ lPause);
				htSessionContext.put("time_user", Long.toString(lSpentNew)); // seconds
				htSessionContext.remove("pause_contact");
				Utils.setSessionStatus(htSessionContext, "upd", oSysLog);
			}
			catch (Exception e) {
				oSysLog.log(Level.INFO, MODULE, sMethod, "Sensor calculation failed", e);
			}
		}
	}

	/**
	 * Calculate and report sensor data.
	 * Used by the time sensor and the lb sensor mechanism
	 * 
	 * @param oConfMgr
	 *            the config manager
	 * @param oSysLog
	 *            the system logger
	 * @param sOrig
	 *            the orig
	 * @param sRid
	 *            the rid
	 * @param htSessionContext
	 *            the session
	 * @param sTgt
	 *            the TGT
	 * @param bSuccess
	 *            successful?
	 */
	public static void calculateAndReportSensorData(ConfigManager oConfMgr, SystemLogger oSysLog,
						String sOrig, String sRid, HashMap htSessionContext, String sTgt, boolean bSuccess)
	{
		String sMethod = "calculateAndReportSensorData";
		long lFirst, lLast;
		
		oSysLog.log(Level.INFO, MODULE, sMethod, "<lbsensor>="+(oConfMgr.isLbSensorConfigured())+
				" <timer_sensor>="+oConfMgr.isTimerSensorConfigured());
		if (!oConfMgr.isLbSensorConfigured() && !oConfMgr.isTimerSensorConfigured())
			return;
		if (htSessionContext == null) {
			oSysLog.log(Level.INFO, MODULE, sMethod, "NO SESSION");
			return;
		}
		String sFirst = (String) htSessionContext.get("first_contact"); // seconds
		String sUserSpent = (String) htSessionContext.get("time_user"); // seconds
		if (sFirst == null) {
			oSysLog.log(Level.INFO, MODULE, sMethod, "LBE not started");
			return;
		}
		try {
			long nowTime = System.currentTimeMillis();
			String sPause = (String)htSessionContext.get("pause_contact"); // seconds
			lFirst = Long.parseLong(sFirst);
			if (sPause != null)  // take as end point
				lLast = Long.parseLong(sPause);
			else
				lLast = System.currentTimeMillis();
			long lTotalSpent = lLast - lFirst;
			oSysLog.log(Level.INFO, MODULE, sMethod, "now="+nowTime+" last="+lLast + " first="+sFirst + " user="+sUserSpent+
							((sPause==null)?"": ", LBE already paused at="+sPause));
			long lUserSpent = 0;
			if (sUserSpent != null) {
				lUserSpent = Long.parseLong(sUserSpent);
				lTotalSpent -= lUserSpent;
			}
			if (bSuccess) {
				// Send data to lbsensor's http_sensor, does not use the queue
				Tools.reportDataToSensor(oConfMgr, "aselect", "lbsensor", "sensor_url", oSysLog, Long.toString(lTotalSpent));
			}

			if (!oConfMgr.isTimerSensorConfigured())  // No TimerSensor requested, skip the rest
				return;
			
			// 20111110, Bauke: added TimerSensor functionality
			String sUsi = (String)htSessionContext.get("usi");
		    String sFirstContact = TimerSensor.timerSensorMilli2Time(Long.parseLong(sFirst));
		    String sTotalSpent = TimerSensor.timerSensorMilli2Time(lTotalSpent);
			String sLast = TimerSensor.timerSensorMilli2Time(lLast);
			String sAppId = (String)htSessionContext.get("app_id");
			String sVisit = (String)htSessionContext.get("authsp_visited");
			int iTimerSensorType = (sVisit!=null)? 4/*authsp*/: 3/*server*/;
			// Thread is the last thread that contributed to processing
		    String sDataLine = String.format("%s,%s,%s,%d,%d,%d,%s,%s,%s,%s,%s,%s", sOrig, (sUsi==null)? "": sUsi,
		    		sAppId, 1/*complete flow*/, iTimerSensorType, Thread.currentThread().getId(),
		    		sFirstContact, sLast, sTotalSpent, Boolean.toString(bSuccess), sRid, (sTgt==null)? "": sTgt.substring(0,41));
			long thenTime = System.currentTimeMillis();
			
			// Time period includes 1 call to reportDataToSensor()
			oSysLog.log(Level.FINE, MODULE, sMethod, "TotalSpent="+sTotalSpent+" User="+sUserSpent+" local="+(thenTime - nowTime)+" mSec");
			
			SendQueue.getHandle().addEntry(sDataLine);
			
			// Report user time as well (could be DigiD for instance)
			if (lUserSpent > 0) {
			    sDataLine = String.format("%s,%s,%s,%d,%d,%d,%s,%s,%s,%s,%s,%s", sOrig, (sUsi==null)? "": sUsi,
			    		sAppId, 1/*complete flow*/, 5/*user*/, Thread.currentThread().getId(),
			    		sFirstContact, sLast, TimerSensor.timerSensorMilli2Time(lUserSpent), Boolean.toString(bSuccess),
			    		sRid, (sTgt==null)? "": sTgt.substring(0,41));
				SendQueue.getHandle().addEntry(sDataLine);
			}
		}
		catch (Exception e) {
			oSysLog.log(Level.INFO, MODULE, sMethod, "Sensor report failed: "+e.getClass()+": "+e.getMessage());
		}
	}

	/**
	 * Report usage to sensor.
	 * 
	 * @param oConfMgr
	 *            the configuration manager
	 * @param sMainTag
	 *            the main tag
	 * @param sSection
	 *            the section
	 * @param sUrlTag
	 *            the url tag
	 * @param oSysLog
	 *            the sys log
	 * @param sData
	 *            the data to be sent
	 * @throws ASelectException
	 *             the aselect exception
	 */
	public static void reportDataToSensor(ConfigManager oConfMgr, String sMainTag, String sSection, String sUrlTag,
						SystemLogger oSysLog, String sData)
	throws ASelectException
	{
		String sMethod = "reportDataToSensor";
		HashMap htResponse = null;
		String sResponse = null;

		oSysLog.log(Level.INFO, MODULE, sMethod, "<lbsensor>="+(oConfMgr.isLbSensorConfigured())+
				" <timer_sensor>="+oConfMgr.isTimerSensorConfigured());
		if (!oConfMgr.isLbSensorConfigured() && !oConfMgr.isTimerSensorConfigured())
			return;

		// 20120529: these were class variables
		IClientCommunicator oClientCommunicator = null;
		String sSensorUrl = null;

		// 2 communicators will be needed, so we can't cache a single one
		oSysLog.log(Level.FINE, MODULE, sMethod, "Looking for: "+sMainTag+"/"+sSection+"/"+sUrlTag);
		Object oConfig = Utils.getSimpleSection(oConfMgr, oSysLog, null, sMainTag, true);
		Object oSensorSection = Utils.getSimpleSection(oConfMgr, oSysLog, oConfig, sSection, false);
		if (oSensorSection == null) {
			oSysLog.log(Level.WARNING, MODULE, sMethod, "Section "+sMainTag+"/"+sSection+" not found, no sensor reporting");
			return;
		}
		sSensorUrl = Utils.getSimpleParam(oConfMgr, oSysLog, oSensorSection, sUrlTag, true);
		if (!Utils.hasValue(sSensorUrl)) {
			oSysLog.log(Level.WARNING, MODULE, sMethod, "Url tag "+sUrlTag+" not found, no sensor reporting");
			return;
		}
		oClientCommunicator = Tools.initClientCommunicator(oConfMgr, oSysLog, oSensorSection);

		HashMap<String, String> htRequest = new HashMap<String, String>();
		htRequest.put("request", "store");
		htRequest.put("data", sData);
		oSysLog.log(Level.FINE, MODULE, sMethod, "Send to Sensor ["+sData+"]");
		try {
			if ("timer_sensor".equals(sSection)) {  // POST
				sResponse = oClientCommunicator.sendStringMessage(sData, sSensorUrl);
				oSysLog.log(Level.FINE, MODULE, sMethod, "POST Result=" + sResponse);
			}
			else {  // GET
				htResponse = oClientCommunicator.sendMessage(htRequest, sSensorUrl);
				oSysLog.log(Level.FINE, MODULE, sMethod, "GET Result=" + htResponse);
			}
		}
		catch (Exception e) {
			oSysLog.log(Level.WARNING, MODULE, sMethod, "Could not contact LB Sensor at: " + sSensorUrl);
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}
	}

	/**
	 * Convert an URL parameter string to a HashMap containing key, value pairs.
	 * See also: HashMap convertCGIMessage(String xMessage) in Utils.
	 * 
	 * @param sTheUrl
	 *            the url to convert
	 * @param oSystemLogger
	 *            the system logger
	 * @return the url attributes
	 */
	public static HashMap<String, String>getUrlAttributes(String sTheUrl, SystemLogger oSystemLogger)
	{
		String sMethod = "getAttributes";
		String sKey = "";
		String sValue = "";
		HashMap<String, String> htAttributes = new HashMap<String, String>();

		// Split the 'sText' string
		String[] saAttrs = sTheUrl.split("&");
		for (int i = 0; i < saAttrs.length; i++) {
			int iEqualSign = saAttrs[i].indexOf("=");

			try {
				if (iEqualSign > 0) {
					sKey = URLDecoder.decode(saAttrs[i].substring(0, iEqualSign), "UTF-8");
					sValue = URLDecoder.decode(saAttrs[i].substring(iEqualSign + 1), "UTF-8");
				}
				else {
					sKey = URLDecoder.decode(saAttrs[i], "UTF-8");
					sValue = "";
				}
				htAttributes.put(sKey, sValue);
			}
			catch (UnsupportedEncodingException e) {
				// just skip this attribute
				oSystemLogger.log(Level.WARNING, MODULE, sMethod, "[" + sTheUrl + "]", e);
			}
		}
		return htAttributes;
	}
	

	/**
	 * Gets the server ip address.
	 * 
	 * @return the dotted ip address
	 */
	public static String getServerIpAddress(SystemLogger oSystemLogger)
	{
		String sMethod = "getServerIpAddress";
	    String s = "";
		try {
		    InetAddress addr = InetAddress.getLocalHost();
		    byte[] ipAddr = addr.getAddress();  // Get IP Address

		    for (int i=0; i<ipAddr.length; i++) {
		    	int ip = ipAddr[i];
		    	s += ((i==0)?"": ".")+String.valueOf(ip<0? ip+256: ip);
		    }
		    String hostname = addr.getHostName();  // Get hostname
		    oSystemLogger.log(Level.INFO, MODULE, sMethod, "Hostname="+hostname+" Ip="+s);
		}
		catch (UnknownHostException e) {
		}
		return s;
	}
}
