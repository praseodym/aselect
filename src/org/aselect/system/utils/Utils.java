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
 * $Id: Utils.java,v 1.10 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: Utils.java,v $
 * Revision 1.10  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.9  2006/04/12 13:20:41  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.8.4.2  2006/04/04 11:05:54  erwin
 * Removed warnings.
 *
 * Revision 1.8.4.1  2006/03/21 07:32:49  leon
 * hashtable2CGIMessage added
 *
 * Revision 1.8  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/08/30 14:20:05  erwin
 * Fixed bug in wildcard match
 *
 * Revision 1.6  2005/05/20 13:10:38  erwin
 * Fixed some minor bugs in Javadoc
 *
 * Revision 1.5  2005/04/07 08:32:52  remco
 * base64 decoder couldn't handle empty strings
 *
 * Revision 1.4  2005/03/24 13:24:22  erwin
 * Removed toLowerCase() for parameters.
 *
 * Revision 1.3  2005/03/16 13:29:19  remco
 * added wildcard matching method
 *
 * Revision 1.2  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.1  2005/02/22 12:03:29  martijn
 * moved org.aselect.utils to org.aselect.system.utils
 *
 * Revision 1.2  2005/01/28 10:09:44  ali
 * Javadoc toegevoegd en kleine code cleanup acties.
 *
 */

package org.aselect.system.utils;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;

/**
 * Static class that implements generic, widely used utility methods. <br>
 * <br>
 * <b>Description: </b> <br>
 * The Utils class implements convenient static methods used widely by A-Select components. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * None. <br>
 * 
 * @author Alfa & Ariss
 */
public class Utils
{
	/**
	 * Static char array for quickly converting bytes to hex-strings.
	 */
	private static final char[] _hexChars = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
	};

	/** "[]" barces UTF-8 encoded. */
	private static final String ENCODED_BRACES = "%5B%5D";

	private static final String MODULE = "Utils";

	/**
	 * Returns an int from 0 to 15 corresponding to the specified hex digit. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * For input 'A' this method returns 10 etc. Input is <u>case-insensitive </u>. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * Only hexadecimal characters [0..f] or [0..F] are processed. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param ch
	 *            Input hexadecimal character.
	 * @return int representing ch.
	 * @throws IllegalArgumentException
	 *             on non-hexadecimal characters.
	 */
	public static int fromDigit(char ch)
	{
		if (ch >= '0' && ch <= '9')
			return ch - '0';
		if (ch >= 'A' && ch <= 'F')
			return ch - 'A' + 10;
		if (ch >= 'a' && ch <= 'f')
			return ch - 'a' + 10;

		throw new IllegalArgumentException("invalid hex digit '" + ch + "'");
	}

	/**
	 * Outputs a hex-string respresentation of a byte array. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method returns the hexadecimal String representation of a byte array. <br>
	 * <br>
	 * Example: <br>
	 * For input <code>[0x13, 0x2f, 0x98, 0x76]</code>, this method returns a String object containing
	 * <code>"132F9876"</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param xBytes
	 *            Source byte array.
	 * @return a String object respresenting <code>xBytes</code> in hexadecimal format.
	 */
	public static String byteArrayToHexString(byte[] xBytes)
	{
		int xLength = xBytes.length;
		char[] xBuffer = new char[xLength * 2];

		for (int i = 0, j = 0, k; i < xLength;) {
			k = xBytes[i++];
			xBuffer[j++] = _hexChars[(k >>> 4) & 0x0F];
			xBuffer[j++] = _hexChars[k & 0x0F];
		}
		return new String(xBuffer);
	}

	/**
	 * Returns a byte array corresponding to a hexadecimal String. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Example: <br>
	 * For input <code>"132F9876"</code>, this method returns an array containing <code>[0x13, 0x2f, 0x98, 0x76]</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <code>xHexString</code> must be a hexadecimal String. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param xHexString
	 *            String containing a hexadecimal string.
	 * @return a byte array containing the converted hexadecimal values.
	 * @throws IllegalArgumentException
	 *             on non-hexadecimal characters.
	 */
	public static byte[] hexStringToByteArray(String xHexString)
	{
		int len = xHexString.length();

		byte[] buf = new byte[((len + 1) / 2)];

		int i = 0, j = 0;
		if ((len % 2) == 1)
			buf[j++] = (byte) fromDigit(xHexString.charAt(i++));

		while (i < len) {
			buf[j++] = (byte) ((fromDigit(xHexString.charAt(i++)) << 4) | fromDigit(xHexString.charAt(i++)));
		}
		return buf;
	}

	/**
	 * Prefixes a String with another String until a specified length is reached. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Example: <br>
	 * <br>
	 * <code>
	 * String xVar = "873";<br>
	 * xVar = prefixString("0", xVar, 5);<br>
	 * System.out.println(xVar);<br><br>
	 * </code> This will print <br>
	 * <br>
	 * <code>
	 * 00873
	 * </code><br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>xPrefix</code> may not be null. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param xPrefix
	 *            character to prefix xString with.
	 * @param xString
	 *            input String.
	 * @param xEndlength
	 *            length of desired output String.
	 * @return String containing the output String.
	 */
	public static String prefixString(String xPrefix, String xString, int xEndlength)
	{
		String xResult;

		xResult = xString;
		while (xResult.length() < xEndlength) {
			xResult = xPrefix + xResult;
		}
		return xResult;
	}

	/**
	 * Replaces all occurences of a string in a source string. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Trivial. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param xSrc
	 *            The source string.
	 * @param xString
	 *            The string that is to be replaced.
	 * @param xReplaceString
	 *            The string that replaces xString.
	 * @return A String containing all occurences of xString replaced by xReplaceString.
	 */
	public static String replaceString(String xSrc, String xString, String xReplaceString)
	{
		StringBuffer xBuffer = new StringBuffer(xSrc);
		int xStart, xEnd;

		if (xReplaceString == null)
			return xSrc;
		while (xBuffer.indexOf(xString) != -1) {
			xStart = xBuffer.indexOf(xString);
			xEnd = xStart + xString.length();
			xBuffer = xBuffer.delete(xStart, xEnd);
			xBuffer = xBuffer.insert(xStart, xReplaceString);
		}
		return xBuffer.toString();
	}

	/**
	 * Converts a CGI-based String to a hashtable. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This methods converts a CGI-based String containing <code>key=value&key=value</code> to a hashtable containing
	 * the keys and corresponding values. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * CGI-based input String (<code>xMessage</code>).<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All keys in the returned hashtable are converted to lowercase. <br>
	 * 
	 * @param xMessage
	 *            CGI-based input String.
	 * @return HashMap containg the keys and corresponding values.
	 */
	public static HashMap convertCGIMessage(String xMessage)
	{
		String xToken, xKey, xValue;
		StringTokenizer xST = null;
		int iPos;
		HashMap<String, String> xResponse = new HashMap<String, String>();

		if (xMessage != null) {
			xST = new StringTokenizer(xMessage, "&");

			while (xST.hasMoreElements()) {
				xToken = (String) xST.nextElement();
				if (!xToken.trim().equals("")) {
					iPos = xToken.indexOf('=');
					if (iPos != -1) {
						xKey = xToken.substring(0, iPos);

						try {
							xValue = xToken.substring(iPos + 1);
						}
						catch (Exception e) {
							xValue = "";
						}

						if (xKey != null && xValue != null) {
							xResponse.put(xKey, xValue);
						}
					}
				}
			}
		}
		return xResponse;
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
	public static String hashtable2CGIMessage(HashMap htInput)
		throws UnsupportedEncodingException
	{
		StringBuffer sbBuffer = new StringBuffer();
		Set keys = htInput.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
			// Enumeration enumKeys = htInput.keys();
			// boolean bStop = !enumKeys.hasMoreElements(); //more elements?
			// while (!bStop)
			// {
			// String sKey = (String)enumKeys.nextElement();
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
			// if (enumKeys.hasMoreElements()) {
			// Append extra '&' after every parameter.
			sbBuffer.append("&");
			// }
		}
		int len = sbBuffer.length();
		return sbBuffer.substring(0, (len > 0) ? len - 1 : len);
	}

	/**
	 * Compare a string against another string that may contain wildcards. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Compares string <code>s</code> against <code>sMask</code>, where <code>sMask</code> may contain wildcards (* and
	 * ?). <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * 
	 * @param s
	 *            The string to compare against <code>sMask</code>.
	 * @param sMask
	 *            The mask to compare against. May contain wildcards.
	 * @return <code>true</code> if they match, <code>false</code> otherwise
	 */
	public static boolean matchWildcardMask(String s, String sMask)
	{
		// check empty string
		if (s.length() == 0) {
			if (sMask.length() == 0 || sMask.equals("*") || sMask.equals("?"))
				return true;
			return false;
		}

		char ch;
		int i = 0;
		StringCharacterIterator iter = new StringCharacterIterator(sMask);

		for (ch = iter.first(); ch != CharacterIterator.DONE && i < s.length(); ch = iter.next()) {
			if (ch == '?')
				i++;
			else if (ch == '*') {
				int j = iter.getIndex() + 1;
				if (j >= sMask.length())
					return true;
				String xSubFilter = sMask.substring(j);
				while (i < s.length()) {
					if (matchWildcardMask(s.substring(i), xSubFilter))
						return true;
					i++;
				}
				return false;
			}
			else if (ch == s.charAt(i)) {
				i++;
			}
			else
				return false;
		}

		return (i == s.length());
	}

	// Bauke: added
	/**
	 * First part of.
	 * 
	 * @param sValue
	 *            the s value
	 * @param max
	 *            the max
	 * @return the string
	 */
	public static String firstPartOf(String sValue, int max)
	{
		if (sValue == null)
			return "null";
		int len = sValue.length();
		return (len <= max) ? sValue : sValue.substring(0, max) + "...";
	}

	/**
	 * Copy hashmap value.
	 * 
	 * @param sName
	 *            the s name
	 * @param hmTo
	 *            the hm to
	 * @param hmFrom
	 *            the hm from
	 * @return the object
	 */
	public static Object copyHashmapValue(String sName, HashMap<String, Object> hmTo, HashMap<String, Object> hmFrom)
	{
		if (hmFrom == null || hmTo == null)
			return null;
		Object oValue = hmFrom.get(sName);
		if (oValue != null)
			hmTo.put(sName, oValue);
		return oValue;
	}

	/**
	 * Copy msg value to hashmap.
	 * 
	 * @param sName
	 *            the s name
	 * @param hmTo
	 *            the hm to
	 * @param imFrom
	 *            the im from
	 * @return the string
	 */
	public static String copyMsgValueToHashmap(String sName, HashMap<String, String> hmTo, IInputMessage imFrom)
	{
		String sValue = null;
		if (imFrom == null || hmTo == null)
			return null;
		try {
			sValue = imFrom.getParam(sName);
			if (sValue != null)
				hmTo.put(sName, sValue);
		}
		catch (Exception e) {
		}
		return sValue;
	}

	// Get 'sParam' within the 'oConfig' section
	// This can be the value of an attribute or the contents of a 'sParam' tag
	// Examples:
	// Get attribute value: (oApplication, "id", true)
	// Get tag value (need not be present): (oApplication, "friendly_name", false)
	//
	/**
	 * Gets the simple param.
	 * 
	 * @param oConfMgr
	 *            the o conf mgr
	 * @param oSysLog
	 *            the o sys log
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the simple param
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static String getSimpleParam(ConfigManager oConfMgr, SystemLogger oSysLog, Object oConfig, String sParam,
			boolean bMandatory)
		throws ASelectException
	{
		final String sMethod = "getSimpleParam";
		try {
			return oConfMgr.getParam(oConfig, sParam); // is not null
		}
		catch (ASelectConfigException e) {
			if (!bMandatory)
				return null;
			oSysLog.log(Level.WARNING, MODULE, sMethod, "Config item '" + sParam + "' not found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Gets the simple int param.
	 * 
	 * @param oConfMgr
	 *            the o conf mgr
	 * @param oSysLog
	 *            the o sys log
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the simple int param
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static int getSimpleIntParam(ConfigManager oConfMgr, SystemLogger oSysLog, Object oConfig, String sParam,
			boolean bMandatory)
		throws ASelectException
	{
		final String sMethod = "getSimpleIntParam";
		String sValue = getSimpleParam(oConfMgr, oSysLog, oConfig, sParam, bMandatory);

		try {
			if (sValue != null)
				return Integer.parseInt(sValue);
			if (!bMandatory)
				return -1;
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}
		catch (NumberFormatException e) {
			if (!bMandatory)
				return -1;
			oSysLog.log(Level.WARNING, MODULE, sMethod, "Value of <" + sParam + "> is not an integer");
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	// Find the 'sParam' section within the 'oConfig' section
	// 'oConfig' can be null to get one of the top level sections
	// Example: (null, "aselect");
	/**
	 * Gets the simple section.
	 * 
	 * @param oConfMgr
	 *            the o conf mgr
	 * @param oSysLog
	 *            the o sys log
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the simple section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public static Object getSimpleSection(ConfigManager oConfMgr, SystemLogger oSysLog, Object oConfig, String sParam,
			boolean bMandatory)
		throws ASelectConfigException
	{
		final String sMethod = "getSimpleSection";
		Object oSection = null;

		oSysLog.log(Level.INFO, MODULE, sMethod, "Param=" + sParam + " cfg=" + oConfMgr);
		try {
			oSection = oConfMgr.getSection(oConfig, sParam);
		}
		catch (ASelectConfigException e) {
			if (!bMandatory)
				return null;
			oSysLog.log(Level.SEVERE, MODULE, sMethod, "Cannot find " + sParam + " section in config file", e);
			throw e;
		}
		return oSection;
	}

	// Get 'sParam' within a node of the 'oConfig' section.
	// The name of the node must match the 'sSection' given.
	// If oConfig is null the global section is used.
	// Examples:
	// Get attribute value: (oConfig, "application", "id")
	// Get tag value: (null, "aselect", "redirect_url")
	//
	/**
	 * Gets the param from section.
	 * 
	 * @param oConfMgr
	 *            the o conf mgr
	 * @param oSysLog
	 *            the o sys log
	 * @param oConfig
	 *            the o config
	 * @param sSection
	 *            the s section
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the param from section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public static String getParamFromSection(ConfigManager oConfMgr, SystemLogger oSysLog, Object oConfig,
			String sSection, String sParam, boolean bMandatory)
		throws ASelectConfigException
	{
		final String sMethod = "getParamFromSection";
		try {
			Object oSection = oConfMgr.getSection(oConfig, sSection);
			return oConfMgr.getParam(oSection, sParam);
		}
		catch (ASelectConfigException e) {
			if (!bMandatory)
				return null;
			oSysLog.log(Level.WARNING, MODULE, sMethod, "Could not retrieve '" + sParam + "' parameter in '" + sSection
					+ "' section", e);
			throw e;
		}
	}

	// Find section with given attribute name and value.
	// If oConfig is null the global section is used.
	// Example: (oConfig, "logging", "id=system")
	/**
	 * Gets the section from section.
	 * 
	 * @param oConfMgr
	 *            the o conf mgr
	 * @param oSysLog
	 *            the o sys log
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param sValue
	 *            the s value
	 * @param bMandatory
	 *            the b mandatory
	 * @return the section from section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public static Object getSectionFromSection(ConfigManager oConfMgr, SystemLogger oSysLog, Object oConfig,
			String sParam, String sValue, boolean bMandatory)
		throws ASelectConfigException
	{
		final String sMethod = "getSectionFromSection";
		Object oLogSection = null;

		try {
			oLogSection = oConfMgr.getSection(oConfig, sParam, sValue);
		}
		catch (Exception e) {
			if (!bMandatory)
				return null;
			oSysLog.log(Level.SEVERE, MODULE, sMethod, "No valid " + sParam + " section with " + sValue + " found", e);
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		return oLogSection;
	}

	// Localization
	// If no language/country is present in 'htSessionContext',
	// store the given values in it.
	/**
	 * Transfer localization.
	 * 
	 * @param htSessionContext
	 *            the ht session context
	 * @param sUserLanguage
	 *            the s user language
	 * @param sUserCountry
	 *            the s user country
	 */
	public static void transferLocalization(HashMap<String, Object> htSessionContext, String sUserLanguage,
			String sUserCountry)
	{
		if (htSessionContext == null)
			return;
		String sloc = (String) htSessionContext.get("language");
		if ((sloc == null || sloc.equals("")) && sUserLanguage != null && !sUserLanguage.equals(""))
			htSessionContext.put("language", sUserLanguage);
		sloc = (String) htSessionContext.get("country");
		if ((sloc == null || sloc.equals("")) && sUserCountry != null && !sUserCountry.equals(""))
			htSessionContext.put("country", sUserCountry);
	}

	/*
	 * Methode decode the credentials passed.
	 */
	/**
	 * Decode credentials.
	 * 
	 * @param credentials
	 *            the credentials
	 * @param oSysLog
	 *            the o sys log
	 * @return the string
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static String decodeCredentials(String credentials, SystemLogger oSysLog)
		throws ASelectException
	{
		String _sMethod = "decodeCredentials";
		String decodedCredentials = null;
		try {
			oSysLog.log(Level.INFO, MODULE, _sMethod, "Credentials are " + credentials);
			byte[] TgtBlobBytes = CryptoEngine.getHandle().decryptTGT(credentials);
			decodedCredentials = Utils.byteArrayToHexString(TgtBlobBytes);
		}
		catch (ASelectException as) {
			oSysLog.log(Level.WARNING, MODULE, _sMethod, "failed to decrypt credentials", as);
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}
		return decodedCredentials;
	}

	/**
	 * Serialize attributes contained in a HashMap. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method serializes attributes contained in a HashMap:
	 * <ul>
	 * <li>They are formatted as attr1=value1&attr2=value2;...
	 * <li>If a "&amp;" or a "=" appears in either the attribute name or value, they are transformed to %26 or %3d
	 * respectively.
	 * <li>The end result is base64 encoded.
	 * </ul>
	 * <br>
	 * 
	 * @param htAttributes - HashMap containing all attributes
	 * @return Serialized representation of the attributes
	 * @throws ASelectException - If serialization fails.
	 */
	public static String serializeAttributes(HashMap htAttributes)
		throws ASelectException
	{
		final String sMethod = "serializeAttributes";
		try {
			if (htAttributes == null || htAttributes.isEmpty())
				return null;
			StringBuffer sb = new StringBuffer();

			Set keys = htAttributes.keySet();
			for (Object s : keys) {
				String sKey = (String) s;
				// for (Enumeration e = htAttributes.keys(); e.hasMoreElements(); ) {
				// String sKey = (String)e.nextElement();
				Object oValue = htAttributes.get(sKey);

				if (oValue instanceof Vector) {// it's a multivalue attribute
					Vector vValue = (Vector) oValue;

					sKey = URLEncoder.encode(sKey + "[]", "UTF-8");
					Enumeration eEnum = vValue.elements();
					while (eEnum.hasMoreElements()) {
						String sValue = (String) eEnum.nextElement();

						// add: key[]=value
						sb.append(sKey).append("=").append(URLEncoder.encode(sValue, "UTF-8"));
						if (eEnum.hasMoreElements())
							sb.append("&");
					}
				}
				else if (oValue instanceof String) {// it's a single value attribute
					String sValue = (String) oValue;
					sb.append(URLEncoder.encode(sKey, "UTF-8")).append("=").append(URLEncoder.encode(sValue, "UTF-8"));
				}

				// if (e.hasMoreElements())
				sb.append("&");
			}
			int len = sb.length();
			String result = sb.substring(0, len - 1);
			BASE64Encoder b64enc = new BASE64Encoder();
			return b64enc.encode(result.getBytes("UTF-8"));
		}
		catch (Exception e) {
			ASelectSystemLogger logger = ASelectSystemLogger.getHandle();
			logger.log(Level.WARNING, MODULE, sMethod, "Could not serialize attributes", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Deserialize attributes and convertion to a <code>HashMap</code>. <br/>
	 * Conatins support for multivalue attributes, with name of type <code>
	 * String</code> and value of type <code>Vector</code>.
	 * 
	 * @param sSerializedAttributes
	 *            the serialized attributes.
	 * @return The deserialized attributes (key,value in <code>HashMap</code>)
	 * @throws ASelectException
	 *             If URLDecode fails
	 */
	public static HashMap deserializeAttributes(String sSerializedAttributes)
		throws ASelectException
	{
		String sMethod = "deSerializeAttributes";
		HashMap htAttributes = new HashMap();
		if (sSerializedAttributes != null) {  // Attributes available
			try {  // base64 decode
				BASE64Decoder base64Decoder = new BASE64Decoder();
				String sDecodedUserAttrs = new String(base64Decoder.decodeBuffer(sSerializedAttributes));
	
				// decode & and = chars
				String[] saAttrs = sDecodedUserAttrs.split("&");
				for (int i = 0; i < saAttrs.length; i++) {
					int iEqualChar = saAttrs[i].indexOf("=");
					String sKey = "";
					String sValue = "";
					Vector vVector = null;
	
					if (iEqualChar > 0) {
						sKey = URLDecoder.decode(saAttrs[i].substring(0, iEqualChar), "UTF-8");
						sValue = URLDecoder.decode(saAttrs[i].substring(iEqualChar + 1), "UTF-8");
	
						if (sKey.endsWith("[]")) { // it's a multi-valued attribute
							// Strip [] from sKey
							sKey = sKey.substring(0, sKey.length() - 2);
							if ((vVector = (Vector) htAttributes.get(sKey)) == null)
								vVector = new Vector();
							vVector.add(sValue);
						}
					}
					else
						sKey = URLDecoder.decode(saAttrs[i], "UTF-8");
	
					if (vVector != null)  // store multivalue attribute
						htAttributes.put(sKey, vVector);
					else  // store singlevalue attribute
						htAttributes.put(sKey, sValue);
				}
			}
			catch (Exception e) {
				ASelectSystemLogger logger = ASelectSystemLogger.getHandle();
				logger.log(Level.WARNING, MODULE, sMethod, "Error during deserialization of attributes", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
		}
		return htAttributes;
	}

	// No organization gathering specified: no org_id in TGT
	// Organization gathering specified but no organization found or choice not made yet: org_id="" in TGT
	// Choice made by the user: org_id has a value
	// As long as org_id is present and empty no gathering will take place at all
	//
	public static boolean handleOrganizationChoice(HashMap<String, Object> htTGTContext, HashMap<String, String> hUserOrganizations)
	{
		String sOrgId = "";
		if (hUserOrganizations == null || hUserOrganizations.size() == 0)
			return false;  // no organizations, no choice
	
		if (hUserOrganizations.size() == 1) {
			Set<String> keySet = hUserOrganizations.keySet();
			Iterator<String> it = keySet.iterator();
			sOrgId = it.next();  // no choice needed
		}
		htTGTContext.put("org_id", sOrgId);  // empty or filled with the chosen org
		return (sOrgId != null && sOrgId.equals(""));
	}

	//
	//
	public static String presentOrganizationChoice(ASelectConfigManager configManager, HashMap htSessionContext,
			String sRid, String sLanguage, HashMap<String, String> hUserOrganizations)
	throws ASelectConfigException, ASelectException, IOException
	{
		String sUserId = (String)htSessionContext.get("user_id");
		String sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);
		String sServerId = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);
		String sSelectForm = configManager.loadHTMLTemplate(null, "orgselect", sLanguage, sLanguage);
		
		sSelectForm = Utils.replaceString(sSelectForm, "[request]", "org_choice");
		if (sUserId != null) sSelectForm = Utils.replaceString(sSelectForm, "[user_id]", sUserId);
		sSelectForm = Utils.replaceString(sSelectForm, "[rid]", sRid);
		sSelectForm = Utils.replaceString(sSelectForm, "[a-select-server]", sServerId);
		sSelectForm = Utils.replaceString(sSelectForm, "[aselect_url]", sServerUrl + "/org_choice");
		
		StringBuffer sb = new StringBuffer();
		Set<String> keySet = hUserOrganizations.keySet();
		Iterator<String> it = keySet.iterator();
		while(it.hasNext()) {
			String sOrgId = it.next();
			String sOrgName = hUserOrganizations.get(sOrgId);
			sb.append("<option value=").append(sOrgId).append(">").append(sOrgName);
			sb.append("</option>");
		}
		sSelectForm = Utils.replaceString(sSelectForm, "[user_organizations]", sb.toString());
		sSelectForm = configManager.updateTemplate(sSelectForm, htSessionContext);
		return sSelectForm;
	}

}