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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.StringCharacterIterator;
import java.util.HashMap;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

/**
 * Static class that implements generic, widely used utility methods. <br>
 * <br>
 * <b>Description: </b> <br>
 * The Utils class implements convenient static methods used widely by A-Select
 * components. <br>
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
	 * Returns an int from 0 to 15 corresponding to the specified hex digit.
	 * <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * For input 'A' this method returns 10 etc. Input is <u>case-insensitive
	 * </u>. <br>
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
	 * This method returns the hexadecimal String representation of a byte
	 * array. <br>
	 * <br>
	 * Example: <br>
	 * For input <code>[0x13, 0x2f, 0x98, 0x76]</code>, this method returns a
	 * String object containing <code>"132F9876"</code>.<br>
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
	 * @return a String object respresenting <code>xBytes</code> in
	 *         hexadecimal format.
	 */
	public static String toHexString(byte[] xBytes)
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
	 * For input <code>"132F9876"</code>, this method returns an array
	 * containing <code>[0x13, 0x2f, 0x98, 0x76]</code>.<br>
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
	public static byte[] stringToHex(String xHexString)
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
	 * Prefixes a String with another String until a specified length is
	 * reached. <br>
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
	 * @return A String containing all occurences of xString replaced by
	 *         xReplaceString.
	 */
	public static String replaceString(String xSrc, String xString, String xReplaceString)
	{
		StringBuffer xBuffer = new StringBuffer(xSrc);
		int xStart, xEnd;

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
	 * This methods converts a CGI-based String containing
	 * <code>key=value&key=value</code> to a hashtable containing the keys and
	 * corresponding values. <br>
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
		HashMap xResponse = new HashMap();

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
	 * Creates a CGI syntax message from the key/value pairs in the input
	 * <code>HashMap</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The used {@link java.util.HashMap}objects are synchronized. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>htInput</code> should be a HashMap containing valid parameters.
	 * <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The return <code>String</code> contains the parameters in CGI syntax.
	 * <br>
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
			//if (enumKeys.hasMoreElements()) {
			// Append extra '&' after every parameter.
			sbBuffer.append("&");
			//}
		}
		int len = sbBuffer.length();
		return sbBuffer.substring(0, (len>0)? len-1: len);
	}

	/**
	 * Compare a string against another string that may contain wildcards. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Compares string <code>s</code> against <code>sMask</code>, where
	 * <code>sMask</code> may contain wildcards (* and ?). <br>
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

		for (ch = iter.first(); ch != StringCharacterIterator.DONE && i < s.length(); ch = iter.next()) {
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
	public static String firstPartOf(String sValue, int max)
	{
		if (sValue == null)
			return "null";
		int len = sValue.length();
		return (len <= max) ? sValue : sValue.substring(0, max) + "...";
	}
	
	public static String getSimpleParam(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectException
	{
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		try {
			return _configManager.getParam(oConfig, sParam);  // is not null
		}
		catch (ASelectConfigException e) {
			if (!bMandatory)
				return null;
			_systemLogger.log(Level.WARNING, MODULE, "getSimpleParam", "Config item '"+sParam+"' not found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	public static String getParamFromSection(Object oConfig, String sSection, String sParam, boolean bMandatory)
	throws ASelectConfigException
	{
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		try {
			Object oSection = _configManager.getSection(oConfig, sSection);
			return _configManager.getParam(oSection, sParam);
		}
		catch (ASelectConfigException e) {
			if (!bMandatory)
				return null;
			_systemLogger.log(Level.WARNING, MODULE, "getParamFromSection",
					"Could not retrieve '"+sParam+"' parameter in '"+sSection+"' section", e);
			throw e;
		}
	}

	public static String getParamFromSection(Object oConfig, String sSection, String sParam)
	throws ASelectConfigException
	{
		return getParamFromSection(oConfig, sSection, sParam, true);
	}
}