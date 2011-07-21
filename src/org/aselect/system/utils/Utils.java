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
import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;

//import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.ISystemLogger;
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
	 * Replaces all occurrences of a string in a source string. <br>
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
	 * @return A String containing all occurrences of xString replaced by xReplaceString.
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
	 * Gets the aselect_specials value from RelayState of app_url.
	 * 
	 * @param htSessionContext
	 *            the session context
	 * @return the specials found or null
	 */
	public static String getAselectSpecials(HashMap htSessionContext, boolean decode, ISystemLogger logger)
	{
		String sMethod = "getAselectSpecials";
		String sSpecials = null;
		
		String sRelay = (String)htSessionContext.get("RelayState");
		if (Utils.hasValue(sRelay) && !sRelay.startsWith("idp=")) {  // try RelayState passed from SP
			sRelay = new String(Base64Codec.decode(sRelay));
			sSpecials = Utils.getParameterValueFromUrl(sRelay, "aselect_specials");
			logger.log(Level.INFO, MODULE, sMethod, "sRelay="+sRelay+" sSpecials="+sSpecials);
		}
		if (sSpecials == null) {  // try application url
			String sAppUrl = (String)htSessionContext.get("app_url");
			sSpecials = Utils.getParameterValueFromUrl(sAppUrl, "aselect_specials");					
			logger.log(Level.INFO, MODULE, sMethod, "sAppUrl="+sAppUrl+" sSpecials="+sSpecials);
		}
		if (decode && Utils.hasValue(sSpecials)) {
			sSpecials = new String(Base64Codec.decode(sSpecials));
			logger.log(Level.INFO, MODULE, sMethod, "sSpecials="+sSpecials);
		}
		return sSpecials;
	}

	/**
	 * Handle all conditional keywords in a HTML form.
	 * 
	 * @param sText
	 *            the HTML text to examine
	 * @param bErrCond
	 *            is if_err true?
	 * @param sSpecials
	 *             the specials to look for
	 * @param logger
	 *            any logger
	 * @return the modified HTML text
	 */
	public static String handleAllConditionals(String sText, boolean bErrCond, String sSpecials, ISystemLogger logger)
	{
		final String sMethod = "handleAllConditionals";

		logger.log(Level.INFO, MODULE, sMethod, "error="+bErrCond+" specials="+sSpecials);
		sText = Utils.replaceConditional(sText, "if_error", bErrCond, logger);
		
		if (sSpecials != null) {
			String sParCond = getParameterValueFromUrl(sSpecials, "if_cond");
			logger.log(Level.INFO, MODULE, sMethod, "parCond="+sParCond);
			if (sParCond != null)
				sText = Utils.replaceConditional(sText, "if_cond,"+sParCond, true, logger);
		}
		
		// Other conditions are false
		sText = Utils.removeAllConditionals(sText, "if_cond", logger);
		return sText;
	}

	/**
	 * Retrieve parameter value from the given URL.
	 * 
	 * @param sUrl
	 *            the URL (null allowed)
	 * @param sParamName
	 *            the parameter name
	 * @return the parameter value or null if not found
	 */
	// Exampl: sAppUrl=https://appl.anoigo.nl/?aselect_specials=aWZfY29uZD1vcmdfbG9naW4mc2V0X2ZvcmNlZF91aWQ=
	public static String getParameterValueFromUrl(String sUrl, String sParamName)
	{
		if (sUrl == null)
			return null;

		String sParCond = null;
		int iArgs = sUrl.indexOf('?');
		if (iArgs >= 0)
			sUrl = sUrl.substring(iArgs+1);
		
		// sUrl now starts with the arguments
		int iCond = sUrl.indexOf(sParamName+"=");
		if (iCond >= 0 && (iCond == 0 || sUrl.charAt(iCond-1)=='&')) {
			iCond += sParamName.length()+1;
			int iAmp = sUrl.indexOf('&', iCond);
			sParCond = (iAmp<0)? sUrl.substring(iCond): sUrl.substring(iCond, iAmp);
		}
		return sParCond;
	}
	
	/**
	 * Replace all unused conditions. Syntax:
	 * [&lt;condition_keyword&gt;,&lt;condition_name&gt;,&lt;true_branch&gt;,&lt;false_branch&gt;]
	 * Currently no escape mechanism for the comma and right bracket.
	 * 
	 * @param sText
	 * 			The source text.
	 * @param sKeyword
	 *            The keyword used to look for the conditional replacement.
	 * @return result with replacements applied
	 */
	public static String removeAllConditionals(String sText, String sKeyword, ISystemLogger logger)
	{
		String sMethod = "removeAllConditionals";
		String sSearch = "[" + sKeyword + ",";
		int idx, len = sSearch.length();
		String sResult = "";
		
		if (sText == null)
			return sText;
		if (logger!=null) logger.log(Level.INFO, MODULE, sMethod, "Search="+sSearch);
		
		while (true) {
			//logger.log(Level.INFO, MODULE, sMethod, "Text="+Utils.firstPartOf(sText, 45));
			idx = sText.indexOf(sSearch);
			if (idx < 0)
				break;
			//logger.log(Level.INFO, MODULE, sMethod, "Cond="+Utils.firstPartOf(sText.substring(idx), 45)+" idx="+idx);
			int iComma = sText.indexOf(',', idx + len);
			int iNextComma = (iComma < 0) ? -1: sText.indexOf(',', iComma+1);
			int iRight = (iNextComma < 0) ? -1: sText.indexOf(']', iNextComma+1);
			//logger.log(Level.INFO, MODULE, sMethod, "comma="+iComma+" next="+iNextComma+" right="+iRight);
			if (iRight < 0) {
				sResult += sText.substring(0, idx + len);
				sText = sText.substring(idx + len);
				continue;
			}
			if (iNextComma < 0 || iComma < 0) {
				sResult += sText.substring(0, iRight+1);
				sText = sText.substring(iRight+1);
				continue;
			}
			// Commas and right bracket found
			// Use the false part
			sResult += sText.substring(0, idx) + sText.substring(iNextComma+1, iRight);
			sText = sText.substring(iRight+1);
		}
		return sResult + sText;
	}
	
	/**
	 * Replace text based on a condition (no logging).
	 */
	public static String replaceConditional(String sText, String sKeyword, boolean bCondition)
	{
		return replaceConditional(sText, sKeyword, bCondition, null);
	}

	/**
	 * Replace text based on a condition.
	 * Syntax: [&lt;keyword&gt;,&lt;true_branch&gt;,&lt;false_branch&gt;]
	 * Currently no escape mechanism for the comma and right bracket.
	 * 
	 * @param sText
	 * 			The source text.
	 * @param sKeyword
	 *          The keyword used to look for the conditional replacement.
	 * @param bCondition
	 *          Use the true branch of the condition?
	 * @return result with replacements applied
	 */
	public static String replaceConditional(String sText, String sKeyword, boolean bCondition, ISystemLogger logger)
	{
		String sMethod = "replaceConditional";
		String sSearch = "[" + sKeyword + ",";
		int idx, len = sSearch.length();
		String sResult = "";

		if (sText == null)
			return sText;

		// RH, 20100622, use of ASelectLogger causes cyclic dependency server<->system
		if (logger!=null) logger.log(Level.INFO, MODULE, sMethod, "Search="+sSearch);
		while (true) {
			idx = sText.indexOf(sSearch);
			if (idx < 0)
				break;
			//if (logger!=null) logger.log(Level.INFO, MODULE, sMethod, "Text="+Utils.firstPartOf(sText.substring(idx), 15)+" idx="+idx);
			int iComma = sText.indexOf(',', idx + len);
			int iRight = sText.indexOf(']', (iComma >= 0) ? iComma+1 : idx + len);
			//if (logger!=null) logger.log(Level.INFO, MODULE, sMethod, "comma="+iComma+" right="+iRight);
			if (iRight < 0) {
				sResult += sText.substring(0, idx + len);
				sText = sText.substring(idx + len);
				continue;
			}
			if (iComma < 0) {
				sResult += sText.substring(0, iRight+1);
				sText = sText.substring(iRight+1);
				continue;
			}
			// Comma and right bracket found
			if (bCondition) {  // Use the true part
				sResult += sText.substring(0, idx) + sText.substring(idx + len, iComma);
			}
			else {  // Use the false part
				sResult += sText.substring(0, idx) + sText.substring(iComma+1, iRight);
			}
			sText = sText.substring(iRight+1);
		}
		return sResult + sText;
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

	/**
	 * Does the string have a decent value (not null and length > 0).
	 * 
	 * @param sText
	 *        the string
	 * @return true, if successful
	 */
	public static boolean hasValue(String sText)
	{
		return (sText != null && sText.length() > 0);  // can use !isEmpty() in Java 1.6
	}
	
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
	 *            the parameter name
	 * @param hmTo
	 *            the HashMap to copy to
	 * @param imFrom
	 *            the Input message to copy from
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

}