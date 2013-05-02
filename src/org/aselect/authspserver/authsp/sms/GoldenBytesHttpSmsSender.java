/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.authspserver.authsp.sms;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.logging.Level;

import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.utils.Utils;

/**
 * Sends request for sms to the GoldenBytes sms gateway
 * @author Bauke
 *
Request:
		POST https://sms-1.quinsy.net/gb/dir/send.asp
		
		Content-Length: 153
		Content-Type: application/x-www-form-urlencoded
		REQUESTTYPE=0&OADC=test&OADCTYPE=2&MESSAGEID=12345678&NUMBERS=%2B31612345678&BODY=test&BILLINGTEXT=TEST
		
Response:
		Content-Type = "text/plain"
		<errno>=[<category>] <error message>
		
Errors categories:
000 - OK
1xx - Critical errors, User action: do not retry the same request
4xx - Database errors. User action: Please retry the same request again with some time in between.
 		This is an internal error. Example: An error in the database
5xx - The request ended with some errors, please see info between brackets		

Detailed list of error messages:
120 - [REQUESTTYPE] Value out of range
121 - [REQUESTTYPE] Value not allowed
122 - [OADCTYPE] Value out of range
123 - [OADC] Too many characters
124 - [OADC] Number not MISDN
125 - [BODY] Is empty
126 - [TIMETOLIVE] Invalid or out of range
127 - [MESSAGEID] Too many characters
128 - [NUMBERS] No numbers
129 - [NUMBERS] Too many numbers
130 - [NUMBERS] Invalid number
133 - [TARIFF] Invalid or out of range
135 - [BODY] Too many characters
139 - [BODY] Length not equal to 260
140 - [BODY] Invalid characters
141 - [BODY] Invalid values in bitmap header
142 - [BODY] Too many characters
143 - [HEADER] Too many characters
144 - [BODY] Invalid characters
145 - [HEADER] Invalid characters
146 - [PRIORITY] Invalid value
147 - [OADC] Invalid OADC
148 - [BODY] Invalid format
150 - [REPLYID] Too many characters
161 - [GEN] Your subscription date has been expired
162 - [GEN] You reached the maximum number of messages in your subscription
165 - [GEN] Request type no longer supported
166 - [GEN] Request type not allowed
199 - [GEN] Message failed reason internal please call GB
*/
public class GoldenBytesHttpSmsSender extends GenericSmsSender
{
	private static final String sModule = "GoldenBytes";

	/**
	 * Instantiates a new GoldenBytes http sms sender.
	 * 
	 * @param url
	 *            the sms gateway provider url
	 * @param user
	 *            the account user
	 * @param password
	 *            the account password
	 * @param gateway
	 *            the (optional) priority gateway if supported by the sms gateway provider
	 */
	public GoldenBytesHttpSmsSender(String url, String user, String password, String gateway, boolean usePost)
	{
		super(url, user, password, gateway, usePost);
	}

	/**
	 * @param sMethod
	 * @param iReturnCode
	 * @param _systemLogger
	 * @param rd
	 * @return
	 * @throws IOException
	 * @throws DataSendException
	 */
	protected int analyzeSmsResult(BufferedReader rd)
	throws IOException, DataSendException
	{
		final Character SEPCHAR = '=';
		String sMethod = "analyzeSmsReturn";
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();

		String line;
		String sResult = "", sResultCode = "";
		
		// Look for a status code line
		while ((line = rd.readLine()) != null) {
			_systemLogger.log(Level.INFO, sModule, sMethod, "line["+line+"]");
			if (line.length() <= 4)
				continue;
			if (Character.isDigit(line.charAt(0)) && Character.isDigit(line.charAt(1)) &&
					Character.isDigit(line.charAt(2)) && line.charAt(3) == SEPCHAR) {
				sResultCode = line.substring(0, 3);
				sResult = line.substring(4);
				break;
			}
		}
		_systemLogger.log(Level.INFO, sModule, sMethod, "code="+sResultCode+"result="+sResult);

		if (!Utils.hasValue(sResultCode)) {
			throw new DataSendException("SMS may not have been sent, no returncode available");
		}
		if (sResultCode.equals("000"))
			return 0;  // OK
		else 
			throw new DataSendException("Could not send sms, returncode=" + sResultCode);
	}

	/**
	 * Assemble the sms message.
	 * 
	 * @param sTemplate
	 *            the template
	 * @param sSecret
	 *            the secret code
	 * @param from
	 *            the sender
	 * @param recipients
	 *            the recipients
	 * @param data
	 *            the data to be sent
	 * @return - 0 = ok
	 * @throws UnsupportedEncodingException
	 */
	protected int assembleSmsMessage(String sTemplate, String sSecret, String from, String recipients, StringBuffer data)
	throws UnsupportedEncodingException
	{
		String sMethod = "assembleSmsMessage";
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();
		final String EQUAL_SIGN = "=";
		final String AMPERSAND = "&";

		String sMessage = applySmsTemplate(sTemplate, sSecret, false);
		
		// Your server is authenticated by source IP address.
		// You may register one or more source IP addresses which are authorized to access your account.
		data.append(URLEncoder.encode("REQUESTTYPE", "UTF-8"));
		data.append(EQUAL_SIGN).append(URLEncoder.encode("0", "UTF-8"));  // zero: plain text
		data.append(AMPERSAND);
		data.append(URLEncoder.encode("OADCTYPE", "UTF-8"));
		data.append(EQUAL_SIGN).append(URLEncoder.encode("2", "UTF-8"));  // Type of originator address: ASCII
		data.append(AMPERSAND);
		data.append(URLEncoder.encode("OADC", "UTF-8"));
		data.append(EQUAL_SIGN).append(URLEncoder.encode(from, "UTF-8"));  // Originator address, alfanumeric, max length 11
		data.append(AMPERSAND);
		data.append(URLEncoder.encode("NUMBERS", "UTF-8")).append(EQUAL_SIGN);  // Recipient phone nunmbers
		data.append(URLEncoder.encode(recipients, "UTF-8"));
		//data.append(AMPERSAND);
		//data.append(URLEncoder.encode("MESSAGEID", "UTF-8")).append(EQUAL_SIGN);  // max length 8
		//data.append(URLEncoder.encode("xxx", "UTF-8"));
		data.append(AMPERSAND);
		data.append(URLEncoder.encode("BODY", "UTF-8")).append(EQUAL_SIGN);  // Text of the message
		data.append(URLEncoder.encode(sMessage, "UTF-8"));
		
		_systemLogger.log(Level.INFO, sModule, sMethod, "url=" + providerUrl + " data=" + data.toString());
		return 0;
	}
}
