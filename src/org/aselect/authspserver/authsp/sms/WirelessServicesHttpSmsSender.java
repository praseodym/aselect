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

/**
 * Sends request for sms to wireless-services sms gateway
 * @author RH
 * 
 */
public class WirelessServicesHttpSmsSender extends GenericSmsSender
{
	private static final String sModule = "WirelessServices";
	private static final String SEPCHAR = "=";
	private static final String GWVERSION = "1.1";

	/**
	 * Instantiates a new wirelessservices http sms sender.
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
	public WirelessServicesHttpSmsSender(String url, String user, String password, String gateway, boolean usePost)
	{
		super(url, user, password, gateway, usePost);
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

		final String EQUAL_SIGN = SEPCHAR;
		final String AMPERSAND = "&";
		
		String sMessage = applySmsTemplate(sTemplate, sSecret, false);

		data.append(URLEncoder.encode("VERSION", "UTF-8")).append(EQUAL_SIGN).append(URLEncoder.encode(GWVERSION, "UTF-8"));
		data.append(AMPERSAND);
		data.append(URLEncoder.encode("UID", "UTF-8")).append(EQUAL_SIGN).append(URLEncoder.encode(this.user, "UTF-8"));
		data.append(AMPERSAND);
		data.append(URLEncoder.encode("PWD", "UTF-8")).append(EQUAL_SIGN).append(URLEncoder.encode(this.password, "UTF-8"));
		data.append(AMPERSAND);
		data.append(URLEncoder.encode("O", "UTF-8")).append(EQUAL_SIGN).append(URLEncoder.encode(from, "UTF-8"));
		data.append(AMPERSAND);
		data.append(URLEncoder.encode("M", "UTF-8")).append(EQUAL_SIGN).append(URLEncoder.encode(sMessage, "UTF-8"));
		data.append(AMPERSAND);
		data.append(URLEncoder.encode("N", "UTF-8")).append(EQUAL_SIGN).append(URLEncoder.encode(recipients, "UTF-8"));

		// gateway == null, Wireless Services cannot specify alternate gateway like this, must use other URL
		if (this.gateway != null && !"".equals(this.gateway.trim())) {
			_systemLogger.log(Level.WARNING, sModule, sMethod, "No alternate gateway support, you must use alternate URL for this");
		}
		_systemLogger.log(Level.FINEST, sModule, sMethod, "url=" + providerUrl + " data=" + data.toString());
		return 0;
	}

	/**
	 * @param rd - the Reader for the result
	 * @return - 0 = ok
	 */
	protected int analyzeSmsResult(BufferedReader rd)
	throws IOException, DataSendException
	{
		String sMethod = "sendSms";
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();

		String line;
		String sResult = "", sResultCode = "";
		while ((line = rd.readLine()) != null) {	// there should be only one significant line, ignore extra lines
			if ("".equals(sResult) && !"".equals(line))
				sResult = line;	// get first non-empty line
		}
		_systemLogger.log(Level.FINEST, sModule, sMethod, "result:" + sResult);

		// Analyze the result
		int resLength = sResult.length();
		if (resLength == 0) {
			throw new DataSendException("SMS provider may not have sent sms, no returncode received");
		}
		int sepPos = sResult.indexOf(SEPCHAR);
		if (sepPos == -1) {
			throw new DataSendException("SMS provider may not have sent sms, no '" + SEPCHAR + "' seperator received");
		}
		sResultCode = sResult.substring(0, sepPos);
		if (!sResultCode.startsWith("0")) {
			throw new DataSendException("SMS provider could not send sms, returncode=" + sResultCode);
		}
		return 0;  // ok
	}
}
