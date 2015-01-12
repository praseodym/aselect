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
import org.aselect.system.utils.Tools;

/**
 * Send an SMS to wireless services to be delivered over a voice channel
 * 
 * @author Bauke Hiemstra - www.anoigo.nl
 */
public class WirelessVoiceSmsSender extends GenericSmsSender
{
	private static final String sModule = "WirelessVoiceSmsSender";

	/**
	 * Instantiates a new sms sender.
	 * 
	 * @param url
	 *            the url
	 * @param user
	 *            the user
	 * @param password
	 *            the password
	 * @param gateway
	 *            the gateway
	 */
	public WirelessVoiceSmsSender(String url, String user, String password, String gateway, boolean usePost)
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

		final String EQUAL_SIGN = "=";
		final String AMPERSAND = "&";

		String sMessage = applySmsTemplate(sTemplate, sSecret, false);
		
		data.append(URLEncoder.encode("code", "UTF-8"));
		data.append(EQUAL_SIGN).append(URLEncoder.encode(sMessage, "UTF-8"));
		
		data.append(AMPERSAND).append(URLEncoder.encode("phonenumber", "UTF-8"));
		data.append(EQUAL_SIGN).append(URLEncoder.encode(recipients, "UTF-8"));

		_systemLogger.log(Level.FINEST, sModule, sMethod, "url=" + providerUrl + " data=" + data.toString());
		return 0;
	}
	
	/**
	 * @param rd - Reader to get the result
	 * @return: 0 = ok, 1 = bad phone number, -1 = errors
	 */
	protected int analyzeSmsResult(BufferedReader rd)
	throws IOException, DataSendException
	{
		String sMethod = "analyzeSmsResult";
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();
		String line;
		String sResult = "", sResultCode = "";
		while ((line = rd.readLine()) != null) {
			sResult = Tools.extractFromXml(line, "body", true);
			if (sResult != null) {
				sResultCode = sResult;
				break;
			}
		}
		_systemLogger.log(Level.INFO, sModule, sMethod, "resultcode=" + sResultCode);
		if (sResultCode.equals("OK"))
			return 0;  // OK
		else if (sResultCode.equals("ERROR"))
			return -1;  // Error detected
		else 
			throw new DataSendException("Wireless services could not send sms, returncode=" + sResultCode);
	}
}
