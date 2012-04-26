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
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.logging.Level;

import org.aselect.authspserver.log.AuthSPSystemLogger;

/**
 * Sends request for sms to wireless-services sms gateway
 * @author RH
 * 
 */
public class WirelessServicesHttpSmsSender implements SmsSender
{
	private static final String sModule = "WirelessServices";
	private static final String SEPCHAR = "=";
	private static final String GWVERSION = "1.1";
	private final String user;
	private final String password;
	private final URL url;
	private final String gateway;

	/**
	 * Instantiates a new wirelessservices http sms sender.
	 * 
	 * @param url
	 *            the sms gateway provider url
	 * @param user
	 *            the account user
	 * @param password
	 *            the account password
	 */
	public WirelessServicesHttpSmsSender(URL url, String user, String password)
	{
		this(url, user, password, null);
	}

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
	public WirelessServicesHttpSmsSender(URL url, String user, String password, String gateway)
	{
		super();
		this.url = url;
		this.user = user;
		this.password = password;
		this.gateway = gateway;
	}

	/**
	 * @param message
	 * 		the body of the message to send
	 * @param from
	 * 		the 'from' info to put in the message, can be alpha (max 11 chars) or numeric (max. 16 digits)
	 * @param recipients
	 * 		comma seperated list of recipient numbers
	 * @return progress step start=15, 19=finished
	 * 
	 * (non-Javadoc)
	 * @see org.aselect.authspserver.authsp.sms.SmsSender#sendSms(java.lang.String, java.lang.String, java.lang.String)
	 */
	public int sendSms(String message, String from, String recipients)
		throws SmsException
	{
		String sMethod = "sendSms";
		int iReturnCode = 15;
		StringBuffer data = new StringBuffer();
		AuthSPSystemLogger _systemLogger;
		_systemLogger = AuthSPSystemLogger.getHandle();

		try {
			final String EQUAL_SIGN = SEPCHAR;
			final String AMPERSAND = "&";
			data.append(URLEncoder.encode("VERSION", "UTF-8"));
			data.append(EQUAL_SIGN);
			data.append(URLEncoder.encode(GWVERSION, "UTF-8"));
			data.append(AMPERSAND);
			data.append(URLEncoder.encode("UID", "UTF-8"));
			data.append(EQUAL_SIGN);
			data.append(URLEncoder.encode(this.user, "UTF-8"));
			data.append(AMPERSAND);
			data.append(URLEncoder.encode("PWD", "UTF-8"));
			data.append(EQUAL_SIGN);
			data.append(URLEncoder.encode(this.password, "UTF-8"));
			data.append(AMPERSAND);
			data.append(URLEncoder.encode("O", "UTF-8")).append(EQUAL_SIGN);
			data.append(URLEncoder.encode(from, "UTF-8"));
			data.append(AMPERSAND);
			data.append(URLEncoder.encode("M", "UTF-8")).append(EQUAL_SIGN);
			data.append(URLEncoder.encode(message, "UTF-8"));
			data.append(AMPERSAND);
			data.append(URLEncoder.encode("N", "UTF-8")).append(EQUAL_SIGN);
			data.append(URLEncoder.encode(recipients, "UTF-8"));

			// gateway == null, Wireless Services cannot specify alternate gateway like this, must use other URL
			if (this.gateway != null && !"".equals(this.gateway.trim())) {
				_systemLogger.log(Level.WARNING, sModule, sMethod, "No alternate gateway support, you must use alternate URL for this");
			}
			iReturnCode++; // 16
			_systemLogger.log(Level.INFO, sModule, sMethod, "url=" + url.toString() + " data=" + data.toString());
			HttpURLConnection conn = (HttpURLConnection)url.openConnection();
//			conn.setRequestProperty("Connection", "close"); // use this if we will explicitly conn.disconnect();
			conn.setRequestMethod("POST");	// Wireless Services prefers POST
			conn.setRequestProperty("Host", url.getHost());	// Wireless Services requires 'Host' header
			conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");	// Wireless Services requires this for POST
			conn.setReadTimeout(10000);
			iReturnCode++; // 17
			conn.setDoOutput(true);
			OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
			wr.write(data.toString());
			wr.flush();
			iReturnCode++; // 18

			// Get the response
			BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line;
			String sResult = "", sResultCode = "";
			while ((line = rd.readLine()) != null) {	// there should be only one significant line, ignore extra lines
				if ("".equals(sResult) && !"".equals(line))
					sResult = line;	// get first non-empty line
			}
			_systemLogger.log(Level.INFO, sModule, sMethod, "result:" + sResult);

			int resLength = sResult.length();
			if (resLength == 0) {
				throw new SmsException("Wireless Services may not have send sms, no returncode from Wireless Services");
			}
			int sepPos = sResult.indexOf(SEPCHAR);
			if (sepPos == -1) {
				throw new SmsException("Wireless Services may not have send sms, no '" + SEPCHAR + "' seperator received from Wireless Services");
			}
			sResultCode = sResult.substring(0, sepPos);
			if (!sResultCode.startsWith("0")) {
				throw new SmsException("Wireless Services could not send sms, returncode from Wireless Services: " + sResultCode);
			}
			
			iReturnCode++; // 19
			wr.close();
			rd.close();
		}
		catch (NumberFormatException e) {
			throw new SmsException("Sending SMS, using \'" + this.url.toString()
					+ "\' failed due to number format exception! " + e.getMessage(), e);
		}
		catch (Exception e) {
			throw new SmsException("Sending SMS, using \'" + this.url.toString() + "\' failed (progress=" + iReturnCode
					+ ")! " + e.getMessage(), e);
		}
		return iReturnCode;
	}
}
