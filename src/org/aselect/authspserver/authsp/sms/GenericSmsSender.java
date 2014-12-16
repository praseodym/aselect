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

 * @author Bauke Hiemstra - www.anoigo.nl
 */
package org.aselect.authspserver.authsp.sms;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;

import org.aselect.authspserver.log.AuthSPSystemLogger;

/**
 * Sends SMS request to an SMS gateway 
 */
public abstract class GenericSmsSender
{
	private static final String sModule = "GenericSmsSender";
	protected String user;
	protected String password;
	protected String providerUrl;
	protected String gateway;
	protected boolean usePostMethod;

	// Wireless Services requires this for POST
	final protected String CONTENT_TYPE = "application/x-www-form-urlencoded";
	
	public String getContentType()
	{
		return CONTENT_TYPE;
	}

	/**
	 * Instantiates a generic http sms sender.
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
	public GenericSmsSender(String sHostUrl, String user, String password, String gateway, boolean usePostMethod)
	{
		this.providerUrl = sHostUrl;
		this.user = user;
		this.password = password;
		this.gateway = gateway;
		this.usePostMethod = usePostMethod;
	}

	/**
	 * Send sms.
	 * 
	 * @param sTemplate
	 *            the SMS message template: e.g. "This is your code: %s."
	 * @param sSecret
	 *            - the body of the message to send
	 * @param from
	 *            - the 'from' info to put in the message, can be alpha (max 11
	 *            chars) or numeric (max. 16 digits)
	 * @param recipients
	 *            - comma seperated list of recipient numbers
	 * @return: 0 = ok, 1 = invalid phone number, -1 = errors
	 * @throws DataSendException
	 */
	public int sendSms(String sTemplate, String sSecret, String from, String recipients)
	throws DataSendException
	{
		String sMethod = "sendSms";
		
		int iReturnCode = -1;
		StringBuffer data = new StringBuffer("");
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, sModule, sMethod, "usePost=" + usePostMethod + " content="+getContentType());

		// Assemble HTTP request
		try {
			iReturnCode = assembleSmsMessage(sTemplate, sSecret, from, recipients, data);
			_systemLogger.log(Level.INFO, sModule, sMethod, "data=" + data.toString()+ " iReturnCode="+iReturnCode);
			if (iReturnCode != 0)
				return iReturnCode;
			
			// Establish the connection
			URL url = null;
			HttpURLConnection conn = null;
			if (usePostMethod) {
				url = new URL(providerUrl);
				conn = (HttpURLConnection)url.openConnection();
				conn.setRequestMethod("POST");	// Wireless Services prefers POST
				conn.setDoOutput(true);
			}
			else {
				// requestMethod = GET
				url = new URL(providerUrl+"?"+data.toString());
				conn = (HttpURLConnection)url.openConnection();
			}
			conn.setRequestProperty("Host", url.getHost());	// Wireless Services requires 'Host' header

			//conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");	// Wireless Services requires this for POST
			conn.setRequestProperty("Content-Type", getContentType());  // x-www-form-urlencoded
			conn.setReadTimeout(10000);
			// conn.setRequestProperty("Connection", "close"); // use this if we will explicitly conn.disconnect();
			
			if (usePostMethod) { // Send the POST request
				OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
				wr.write(data.toString());
				wr.flush();
				wr.close();
			}

			// Get the response
			BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			iReturnCode = analyzeSmsResult(rd);
			rd.close();
		}
		catch (Exception e) {
			throw new DataSendException("Sending SMS, using \'" + this.providerUrl + "\' failed, " + e.getMessage(), e);
		}
		return iReturnCode;
	}

	/**
	 * Apply sms template, by inserting the secret code into it.
	 * 
	 * @param sTemplate - the template
	 * @param sSecret - the secret
	 * @param expandDigits - add a space between digits?
	 * @return - result after inserting the 'sSecret' in the 'sTemplate
	 */
	protected String applySmsTemplate(String sTemplate, String sSecret, boolean expandDigits)
	{
		String sMethod = "applySmsTemplate";
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, sModule, sMethod, "sTemplate="+sTemplate+" expandDigits=" + expandDigits);

		if (expandDigits) {
			// insert spaces between digits in sSecret
			StringBuffer sWork = new StringBuffer(2*sSecret.length());
			for (int i=0; i<sSecret.length(); i++) {
				char c = sSecret.charAt(i);
				if (i>0 && Character.isDigit(c) && Character.isDigit(sWork.charAt(sWork.length()-1))) {
					sWork.append(' ');
				}
				sWork.append(c);
			}
			sSecret = sWork.toString();
		}
		// 20130502, Bauke: added '%s' alternative
		String sReplace = (sTemplate.contains("%s"))? "%s": "0";
		String sMessage = sTemplate.replaceAll(sReplace, sSecret);
		_systemLogger.log(Level.INFO, sModule, sMethod, "sMessage="+sMessage);
		return sMessage;
	}

	/**
	 * Assemble sms message.
	 * 
	 * @param message
	 *            the message to be sent
	 * @param from
	 *            the id of the sender
	 * @param recipients
	 *            the recipient phone numbers
	 * @param data
	 *            the data
	 * @return the int
	 * @throws UnsupportedEncodingException
	 */
	abstract protected int assembleSmsMessage(String sTemplate, String sSecret, String from, String recipients, StringBuffer data)
	throws UnsupportedEncodingException;
	
	/**
	 * Analyze sms result.
	 * 
	 * @param rd
	 *            the Reader to get at the result
	 * @return the int
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws DataSendException
	 */
	abstract protected int analyzeSmsResult(BufferedReader rd)
	throws IOException, DataSendException;
}
