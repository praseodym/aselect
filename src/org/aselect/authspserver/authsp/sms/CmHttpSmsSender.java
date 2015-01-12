/*
 * * Copyright (c) Anoigo. All rights reserved.
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

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.velocity.app.event.implement.EscapeXmlReference;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.utils.Utils;

/**
 * Sends request for sms to the CM sms gateway
 * @author Bauke Hiemstra
 * 
 */
public class CmHttpSmsSender extends GenericSmsSender
{
	private static final String sModule = "CM";
	private static final String SEPCHAR = "=";

	private String sCustomerId = null;

	private String xmlSmsMessage =
		"<?xml version=\"1.0\"?>\n" +
		"<MESSAGES>\n" +
		"<CUSTOMER ID=\"[CUSTOMER]\"/>\n" +
		"<USER LOGIN=\"[LOGIN]\" PASSWORD=\"[PASSWORD]\"/>\n" +
		"<MSG>\n" +
			"<FROM>[SENDER]</FROM>\n" +
			"<BODY TYPE=\"TEXT\">[MESSAGE]</BODY>\n" +
			"<TO>[NUMBER]</TO>\n" +
		"</MSG>\n" +
		"</MESSAGES>\n";

	final String CONTENT_TYPE = "text/xml; charset=utf-8";
	
	// Override the default from GenericSmsSender
	public String getContentType()
	{
		return CONTENT_TYPE;
	}

	/**
	 * Instantiates a new CM http sms sender.
	 * 
	 * @param url
	 *            the sms gateway provider url
	 * @param user
	 *            the account user
	 * @param password
	 *            the account password
	 * @param gateway
	 *            the (optional) priority gateway if supported by the sms
	 *            gateway provider
	 * @param usePost
	 *            use POST instead of GET
	 */
	public CmHttpSmsSender(String url, String customer, String user, String password, String gateway, boolean usePost)
	{
		super(url, user, password, gateway, usePost);
		sCustomerId = customer;
	}
	
	/**
	 * Assemble the sms message.
	 * This XML document should be encoded in UTF-8.
	 * The values within the document elements should be XML encoded
	 * 
	 * @param sTemplate
	 *            the template
	 * @param sSecret
	 *            the secret code
	 * @param from
	 *            the sender
	 * @param recipients
	 *            the recipients
	 * @param sbResult
	 *            the data to be sent
	 * @return - 0 = ok
	 * @throws UnsupportedEncodingException
	 */
	protected int assembleSmsMessage(String sTemplate, String sSecret, String from, String recipients, StringBuffer sbResult)
	throws UnsupportedEncodingException
	{
		String sMethod = "assembleSmsMessage";
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, sModule, sMethod, "url=" + providerUrl);
		
		String sMessage = applySmsTemplate(sTemplate, sSecret, false);
		_systemLogger.log(Level.FINEST, sModule, sMethod, "msg="+escapeXmlString(sMessage)+" cust="+sCustomerId+
				" user="+this.user+" password="+this.password+" from="+from+" rcp="+recipients);
		String sData = xmlSmsMessage.replaceAll("\\[MESSAGE\\]", escapeXmlString(sMessage));
		sData = sData.replaceAll("\\[CUSTOMER\\]", sCustomerId);
		sData = sData.replaceAll("\\[LOGIN\\]", escapeXmlString(this.user));
		sData = sData.replaceAll("\\[PASSWORD\\]", escapeXmlString(this.password));
		sData = sData.replaceAll("\\[SENDER\\]", escapeXmlString(from));
		sData = sData.replaceAll("\\[NUMBER\\]", recipients);  // a single phone number
		
		// gateway has no value
		if (Utils.hasValue(this.gateway)) {
			_systemLogger.log(Level.WARNING, sModule, sMethod, "Alternate gateway supplied, but not supported");
		}
		_systemLogger.log(Level.FINEST, sModule, sMethod, "append");
		sbResult.append(sData);
		_systemLogger.log(Level.FINEST, sModule, sMethod, "data=" + sbResult.toString());
		return 0;
	}
	
	/**
	 * Returns the string where all non-ascii and <, &, > are encoded as numeric
	 * entities. The result is safe to include anywhere in a text field in an
	 * XML-string. If no characters were escaped, the original string is
	 * returned.
	 * 
	 * @param unescapedString
	 *            the unescaped string
	 * @return the result
	 */
	public static String escapeXmlString(String unescapedString)
	{
	    boolean anyCharactersEscaped = false;

	    if (unescapedString == null)
	        return null;
	    
	    StringBuffer stringBuffer = new StringBuffer();
	    for (int i = 0; i < unescapedString.length(); i++) {
	        char ch = unescapedString.charAt(i);

	        if (ch < 32 || ch > 126 || ch == '<' || ch == '&' || ch == '>') {
	            stringBuffer.append("&#" + (int)ch + ";");
	            anyCharactersEscaped = true;
	        }
	        else {
	            stringBuffer.append(ch);
	        }
	    }
	    return (anyCharactersEscaped)? stringBuffer.toString(): unescapedString;
	}
	
	/**
	 * Every request will get an HTTP response with status 200 (OK), even if the request is malformed.
	 * If the request was correct, the response will be empty.
	 * If the request was malformed, the response will start with �ERROR�.
	 * @param rd - the Reader for the result
	 * @return - 0 = ok
	 */
	protected int analyzeSmsResult(BufferedReader rd)
	throws IOException, DataSendException
	{
		String sMethod = "sendSms";
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();

		String line;
		String sResult = "";
		while ((line = rd.readLine()) != null) {	// there should be only one significant line, ignore extra lines
			if ("".equals(sResult) && !"".equals(line))
				sResult = line;	// get first non-empty line
		}
		_systemLogger.log(Level.FINEST, sModule, sMethod, "result:" + sResult);

		// Analyze the result
		if (sResult.startsWith("Error:") || sResult.startsWith("ERROR")) {
			throw new DataSendException("SMS provider could not send sms, error=" + sResult.substring(6));
		}
		return 0;  // ok
	}
}
