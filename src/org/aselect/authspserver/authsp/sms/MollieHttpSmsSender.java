/*
 * @author ernst-jan
 * Created on Nov 26, 2004
 *
 */
package org.aselect.authspserver.authsp.sms;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.logging.Level;

import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.utils.Tools;

/*
 * 14-11-2007:  Adapted to the latest www.mollie.nl protocol
 * Both POST and GET are allowed
 * 1-5-2013: Added voice gateway
 * 
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright UMC Nijmegen (http://www.umcn.nl)
 */
public class MollieHttpSmsSender extends GenericSmsSender
{
	private static final String sModule = "MollieHttpSmsSender";
	private boolean _useVoice = false;

	/**
	 * Instantiates a new mollie http sms sender.
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
	public MollieHttpSmsSender(String url, String user, String password, String gateway, boolean usePost, boolean useVoice)
	{
		super(url, user, password, gateway, usePost);
		_useVoice = useVoice;
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
		
		// 20130502, Bauke: If _useVoice: Insert spaces between digits in the message
		String sMessage = applySmsTemplate(sTemplate, sSecret, _useVoice);
		
		data.append(URLEncoder.encode("username", "UTF-8"));
		data.append(EQUAL_SIGN).append(URLEncoder.encode(this.user, "UTF-8"));
		
		data.append(AMPERSAND).append(URLEncoder.encode("password", "UTF-8"));
		data.append(EQUAL_SIGN).append(URLEncoder.encode(this.password, "UTF-8"));
		
		data.append(AMPERSAND).append(URLEncoder.encode("originator", "UTF-8"));
		data.append(EQUAL_SIGN).append(URLEncoder.encode(from, "UTF-8"));

		data.append(AMPERSAND).append(URLEncoder.encode("message", "UTF-8"));
		data.append(EQUAL_SIGN).append(URLEncoder.encode(sMessage, "UTF-8"));
		
		data.append(AMPERSAND).append(URLEncoder.encode("recipients", "UTF-8"));
		data.append(EQUAL_SIGN).append(URLEncoder.encode(recipients, "UTF-8"));

		// RH, 20080729, sn
		// gateway == null, use mollies default gateway
		if (this.gateway != null && !"".equals(this.gateway.trim())) {
			data.append(AMPERSAND).append(URLEncoder.encode("gateway", "UTF-8"));
			data.append(EQUAL_SIGN).append(URLEncoder.encode(this.gateway, "UTF-8"));
		}
		// RH, 20080729, en
		_systemLogger.log(Level.FINEST, sModule, sMethod, "url=" + providerUrl + " data=" + data.toString());
		return 0;
	}

/* Response:	
	<?xml version="1.0" ?>
	<response>
	    <item type="sms">
	        <recipients>1</recipients>
	        <success>true</success>
	        <resultcode>10</resultcode>
	        <resultmessage>Message successfully sent.</resultmessage>
	    </item>
	</response>
*/
/*	Possible resultcodes from mollie.nl:
    10 - succesvol verzonden
    20 - geen 'username' opgegeven
    21 - geen 'password' opgegeven
    22 - geen of onjuiste 'originator' opgegeven
    23 - geen 'recipients' opgegeven
    24 - geen 'message' opgegeven
    25 - geen juiste 'recipients' opgegeven
    26 - geen juiste 'originator' opgegeven
    27 - geen juiste 'message' opgegeven
    28 - probleem met charset
    29 - andere parameterfout
    30 - incorrecte 'username' of 'password'
    31 - onvoldoende credits om te versturen
    98 - gateway onbereikbaar
    99 - onbekende fout
 */ 
	/**
	 * @param rd - Reader to get the result
	 * @return: 0 = ok, 1 = bad phone number
	 */
	protected int analyzeSmsResult(BufferedReader rd)
	throws IOException, DataSendException
	{
		String sMethod = "analyzeSmsResult";
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();
		String line;
		String sResult = "", sResultCode = "";
		while ((line = rd.readLine()) != null) {
			sResult = Tools.extractFromXml(line, "resultcode", true);
			if (sResult != null) {
				sResultCode = sResult;
				break;
			}
		}
		_systemLogger.log(Level.FINEST, sModule, sMethod, "resultcode=" + sResultCode);
		if (sResultCode.equals("10"))
			return 0;  // OK
		else if (sResultCode.equals("25"))
			return 1;  // Bad phone number
		else 
			throw new DataSendException("Mollie could not send sms, returncode=" + sResultCode);
	}
}
