/*
 * @author ernst-jan
 * Created on Nov 26, 2004
 *
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
import org.aselect.system.utils.Tools;

/*
 * 14-11-2007:  Adapted to the latest www.mollie.nl protocol
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright UMC Nijmegen (http://www.umcn.nl)
 */
public class MollieHttpSmsSender implements SmsSender
{
	private static final String sModule = "Mollie";
	private final String user;
	private final String password;
	private final URL url;
	private final String gateway;

	/**
	 * Instantiates a new mollie http sms sender.
	 * 
	 * @param url
	 *            the url
	 * @param user
	 *            the user
	 * @param password
	 *            the password
	 */
	public MollieHttpSmsSender(URL url, String user, String password)
	{
		this(url, user, password, null);
	}

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
	public MollieHttpSmsSender(URL url, String user, String password, String gateway)
	{
		super();
		this.url = url;
		this.user = user;
		this.password = password;
		this.gateway = gateway;
	}
	
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
	/*
	 * (non-Javadoc)
	 * @see org.aselect.authspserver.authsp.sms.SmsSender#sendSms(java.lang.String, java.lang.String, java.lang.String)
	 */
	public int sendSms(String message, String from, String recipients)
	throws SmsException
	{
		String sMethod = "sendSms";
		int iReturnCode = -1;
		StringBuffer data = new StringBuffer();
		AuthSPSystemLogger _systemLogger;
		_systemLogger = AuthSPSystemLogger.getHandle();

		try {
			final String EQUAL_SIGN = "=";
			final String AMPERSAND = "&";
			data.append(URLEncoder.encode("username", "UTF-8"));
			data.append(EQUAL_SIGN).append(URLEncoder.encode(this.user, "UTF-8"));
			data.append(AMPERSAND).append(URLEncoder.encode("password", "UTF-8"));
			data.append(EQUAL_SIGN).append(URLEncoder.encode(this.password, "UTF-8"));
			data.append(AMPERSAND).append(URLEncoder.encode("originator", "UTF-8"));
			data.append(EQUAL_SIGN).append(URLEncoder.encode(from, "UTF-8"));
			data.append(AMPERSAND).append(URLEncoder.encode("message", "UTF-8"));
			data.append(EQUAL_SIGN).append(URLEncoder.encode(message, "UTF-8"));
			data.append(AMPERSAND).append(URLEncoder.encode("recipients", "UTF-8"));
			data.append(EQUAL_SIGN).append(URLEncoder.encode(recipients, "UTF-8"));

			// RH, 20080729, sn
			// gateway == null, use mollies default gateway
			if (this.gateway != null && !"".equals(this.gateway.trim())) {
				data.append(AMPERSAND).append(URLEncoder.encode("gateway", "UTF-8"));
				data.append(EQUAL_SIGN).append(URLEncoder.encode(this.gateway, "UTF-8"));
			}
			// RH, 20080729, en
			_systemLogger.log(Level.INFO, sModule, sMethod, "url=" + url.toString() + " data=" + data.toString());
			HttpURLConnection conn = (HttpURLConnection)url.openConnection();
			conn.setDoOutput(true);
			OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
			wr.write(data.toString());
			wr.flush();

			// Get the response
			// Bauke: adapted to latest protocol
			BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line;
			String sResult = "", sResultCode = "";
			while ((line = rd.readLine()) != null) {
//				System.out.println(line);	// RH, 20110104, o
				sResult = Tools.extractFromXml(line, "resultcode", true);
				if (sResult != null) {
					sResultCode = sResult;
					break;
				}
			}
			_systemLogger.log(Level.INFO, sModule, sMethod, "resultcode=" + sResultCode);
			if (sResultCode.equals("10"))
				iReturnCode = 0;  // OK
			else if (sResultCode.equals("25"))
				iReturnCode = 1;  // Bad phonenumber
			else 
				throw new SmsException("Mollie could not send sms, returncode from Mollie: " + sResultCode + ".");
			
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
