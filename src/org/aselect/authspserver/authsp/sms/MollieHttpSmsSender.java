/*
 * @author ernst-jan
 * Created on Nov 26, 2004
 *
 */
package org.aselect.authspserver.authsp.sms;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.net.URLConnection;
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
	private final String user;
	private final String password;
	private final URL url;
	private final String gateway;

	/**
	 *  
	 */
	public MollieHttpSmsSender(URL url, String user, String password)
	{
		this(url, user, password, null);
	}
	/**
	 *  
	 */
	public MollieHttpSmsSender(URL url, String user, String password, String gateway)
	{
		super();
		this.url = url;
		this.user = user;
		this.password = password;
		this.gateway = gateway;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.aselect.authspserver.authsp.sms.SmsSender#sendSms(java.lang.String,
	 *      java.lang.String, java.lang.String)
	 */
	public int sendSms(String message, String from, String recipients) throws SmsException
	{
		int returncode = 15;
		StringBuffer data = new StringBuffer();
	    AuthSPSystemLogger _systemLogger;
		_systemLogger = AuthSPSystemLogger.getHandle();

		try {
			final String EQUAL_SIGN = "=";
			final String AMPERSAND = "&";
			// data.append(this.url);
			data.append(URLEncoder.encode("username", "UTF-8"));
			data.append(EQUAL_SIGN);
			data.append(URLEncoder.encode(this.user, "UTF-8"));
			data.append(AMPERSAND);
			data.append(URLEncoder.encode("password", "UTF-8"));
			data.append(EQUAL_SIGN);
			data.append(URLEncoder.encode(this.password, "UTF-8"));
			data.append(AMPERSAND);
			data.append(URLEncoder.encode("originator", "UTF-8")).append(EQUAL_SIGN);
			data.append(URLEncoder.encode(from, "UTF-8"));
			data.append(AMPERSAND);
			data.append(URLEncoder.encode("message", "UTF-8")).append(EQUAL_SIGN);
			data.append(URLEncoder.encode(message, "UTF-8"));
			data.append(AMPERSAND);
			data.append(URLEncoder.encode("recipients", "UTF-8")).append(EQUAL_SIGN);
			data.append(URLEncoder.encode(recipients, "UTF-8"));

			// RH, 20080729, sn
			// gateway == null, use mollies default gateway
			if ( this.gateway != null && !"".equals(this.gateway.trim()) ) {
				data.append(AMPERSAND);
				data.append(URLEncoder.encode("gateway", "UTF-8")).append(EQUAL_SIGN);
				data.append(URLEncoder.encode(this.gateway, "UTF-8"));
			}
			// RH, 20080729, en
			
			_systemLogger.log(Level.INFO, "Mollie", "sendSms", "url="+url.toString()+" data="+data.toString());
			returncode++; // 16
			URLConnection conn = url.openConnection();
			returncode++; // 17
			conn.setDoOutput(true);
			OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
			wr.write(data.toString());
			wr.flush();
			returncode++; // 18

			// Get the response
			BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line;
			
			// Bauke: adapted to latest protocol
			String sResult, sResultCode = "";
			while ((line = rd.readLine()) != null) {
				System.out.println(line);
				sResult = Tools.extractFromXml(line, "resultcode", true);
				if (sResult != null) {
					sResultCode = sResult;
					break;
				}
			}
			_systemLogger.log(Level.INFO, "Mollie", "sendSms", "resultcode="+sResultCode);
			if (!sResultCode.equals("10")) {
				throw new SmsException("Mollie could not send sms, returncode from Mollie: " + sResultCode + ".");
			}
			
			returncode++; // 19
			wr.close();
			rd.close();
		}
		catch (NumberFormatException e) {
			throw new SmsException("Sending SMS, using \'" + this.url.toString() + "\' failed due to number format exception! " + e.getMessage(), e);
		}
		catch (Exception e) {
			throw new SmsException("Sending SMS, using \'" + this.url.toString() + "\' failed (progress=" + returncode + ")! " + e.getMessage(), e);
		}
		return returncode;
	}
}
