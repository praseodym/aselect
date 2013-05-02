/**
 *  Copyright (c) Anoigo. All rights reserved.
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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;

import org.aselect.authspserver.log.AuthSPSystemLogger;

/**
 * * A simple factory that creates SmsSender for various outbound sms providers <br>
 * <br>
 * <b>Description:</b>
 * Factory that can create an SmsSender depending on supplied parameter (mollie, wireless-services)  
 * defaults to "mollie" provider
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * @author RH
 *
 */
public class SmsSenderFactory
{
	private static final String MODULE = "SmsSenderFactory";
	static AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();
	
	/**
	 * * creator method <br>
	 * <br>
	 * <b>Description:</b> Creates an SmsSender depending on supplied provider
	 * defaults to the "mollie" provider <br>
	 * <br>
	 * .
	 * 
	 * @param sProviderUrl
	 *            The sms gateway provider url. May be https if appropriate
	 *            certificate is loaded in cacerts
	 * @param user
	 *            sms gateway account username
	 * @param password
	 *            sms gateway account password
	 * @param gateway
	 *            optional priority level, not supported by all sms providers
	 * @param gw_provider
	 *            identifier for sms gateway provider, defaults to mollie
	 * @return the generic sms sender
	 * @throws MalformedURLException
	 * 			for bad url values
	 */
	public static GenericSmsSender createSmsSender(String sProviderUrl, String user, String password, String gateway, String gw_provider)
	throws MalformedURLException
	{
		String sMethod = "createSmsSender";
		new URL(sProviderUrl);  // check the sUrl given for correctness
		_systemLogger.log(Level.INFO, MODULE, sMethod, "SmsProvider="+gw_provider+" Url="+sProviderUrl); 
		if ("wireless_service".equalsIgnoreCase(gw_provider) || "wireless-service".equalsIgnoreCase(gw_provider)) {
			return new WirelessServicesHttpSmsSender(sProviderUrl, user, password, gateway, true /*use POST*/);
		}
		if ("wireless_voice".equalsIgnoreCase(gw_provider) || "wireless-voice".equalsIgnoreCase(gw_provider)) {
			return new WirelessVoiceSmsSender(sProviderUrl, user, password, gateway, true/*use POST*/);
			//return new MollieHttpSmsSender(sProviderUrl, user, password, gateway, false/*use POST*/);  // TESTING with mollie!
		}
		else if ("GoldenBytes".equalsIgnoreCase(gw_provider)) {
			return new GoldenBytesHttpSmsSender(sProviderUrl, user, password, gateway, true/*use POST*/);
		}
		else if ("mollie_voice".equalsIgnoreCase(gw_provider)) {
			return new MollieHttpSmsSender(sProviderUrl, user, password, gateway, true/*use POST*/, true/*voice*/);
		}
		else {	// defaults to "mollie"
			return new MollieHttpSmsSender(sProviderUrl, user, password, gateway, true/*use POST*/, false/*sms*/);
		}
	}
}
