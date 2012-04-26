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

import java.net.URL;

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
	private static final String PROVIDER_WIRELESSSERVICES = "wireless-services";

	/**
	 * * creator method <br>
	 * <br>
	 * <b>Description:</b>
	 * Creates an SmsSender depending on supplied provider parameter (mollie, wirelessservices)  
	 * defaults to "mollie" provider
	 * <br>
	 * <br>
	 * 	 @param url
	 * 		The sms gateway provider url. May be https if appropriate certificate is loaded in cacerts
	 * 	 @param user
	 * 		sms gateway account username
	 * 	 @param password
	 * 		sms gateway account password
	 * 	 @param gateway
	 * 		optional priority level, not supported by all sms providers
	 * 	 @param gw_provider
	 * 		identifier for sms gateway provider, currently [ wireless-services | mollie ] defaults to mollie
	 * 
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 */
	public static SmsSender createSmsSender(URL url, String user, String password, String gateway, String gw_provider)
	{
		if (PROVIDER_WIRELESSSERVICES.equalsIgnoreCase(gw_provider)) {
			return new  WirelessServicesHttpSmsSender(url, user, password, gateway);
		}
		else if ("GoldenBytes".equalsIgnoreCase(gw_provider)) {
			return new GoldenBytesHttpSmsSender(url, user, password, gateway);
		}
		else {	// default to "mollie"
			return new  MollieHttpSmsSender(url, user, password, gateway);
		}
	}
}
