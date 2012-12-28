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
package org.aselect.authspserver.authsp.delegator;

import java.net.URL;

/**
 * * A simple factory that creates a delegate for various delegated auth providers <br>
 * <br>
 * <b>Description:</b>
 * Factory that can create adelegate depending on supplied parameter (HTTP, ...)  
 * defaults to "HTTPDelegate" provider
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * @author RH
 *
 */
public class DelegateFactory
{
	public static final String HTTP_DELEGATE = "http";
	public static final String HTTPS_TRUSTALL_DELEGATE = "httpstrustall";

	/**
	 * * creator method <br>
	 * <br>
	 * <b>Description:</b>
	 * Creates a delegater depending on supplied provider parameter (http, ...)  
	 * defaults to "mollie" provider
	 * <br>
	 * <br>
	 * 	 @param url
	 * 		The delegate authsp provider url. May be https if appropriate certificate is loaded in cacerts
	 * 	 @param user
	 * 		delegate gateway account username, if provided, http basic authentication will be used
	 * 	 @param password
	 * 		delegate gateway account password
	 * 	 @param gateway
	 * 		optional priority level, not supported by all delegate providers
	 * 	 @param provider
	 * 		identifier for delegate gateway provider, currently http defaults to http
	 * 
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 */
	public static Delegate createDelegate(URL url, String user, String password, String gateway, String provider)
	{
		if (HTTP_DELEGATE.equalsIgnoreCase(provider)) {
			return new  HTTPDelegate(url, user, password);
		} else if (HTTPS_TRUSTALL_DELEGATE.equalsIgnoreCase(provider)) {
			return new  HTTPSTrustAllDelegate(url, user, password);
		}
		else {	// default to "http"
			return new  HTTPDelegate(url, user, password);
		}
	}
}
