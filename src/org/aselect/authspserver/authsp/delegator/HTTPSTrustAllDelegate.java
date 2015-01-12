/**
  * * Copyright (c) Anoigo. All rights reserved.
 *
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 * 
 */

/** 
 * HTTPDelegate.java 
 *
 * Changelog:
 *
 *
 */
package org.aselect.authspserver.authsp.delegator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


import org.apache.commons.codec.binary.Base64;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.utils.Tools;

/**
 * @author RH
 */

public class HTTPSTrustAllDelegate implements Delegate
{
	private static final String sModule = "HTTPDelegate";
	private final String delegateuser;
	private final String delegatepassword;
	private final URL url;
	

	/**
	 * Instantiates a new HTTPDelegate.
	 * 
	 * @param url
	 *            the url
	 */
	public HTTPSTrustAllDelegate(URL url)
	{
		this(url, null, null);
	}

	/**
	 * Instantiates a new HTTPDelegate.
	 * 
	 * @param url
	 *            the url
	 * @param user
	 *            the user
	 * @param password
	 *            the password
	 */
	public HTTPSTrustAllDelegate(URL url, String user, String password)
	{
		super();
		this.url = url;
		this.delegateuser = user;
		this.delegatepassword = password;
	}
	
	/*	Possible resultcodes from authentication server:
    200 - authentication success
    204 - authentication success, testing fase
    300 - more information required
    400 - authentication failure
    406 - authentication failure, testing fase
 */ 
	
	public int authenticate( Map<String, String> requestparameters, Map<String, List<String>> responseparameters )
	throws DelegateException
	{
		String sMethod = "authenticate";
		int iReturnCode = -1;
		
		AuthSPSystemLogger _systemLogger;
		_systemLogger = AuthSPSystemLogger.getHandle();

		_systemLogger.log(Level.FINEST, sModule, sMethod, "requestparameters=" + requestparameters + " , responseparameters=" + responseparameters);
		StringBuffer data = new StringBuffer();
		String sResult = "";;

		try {
			final String EQUAL_SIGN = "=";
			final String AMPERSAND = "&";
			final String NEWLINE = "\n";
			for (String key :  requestparameters.keySet()) {
				data.append(URLEncoder.encode(key, "UTF-8"));
				data.append(EQUAL_SIGN).append(URLEncoder.encode(((String)requestparameters.get(key) == null) ? "" :(String)requestparameters.get(key) , "UTF-8"));
				data.append(AMPERSAND);
			}
			
			if (data.length() > 0 ) data.deleteCharAt( data.length() - 1 );	// remove last AMPERSAND
//			data.append(NEWLINE).append(NEWLINE);
//			_systemLogger.log(Level.FINE, sModule, sMethod, "url=" + url.toString() + " data={" + data.toString() + "}");	// no data shown in production environment

			
			/////////////	HERE WE DO THE TRUST ALL STUFF ///////////////////////////////
		    // Create a trust manager that does not validate certificate chains
		    final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
		        public void checkClientTrusted( final X509Certificate[] chain, final String authType ) {
		        }
		        public void checkServerTrusted( final X509Certificate[] chain, final String authType ) {
		        }
		        public X509Certificate[] getAcceptedIssuers() {
		            return null;
		        }
		    } };
			/////////////	HERE WE DO THE TRUST ALL STUFF ///////////////////////////////

		    // Install the all-trusting trust manager
		    final SSLContext sslContext = SSLContext.getInstance( "SSL" );
		    sslContext.init( null, trustAllCerts, new java.security.SecureRandom() );
		    // Create an ssl socket factory with our all-trusting manager
		    final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
		    
			
			HttpURLConnection conn = (HttpURLConnection)url.openConnection();
			
			/////////////	HERE WE DO THE TRUST ALL STUFF ///////////////////////////////
		    // Tell the url connection object to use our socket factory which bypasses security checks
		    ( (HttpsURLConnection) conn ).setSSLSocketFactory( sslSocketFactory );
			/////////////	HERE WE DO THE TRUST ALL STUFF ///////////////////////////////
			
			// Basic authentication
			if (this.delegateuser != null) {
				  byte [] bEncoded = Base64.encodeBase64((this.delegateuser+":"+(delegatepassword == null ? "" : delegatepassword) ).getBytes("UTF-8")); 
				  String encoded = new String(bEncoded, "UTF-8");
				  conn.setRequestProperty("Authorization", "Basic "+encoded);
					_systemLogger.log(Level.FINEST, sModule, sMethod, "Using basic authentication, user=" + this.delegateuser);
			}
//			conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
			conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");	// They (the delegate party) don't accept charset !!
			conn.setDoOutput(true);
			conn.setRequestMethod("POST") ;
			OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
			wr.write(data.toString());
			
			wr.flush();
			wr.close();

			// Get the response
			iReturnCode = conn.getResponseCode();
			Map<String, List<String>> hFields = conn.getHeaderFields();
			
			_systemLogger.log(Level.FINEST, sModule, sMethod, "response=" + iReturnCode);
			BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line;
			// Still to decide on response protocol
			while ((line = rd.readLine()) != null) {
				sResult += line;
			}
			_systemLogger.log(Level.INFO, sModule, sMethod, "sResult=" + sResult);
			// Parse response  here
			// For test return request parameters
//			responseparameters.putAll(requestparameters);
			responseparameters.putAll(hFields);
			
			rd.close();
		}
		catch (IOException e) {
			_systemLogger.log(Level.INFO, sModule, sMethod, "Error while reading sResult data, maybe no data at all. sResult=" + sResult);
		}

		catch (NumberFormatException e) {
			throw new DelegateException("Sending authenticate request, using \'" + this.url.toString()
					+ "\' failed due to number format exception! " + e.getMessage(), e);
		}
		catch (Exception e) {
			throw new DelegateException("Sending authenticate request, using \'" + this.url.toString() + "\' failed (progress=" + iReturnCode
					+ ")! " + e.getMessage(), e);
		}
		return iReturnCode;
	}
}
