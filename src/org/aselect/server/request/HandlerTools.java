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
package org.aselect.server.request;

import java.net.URLDecoder;

import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.BASE64Encoder;

/*
 * Generic Tools for all Handler routines
 * 
 * 20100228, Bauke: moved all copies of (de)serializeAttributes to HandlerTools
 */
public class HandlerTools
{
	final static String MODULE = "HandlerTools";

	// Set-Cookie: aselect_credentials=329...283; Domain=.anoigo.nl; Path=/aselectserver/server; Secure
	// This code can be used to set HttpOnly (not supported by Java Cookies)
	/**
	 * Put cookie value.
	 * 
	 * @param response
	 *            the response
	 * @param sCookieName
	 *            the s cookie name
	 * @param sCookieValue
	 *            the s cookie value
	 * @param sCookieDomain
	 *            the s cookie domain
	 * @param iAge
	 *            the i age
	 * @param logger
	 *            the logger
	 */
	public static void putCookieValue(HttpServletResponse response, String sCookieName, String sCookieValue,
			String sCookieDomain, int iAge, ASelectSystemLogger logger)
	{
		String sMethod = "putCookieValue";
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		String addedSecurity = _configManager.getAddedSecurity();
		String sCookiePath = _configManager.getCookiePath();

		String sValue = sCookieName + "=" + sCookieValue;
		if (sCookieDomain != null)
			sValue += "; Domain=" + sCookieDomain;
		sValue += "; Version=1; Path=" + sCookiePath; // was: "/aselectserver/server";
		// if (iAge != -1) sValue += "; expires=<date>"
		// format: Wdy, DD-Mon-YYYY HH:MM:SS GMT, e.g.: Fri, 31-Dec-2010, 23:59:59 GMT

		if (iAge >= 0)
			sValue += "; Max-Age=" + iAge;

		if (addedSecurity != null && addedSecurity.contains("cookies"))
			sValue += "; Secure; HttpOnly";

		logger.log(Level.INFO, MODULE, sMethod, "Add Cookie, Header: " + sValue);
		response.setHeader("Set-Cookie", sValue);
	}

	// Age -1 means keep for the session only, 0 means delete, positive values: keep until Age (in seconds) expires
	// NOT USED, because the Java API does not support HttpOnly
	/**
	 * Xxx_put cookie value.
	 * 
	 * @param response
	 *            the response
	 * @param sCookieName
	 *            the s cookie name
	 * @param sCookieValue
	 *            the s cookie value
	 * @param sCookieDomain
	 *            the s cookie domain
	 * @param iAge
	 *            the i age
	 * @param logger
	 *            the logger
	 */
	public static void xxx_putCookieValue(HttpServletResponse response, String sCookieName, String sCookieValue,
			String sCookieDomain, int iAge, ASelectSystemLogger logger)
	{
		String sMethod = "putCookieValue";
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		String addedSecurity = _configManager.getAddedSecurity();
		String sCookiePath = _configManager.getCookiePath();

		Cookie cookie = new Cookie(sCookieName, sCookieValue); // does not work +"; HttpOnly");
		if (sCookieDomain != null)
			cookie.setDomain(sCookieDomain);
		cookie.setPath(sCookiePath); // was: "/aselectserver/server");
		cookie.setVersion(1);
		if (iAge != -1)
			cookie.setMaxAge(iAge);

		if (addedSecurity != null && addedSecurity.contains("cookies"))
			cookie.setSecure(true);

		logger.log(Level.INFO, MODULE, sMethod, "Add Cookie: " + sCookieName + " Value=" + sCookieValue + " Domain="
				+ cookie.getDomain() + " Path=" + cookie.getPath() + " Age=" + iAge);
		response.addCookie(cookie);
	}

	/**
	 * Del cookie value.
	 * 
	 * @param response
	 *            the response
	 * @param sCookieName
	 *            the s cookie name
	 * @param sCookieDomain
	 *            the s cookie domain
	 * @param logger
	 *            the logger
	 */
	public static void delCookieValue(HttpServletResponse response, String sCookieName, String sCookieDomain,
			ASelectSystemLogger logger)
	{
		String sMethod = "delCookieValue";
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		String sCookiePath = _configManager.getCookiePath();

		Cookie cookie = new Cookie(sCookieName, "i am invisible");
		if (sCookieDomain != null)
			cookie.setDomain(sCookieDomain);
		cookie.setPath(sCookiePath); // was: "/aselectserver/server");
		cookie.setMaxAge(0);
		logger.log(Level.INFO, MODULE, sMethod, "Delete Cookie=" + sCookieName + " Domain=" + sCookieDomain);
		response.addCookie(cookie);
	}

	// Bauke: added
	/**
	 * Gets the cookie value.
	 * 
	 * @param request
	 *            the request
	 * @param sName
	 *            the s name
	 * @param logger
	 *            the logger
	 * @return the cookie value
	 */
	public static String getCookieValue(HttpServletRequest request, String sName, ASelectSystemLogger logger)
	{
		String sMethod = "getCookieValue";
		String sReturnValue = null;
		Cookie oCookie[] = request.getCookies();
		if (oCookie == null)
			return null;
		for (int i = 0; i < oCookie.length; i++) {
			String sCookieName = oCookie[i].getName();
			if (logger != null) { // allow for null logger
				logger.log(Level.INFO, MODULE, sMethod, "Try " + sCookieName);
			}
			if (sCookieName.equals(sName)) {
				String sCookieValue = oCookie[i].getValue();
				// remove '"' surrounding the cookie if applicable
				int iLength = sCookieName.length();
				if (sCookieName.charAt(0) == '"' && sCookieName.charAt(iLength - 1) == '"') {
					sCookieName = sCookieName.substring(1, iLength - 1);
				}
				if (logger != null) {// allow for null logger
					logger.log(Level.INFO, MODULE, sMethod, sCookieName + "=" + sCookieValue);
				}
				sReturnValue = sCookieValue;
				break;
			}
		}
		return sReturnValue;
	}

	/**
	 * Log cookies.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param logger
	 *            the logger
	 */
	public static void logCookies(HttpServletRequest servletRequest, ASelectSystemLogger logger)
	{
		String sMethod = "logCookies()";
		Cookie[] aCookies = servletRequest.getCookies();
		if (aCookies == null) {
			logger.log(Level.FINER, MODULE, sMethod, "No Cookies");
			return;
		}

		for (int i = 0; i < aCookies.length; i++) {
			logger.log(Level.INFO, MODULE, sMethod, "Cookie " + aCookies[i].getName() + "=" + aCookies[i].getValue()
					+ ", Path=" + aCookies[i].getPath() + ", Domain=" + aCookies[i].getDomain() + ", Age="
					+ aCookies[i].getMaxAge());
		}
	}
}
