package org.aselect.server.request;

import java.util.logging.Level;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

public class HandlerTools
{
	final static String MODULE = "HandlerTools";
	
	// Set-Cookie: aselect_credentials=329...283; Domain=.anoigo.nl; Path=/aselectserver/server; Secure
	// This code can be used to set HttpOnly (not supported by Java Cookies)
	public static void putCookieValue(HttpServletResponse response, String sCookieName,
			String sCookieValue, String sCookieDomain, int iAge, ASelectSystemLogger logger)
	{
		String sMethod = "putCookieValue";
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		String addedSecurity = _configManager.getAddedSecurity();
		
		String sValue = sCookieName+"="+sCookieValue;
		if (sCookieDomain != null)
			sValue += "; Domain="+sCookieDomain;
		sValue += "; Version=1; Path=/aselectserver/server";
		// if (iAge != -1) sValue += "; expires=<date>"
		// format: Wdy, DD-Mon-YYYY HH:MM:SS GMT, e.g.: Fri, 31-Dec-2010, 23:59:59 GMT

        if (iAge >= 0) sValue += "; Max-Age="+iAge;
        
		if (addedSecurity != null && addedSecurity.contains("cookies"))
			sValue += "; Secure; HttpOnly";

		logger.log(Level.INFO, MODULE, sMethod, "Add Cookie, Header: "+sValue);
		response.setHeader("Set-Cookie", sValue);
	}

	// Age -1 means keep for the session only, 0 means delete, positive values: keep until Age (in seconds) expires
	// NOT USED, because the Java API does not support HttpOnly
	public static void xxx_putCookieValue(HttpServletResponse response, String sCookieName, String sCookieValue,
			String sCookieDomain, int iAge, ASelectSystemLogger logger)
	{
		String sMethod = "putCookieValue";
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		String addedSecurity = _configManager.getAddedSecurity();
		
		Cookie oCookie = new Cookie(sCookieName, sCookieValue);  // does not work +"; HttpOnly");
		if (sCookieDomain != null)
			oCookie.setDomain(sCookieDomain);
		oCookie.setPath("/aselectserver/server");
		oCookie.setVersion(1);
		if (iAge != -1) oCookie.setMaxAge(iAge);
		
		if (addedSecurity != null && addedSecurity.contains("cookies"))
			oCookie.setSecure(true);
	    
		logger.log(Level.INFO, MODULE, sMethod, "Add Cookie: "+sCookieName+" Value="+sCookieValue+
	    		" Domain="+oCookie.getDomain()+" Path="+oCookie.getPath()+" Age="+iAge);
		response.addCookie(oCookie);
	}

	public static void delCookieValue(HttpServletResponse response, String sCookieName, String sCookieDomain, ASelectSystemLogger logger)
	{
		String sMethod = "delCookieValue";
		Cookie cookie = new Cookie(sCookieName, "i am invisible");
		if (sCookieDomain != null) cookie.setDomain(sCookieDomain);
		cookie.setPath("/aselectserver/server");
		cookie.setMaxAge(0);
		logger.log(Level.INFO, MODULE, sMethod, "Delete Cookie="+sCookieName+" Domain="+sCookieDomain);
		response.addCookie(cookie);
	}

	// Bauke: added
	public static String getCookieValue(HttpServletRequest request, String sName, ASelectSystemLogger logger)
	{
		String sMethod = "getCookieValue";
		String sReturnValue = null;
		Cookie oCookie[] = request.getCookies();
		if (oCookie == null)
			return null;
	    for (int i = 0; i < oCookie.length; i++)
	    {
	        String sCookieName = oCookie[i].getName();
	        if (logger != null) { // allow for null logger
	        	logger.log(Level.INFO, MODULE, sMethod, "Try "+sCookieName);
	        }
	        if (sCookieName.equals(sName))
	        {
	            String sCookieValue = oCookie[i].getValue();
	            //remove '"' surrounding the cookie if applicable
	            int iLength = sCookieName.length();
	            if(sCookieName.charAt(0) == '"' && sCookieName.charAt(iLength-1) == '"')
	            {
	                sCookieName = sCookieName.substring(1, iLength-1);
	            }
		        if (logger != null) {// allow for null logger 
		        	logger.log(Level.INFO, MODULE, sMethod, sCookieName+"="+sCookieValue);
		        }
	            sReturnValue = sCookieValue;
	            break;
	        }
	    }
		return sReturnValue;
	}

	public static void logCookies(HttpServletRequest servletRequest, ASelectSystemLogger logger)
	{
		String sMethod = "logCookies()";
	    Cookie[] aCookies = servletRequest.getCookies();
	    if (aCookies == null) {
	        logger.log(Level.FINER, MODULE, sMethod, "No Cookies");
	        return;
	    }
	
	    for (int i = 0; i < aCookies.length; i++)
	    {
	    	logger.log(Level.INFO, MODULE, sMethod, "Cookie "+aCookies[i].getName()+"="+aCookies[i].getValue()+
	        		", Path="+aCookies[i].getPath()+", Domain="+aCookies[i].getDomain()+", Age="+aCookies[i].getMaxAge());
	    }
	}
	
	public static String getSimpleParam(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectException
	{
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		try {
			return _configManager.getParam(oConfig, sParam);  // is not null
		}
		catch (ASelectConfigException e) {
			if (!bMandatory)
				return null;
			_systemLogger.log(Level.WARNING, MODULE, "getSimpleParam", "Config item '"+sParam+"' not found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	public static String getParamFromSection(Object oConfig, String sSection, String sParam, boolean bMandatory)
	throws ASelectConfigException
	{
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		try {
			Object oSection = _configManager.getSection(oConfig, sSection);
			return _configManager.getParam(oSection, sParam);
		}
		catch (ASelectConfigException e) {
			if (!bMandatory)
				return null;
			_systemLogger.log(Level.WARNING, MODULE, "getParamFromSection",
					"Could not retrieve '"+sParam+"' parameter in '"+sSection+"' section", e);
			throw e;
		}
	}

	public static String getParamFromSection(Object oConfig, String sSection, String sParam)
	throws ASelectConfigException
	{
		return getParamFromSection(oConfig, sSection, sParam, true);
	}
}
