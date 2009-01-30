/**
 * 
 */
package org.aselect.system.logging.filter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

//import org.slf4j.MDC;
import org.apache.log4j.MDC;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.logging.Audit;
import org.aselect.system.logging.AuditLevel;


/**
 * @author RH
 *
 */
public class AuditFilter implements Filter {

	private static final String _MODULE = "AuditFilter";

	private static final String REQUEST_TGT = "tgt@";
	private static final String REQUEST_COOKIE = "cookie@";
	private static final String REQUEST_PARM = "requestparm@";
	private FilterConfig filterConfig;
	ASelectSystemLogger _logger;
	private Hashtable<String, String> requestParms = new Hashtable<String, String>();
	private Hashtable<String, String> cookies = new Hashtable<String, String>();
	private Hashtable<String, Hashtable<String, String>> tgts = new Hashtable<String, Hashtable<String, String>>();
    private Hashtable htTGTContext;
	
	/* (non-Javadoc)
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy() {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	@SuppressWarnings("unchecked")
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
        // Retrieves the session object from the current request.
//        HttpSession session = ((HttpServletRequest)request).getSession(false);
        HttpSession session = ((HttpServletRequest)request).getSession();
        
        // Put the ip_address into the diagnostic context.
        // Use %X{a_ip_address} in the layout pattern to 
        // include this information.
        MDC.put("a_remote_address", 
        		request.getRemoteAddr());
        if (session != null) {
            MDC.put("a_session_id", 
            		session.getId());
        }
        Enumeration parms = requestParms.keys();
        while (parms.hasMoreElements()) {
        	String parm = (String)parms.nextElement(); 
//            MDC.put("a_rid", 
//            		request.getParameter("rid") == null ? "" : request.getParameter("rid"));
            MDC.put(requestParms.get(parm), 
            		request.getParameter(parm) == null ? "" : request.getParameter(parm));
            
        }
        Enumeration logCookies = cookies.keys();
        while (logCookies.hasMoreElements()) {
        	String cookieName = (String)logCookies.nextElement();
        	String cookieValue = HandlerTools.getCookieValue((HttpServletRequest)request, cookieName, null); 
//            MDC.put("a_rid", 
//            		request.getParameter("rid") == null ? "" : request.getParameter("rid"));
            MDC.put((String)cookies.get(cookieName), 
            		cookieValue == null ? "" : cookieValue);
        }
        Enumeration cookieSet = tgts.keys();
        while (cookieSet.hasMoreElements()) {
        	String cookieName = (String)cookieSet.nextElement();
	        String tgt = HandlerTools.getCookieValue((HttpServletRequest)request, cookieName, null);
			if (tgt != null) {
				htTGTContext = TGTManager.getHandle().getTGT(tgt);
				if (htTGTContext != null) {
					 Hashtable<String, String> tgtParms = tgts.get(cookieName);
					 Enumeration cookieParms = tgtParms.keys();
					while (cookieParms.hasMoreElements()) {
						String cookieParm = (String)cookieParms.nextElement();
						String parmVal = (String)htTGTContext.get(cookieParm);
						MDC.put( (String)tgtParms.get(cookieParm), parmVal == null ? "" :parmVal );
					}
				}
	        }
		}
        // Continue processing the rest of the filter chain.
        chain.doFilter(request, response);
        
        // TODO dynamically remove other attributes from MDC
        // maybe set up some vector with all MDC attributes to easily remove them later
        MDC.remove("a_remote_address");
        MDC.remove("a_session_id");

	}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	@SuppressWarnings("unchecked")
	public void init(FilterConfig filterConfig) throws ServletException {
		final String sMethod = "init()";
		_logger = ASelectSystemLogger.getHandle();
		 this.filterConfig = filterConfig;
		 filterConfig.getFilterName();  // We probably want this later
		 Enumeration filterParms = filterConfig.getInitParameterNames();
		 while (filterParms.hasMoreElements()) {
			 String fullParmName = (String)filterParms.nextElement();
			 if (fullParmName.toLowerCase().startsWith(REQUEST_PARM)) {
				 String name = fullParmName.substring(REQUEST_PARM.length());
				 String val = filterConfig.getInitParameter(fullParmName);
				 if (val != null && !"".equals(val)) {
					 requestParms.put(name, val);
				 }
			 }
			 if (fullParmName.toLowerCase().startsWith(REQUEST_COOKIE)) {
				 String name = fullParmName.substring(REQUEST_COOKIE.length());
				 String val = filterConfig.getInitParameter(fullParmName);
				 if (val != null && !"".equals(val)) {
					 cookies.put(name, val);
				 }
			 }
			 if (fullParmName.toLowerCase().startsWith(REQUEST_TGT)) {
				 String fullCookieName = fullParmName.substring(REQUEST_TGT.length());
				 _logger.log(Audit.INFO, _MODULE, sMethod, "fullCookieName:" + fullCookieName);
				 
				 int i = fullCookieName.indexOf("@");
				 if ( i >= 0 ) {
						 String cookieName = fullCookieName.substring(0, i);
						 _logger.log(Audit.INFO, _MODULE, sMethod, "cookieName:" + cookieName);
						 String parmName = fullCookieName.substring(i+1);
						 _logger.log(Audit.INFO, _MODULE, sMethod,"parmName:" + parmName);
						 String val = filterConfig.getInitParameter(fullParmName);
						 _logger.log(Audit.INFO, _MODULE, sMethod,"val:" + val);
						 if (val != null && !"".equals(val)) {
							 Hashtable<String, String> tgtParms = tgts.get(cookieName);
							 if (tgtParms == null) {
								 tgtParms = new Hashtable<String, String>();
							 }
							 tgtParms.put(parmName, val);
							 tgts.put(cookieName, tgtParms);
						 }
				 }
			 }
		 }
	}

}
