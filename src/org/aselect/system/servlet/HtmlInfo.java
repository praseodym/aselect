//
//Module:	HtmlInfo.java
//
//Author:	Bauke Hiemstra, bauke.hiemstra@anoigo.nl
//
package org.aselect.system.servlet;

import java.io.*;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.*;
import javax.servlet.http.*;

// RH, 20100621, Remove cyclic dependency system<->server
// import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.logging.ISystemLogger;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;

public class HtmlInfo extends HttpServlet
{
	protected String _sModule = "HtmlInfo";
	static final long serialVersionUID = 1;
	public static final String BASICSTR = "Basic ";
	private static final String ServletID = "HtmlInfo";

	/**
	 * Gets the my id.
	 * 
	 * @return the my id
	 */
	protected String getMyID()
	{
		return ServletID;
	}

	/**
	 * Handle html info.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @param systemLogger
	 *            the system logger
	 * @param htServiceRequest
	 *            the ht service request
	 */
	public void handleHtmlInfo(HttpServletRequest request, HttpServletResponse response,
			// RH, 20100621, Remove cyclic dependency system<->server
//			ASelectSystemLogger systemLogger, HashMap htServiceRequest)
			ISystemLogger systemLogger, HashMap htServiceRequest)
	{
		try {
			doGet(request, response, systemLogger);
		}
		catch (ServletException e) {
		}
		catch (IOException e) {
		}
	}

	/**
	 * Do get.
	 * 
	 * @param servletRequest
	 *            the request
	 * @param servletResponse
	 *            the response
	 * @param systemLogger
	 *            the system logger
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	// RH, 20100621, Remove cyclic dependency system<->server
//	public void doGet(HttpServletRequest request, HttpServletResponse response, ASelectSystemLogger systemLogger)
	public void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse, ISystemLogger systemLogger)
	throws ServletException, IOException
	{
		String sMethod = "handleHtmlInfo";
		int idx;
		String base64coded, decoded = null, username = null, password = null;
		String AuthHeader = servletRequest.getHeader("Authorization");
		BASE64Decoder decoder = new BASE64Decoder();

		systemLogger.log(Level.INFO, _sModule, sMethod, "htmlInfo { " + getMyID() + ", "
				+ Thread.currentThread().getName());

		String path = servletRequest.getPathInfo();
		String url = servletRequest.getRequestURI();
		systemLogger.log(Level.INFO, _sModule, sMethod, "path=" + path + ", uri=" + url);

		PrintWriter htmlpage = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

		htmlpage.println("<html>");
		htmlpage.println("<body>");

		htmlpage.println("<b>Query string</b><br>");
		htmlpage.println("<pre>");
		htmlpage.println(Tools.htmlEncode(servletRequest.getQueryString()));
		htmlpage.println("</pre>");

		String base64 = servletRequest.getParameter("base64");
		if (base64 != null) {
			decoded = new String(decoder.decodeBuffer(base64));
			htmlpage.println("<pre>Base64 decoded: " + decoded + "</pre>");
		}

		htmlpage.println("<b>HTML headers</b><br>");
		Enumeration hdrnames = servletRequest.getHeaderNames();
		htmlpage.println("<pre>");
		while (hdrnames.hasMoreElements()) {
			String hdrname = (String) hdrnames.nextElement();
			htmlpage.println(hdrname + ": " + Tools.htmlEncode(servletRequest.getHeader(hdrname)));
		}
		htmlpage.println("</pre>");

		// The authorization header looks like:
		// Basic Y249TklHRSxvPURJR0lEOg==
		if (AuthHeader != null) {
			idx = AuthHeader.indexOf(BASICSTR);
			if (idx >= 0) {
				base64coded = AuthHeader.substring(BASICSTR.length());
				try {
					decoded = new String(decoder.decodeBuffer(base64coded));
					// decoded looks like: username:password
					idx = decoded.indexOf(":");
					if (idx >= 0) {
						username = decoded.substring(0, idx);
						password = decoded.substring(idx + 1);
					}
				}
				catch (Exception e) {
					htmlpage.println(e.toString());
				}
			}
		}

		htmlpage.println("<b>HTML authorization header</b><br>");
		htmlpage.println("<pre>");
		htmlpage.println("Encoded : " + servletRequest.getHeader("Authorization"));
		htmlpage.println("Decoded : " + decoded);
		htmlpage.println("Username: " + username);
		htmlpage.println("Password: " + password);
		htmlpage.println("</pre>");

		htmlpage.println("<b>HTML parameters</b><br>");
		Enumeration parnames = servletRequest.getParameterNames();
		htmlpage.println("<pre>");
		while (parnames.hasMoreElements()) {
			String parname = (String) parnames.nextElement();
			htmlpage.println(Tools.htmlEncode(parname + " = " + servletRequest.getParameter(parname)));
		}
		htmlpage.println("</pre>");

		htmlpage.println("</body>");
		htmlpage.println("</html>");

		systemLogger.log(Level.INFO, _sModule, sMethod, "} htmlInfo " + getMyID() + ", "
				+ Thread.currentThread().getName());
	}
}
