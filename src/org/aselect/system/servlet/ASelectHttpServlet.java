/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 */

/* 
 * $Id: ASelectHttpServlet.java,v 1.16 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectHttpServlet.java,v $
 * Revision 1.16  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.15  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.14  2005/09/07 12:30:23  erwin
 * Added todo for error handling in restart servlets
 *
 * Revision 1.13  2005/04/27 14:58:11  erwin
 * Fixex restart logging
 *
 * Revision 1.12  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.11  2005/03/29 10:41:07  erwin
 * - Added default methods
 * - Made isRestartableServlet() abstract
 *
 * Revision 1.10  2005/03/10 11:02:57  remco
 * fixed comments and dutch error messages
 *
 * Revision 1.9  2005/03/10 10:58:25  remco
 * fixed javadoc
 *
 * Revision 1.8  2005/03/09 12:13:10  erwin
 * Improved error handling. removed '.' in method name.
 *
 * Revision 1.7  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.6  2005/03/01 15:29:25  erwin
 * Fixed Javadoc warnings
 *
 * Revision 1.5  2005/02/23 10:43:00  erwin
 * Applied code style.
 *
 * Revision 1.4  2005/02/22 10:32:14  erwin
 * Applied code style and added JavaDoc.
 *
 *
 */

package org.aselect.system.servlet;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// RH, 20100621, Remove cyclic dependency system<->server
//import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.logging.ISystemLogger;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Utils;

/**
 * Base servlet for A-Select (core) components. <br>
 * <br>
 * <b>Description: </b> <br>
 * This base servlet contains functionality for restartable and initialisable Servlets. In addition it contains some
 * helpfull methods which are shared among different A-Select Servlet components. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * You <b>must</b> use the <code>isRestartInProgress()</code> method in your <code>service()</code> (or other request
 * handling methods) to ensure that the servlet is not currently restarting. If it is, then you should halt processing.
 * It is possible to process events during a restart, but it is very dangerous since a restart can potentially change
 * the entire state of your servlet. <br>
 * <br>
 * Other than that, this class is thread-safe.
 * 
 * @author Alfa & Ariss
 */
@SuppressWarnings("serial")
public abstract class ASelectHttpServlet extends HttpServlet
{
	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "ASelectHttpServlet";

	/**
	 * Flag indicating whether we are initializing or re-initializing
	 */
	private boolean _bFirstInit = true;

	/**
	 * Initialises the <code>Servlet</code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Performs the following steps:
	 * <ul>
	 * <li>Calls the super its initialisation</li>
	 * <li>Registers this <code>ASelectHttpServlet</code> as a restartable servlet if applicable</li>
	 * </ul>
	 * 
	 * @param config
	 *            the config
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	@Override
	public void init(ServletConfig config)
		throws ServletException
	{
		super.init(config);
		if (isRestartableServlet())
			registerRestartableServlet(getModuleName());
	}

	/**
	 * Set HTTP headers that disable browser caching. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Sets HTTP 1.0 or HTTP 1.1 disable caching headers depending on the request. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oRequest != null</code></li>
	 * <li><code>oResponse != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <code>oResponse</code> contains caching disable headers. <br>
	 * 
	 * @param oRequest
	 *            The HTTP request.
	 * @param oResponse
	 *            The HTTP response.
	 */
	public void setDisableCachingHttpHeaders(HttpServletRequest oRequest, HttpServletResponse oResponse)
	{
		// turn off caching
		if (oRequest.getProtocol().equalsIgnoreCase("HTTP/1.0")) {
			oResponse.setHeader("Pragma", "no-cache");
		}
		else if (oRequest.getProtocol().equalsIgnoreCase("HTTP/1.1")) {
			oResponse.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
		}
		// turn off caching by proxies
		oResponse.setHeader("Expires", "-1");
	}

	/**
	 * Show an HTML error page. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The following tags will be replaced in the error template:
	 * <ul>
	 * <li>[error_code] containing the error code</li>
	 * <li>[error_message] containing the error message</li>
	 * </ul>
	 * 
	 * @param pwOut
	 *            the <code>PrintWriter</code> that is the target for displaying the html error page.
	 * @param sTemplate
	 *            The base HTML error template.
	 * @param sError
	 *            The error that should be shown in the error page.
	 * @param sErrorMessage
	 *            The error message that should be shown in the error page.
	 */
//	public void showErrorPage(PrintWriter pwOut, String sTemplate, String sError, String sErrorMessage, String sLanguage)
	public void showErrorPage(PrintWriter pwOut, String sTemplate, String sError, String sErrorMessage, String sLanguage, ISystemLogger sLogger)
	{
		String sMethod = "showErrorPage";
//		ASelectSystemLogger _oAuthSPSystemLogger = ASelectSystemLogger.getHandle();
//		_oAuthSPSystemLogger.log(Level.INFO, MODULE, sMethod, "FORM[" + sTemplate + "] " + sError + ":" + sErrorMessage);
		sLogger.log(Level.INFO, MODULE, sMethod, "FORM[" + sTemplate + "] " + sError + ":" + sErrorMessage);

		String sErrorForm = new String(sTemplate);
		sErrorForm = Utils.replaceString(sErrorForm, "[error]", sError);  // obsoleted 20100817
		sErrorForm = Utils.replaceString(sErrorForm, "[error_code]", sError);
		sErrorForm = Utils.replaceString(sErrorForm, "[error_message]", sErrorMessage);
		sErrorForm = Utils.replaceString(sErrorForm, "[language]", sLanguage);
		sErrorForm = Utils.replaceConditional(sErrorForm, "if_error", sErrorMessage != null && !sErrorMessage.equals(""));
		pwOut.println(sErrorForm);
	}

	/**
	 * Determines whether or not a Servlet is restartable. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method should return <code>true</code> if the Servlet is restartable, <code>false</code> otherwise. <br>
	 * <br>
	 * 
	 * @return <code>true</code> if the Servlet is restartable, otherwise <code>false</code>.
	 */
	protected abstract boolean isRestartableServlet();

	/**
	 * Determine whether this is a first-time init or a re-initialization <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method can be used in your <code>init()</code> method to check whether it is a first-time initialization, or
	 * a re-initialization after a restart API call. <br>
	 * 
	 * @return <code>true</code> if this is a re-initialization, <code>false</code> otherwise.
	 */
	protected boolean isReinit()
	{
		boolean bRetVal = !_bFirstInit;
		_bFirstInit = false;
		return bRetVal;
	}

	/**
	 * Retrieve the modulename. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Constructs a module name form the class name. This method strips package prefix and the "Servlet" postfix. <br>
	 * <br>
	 * 
	 * @return The constructed module name.
	 */
	protected String getModuleName()
	{
		String sModule = this.getClass().getName();
		sModule = sModule.substring(sModule.lastIndexOf(".") + 1);
		if (sModule.endsWith("Servlet"))
			sModule = sModule.toLowerCase().substring(0, sModule.length() - 7);

		return sModule;
	}

	/**
	 * Retrieve the working directory. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Return the working directory which A-Select uses for logging, configuration, and other data storage. <br>
	 * <br>
	 * The working dir is read as an Init paramater from the servlets Deployment Descriptor. e.g.:
	 * 
	 * <pre>
	 * <code>
	 * 
	 * 
	 * &lt;servlet&gt;
	 * ...
	 * &lt;init-param&gt;
	 * &lt;param-name&gt;working_dir&lt;/param-name&gt;
	 * &lt;param-value&gt;[param value]&lt;/param-value&gt;
	 * &lt;/init-param&gt;
	 * ...
	 * &lt;/servlet&gt;
	 * 
	 * 
	 * </code>
	 * </pre>
	 * 
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The working dir is set in the Servlet its Deployment Descriptor. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @return The working directory.
	 */
	protected String getWorkingDir()
	{
		return this.getServletConfig().getInitParameter("working_dir");
	}

	/**
	 * Handles the restart request. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method should be called if a sub class receives a restart request. This methods calls
	 * {@link ASelectHttpServlet#restartServlets(SystemLogger)}which restarts all restartable servlets in the servlet
	 * context. <br>
	 * <br>
	 * <i>Note: The restart request should be handled by one <code>Servlet</code> in the context. </i> <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * This method should be called serial. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oRequest != null</code></li>
	 * <li><code>sMySharedSecret != null</code></li>
	 * <li><code>pwOut != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All restartable servlets in the context are restarted. <br>
	 * 
	 * @param oRequest
	 *            The HTTP request.
	 * @param sMySharedSecret
	 *            The shared secret on which the received Shared_secret is validated upon.
	 * @param pwOut
	 *            The ouput.
	 * @param systemLogger
	 *            The logger for system logging.
	 * @return A-Select result code.
	 */
	protected String handleRestartRequest(HttpServletRequest oRequest, String sMySharedSecret, PrintWriter pwOut,
			SystemLogger systemLogger)
	{
		// TODO The error handling differs from standard A-Select
		// TODO The result is ignored in the A-Select and AuthSP Server (Erwin van den Beld)
		String sMethod = "handleRestartRequest()";
		String sSharedSecret = oRequest.getParameter("shared_secret");

		if (sSharedSecret == null) {
			if (systemLogger != null)
				systemLogger.log(Level.WARNING, MODULE, sMethod, "parameter 'shared_secret' not found");
			else
				System.err.println("parameter 'shared_secret' not found");

			return Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST;
		}
		if (!sSharedSecret.equals(sMySharedSecret)) {
			StringBuffer sbError = new StringBuffer("Invalid 'shared_secret' received from ");
			sbError.append(oRequest.getRemoteAddr());

			if (systemLogger != null)
				systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			else
				System.err.println(sbError.toString());

			return Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST;
		}

		String sResult = (restartServlets(systemLogger) ? Errors.ERROR_ASELECT_SUCCESS
				: Errors.ERROR_ASELECT_INTERNAL_ERROR);
		pwOut.print("result_code=" + sResult);
		return sResult;
	}

	/**
	 * Restart all restartable servlets within this context. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Restarts all servlets in the <code>Servlet</code> context:
	 * <ul>
	 * <li>Set restarting in progress attribute in servlet context.</li>
	 * <li>Restart all servlets in the context.</li>
	 * <li>Disable restarting in progress attribute in servlet context.</li>
	 * </ul>
	 * <br>
	 * <i>Note: this method logs possible errors. </i> <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All restartable servlets in the context are restarted. <br>
	 * 
	 * @param logger
	 *            The system logger.
	 * @return false if one or more restart requests fail, otherwise true.
	 */
	protected synchronized boolean restartServlets(SystemLogger logger)
	{
		String sMethod = "restartServlets()";
		StringBuffer sb = null;
		boolean bEndResult = true;

		HashMap htRestartServlets = (HashMap) this.getServletConfig().getServletContext().getAttribute(
				"restartable_servlets");
		if (htRestartServlets == null) {
			sb = new StringBuffer(getModuleName()).append(".").append(sMethod).append("::").append(
					"ERROR::\"Restart: no restartable servlets registered.\"");
			if (logger != null)
				logger.log(Level.INFO, MODULE, sMethod, sb.toString());
			else
				System.err.println(sb.toString());

			return false;
		}

		try {
			this.getServletConfig().getServletContext().setAttribute("restarting_servlets", "true");
			StringBuffer sbResult = new StringBuffer("Restart: ");
			Set keys = htRestartServlets.keySet();
			for (Object s : keys) {
				String sKey = (String) s;
				// for (Enumeration e = htRestartServlets.keys(); e.hasMoreElements();)
				// {
				// String sKey = (String)e.nextElement();
				ASelectHttpServlet servlet = (ASelectHttpServlet) htRestartServlets.get(sKey);
				boolean bResult = true;
				try {
					servlet.init(servlet.getServletConfig());
				}
				catch (Exception eX) {
					bResult = false;
				}
				bEndResult &= bResult;
				sbResult.append(sKey).append(" (");
				sbResult.append(bResult ? "OK" : "Failed");
				sbResult.append(")");
				// if (e.hasMoreElements())
				sbResult.append(", ");
			}
			int len = sbResult.length();
			String sResult = sb.substring(0, len - 2);
			if (logger != null)
				logger.log(Level.INFO, MODULE, sMethod, sResult);
			else
				System.err.println(sResult);
		}
		catch (Exception e) {
			if (logger != null)
				logger.log(Level.SEVERE, getModuleName(), sMethod, "Restarting servlets failed", e);
			else
				System.err.println(getModuleName() + " " + sMethod + e.getMessage());

			bEndResult = false;
		}
		this.getServletConfig().getServletContext().removeAttribute("restarting_servlets");
		return bEndResult;
	}

	/**
	 * Check if a restart is currently in progress. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method reads the servlet configuration attribute "restarting_servlets". If this attribute is true then all
	 * restartable servlets within this context are in the process of being restarted. <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * Be careful in handling requests during a restart. A restart may potentially change the entire state of the
	 * servlets within the context.
	 * 
	 * @return true if servlets in the context are restarting, otherwise false.
	 */
	protected boolean isRestartInProgress()
	{
		String sRestarting = (String) this.getServletConfig().getServletContext().getAttribute("restarting_servlets");
		return sRestarting != null && sRestarting.equals("true");
	}

	/**
	 * This method returns a "Server Busy" if restarting is in progress. <br>
	 * <br>
	 * <i>Note: If this method is overwritten in a sub class, it should be called explicitly, or you must use the
	 * <code>isRestartInProgress()</code> method </i> <br>
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#service(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void service(HttpServletRequest request, HttpServletResponse response)
		throws ServletException, java.io.IOException
	{
		if (isRestartInProgress())
			response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
		else
			super.service(request, response);
	}

	/**
	 * Register <code>Servlet</code> as being restartable. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This methods adds the <code>Servlet</code> to the "restartable_servlets" context attribute. <br>
	 * <br>
	 * 
	 * @param sServletName
	 *            The name of the servlet which is used as key.
	 */
	private void registerRestartableServlet(String sServletName)
	{
		ServletConfig config = getServletConfig();
		HashMap hRestartServlets = (HashMap) config.getServletContext().getAttribute("restartable_servlets");
		if (hRestartServlets == null)
			hRestartServlets = new HashMap();
		hRestartServlets.put(sServletName, this);
		config.getServletContext().setAttribute("restartable_servlets", hRestartServlets);
	}
}