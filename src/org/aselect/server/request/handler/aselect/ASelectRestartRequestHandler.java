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
 * $Id: ASelectRestartRequestHandler.java,v 1.2 2006/05/03 10:10:18 tom Exp $ 
 */

package org.aselect.server.request.handler.aselect;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.servlet.ASelectHttpServlet;

/**
 * Handles the A-Select <i>restart</i> request.
 * <br><br>
 * <b>Description:</b><br>
 * This class handles restart requests. It restarts the A-Select servlet that will
 * proceed to reread its configuration without having to restart the servlet container (e.g. Tomcat).
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class ASelectRestartRequestHandler extends AbstractRequestHandler
{
	private final static String MODULE = "ASelectRestartRequestHandler";
	private String _sMySharedSecret = null;

	/**
	 * Initializes the Restart request handler.
	 * <br><br>
	 * <b>Description:</b><br>
	 * Reads the following configuration:<br/><br/>
	 * &lt;handler&gt;<br/>
	 * &lt;shared_secret&gt;[shared_secret]&lt;/shared_secret&gt;<br/>
	 * &lt;/handler&gt;<br/>
	 * <ul>
	 * <li><b>shared_secret</b> - The shared secret that must be sent with the request</li>
	 * </ul>  
	 * <br><br>
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		try {
			super.init(oServletConfig, oConfig);

			try {
				_sMySharedSecret = _configManager.getParam(oConfig, "shared_secret");
			}
			catch (ASelectConfigException e) {
				_sMySharedSecret = null;
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Could not retrieve 'shared_secret' config parameter in aselect config section.", e);
				throw e;
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * <b>Description: </b> <br>
	 * This method should be called if a sub class receives a restart request.
	 * This methods calls restartServlets() which restarts
	 * all restartable servlets in the servlet context. <br>
	 * <br>
	 * <i>Note: The restart request should be handled by one
	 * <code>Servlet</code> in the context. </i> <br>
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
	 * <br><br>
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		try {
			String sSharedSecret = request.getParameter("shared_secret");

			if (sSharedSecret == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Parameter 'shared_secret' not found in restart request from " + request.getRemoteAddr());

				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			if (!sSharedSecret.equals(_sMySharedSecret)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid 'shared_secret' received from "
						+ request.getRemoteAddr());

				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			String sResult = (restartServlets() ? Errors.ERROR_ASELECT_SUCCESS : Errors.ERROR_ASELECT_INTERNAL_ERROR);

			PrintWriter pwOut = response.getWriter();
			pwOut.print("result_code=" + sResult);
			if (pwOut != null)
				pwOut.close();
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return new RequestState(null);
	}

	/**
	 * Removes class variables from memory.
	 * <br><br>
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#destroy()
	 */
	public void destroy()
	{
		//does nothing        
	}

	/**
	 * Restart all restartable servlets within this context. 
	 * <br>
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
	 * <b>Preconditions: </b> 
	 * <br>-<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All restartable servlets in the context are restarted. <br>
	 * <br>
	 * @return false if one or more restart requests fail, otherwise true.
	 */
	private synchronized boolean restartServlets()
	{
		String sMethod = "restartServlets()";
		boolean bEndResult = true;
		try {
			ServletContext oServletContext = _oServletConfig.getServletContext();

			HashMap htRestartServlets = (HashMap) oServletContext.getAttribute("restartable_servlets");
			if (htRestartServlets == null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Restart: no restartable servlets registered");
				return false;
			}

			oServletContext.setAttribute("restarting_servlets", "true");
			StringBuffer sbResult = new StringBuffer("Restart: ");

			Set keys = htRestartServlets.keySet();
			for (Object s : keys) {
				String sKey = (String) s;
				//Enumeration enumRestartServlets = htRestartServlets.keys();
				//while (enumRestartServlets.hasMoreElements())
				//{
				//	String sKey = (String)enumRestartServlets.nextElement();
				ASelectHttpServlet oASelectHttpServlet = (ASelectHttpServlet) htRestartServlets.get(sKey);
				boolean bResult = true;
				try {
					oASelectHttpServlet.init(oASelectHttpServlet.getServletConfig());
				}
				catch (Exception e) {
					bResult = false;
				}
				bEndResult &= bResult;

				sbResult.append(sKey).append(" (");
				sbResult.append(bResult ? "OK" : "Failed");
				sbResult.append(")");
				//if (enumRestartServlets.hasMoreElements())
				sbResult.append(", ");
			}
			int len = sbResult.length();
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbResult.substring(0, len - 2));

			oServletContext.removeAttribute("restarting_servlets");
		}
		catch (Exception e) {
			bEndResult = false;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Restarting servlets failed", e);
		}
		return bEndResult;
	}
}
