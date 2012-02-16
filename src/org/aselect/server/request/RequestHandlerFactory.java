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
 * $Id: RequestHandlerFactory.java,v 1.3 2006/04/26 12:18:08 tom Exp $ 
 */

package org.aselect.server.request;

import java.io.IOException;

import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.IRequestHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

/**
 * Factory that invokes the appropriate request handler. <br>
 * <br>
 * <b>Description:</b><br>
 * Using the request URL this Factory will try and match it with the configured regular expressions and invoke the
 * associated request handler. The first match will process the request. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - The factory is singleton <br>
 * 
 * @author Alfa & Ariss
 */
public class RequestHandlerFactory
{
	private final static String MODULE = "RequestHandlerFactory";
	private static RequestHandlerFactory _oRequestHandlerFactory;
	private ASelectSystemLogger _systemLogger;
	private ASelectConfigManager _configManager;
	private HashMap<String, Object> _htRequestHandlers;
	private Vector _vRequestHandlers; // keeps the sequence intact
	private boolean firstRun = true;

	/**
	 * Initializes the Factory and the configured Request Handlers. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * <ul>
	 * <li>Reads the handler configurations</li>
	 * <li>Creates IAuthnRequestHandler objects</li>
	 * <li>Initializes the IAuthnRequestHandler objects</li>
	 * <li>Stores the objects in a HashMap</li>
	 * </ul>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * Requires the following configuration:<br/>
	 * <br/>
	 * &lt;requests&gt;<br/>
	 * &nbsp;&lt;handlers&gt;<br/>
	 * &nbsp;&nbsp;&lt;handler<br/>
	 * &nbsp;&nbsp;&nbsp;id='[unique handler name]'<br/>
	 * &nbsp;&nbsp;&nbsp;class='[class name]'<br/>
	 * &nbsp;&nbsp;&nbsp;target='[regular expression]'&gt;<br/>
	 * &nbsp;&nbsp;&nbsp;&nbsp;...<br/>
	 * &nbsp;&nbsp;&lt;/handler&gt;<br/>
	 * &nbsp;&lt;/handlers&gt;<br/>
	 * &lt;/requests&gt;<br/>
	 * <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - All initialized request handlers will be stored in the <code>_htRequestHandlers</code> - The sequence that must
	 * be used while matching a request is stored in <code>_vRequestHandlers</code> <br>
	 * 
	 * @param oServletConfig
	 *            The Servlet configuration of the Parent (Servlet) object
	 * @param oConfig
	 *            The configuration object containing the request handler config
	 * @throws ASelectException
	 *             if initalization fails
	 */
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";
		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			_configManager = ASelectConfigManager.getHandle();

			Object oHandlers = null;
			try {
				oHandlers = _configManager.getSection(oConfig, "handlers");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, "No config section 'handlers' found", e);
				throw e;
			}

			Object oHandler = null;
			try {
				oHandler = _configManager.getSection(oHandlers, "handler");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, "No config item 'handler' in section 'handlers' found", e);
				throw e;
			}

			_htRequestHandlers = new HashMap();
			_vRequestHandlers = new Vector();
			while (oHandler != null) {
				String sClass = null;
				try {
					sClass = _configManager.getParam(oHandler, "class");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, "No config item 'class' in section 'handler' found", e);
					throw e;
				}

				Class cRequestHandler = null;
				IRequestHandler oRequestHandler = null;
				try {
					cRequestHandler = Class.forName(sClass);
					oRequestHandler = (IRequestHandler) cRequestHandler.newInstance();
				}
				catch (Exception e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Not a correct 'IAuthnRequestHandler' class: "
							+ sClass, e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					oRequestHandler.init(oServletConfig, oHandler);
				}
				catch (ASelectException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Could not initialize IAuthnRequestHandler Object from class: " + sClass);
					throw e;
				}

				if (_htRequestHandlers.containsKey(oRequestHandler.getID())) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request handler id is not unique: "
							+ oRequestHandler.getID());
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}

				_htRequestHandlers.put(oRequestHandler.getID(), oRequestHandler);

				// The Vector contains the sequence of matching the requests
				// The sequence is now the sequence used in config
				_vRequestHandlers.add(oRequestHandler);

				_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully started request handler with ID: "
						+ oRequestHandler.getID());

				oHandler = _configManager.getNextSection(oHandler);
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
	 * Processes an incoming Servlet request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This function performs the following tasks:
	 * <ul>
	 * <li>Search for a matching requesthandler</li>
	 * <li>Invoke the matched requesthandler that will then process the request</li>
	 * <li>If the requesthandler returns with a request state containing a nexthandler, then the next handler will also
	 * be invoked</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param request
	 *            the HttpServletRequest containing the request
	 * @param response
	 *            the HttpServletResponse were the response will be send
	 * @throws ASelectException
	 *             if the matching request handler can't process the request
	 */
	public void process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process()";
		boolean bMatches = false;
		IRequestHandler oRequestHandler = null;
		RequestState oRequestState = null;

		try {
			String qry = request.getQueryString();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "TRY2MATCH " + request.getRequestURI() + ": "
					+ request.getContextPath() + "~" + request.getServletPath() + "~" + Utils.firstPartOf(qry, 30));

			Enumeration enumHandlers = _vRequestHandlers.elements();

			// Log them all
			while (enumHandlers.hasMoreElements() && firstRun) {
				oRequestHandler = (IRequestHandler) enumHandlers.nextElement();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "MATCH=" + oRequestHandler.getPattern() + " -> "
						+ oRequestHandler.getID());
			}
			firstRun = false;
			enumHandlers = _vRequestHandlers.elements();
			while (enumHandlers.hasMoreElements() && !bMatches) {
				oRequestHandler = (IRequestHandler) enumHandlers.nextElement();
				bMatches = matchTarget(request, oRequestHandler.getPattern());
			}

			if (bMatches && oRequestHandler != null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "HANDLE<< oRequestHandler=" + oRequestHandler.getID());
				oRequestState = oRequestHandler.process(request, response);
				_systemLogger.log(Level.INFO, MODULE, sMethod, ">>HANDLE oRequestHandler=" + oRequestHandler.getID());
			}

			// request handler chaining
			while (oRequestState != null && oRequestState.hasNextHandler()) {
				oRequestHandler = (IRequestHandler) _htRequestHandlers.get(oRequestState.getNextHandler());
				if (oRequestHandler != null) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "CHAIN<< oRequestHandler=" + oRequestHandler.getID());
					oRequestState = oRequestHandler.process(request, response);
					_systemLogger.log(Level.INFO, MODULE, sMethod, ">>CHAIN oRequestHandler=" + oRequestHandler.getID());
				}
				else
					oRequestState = null;
			}
		}
		// 20100509, Bauke: added, show result page to the user, instead of a blank screen
		catch (ASelectException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Processing failed, ASelectException="+e);
			showErrorPage(request, response, Errors.ERROR_ASELECT_INTERNAL_ERROR);
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Processing failed, Exception="+e);
			showErrorPage(request, response, Errors.ERROR_ASELECT_INTERNAL_ERROR);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Returns an instance of this object. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * creates a new instance of the <code>RequestHandlerFactory</code> if the <code>_oRequestHandlerFactory</code>
	 * variable is <code>null</code>, else returns the object containing the <code>_oRequestHandlerFactory</code>
	 * object. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - An instance of the class according the Singleton design pattern <br>
	 * 
	 * @return always the same <code>RequestHandlerFactory</code> instance
	 */
	public static RequestHandlerFactory getHandle()
	{
		if (_oRequestHandlerFactory == null)
			_oRequestHandlerFactory = new RequestHandlerFactory();

		return _oRequestHandlerFactory;
	}

	/**
	 * Destroys all objects created as class instance by this object. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * clears the class variables <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 */
	public void destroy()
	{
		if (_vRequestHandlers != null)
			_vRequestHandlers.clear();

		for (Map.Entry<String, Object> entry : _htRequestHandlers.entrySet()) {
			IRequestHandler oRequestHandler = (IRequestHandler) entry.getValue();
			oRequestHandler.destroy();
		}
	}

	/**
	 * Contructor has been made private according the Singleton pattern.
	 */
	private RequestHandlerFactory() {
		// does nothing
	}

	/**
	 * Matches the request URI to with the configured regular expression. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Compares the request URI to the regular expression configured for the request handler <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>request != null</li> <li>pTargetPattern != null</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param request
	 *            the HttpServletRequest containing the request
	 * @param pTargetPattern
	 *            the Pattern containing the regular expression
	 * @return TRUE if request URI matches the supplied pattern
	 * @throws ASelectException
	 *             if an error ocurred while matching
	 */
	private boolean matchTarget(HttpServletRequest request, Pattern pTargetPattern)
		throws ASelectException
	{
		String sMethod = "matchTarget()";
		boolean bReturn = false;
		StringBuffer sbCompareTo = new StringBuffer();

		try {
			// request info
			String sContextPath = request.getContextPath();
			String sServletPath = request.getServletPath();
			String sQueryString = request.getQueryString();

			// compare to info
			String sRequestURI = request.getRequestURI();
			String sCompareTo = sRequestURI.substring(sContextPath.length() + sServletPath.length());

			sbCompareTo.append(sCompareTo);

			if (sQueryString != null) {
				sbCompareTo.append('?');
				sbCompareTo.append(sQueryString);
			}

			// int len = sbCompareTo.length();
			// if (len > 40) len = 40;
			// _systemLogger.log(Level.INFO, MODULE, sMethod, "MATCH "+pTargetPattern.toString()+"<>" +
			// sbCompareTo.substring(0, len)+"...");
			Matcher mTarget = pTargetPattern.matcher(sbCompareTo.toString());

			bReturn = mTarget.matches();
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not match pattern", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return bReturn;
	}

	/**
	 * Gets the request handlers.
	 * 
	 * @return the request handlers
	 */
	public Vector getRequestHandlers()
	{
		return _vRequestHandlers;
	}
	
	/**
	 * Shows the main A-Select Error page with the appropriate errors. <br>
	 * <br>
	 * @param request - the HTTP request
	 * @param response - the HTTP response
	 * @param sErrorCode - error code to display
	 * @throws ASelectException - on failure
	 */
	protected void showErrorPage(HttpServletRequest request, HttpServletResponse response, String sErrorCode)
	throws ASelectException
	{
		String sMethod = "showErrorPage";
		PrintWriter pwOut = null;
		
		Locale loc = request.getLocale();
		String _sUserLanguage = loc.getLanguage();
		String _sUserCountry = loc.getCountry();
		String sErrorMessage = _configManager.getErrorMessage(sErrorCode, _sUserLanguage, _sUserCountry);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "FORM[error] " + sErrorCode + ":" + sErrorMessage);
		try {
			String sErrorForm = _configManager.getForm("error", _sUserLanguage, _sUserCountry);
			sErrorForm = Utils.replaceString(sErrorForm, "[error]", sErrorCode);  // obsoleted 20100817
			sErrorForm = Utils.replaceString(sErrorForm, "[error_code]", sErrorCode);
			sErrorForm = Utils.replaceString(sErrorForm, "[error_message]", sErrorMessage);
			sErrorForm = Utils.replaceString(sErrorForm, "[language]", _sUserLanguage);
			sErrorForm = Utils.handleAllConditionals(sErrorForm, Utils.hasValue(sErrorMessage), null, _systemLogger);
			// updateTemplate() accepts a null session to remove unused special fields!
			sErrorForm = _configManager.updateTemplate(sErrorForm, null /* no session available */);

			pwOut = response.getWriter();
			response.setContentType("text/html");
			Tools.pauseSensorData(_systemLogger, null);  //20111102, no session available at this point
			pwOut.println(sErrorForm);
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Display error page: IO Exception, errorCode="+sErrorCode, e);
			throw new ASelectException(Errors.ERROR_ASELECT_IO, e);
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Display error page: ASelectException, sErrorCode="+sErrorCode, e);
			throw e;
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
		}
	}

}
