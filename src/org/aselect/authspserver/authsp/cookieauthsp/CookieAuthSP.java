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
package org.aselect.authspserver.authsp.cookieauthsp;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.authsp.AbstractAuthSP;
import org.aselect.authspserver.authsp.cookieauthsp.Errors;
import org.aselect.authspserver.session.AuthSPPreviousSessionManager;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Utils;

/**
 * . <br>
 * CookieAuthSP is an AuthSP used for authentication based on previously set cookie <br>
 * <b>Description: </b> <br>
 * The CookieAuthSP uses the existence of a previously stored cookie as an access denied or access granted. <br>
 * <br>
 * 
 */
public class CookieAuthSP extends AbstractAuthSP  // 20141201, Bauke: inherit goodies from AbstractAuthSP
{
	private static final long serialVersionUID = -2996268295941444515L;
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static String MODULE = "CookieAuthSP";
	/**
	 * The Cookie AuthSP version string
	 */
	private static String VERSION = "A-Select CookieAuthSP 1.0";

	/** The PreviousSessionmanager */
	private AuthSPPreviousSessionManager _previousSessionManager;

	/**
	 * The authentication mode that is configured
	 */
	private String _sAuthMode;

	//private String _sFailureHandling;
	
	/**
	 * Initialization of the CookieAuthSPP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The CookieAuthSP uses the following components from the A-Select AuthSP Server<br>
	 * - the config manager<br>
	 * - the crypto engine<br>
	 * - the user friendly name<br>
	 * - the working directory<br>
	 * <br>
	 * Initialization includes:<br>
	 * - It loads the AuthSP components from the servlet context.<br>
	 * - It loads the error messages from the errors.conf file.<br>
	 * - It loads the error.html file.<br>
	 * - Sets the configured authentication_mode (default = grant all users)<br>
	 * <br>
	 * <br>
	 * <b>Preconditions:</b><br>
	 * - the AuthSPServer must be succesfully started<br>
	 * - an error config file must exist:<br>
	 * <i>workingdir/conf/cookieauthsp/errors/errors.conf</i><br>
	 * - an error template file must exist:<br>
	 * <i>workingdir/conf/cookieauthsp/html/error.html</i><br>
	 * - needs an 'authsp' config section with name='cookieauthsp' in the configuration of the AuthSP Server <br>
	 * <br>
	 * 
	 * @param oServletConfig
	 *            the servlet config
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	@Override
	public void init(ServletConfig oServletConfig)
	throws ServletException
	{
		String sMethod = "init";

		try {
			super.init(oServletConfig, true, Errors.ERROR_COOKIE_INTERNAL);

			StringBuffer sbInfo = new StringBuffer("Starting: ").append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			_previousSessionManager = AuthSPPreviousSessionManager.getHandle();
			
			// pre-load error form
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "error.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");

			sbInfo = new StringBuffer("Successfully started: ").append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		catch (ASelectException ase) {
			throw new ServletException(ase);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR", e);
			StringBuffer sbError = new StringBuffer("Could not initialize ");
			sbError.append(MODULE).append(" : ").append(e.getMessage());
			throw new ServletException(sbError.toString(), e);
		}
	}

	/**
	 * Processes requests for HTTP <code>GET</code>. <br>
	 * <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">name</td>
	 * <td style="" bgcolor="#EEEEFF">value</td>
	 * <td style="" bgcolor="#EEEEFF">encoded</td>
	 * </tr>
	 * <tr>
	 * <td>rid</td>
	 * <td>A-Select Server request id</td>
	 * <td>no</td>
	 * </tr>
	 * <tr>
	 * <td>as_url</td>
	 * <td>A-Select Server URL</td>
	 * <td>yes</td>
	 * </tr>
	 * <tr>
	 * <td>uid</td>
	 * <td>A-Select User ID</td>
	 * <td>yes</td>
	 * </tr>
	 * <tr>
	 * <td>a-select-server</td>
	 * <td>A-Select Server ID</td>
	 * <td>no</td>
	 * </tr>
	 * <tr>
	 * <td>signature</td>
	 * <td>signature of all paramaters in the above sequence</td>
	 * <td>yes</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ServletException, java.io.IOException
	{
		String sMethod = "doGet";
		String sQueryString = "";
		String sLanguage = null;
		
		servletResponse.setContentType("text/html; charset=utf-8");
		setDisableCachingHttpHeaders(servletRequest, servletResponse);
		sQueryString = servletRequest.getQueryString();
		HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, true);  // URL decoded result

		try {
			sLanguage = (String) htServiceRequest.get("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;			
			String sCountry = (String) htServiceRequest.get("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;
			
			String sMyUrl = servletRequest.getRequestURL().toString();
			htServiceRequest.put("my_url", sMyUrl);

			String sRid = (String) htServiceRequest.get("rid");
			String sAsUrl = (String) htServiceRequest.get("as_url");
			String sCookiename = (String) htServiceRequest.get("cookiename");
			String sAsId = (String) htServiceRequest.get("a-select-server");
			String sSignature = (String) htServiceRequest.get("signature");

			if ((sRid == null) || (sAsUrl == null) || (sCookiename == null) || (sAsId == null) || (sSignature == null)) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Invalid request, at least one mandatory parameter is missing.");
				throw new ASelectException(Errors.ERROR_COOKIE_INVALID_REQUEST);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "GET {"+servletRequest+" --> "+sMethod+": "+sQueryString);

			// 20120110, Bauke: no longer needed, done by convertCGIMessage()
			//sAsUrl = URLDecoder.decode(sAsUrl, "UTF-8");
			//sUid = URLDecoder.decode(sUid, "UTF-8");
			//sSignature = URLDecoder.decode(sSignature, "UTF-8");

			StringBuffer sbSignature = new StringBuffer(sRid).append(sAsUrl);
			sbSignature.append(sCookiename).append(sAsId);

			// optional country and language code
			if (sCountry != null) sbSignature.append(sCountry);
			if (sLanguage != null) sbSignature.append(sLanguage);

			if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
				throw new ASelectException(Errors.ERROR_COOKIE_INVALID_REQUEST);
			}

			// Get cookie value here and verify if we know this cookie
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Looking for cookie with name:" + sCookiename);
			
			Cookie[] cookies = servletRequest.getCookies();
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Number of cookies found= " + (cookies == null ? 0 : cookies.length));
			String v = null;
			Hashtable htPreviousSessionContext = null;
			for ( Cookie c : cookies) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found cookie: " + c.getName() + ", with value: " +  c.getValue());
				if (c.getName().equalsIgnoreCase(sCookiename)) {
					v = c.getValue();
					break;
				}
			}
			_sAuthMode = Errors.ERROR_COOKIE_ACCESS_DENIED;
			
			if ( v != null ) { // we found a value for our cookie
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found cookie value:" + v);
				// We verify if we know this cookie here
				
				try {
					htPreviousSessionContext = (Hashtable) _previousSessionManager.getHandle().get(v);
					
				} catch (ASelectStorageException e) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Cookie value not in storage");
					htPreviousSessionContext = null;
				}
				if (htPreviousSessionContext != null) {
					_sAuthMode = Errors.ERROR_COOKIE_SUCCESS;
					_authenticationLogger.log(new Object[] {
							MODULE, sCookiename, servletRequest.getRemoteAddr(), sAsId, "granted"
					});
					
				} else {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "No cookie found with name:" + sCookiename);
					_sAuthMode = Errors.ERROR_COOKIE_ACCESS_DENIED;
					_authenticationLogger.log(new Object[] {
							MODULE, sCookiename, servletRequest.getRemoteAddr(), sAsId, "denied", _sAuthMode
					});
					
				}
			} else {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No cookie found with name:" + sCookiename);
				_sAuthMode = Errors.ERROR_COOKIE_ACCESS_DENIED;
				_authenticationLogger.log(new Object[] {
						MODULE, sCookiename, servletRequest.getRemoteAddr(), sAsId, "denied", _sAuthMode
				});
			}
			
			handleResult(htServiceRequest, servletResponse, _sAuthMode, sLanguage, _sFailureHandling, htPreviousSessionContext);
		}
		catch (ASelectException e) {
			handleResult(htServiceRequest, servletResponse, e.getMessage(), sLanguage, _sFailureHandling);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			handleResult(htServiceRequest, servletResponse, Errors.ERROR_COOKIE_COULD_NOT_AUTHENTICATE_USER, sLanguage, _sFailureHandling);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "} NULL GET");
	}

	/**
	 * Private entry point of the CookieAuthSP. This will not be used, so always an error page will be shown. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ServletException, java.io.IOException
	{
		String sMethod = "doPost";

		servletResponse.setContentType("text/html; charset=utf-8");
		setDisableCachingHttpHeaders(servletRequest, servletResponse);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "CookieAuthSP POST {" + servletRequest + ", qry="
				+ servletRequest.getQueryString());

		String request = (String)servletRequest.getParameter("request");  // is URLdecoded
		String cookiename = (String)servletRequest.getParameter("cookiename");
		String sTgt = (String)servletRequest.getParameter("tgt");
		String uid = (String)servletRequest.getParameter("uid");
		
		String sAsId = (String)servletRequest.getParameter("a-select-server");
		String sSignature = (String)servletRequest.getParameter("signature");
		
		StringBuffer sbSignature = new StringBuffer(request);
		sbSignature.append(cookiename);
		sbSignature.append(sTgt);
		sbSignature.append(uid == null ? "" : uid);
		sbSignature.append(sAsId);


		HashMap serviceRequest = new HashMap();
		// we have to get some sort of rid and AsUrl and language

		StringBuffer sbResponse = new StringBuffer("status=");
		
		if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
			sbResponse.append(Errors.ERROR_COOKIE_INVALID_REQUEST);
		} else {
			
			// Do the cookie save stuff here
			Hashtable htPreviousSessionContext = new Hashtable();

			htPreviousSessionContext.put(cookiename, sTgt);
			htPreviousSessionContext.put("uid", uid);
			try {
				_previousSessionManager.create(sTgt, htPreviousSessionContext);
				sbResponse.append(Errors.ERROR_COOKIE_SUCCESS);
			}
			catch (ASelectStorageException e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Cookie already present:" + sTgt);
				sbResponse.append(Errors.ERROR_COOKIE_INVALID_REQUEST);
			}
		}
	
		String response = sbResponse.toString();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Respond with result:" + response);
		servletResponse.setContentLength(response.length());
		servletResponse.getWriter().write(response);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "End CookieAuthSP POST");
	}

	/**
	 * Determines whether or not the CookieAuthSP is restartable. <br>
	 * <br>
	 * 
	 * @return true, if checks if is restartable servlet
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	@Override
	protected boolean isRestartableServlet()
	{
		// RM_17_01
		return false;
	}

	private void handleResult(HashMap servletRequest, HttpServletResponse servletResponse,
			String sResultCode, String sLanguage, String failureHandling)
	throws IOException
	{	
		handleResult(servletRequest, servletResponse, sResultCode, sLanguage, failureHandling, null);
	}
	
	/**
	 * Creates a redirect url and redirects the user back to the A-Select Server. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            The servlet request
	 * @param servletResponse
	 *            The servlet response
	 * @param sResultCode
	 *            The error code that should be sent to the A-Select Server
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	private void handleResult(HashMap servletRequest, HttpServletResponse servletResponse,
					String sResultCode, String sLanguage, String failureHandling, Hashtable previousSessionContext)
	throws IOException
	{
		String sMethod = "handleResult";

		PrintWriter pwOut = null;
		try {
			pwOut = servletResponse.getWriter();
			if (failureHandling.equalsIgnoreCase(DEFAULT_FAILUREHANDLING) || sResultCode.equals(Errors.ERROR_COOKIE_SUCCESS)) {
				String sRid = (String)servletRequest.get("rid");
				String sAsUrl = (String)servletRequest.get("as_url");
				String sAsId = (String)servletRequest.get("a-select-server");
				if (sRid == null || sAsUrl == null || sAsId == null) {
					getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
				}
				else {
					StringBuffer sbSignature = new StringBuffer(sRid);
					sbSignature.append(sResultCode);
					
					String uid = "";
					if (previousSessionContext != null && previousSessionContext.get("uid") != null ) {
						uid = (String) previousSessionContext.get("uid");
					}
					sbSignature.append(uid);
					sbSignature.append(sAsId);
					String sSignature = _cryptoEngine.generateSignature(sbSignature.toString());

					// rid those not need to be url encoded by definition contains no characters to be encoded
					// a-select-server is never url encoded because of the way aselectserver handles this parameter

					StringBuffer sbRedirect = new StringBuffer(sAsUrl);
					sbRedirect.append("&rid=").append(sRid);
					sbRedirect.append("&result_code=").append(URLEncoder.encode(sResultCode, "UTF-8"));
					sbRedirect.append("&uid=").append(URLEncoder.encode(uid, "UTF-8"));
					sbRedirect.append("&a-select-server=").append(sAsId);
					sbRedirect.append("&signature=").append(URLEncoder.encode(sSignature, "UTF-8"));

					_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIR " + sbRedirect);
					servletResponse.sendRedirect(sbRedirect.toString());
				}
			}
			else {
				getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
			}
		}
		catch (ASelectException eAS) // could not generate signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate CookieAuthSP signature", eAS);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_COOKIE_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (UnsupportedEncodingException eUE) // could not encode signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode NULL AuthSP signature", eUE);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_COOKIE_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (IOException eIO) // Could not write output
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "IO error while handling authentication result", eIO);
			throw eIO;
		}
		finally {
			if (pwOut != null)
				pwOut.close();
		}
	}
}