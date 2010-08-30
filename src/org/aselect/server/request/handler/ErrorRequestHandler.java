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

package org.aselect.server.request.handler;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

public class ErrorRequestHandler extends AbstractRequestHandler
{
	private final static String MODULE = "ErrorRequestHandler";
	private final static String SIAM_DEFAULT_ERROR_FILENAME = "error_request.html";
	private final static int SIAM_MAX_ERROCODE_LENGTH = 8;
	private final static List<String> VALID_LANGS = Arrays.asList(Locale.getISOLanguages()); 
	private final static List<String> VALID_CNTRY = Arrays.asList(Locale.getISOCountries()); 
	
	/**
	 * Init method <br>
	 * .
	 * 
	 * @param servletConfig
	 *            ServletConfig.
	 * @param config
	 *            Object.
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";
		try {
			super.init(oServletConfig, oConfig);
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
	 * Process incoming request <br>
	 * .
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If processing of meta data request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "process");
//		String sRid = request.getParameter("rid");
//		_systemLogger.log(Level.INFO, MODULE, "rid:", sRid);
		
//		_configManager.getForm(sForm, sLanguage, sCountry);
//		HashMap context = _oSessionManager.getSessionContext(sRid);
//		String appId = (String)context.get("app_id");
		
		// check for valid error_code	
		String sErrorCode = request.getParameter("error_code");
		sErrorCode = (sErrorCode != null) ? sErrorCode : "";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "error_code:" +  sErrorCode);
		try {
			@SuppressWarnings("unused")
			int nErrorCode = Integer.parseInt(sErrorCode);
		}
		catch (NumberFormatException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "error_code non-numeric, trimmed to " + SIAM_MAX_ERROCODE_LENGTH + " chars and urlencoded:" + sErrorCode);
			try {
				// We don't want anything nasty injected in the form
				sErrorCode = URLEncoder.encode(sErrorCode.substring(0, SIAM_MAX_ERROCODE_LENGTH), "UTF-8");
			}
			catch (UnsupportedEncodingException e1) {
				// This should not happen on "UTF-8"
				sErrorCode = sErrorCode.substring(0, SIAM_MAX_ERROCODE_LENGTH);
			}
		}
	
		showErrorPage(request, response, sErrorCode);
		return null;
	}

	
	/**
	 * Shows the application specific Error page with the appropriate errors. <br>
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
		String _sUserLanguage = request.getParameter("language");
		String _sUserCountry = request.getParameter("country");
		
	
		if (_sUserLanguage == null || "".equals(_sUserLanguage) || !VALID_LANGS.contains(_sUserLanguage.toLowerCase()) ) {
			_sUserLanguage = request.getLocale().getLanguage();
		}
		if ( _sUserCountry == null || "".equals(_sUserCountry) || !VALID_CNTRY.contains(_sUserCountry.toUpperCase()) ) {
			_sUserCountry = request.getLocale().getCountry();
		}
		// Only allow valid locales
		Locale loc = new Locale(_sUserLanguage, _sUserCountry);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Using locale language=" + loc.getLanguage() + ", country=" + loc.getCountry());
		
		String sErrorMessage = _configManager.getErrorMessage(sErrorCode, _sUserLanguage, _sUserCountry);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "FORM[error] " + sErrorCode + ":" + sErrorMessage);
		try {
			String app_id = request.getParameter("app_id");
			app_id = (app_id != null) ? app_id : "";
			String sFileName = SIAM_DEFAULT_ERROR_FILENAME;
			if (!"".equals(app_id)) {
				// get application specific error form
				// only allow for valid app_id
				try {
					Object app_section = _configManager.getSection( _configManager.getSection(null, "applications"), "application", "id=" + app_id);
					try {
						sFileName = _configManager.getParam(app_section, "error_page");
					}
					catch (ASelectConfigException e1) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "error_page tag not found in config for application:"+app_id + ", using default:" + SIAM_DEFAULT_ERROR_FILENAME);
					}
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "application config not found for application: "+app_id + " setting application to 'unknown'", e);
					app_id = "unknown";
				}
			}
			// .html will be stripped from sFileName
			String sErrorForm = _configManager.loadHTMLTemplate(_configManager.getWorkingdir(), sFileName, loc.getLanguage(), loc.getCountry());
			sErrorForm = Utils.replaceString(sErrorForm, "[error]", sErrorCode);  // obsoleted 20100817
			sErrorForm = Utils.replaceString(sErrorForm, "[error_code]", sErrorCode);
			sErrorForm = Utils.replaceString(sErrorForm, "[error_message]", sErrorMessage);
			sErrorForm = Utils.replaceString(sErrorForm, "[language]", loc.getLanguage());
			sErrorForm = Utils.replaceString(sErrorForm, "[country]", loc.getCountry());
			sErrorForm = Utils.replaceString(sErrorForm, "[app_id]", app_id);
			sErrorForm = Utils.handleAllConditionals(sErrorForm, Utils.hasValue(sErrorMessage), null, _systemLogger);
			// updateTemplate() accepts a null session to remove unused special fields!
			sErrorForm = _configManager.updateTemplate(sErrorForm, null /* no session available */);

			pwOut = response.getWriter();
			response.setContentType("text/html");
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

	
	
	public void destroy()
	{
		// do nothing, for now
	}
	
}
