package org.aselect.server.request.handler.xsaml20.sp;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.Version;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.LogoutRequestSender;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.SingleLogoutService;

public class Xsaml20_Logout extends Saml20_BaseHandler
{
	private final static String _sModule = "Xsaml20_Logout";

	// The managers and engine
	private TGTManager _oTGTManager;

	private String _sFederationUrl; // the url to send the saml request to
	private String _sReturnUrl;
    private String _sFriendlyName = "";
    private String _sLogoutResultPage = "";

	/**
	 * Init for class Xsaml20_Logout. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig
	 * @param oConfig
	 *            Object
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";
		super.init(oServletConfig, oConfig);
		_oTGTManager = TGTManager.getHandle();

		Object aselect = _configManager.getSection(null, "aselect");
		_sFederationUrl = _configManager.getParam(aselect, "federation_url");
		_sReturnUrl = _configManager.getParam(aselect, "redirect_url");
		_sFriendlyName = _configManager.getParam(aselect, "organization_friendly_name");

	    _sLogoutResultPage = _configManager.loadHTMLTemplate(_configManager.getWorkingdir(), "logoutresult.html");    
	    _sLogoutResultPage = org.aselect.system.utils.Utils.replaceString(_sLogoutResultPage, "[version]", Version.getVersion());
	    // Was: [organization_friendly_name], replaced 20081104
	    _sLogoutResultPage = org.aselect.system.utils.Utils.replaceString(_sLogoutResultPage, "[organization_friendly]", _sFriendlyName);
	}

	/**
	 * Process the user's Logout request (received by the SP).
	 * Also send a "LogoutRequest" to the IdP.
	 * <br>
	 * 
	 * @param request
	 *            HttpServletRequest
	 * @param response
	 *            HttpServletResponse
	 * @throws ASelectException
	 *             If processing logout request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process";

		String paramRequest = request.getParameter("request");
		_systemLogger.log(Level.INFO, _sModule, sMethod, "request="+paramRequest);
		if ("kill_tgt".equals(paramRequest)) {
			handleKillTGTRequest(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "kill_tgt request expected");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		return null;
	}

	/**
	 * This function handles the <code>request=kill_tgt</code> request. <br>
	 * 
	 * @param request - The input message.
	 * @param response - The output message.
	 * @throws ASelectException - If proccessing fails.
	 */
	private void handleKillTGTRequest(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "handleKillTGTRequest";

		// get mandatory parameters
		String sEncTGT = request.getParameter("tgt_blob");
		String sASelectServer = request.getParameter("a-select-server");

		if (sEncTGT == null || sEncTGT.equals("") || sASelectServer == null || sASelectServer.equals("")) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameters");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		String sTGT = null;
		try {
			byte[] baTgtBlobBytes = CryptoEngine.getHandle().decryptTGT(sEncTGT);
			sTGT = Utils.toHexString(baTgtBlobBytes);
		}
		catch (ASelectException eAC) {  // decrypt failed
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eAC);
		}
		catch (IllegalArgumentException eIA) {  // HEX conversion fails
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eIA);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eIA);
		}

		// 20090627, Bauke: added option to supply return URL
		// can be done here, because this is a browser request
		String sLogoutReturnUrl = request.getParameter("logout_return_url");
		
		// Check if the TGT exists
		if (!_oTGTManager.containsKey(sTGT)) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unknown TGT / Already logged out");
			if (!"".equals(sLogoutReturnUrl)) {
				// Redirect to the url in sRelayState
				String sAmpQuest = (sLogoutReturnUrl.indexOf('?') >= 0) ? "&": "?"; 
				String url = sLogoutReturnUrl + sAmpQuest + "result_code=" + Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT;
				try {
					response.sendRedirect(url);
				}
				catch (IOException e) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, e.getMessage(), e);
				}
			}
			else {
				PrintWriter pwOut = null;
				try {					
					String sHtmlPage = Utils.replaceString(_sLogoutResultPage, "[result_code]", Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT);
					pwOut = response.getWriter();
				    response.setContentType("text/html");
		            pwOut.println(sHtmlPage);
					return;
				}
				catch (IOException e) {
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
				}
				finally {
		            if (pwOut != null) {
		                pwOut.close();
		            }
				}
			}
		}
		HashMap htTGTContext = _oTGTManager.getTGT(sTGT);

		// check if request should be signed
		// RH, 20080701, sn
		// This request comes from browser or the idp.
		// We know that the tgt if it exists is encrypted
		// Can we be sure it is signed? Can we be sure it is there?
		// TODO sort things out here
		// RH, 20080701, en
		// _systemLogger.log(Level.INFO, _sModule, sMethod, "NOTE SIGNING CHECK DISABLED"); // RH, 20080701, o
/*		if (_applicationManager.isSigningRequired()) {
			// Note: we should do this earlier, but we don't have an app_id until now
			String sAppId = (String) htTGTContext.get("app_id");
			StringBuffer sbData = new StringBuffer(sASelectServer).append(sEncTGT);
			verifyApplicationSignature(request, sbData.toString(), sAppId);
		}
*/
		// Kill the ticket granting ticket
		_oTGTManager.remove(sTGT);

		// Delete the client cookie
        String sCookieDomain = _configManager.getCookieDomain();
        HandlerTools.delCookieValue(response, "aselect_credentials", sCookieDomain, _systemLogger);

		// now send a saml LogoutRequest to the federation idp
		LogoutRequestSender logoutRequestSender = new LogoutRequestSender();
		String sNameID = (String) htTGTContext.get("name_id");

		// metadata
		MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
		String url = metadataManager.getLocation(_sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,
				SAMLConstants.SAML2_REDIRECT_BINDING_URI);

		if (url != null) {
			logoutRequestSender.sendLogoutRequest(url, _sReturnUrl/*issuer*/, sNameID,
						request, response, "urn:oasis:names:tc:SAML:2.0:logout:user", sLogoutReturnUrl);
		}
	}

	public void destroy()
	{
	}
}
