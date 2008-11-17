package org.aselect.server.request.handler.xsaml20.sp;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Hashtable;
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

//public class Xsaml20_Logout extends ProtoRequestHandler  // RH, 20080602, o
public class Xsaml20_Logout extends Saml20_BaseHandler  // RH, 20080602, n
{
	private final static String _sModule = "Xsaml20_Logout";

	// The managers and engine
	private TGTManager _oTGTManager;
//	private ApplicationManager _applicationManager;
//	private CryptoEngine _cryptoEngine;

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
		super.init(oServletConfig, oConfig);
		String sMethod = "init";
		_oTGTManager = TGTManager.getHandle();
//		_applicationManager = ApplicationManager.getHandle();

		Object aselect = _configManager.getSection(null, "aselect");
		_sFederationUrl = _configManager.getParam(aselect, "federation_url");
		_sReturnUrl = _configManager.getParam(aselect, "redirect_url");
		_sFriendlyName = _configManager.getParam(aselect, "organization_friendly_name");


	    _sLogoutResultPage = _configManager.loadHTMLTemplate(_configManager.getWorkingdir(), "logoutresult.html");    
	    _sLogoutResultPage = org.aselect.system.utils.Utils.replaceString(_sLogoutResultPage, "[version]", Version.getVersion());
	    // Was: [organization_friendly_name], replaced 20081104
	    _sLogoutResultPage = org.aselect.system.utils.Utils.replaceString(_sLogoutResultPage, "[organization_friendly]", _sFriendlyName);

	    /*try {
			_sLogoutPage = _configManager.getParam(aselect, "logout_page");
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod,
					"No config item 'logout_page' found in 'aselect' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}*/
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
		String sMethod = "process()";

		String paramRequest = request.getParameter("request");
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
	 * @param request
	 *            The input message.
	 * @param response
	 *            The output message.
	 * @throws ASelectException
	 *             If proccessing fails.
	 */
	private void handleKillTGTRequest(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "handleKillTGTRequest()";

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
		catch (ASelectException eAC) // decrypt failed
		{
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eAC);
		}
		catch (IllegalArgumentException eIA) // HEX conversion fails
		{
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eIA);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eIA);
		}

		// check if the TGT exists
		if (!_oTGTManager.containsKey(sTGT)) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unknown TGT");
			PrintWriter pwOut = null;
			try {
				// already logged out?
				//String url = _sLogoutPage + "?result_code=" + Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT;
				//response.sendRedirect(url);
				
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
		Hashtable htTGTContext = _oTGTManager.getTGT(sTGT);

		// check if request should be signed
		// RH, 20080701, sn
		// This request comes from browser or the idp.
		// We now that the tgt if it exists is encrypted
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

		//Cookie cookie = new Cookie("aselect_credentials", "no you cannot see me");
		//cookie.setMaxAge(0);
		//_systemLogger.log(Level.INFO, _sModule, sMethod, "Delete Cookie=" + "aselect_credentials");
		//response.addCookie(cookie);

		// now send a saml LogoutRequest to the federation idp
		LogoutRequestSender logoutRequestSender = new LogoutRequestSender();
		String sNameID = (String) htTGTContext.get("name_id");

		// metadata
		MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
		String url = metadataManager.getLocation(_sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,
				SAMLConstants.SAML2_REDIRECT_BINDING_URI);

		logoutRequestSender.sendLogoutRequest(url, _sReturnUrl, sNameID, request, response, "urn:oasis:names:tc:SAML:2.0:logout:user");
	}

	/**
	 * Verify the application signing signature. <br>
	 * <br>
	 * 
	 * @param request
	 *            The input message.
	 * @param sData
	 *            The data to validate upon.
	 * @param sAppId
	 *            The application ID.
	 * @throws ASelectException
	 *             If signature is invalid.
	 */
/*	private void verifyApplicationSignature(HttpServletRequest request, String sData, String sAppId)
	throws ASelectException
	{
		String sMethod = "verifyApplicationSignature()";

		String sSignature = request.getParameter("signature");
		if (sSignature == null || request.equals("")) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required 'signature' parameter");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		PublicKey pk = null;

		try {
			pk = _applicationManager.getSigningKey(sAppId);
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid application ID: \"" + sAppId
					+ "\". Could not find signing key for application.", e);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		if (!_cryptoEngine.verifyApplicationSignature(pk, sData, sSignature)) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid signature");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}*/

	public void destroy()
	{
	}
}
