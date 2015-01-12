/**
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
package org.aselect.server.authspprotocol.handler;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthSPException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.utils.Utils;

/**
 * The SocialAuth AuthSP Handler. <br>
 * 
 * @author Bauke Hiemstra - www.anoigo.nl
 */
public class SocialAuthSPHandler implements IAuthSPProtocolHandler
{
	/** The module name. */
	private final static String MODULE = "SocialAuthSPHandler";

	/* Specific error codes from the AuthSP */
	private final static String SOCIAL_NO_ERROR = "000";
	private final static String SOCIAL_INVALID_REQUEST = "009";
	private final static String SOCIAL_INTERNAL_SERVER_ERROR = "010";

	private ASelectConfigManager _oConfigManager;
	private SessionManager _oSessionManager;
	private ASelectSystemLogger _systemLogger;
	private ASelectAuthenticationLogger _authenticationLogger;
	private String _sAuthsp;
	private String _sAuthspUrl;
	
	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#myRidName()
	 */
	public String getLocalRidName() { return "rid"; }

	/**
	 * @param oAuthSpConfig
	 *            the configuration object
	 * @param oAuthSpResource
	 *            the oAuthSp resource
	 * @throws ASelectAuthSPException
	 *
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
	 */
	public void init(Object oAuthSpConfig, Object oAuthSpResource)
	throws ASelectAuthSPException
	{
		String sMethod = "init";
		Object oASelectConfig = null;
		
		try {
			// retrieve handles
			_oConfigManager = ASelectConfigManager.getHandle();
			_oSessionManager = SessionManager.getHandle();
			_authenticationLogger = ASelectAuthenticationLogger.getHandle();
			_systemLogger = ASelectSystemLogger.getHandle();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Starting: "+MODULE);

			try {
				_sAuthsp = _oConfigManager.getParam(oAuthSpConfig, "id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'id' config item found in authsp section");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
			try {
				_sAuthspUrl = _oConfigManager.getParam(oAuthSpResource, "url");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'id' config item found in authsp resource section");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			try {
				oASelectConfig = _oConfigManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No main 'aselect' config section found", e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
		}
		catch (ASelectAuthSPException eAA) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", eAA);
			throw eAA;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize due to internal error", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Computes the request which will be sent to the Delegator AuthSP. <br>
	 * <br>
	 * 
	 * @param sRid
	 *            the s rid
	 * @return the hash map
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#computeAuthenticationRequest(java.lang.String)
	 */
	public HashMap computeAuthenticationRequest(String sRid, HashMap htSessionContext)
	{
		String sMethod = "computeAuthenticationRequest";
		String sSignature = null;
		String sServerId = null;
		StringBuffer sbTemp = null;
		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);

		try {
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session context available for rid="+sRid);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			HashMap htAllowedAuthsps = (HashMap) htSessionContext.get("allowed_user_authsps");
			if (htAllowedAuthsps == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Allowed user AuthSPs missing in session context.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			String sSocialLogin = (String)htSessionContext.get("social_login");
			if (!Utils.hasValue(sSocialLogin)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Parameter 'social_login' has no value");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			sbTemp = new StringBuffer((String) htSessionContext.get("my_url"));
			sbTemp.append("?authsp=").append(_sAuthsp);
			String sAsUrl = sbTemp.toString();
			
			String sCountry = (String) htSessionContext.get("country");
			if (sCountry == null || sCountry.trim().length() < 1) {
				sCountry = null;
			}
			String sLanguage = (String) htSessionContext.get("language");
			if (sLanguage == null || sLanguage.trim().length() < 1) {
				sLanguage = null;
			}
			
			try {
				sServerId = _oConfigManager.getParam(_oConfigManager.getSection(null, "aselect"), "server_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			String sAppId = (String)htSessionContext.get("app_id");
			if (sAppId == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "AppId missing in session context.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			// Signature calculation (before URL encoding)
			sbTemp = new StringBuffer(sAsUrl).append(sRid).append(sAppId).append(sServerId).append(sSocialLogin);
			if (sLanguage != null) sbTemp.append(sLanguage);
			if (sCountry != null) sbTemp.append(sCountry);
			sSignature = CryptoEngine.getHandle().generateSignature(_sAuthsp, sbTemp.toString());
			if (sSignature == null) {
				htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
				return htResponse;
			}
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Signature="+sSignature);

			try {
				sbTemp = new StringBuffer(_sAuthspUrl);
				sbTemp.append("?as_url=").append(URLEncoder.encode(sAsUrl, "UTF-8"));
				sbTemp.append("&rid=").append(sRid);
				sbTemp.append("&app_id=").append(URLEncoder.encode(sAppId, "UTF-8"));
				sbTemp.append("&a-select-server=").append(URLEncoder.encode(sServerId, "UTF-8"));
				sbTemp.append("&social_login=").append(sSocialLogin);
				if (sLanguage != null) sbTemp.append("&language=").append(sLanguage);
				if (sCountry != null) sbTemp.append("&country=").append(sCountry);
				sbTemp.append("&signature=").append(URLEncoder.encode(sSignature, "UTF-8"));
			
				htResponse.put("redirect_url", sbTemp.toString());
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Encoding failed: "+e);
				htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
		}
		catch (ASelectAuthSPException eAA) {  // allready logged
			htResponse.put("result", eAA.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not compute authentication request due to internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}

	/**
	 * Verifies the response coming from the Social AuthSP.<br>
	 * <br> 
	 * @param htAuthspResponse
	 *            the authsp response
	 * @param htSessionContext
	 *            the session context, must be available
	 * @return the result hash map
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#verifyAuthenticationResponse(java.util.HashMap)
	 */
	// 20120403, Bauke: added htSessionContext
	public HashMap verifyAuthenticationResponse(HashMap htAuthspResponse, HashMap htSessionContext)
	{
		String sMethod = "verifyAuthenticationResponse";
		StringBuffer sbTemp;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "htAuthspResponse=" + htAuthspResponse);

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);	// defensive approach
		try {
			String sRid = (String) htAuthspResponse.get("rid");
			String sAsUrl = (String) htAuthspResponse.get("my_url");
			String sResultCode = (String) htAuthspResponse.get("result_code");
			String sAsServer = (String) htAuthspResponse.get("a-select-server");
			String sUid = (String) htAuthspResponse.get("uid");
			String sSignature = (String) htAuthspResponse.get("signature");

			if ((sRid == null) || (sResultCode == null) || (sSignature == null) || (sAsServer == null)) {
				sbTemp = new StringBuffer("incorrect AuthSP response");
				_systemLogger.log(Level.WARNING, MODULE, sMethod,  sbTemp.toString());
				htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
				return htResponse;
			}
			sbTemp = new StringBuffer(sAsUrl).append("?authsp=").append(_sAuthsp);
			sAsUrl = sbTemp.toString();

			sSignature = URLDecoder.decode(sSignature, "UTF-8");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sSignature="+sSignature);
			sAsUrl = URLDecoder.decode(sAsUrl, "UTF-8");
			if (sUid != null) sUid = URLDecoder.decode(sUid, "UTF-8");
			
			sbTemp = new StringBuffer(sRid).append(sAsUrl).append(sResultCode).append(sAsServer);
			if (sUid != null)
				sbTemp.append(sUid);
			
			boolean bVerifies = CryptoEngine.getHandle().verifySignature(_sAuthsp, sbTemp.toString(), sSignature);
			if (!bVerifies) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid signature in response from AuthSP:" + _sAuthsp);
				htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
				return htResponse;
			}

			// 20120403, Bauke: session is available as a parameter
			String sOrg = (String) htSessionContext.get("organization");
			String sSocialLogin = (String)htSessionContext.get("social_login");
			if (sResultCode.equalsIgnoreCase(SOCIAL_NO_ERROR)) {
				// Log the user authentication
				_authenticationLogger.log(new Object[] { MODULE, sUid, htAuthspResponse.get("client_ip"),
						sOrg, (String) htSessionContext.get("app_id"), "granted,"+sSocialLogin
				});
				htResponse.put("rid", sRid);
				htResponse.put("uid", sUid);  // NOTE: this actually is the user's email address
				htResponse.put("result",  Errors.ERROR_ASELECT_SUCCESS);				
				return htResponse;
			}
			
			// Access denied
			_authenticationLogger.log(new Object[] { MODULE, sUid, htAuthspResponse.get("client_ip"),
				sOrg, (String) htSessionContext.get("app_id"), "denied", sResultCode+","+sSocialLogin
			});
			htResponse.put("authsp_type", "social");
			if (sResultCode.equalsIgnoreCase(SOCIAL_INVALID_REQUEST)) {
				sbTemp = new StringBuffer();
				sbTemp.append("error from from AuthSP: ").append(sResultCode);
				htResponse.put("result", Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			else if (sResultCode.equalsIgnoreCase(SOCIAL_INTERNAL_SERVER_ERROR)) {
				sbTemp = new StringBuffer();
				sbTemp.append("error from from AuthSP: ").append(sResultCode);
				htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			else {
				htResponse.put("result", sResultCode);
				sbTemp = new StringBuffer();
				sbTemp.append("error from from AuthSP: ").append(sResultCode);
			}
			_systemLogger.log(Level.INFO,  MODULE, sMethod, sbTemp.toString());
		}
		catch (Exception e) {
			sbTemp = new StringBuffer(e.getMessage());
			_systemLogger.log(Level.INFO,  MODULE, sMethod, sbTemp.toString());
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}
}