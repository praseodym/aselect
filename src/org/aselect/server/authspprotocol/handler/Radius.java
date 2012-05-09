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
 * $Id: Radius.java,v 1.19 2006/05/03 09:46:50 tom Exp $ 
 * 
 * Changelog:
 * $Log: Radius.java,v $
 * Revision 1.19  2006/05/03 09:46:50  tom
 * Removed Javadoc version
 *
 * Revision 1.18  2006/04/03 08:44:12  erwin
 * Changed signature checking (fixed bug #165)
 *
 * Revision 1.17  2005/09/08 13:06:53  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.16  2005/05/02 13:22:01  martijn
 * removed logging: "starting Radius" that was displayed every authentication with radius
 *
 * Revision 1.15  2005/04/15 12:06:31  tom
 * Removed old logging statements
 *
 * Revision 1.14  2005/04/01 14:17:41  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.13  2005/03/23 11:02:44  erwin
 * Improved some log levels
 *
 * Revision 1.12  2005/03/23 10:56:33  erwin
 * - Added A-Select server ID to signing from AuthSP.
 * - Updated javadoc
 * - Fixed problem with session expiration
 *
 * Revision 1.11  2005/03/17 07:51:00  tom
 * Added IP to authentication log
 *
 * Revision 1.10  2005/03/10 16:16:46  tom
 * Added new Authentication Logger
 *
 * Revision 1.9  2005/03/10 08:16:34  tom
 * Added new Logger functionality
 *
 * Revision 1.8  2005/03/10 07:46:29  tom
 * Refactored errors
 *
 * Revision 1.7  2005/03/09 10:20:30  erwin
 * Renamed and moved errors.
 *
 * Revision 1.6  2005/03/08 08:37:27  leon
 * Bug fixed in the init
 *
 * Revision 1.5  2005/03/07 15:55:00  leon
 * Added Javadoc
 *
 * Revision 1.4  2005/03/04 16:26:31  leon
 * AuthSPProtocolHandler refactored to IAuthSPProtocolHandler
 *
 * Revision 1.3  2005/03/04 16:15:03  leon
 * new failure handling
 *
 * Revision 1.2  2005/03/04 13:41:46  leon
 * - Code Restyle
 * - Java doc added
 * - Authentication and System Logger handling
 *
 */
package org.aselect.server.authspprotocol.handler;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.system.error.Errors;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.exception.ASelectAuthSPException;
import org.aselect.system.exception.ASelectConfigException;

/**
 * The Radius AuthSP Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * The Radius AuthSP Handler communicates with the Radius AuthSP by redirecting the client. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * <br>
 * <b>Protocol Description:</b> <br>
 * <i><a name="outgoing">Outgoing request going to the Radius AuthSP:</a></i> <br>
 * <table border="1" cellspacing="0" cellpadding="3">
 * <tr>
 * <td style="" bgcolor="#EEEEFF"><b>name</b></td>
 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
 * </tr>
 * <tr>
 * <td>rid</td>
 * <td>A-Select Server request id</td>
 * </tr>
 * <tr>
 * <td>as_url</td>
 * <td>A-Select Server url</td>
 * </tr>
 * <tr>
 * <td>uid</td>
 * <td>A-Select Server user ID</td>
 * </tr>
 * <tr>
 * <td>a-select-server</td>
 * <td>A-Select Server ID</td>
 * </tr>
 * <tr>
 * <td>signature</td>
 * <td>Signature of all paramaters in the above sequence</td>
 * </tr>
 * </table>
 * <br>
 * <i><a name="incoming"> Incoming response, which is returned by the Radius AuthSP: </a></i>
 * <table border="1" cellspacing="0" cellpadding="3">
 * <tr>
 * <td style="" bgcolor="#EEEEFF"><b>name</b></td>
 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
 * </tr>
 * <tr>
 * <td>rid</td>
 * <td>A-Select Server request id</td>
 * </tr>
 * <tr>
 * <td>result_code</td>
 * <td>AuthSP result code</td>
 * </tr>
 * <tr>
 * <td>a-select-server</td>
 * <td>A-Select Server ID</td>
 * </tr>
 * <tr>
 * <td>signature</td>
 * <td>Signature over the following data:
 * <ol>
 * <li>rid</li>
 * <li>The URL that was created in <code>computeAuthenticationRequest()</code>
 * <li>result_code</li>
 * <li>a-select-server</li>
 * </ol>
 * </td>
 * </tr>
 * </table>
 * 
 * @author Alfa & Ariss
 */
public class Radius implements IAuthSPProtocolHandler
{
	private String _sAuthsp;
	private String _sAuthspUrl;
	private String _ASelectServerId;

	private ASelectConfigManager _oConfigManager;
	private SessionManager _oSessionManager;
	private ASelectSystemLogger _oASelectSystemLogger;
	private ASelectAuthenticationLogger _oASelectAuthenticationLogger;
	private final static String MODULE = "Radius";
	private final static String ERROR_RADIUS_NO_ERROR = "000";
	private final static String ERROR_RADIUS_ACCESS_DENIED = "800";
	
	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#myRidName()
	 */
	public String getLocalRidName() { return "rid"; }

	/**
	 * Initializes the Radius AuthSP handler. <br>
	 * Resolves the following config items:
	 * <ul>
	 * <li>The AuthSP id</li>
	 * <li>The url to the authsp (from the resource)</li>
	 * <li>The server id from the A-Select main config</li>
	 * </ul>
	 * 
	 * @param authSPConfig
	 *            the auth sp config
	 * @param authSPResource
	 *            the auth sp resource
	 * @throws ASelectAuthSPException
	 *             the a select auth sp exception
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
	 */
	public void init(Object authSPConfig, Object authSPResource)
		throws ASelectAuthSPException
	{
		String sMethod = "init()";
		Object oASelectConfig = null;
		try {
			_oConfigManager = ASelectConfigManager.getHandle();
			_oSessionManager = SessionManager.getHandle();
			_oASelectAuthenticationLogger = ASelectAuthenticationLogger.getHandle();
			_oASelectSystemLogger = ASelectSystemLogger.getHandle();
			try {
				_sAuthsp = _oConfigManager.getParam(authSPConfig, "id");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'id' config item found in authsp section");

				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			try {
				_sAuthspUrl = _oConfigManager.getParam(authSPResource, "url");
			}
			catch (ASelectConfigException e) {
				StringBuffer sbFailed = new StringBuffer(
						"No valid 'url' config item found in resource section of authsp with id='");
				sbFailed.append(_sAuthsp);
				sbFailed.append("'");
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString());

				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			try {
				oASelectConfig = _oConfigManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "No main 'aselect' config section found", e);

				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			try {
				_ASelectServerId = _oConfigManager.getParam(oASelectConfig, "server_id");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'server_id' config item found in main 'aselect' section");

				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
		}
		catch (ASelectAuthSPException eAA) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", eAA);
			throw eAA;
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize due to internal error", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Creates the Authentication Request for the Radius AuthSP, which will be send by redirecting the user. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method creates a hashtable with the follwing contents:
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF"><b>key</b></td>
	 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
	 * </tr>
	 * <tr>
	 * <td>result</td>
	 * <td>
	 * {@link Errors#ERROR_ASELECT_SUCCESS} or an error code if creating the authentication request URL fails</td>
	 * </tr>
	 * <tr>
	 * <td>redirect_url</td>
	 * <td>The URL to the AuthSP including the protocol parameters as specified in the <a href="#outgoing">class
	 * description</a>.</td>
	 * </tr>
	 * </table>
	 * 
	 * @param sRid
	 *            the s rid
	 * @return the hash map
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#computeAuthenticationRequest(java.lang.String)
	 */
	public HashMap computeAuthenticationRequest(String sRid, HashMap htSessionContext)
	{
		String sMethod = "computeAuthenticationRequest";
		StringBuffer sbTemp;

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		try {
			// 20120403, Bauke: passes as parameter: HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				sbTemp = new StringBuffer("could not fetch session context for rid=").append(sRid);
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbTemp.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			HashMap htAllowedAuthsps = (HashMap) htSessionContext.get("allowed_user_authsps");
			if (htAllowedAuthsps == null) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"allowed_user_authsps missing in session context");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			String sUserId = (String) htAllowedAuthsps.get(_sAuthsp);
			if (sUserId == null) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "missing radius user attributes ");
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

			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sAsUrl);
			sbSignature.append(sUserId);
			sbSignature.append(_ASelectServerId);

			if (sCountry != null)
				sbSignature.append(sCountry);

			if (sLanguage != null)
				sbSignature.append(sLanguage);

			String sSignature;
			sSignature = CryptoEngine.getHandle().generateSignature(_sAuthsp, sbSignature.toString());
			if (sSignature == null) {
				sbTemp = new StringBuffer("Could not generate signature for authsp: ").append(_sAuthsp);
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbTemp.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			sSignature = URLEncoder.encode(sSignature, "UTF-8");
			sUserId = URLEncoder.encode(sUserId, "UTF-8");
			sAsUrl = URLEncoder.encode(sAsUrl, "UTF-8");

			StringBuffer sbRedirect = new StringBuffer(_sAuthspUrl);
			sbRedirect.append("?as_url=").append(sAsUrl);
			sbRedirect.append("&rid=").append(sRid);
			sbRedirect.append("&uid=").append(sUserId);
			sbRedirect.append("&a-select-server=").append(_ASelectServerId);
			sbRedirect.append("&signature=").append(sSignature);

			if (sCountry != null)
				sbRedirect.append("&country=").append(sCountry);

			if (sLanguage != null)
				sbRedirect.append("&language=").append(sLanguage);

			htResponse.put("redirect_url", sbRedirect.toString());
			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectAuthSPException e) {
			htResponse.put("result", e.getMessage());
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}

	/**
	 * Checks the response from the Radius AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method verifies the response from the AuthSP. The response parameters are placed in
	 * <code>htAuthspResponse</code> and are described in the <a href="#incoming">class description</a>. <br>
	 * <br>
	 * This method creates a hashtable with the following contents:
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF"><b>key</b></td>
	 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
	 * </tr>
	 * <tr>
	 * <td>result</td>
	 * <td>
	 * {@link Errors#ERROR_ASELECT_SUCCESS} or an error code if the authentication response was invalid or the user
	 * was not authenticated.</td>
	 * </tr>
	 * <tr>
	 * <td>rid</td>
	 * <td>The A-Select request identifier of this authentication.</td>
	 * </tr>
	 * </table>
	 * 
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

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		try {
			String sRid = (String) htAuthspResponse.get("rid");
			String sAsUrl = (String) htAuthspResponse.get("my_url");
			String sResultCode = (String) htAuthspResponse.get("result_code");
			String sSignature = (String) htAuthspResponse.get("signature");
			String sAsId = (String) htAuthspResponse.get("a-select-server");

			if ((sRid == null) || (sResultCode == null) || (sAsId == null) || (sSignature == null)) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"Incorrect AuthSP response: one or more parameters missing.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			// create complete as_url
			sbTemp = new StringBuffer(sAsUrl);
			sbTemp.append("?authsp=");
			sbTemp.append(_sAuthsp);
			sAsUrl = sbTemp.toString();

			// validate signature
			sSignature = URLDecoder.decode(sSignature, "UTF-8");
			sbTemp = new StringBuffer(sRid);
			sbTemp.append(sAsUrl);
			sbTemp.append(sResultCode);
			sbTemp.append(sAsId);

			boolean bVerifies = false;
			bVerifies = CryptoEngine.getHandle().verifySignature(_sAuthsp, sbTemp.toString(), sSignature);
			if (!bVerifies) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "invalid signature in response from AuthSP:"
						+ _sAuthsp);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			// 20120403, Bauke: session is available as a parameter
			String sUserId = (String) htSessionContext.get("user_id");
			String sOrg = (String) htSessionContext.get("organization");

			if (sResultCode.equalsIgnoreCase(ERROR_RADIUS_ACCESS_DENIED)) {
				_oASelectAuthenticationLogger.log(new Object[] {
					MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg, (String) htSessionContext.get("app_id"),
					"denied", sResultCode
				});
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
			}
			else if (!sResultCode.equalsIgnoreCase(ERROR_RADIUS_NO_ERROR)) {
				sbTemp = new StringBuffer("error from AuthSP: ");
				sbTemp.append(sResultCode);
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbTemp.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			_oASelectAuthenticationLogger.log(new Object[] {
				MODULE, sUserId, htAuthspResponse.get("client_ip"), sOrg, (String) htSessionContext.get("app_id"),
				"granted"
			});

			htResponse.put("rid", sRid);
			htResponse.put("authsp_type", "radius");
			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectAuthSPException e) {
			htResponse.put("result", e.getMessage());
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}
}
