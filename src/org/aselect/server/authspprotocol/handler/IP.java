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
 * $Id: IP.java,v 1.9 2006/05/03 09:46:50 tom Exp $ 
 * 
 * Changelog:
 * $Log: IP.java,v $
 * Revision 1.9  2006/05/03 09:46:50  tom
 * Removed Javadoc version
 *
 * Revision 1.8  2005/09/08 13:06:53  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/04/01 14:17:41  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.6  2005/03/24 16:02:53  martijn
 * redirecting the ipranges seperated by &
 *
 * Revision 1.5  2005/03/24 15:28:19  martijn
 * initialize HashMap
 *
 * Revision 1.4  2005/03/24 15:21:45  martijn
 * using array.size() instead of capacity
 *
 * Revision 1.3  2005/03/24 15:16:01  martijn
 * retrieving id of iprange from the iprange config section
 *
 * Revision 1.2  2005/03/24 14:42:52  martijn
 * code restyle, javadoc and error handling
 *
 */

package org.aselect.server.authspprotocol.handler;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Vector;
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

/**
 * The IP AuthSP Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * The IP AuthSP Handler communicates with the IP AuthSP by using redirections. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * <br>
 * <b>Protocol Description</b> <br>
 * <i><a name="outgoing">Outgoing request going to the IP AuthSP:</a></i> <br>
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
 * <td>uid</td>
 * <td>A-Select Server user ID</td>
 * </tr>
 * <tr>
 * <td>as_url</td>
 * <td>A-Select Server url</td>
 * </tr>
 * <tr>
 * <td>iprange[1..n]</td>
 * <td>All configured ip ranges (numbered)</td>
 * </tr>
 * <tr>
 * <td>a-select-server</td>
 * <td>A-Select Server ID</td>
 * </tr>
 * <tr>
 * <td>signature</td>
 * <td>signature of all paramater values in the above sequence</td>
 * </tr>
 * </table>
 * <br>
 * <i><a name="incoming"> Incoming response, which is returned by the IP AuthSP: </a></i> <br>
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
public class IP implements IAuthSPProtocolHandler
{
	private final static String MODULE = "IP";
	private final static String IP_ACCESS_DENIED = "800";
	private final static String IP_NO_ERROR = "000";

	private ASelectConfigManager _oASelectConfigManager;
	private SessionManager _oSessionManager;
	private ASelectSystemLogger _oASelectSystemLogger;
	private ASelectAuthenticationLogger _oASelectAuthenticationLogger;
	private CryptoEngine _oCryptoEngine;

	private String _sAuthsp;
	private String _sAuthspUrl;
	private String _sASelectID;

	private HashMap _htIPRangesCGI;
	private HashMap _htIPRanges;
	
	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#myRidName()
	 */
	public String getLocalRidName() { return "rid"; }

	/**
	 * Initializes the <code>IP</code> AuthSP handler. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Performs the following steps:
	 * <ul>
	 * <li>Retrieve handles to required managers and loggers</li>
	 * <li>Retrieve A-Select Server ID from configuration</li>
	 * <li>Retrieve AuthSP ID from configuration</li>
	 * <li>Retrieve all ip ranges from configuration</li>
	 * <li>Retrieve AuthSP URL from configuration</li>
	 * </ul>
	 * <br>
	 * 
	 * @param oAuthSPConfig
	 *            the o auth sp config
	 * @param oAuthSPResource
	 *            the o auth sp resource
	 * @throws ASelectAuthSPException
	 *             the a select auth sp exception
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
	 */
	public void init(Object oAuthSPConfig, Object oAuthSPResource)
	throws ASelectAuthSPException
	{
		String sMethod = "init()";

		_htIPRanges = new HashMap();
		_htIPRangesCGI = new HashMap();

		try {
			_oASelectConfigManager = ASelectConfigManager.getHandle();
			_oSessionManager = SessionManager.getHandle();
			_oASelectAuthenticationLogger = ASelectAuthenticationLogger.getHandle();
			_oASelectSystemLogger = ASelectSystemLogger.getHandle();
			_oCryptoEngine = CryptoEngine.getHandle();

			Object oASelect = null;
			try {
				oASelect = _oASelectConfigManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'aselect' config section found", e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sASelectID = _oASelectConfigManager.getParam(oASelect, "server_id");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'server_id' config item in 'aselect' section found", e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sAuthsp = _oASelectConfigManager.getParam(oAuthSPConfig, "id");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'id' config item found", e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sAuthspUrl = _oASelectConfigManager.getParam(oAuthSPResource, "url");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'url' config item found", e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			Object oApplications = null;
			try {
				oApplications = _oASelectConfigManager.getSection(oAuthSPConfig, "applications");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'applications' config section found", e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			Object oApplication = null;
			try {
				oApplication = _oASelectConfigManager.getSection(oApplications, "application");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'application' config section found", e);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			while (oApplication != null) {
				String sAppID = null;
				try {
					sAppID = _oASelectConfigManager.getParam(oApplication, "app_id");
				}
				catch (ASelectConfigException e) {
					_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
							"No valid 'app_id' config item found in 'application' section", e);
					throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				Object oIPRange = null;
				try {
					oIPRange = _oASelectConfigManager.getSection(oApplication, "iprange");
				}
				catch (ASelectConfigException e) {
					_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
							"No valid 'iprange' config section found", e);
					throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				Vector vRanges = new Vector();
				while (oIPRange != null) {
					String sRangeID = null;
					try {
						sRangeID = _oASelectConfigManager.getParam(oIPRange, "id");
					}
					catch (ASelectConfigException e) {
						StringBuffer sbError = new StringBuffer(
								"No valid 'id' config item found in 'application' section with 'app_id':");
						sbError.append(sAppID);

						_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
						throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					if (sRangeID.length() > 0)
						vRanges.add(sRangeID);

					oIPRange = _oASelectConfigManager.getNextSection(oIPRange);
				}

				StringBuffer sbRangesCGI = new StringBuffer();
				StringBuffer sbRanges = new StringBuffer();
				for (int i = 0; i < vRanges.size(); i++) {
					String sRangeID = (String) vRanges.get(i);
					sbRangesCGI.append("&");
					sbRangesCGI.append("ip_range");
					sbRangesCGI.append(i + 1);
					sbRangesCGI.append("=");
					sbRangesCGI.append(sRangeID);

					sbRanges.append(sRangeID);
				}

				if (sbRanges.length() > 0) {
					// TODO The IP ranges CGI string must become an official CGI Array (Martijn)
					_htIPRangesCGI.put(sAppID, sbRangesCGI.toString());
					_htIPRanges.put(sAppID, sbRanges.toString());
				}

				oApplication = _oASelectConfigManager.getNextSection(oApplication);
			}

		}
		catch (ASelectAuthSPException e) {
			throw e;
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize IP AuthSP Handler", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Creates the authentication request URL. <br>
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
	 * <td>The URL to the AuthSP including the protocol parameters as specified if the <a href="#outgoing">class
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

		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		try {
			// 20120403, Bauke: passes as parameter: HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				StringBuffer sbError = new StringBuffer("could not fetch session context for rid: ");
				sbError.append(sRid);
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			String sAppId = (String) htSessionContext.get("app_id");
			if (sAppId == null) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "No 'app_id' found in session");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			String sUserId = (String) htSessionContext.get("user_id");

			// find configured ip ranges
			String sIPRangesCGI = (String) _htIPRangesCGI.get(sAppId);
			if (sIPRangesCGI == null) {
				StringBuffer sbError = new StringBuffer("no ip ranges defined for app_id: ");
				sbError.append(sAppId);
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			String sIPRanges = (String) _htIPRanges.get(sAppId);
			if (sIPRanges == null) {
				StringBuffer sbError = new StringBuffer("no ip ranges defined for app_id: ");
				sbError.append(sAppId);
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			String sMyURL = (String) htSessionContext.get("my_url");
			StringBuffer sbMyURL = new StringBuffer(sMyURL);
			sbMyURL.append("?authsp=");
			sbMyURL.append(_sAuthsp);
			String sAsUrl = sbMyURL.toString();

			String sCountry = (String) htSessionContext.get("country");
			if (sCountry == null || sCountry.trim().length() < 1) {
				sCountry = null;
			}

			String sLanguage = (String) htSessionContext.get("language");
			if (sLanguage == null || sLanguage.trim().length() < 1) {
				sLanguage = null;
			}

			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sUserId);
			sbSignature.append(sAsUrl);
			sbSignature.append(sIPRanges);
			sbSignature.append(_sASelectID);

			if (sCountry != null)
				sbSignature.append(sCountry);

			if (sLanguage != null)
				sbSignature.append(sLanguage);

			String sSignature = _oCryptoEngine.generateSignature(_sAuthsp, sbSignature.toString());
			if (sSignature == null) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate signature");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			sSignature = URLEncoder.encode(sSignature, "UTF-8");
			sAsUrl = URLEncoder.encode(sAsUrl, "UTF-8");
			sUserId = URLEncoder.encode(sUserId, "UTF-8");

			StringBuffer sbRedirect = new StringBuffer(_sAuthspUrl);
			sbRedirect.append("?as_url=").append(sAsUrl);
			sbRedirect.append("&rid=").append(sRid);
			sbRedirect.append("&uid=").append(sUserId);
			sbRedirect.append("&a-select-server=").append(_sASelectID);

			if (sCountry != null)
				sbRedirect.append("&country=").append(sCountry);

			if (sLanguage != null)
				sbRedirect.append("&language=").append(sLanguage);

			// TODO The id's of the ranges must be encoded (Martijn)
			sbRedirect.append(sIPRangesCGI);
			sbRedirect.append("&signature=").append(sSignature);

			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
			htResponse.put("redirect_url", sbRedirect.toString());
		}
		catch (ASelectAuthSPException e) {
			htResponse.put("result", e.getMessage());
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not compute authentication request due to internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}

	/**
	 * Verifies the response from the AuthSP. <br>
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
	 * @param htAuthSPResponse
	 *            the auth sp response
	 * @param htSessionContext
	 *            the session context, must be available
	 * @param htSessionContext
	 *            the session context, must be available
	 * @return the result hash map
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#verifyAuthenticationResponse(java.util.HashMap)
	 */
	// 20120403, Bauke: added htSessionContext
	public HashMap verifyAuthenticationResponse(HashMap htAuthSPResponse, HashMap htSessionContext)
	{
		String sMethod = "verifyAuthenticationResponse";
		String sUserId = null;
		String sOrganization = null;
		String sAppID = null;
		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		try {
			String sRid = (String) htAuthSPResponse.get("rid");
			String sAsUrl = (String) htAuthSPResponse.get("my_url");
			String sResultCode = (String) htAuthSPResponse.get("result_code");
			String sSignature = (String) htAuthSPResponse.get("signature");

			if ((sRid == null) || (sResultCode == null) || (sSignature == null)) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"Incorrect AuthSP response: one or more parameters missing.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			StringBuffer sbMyURL = new StringBuffer(sAsUrl);
			sbMyURL.append("?authsp=");
			sbMyURL.append(_sAuthsp);
			sAsUrl = sbMyURL.toString();

			StringBuffer sbSignature = new StringBuffer(sRid);
			sbSignature.append(sAsUrl);
			sbSignature.append(sResultCode);

			sSignature = URLDecoder.decode(sSignature, "UTF-8");
			if (!_oCryptoEngine.verifySignature(_sAuthsp, sbSignature.toString(), sSignature)) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid signature in response from AuthSP:"
						+ _sAuthsp);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			// 20120403, Bauke: session is available as a parameter
			sUserId = (String) htSessionContext.get("user_id");
			sOrganization = (String) htSessionContext.get("organization");
			sAppID = (String) htSessionContext.get("app_id");

			if (!sResultCode.equalsIgnoreCase(IP_NO_ERROR)) {
				if (sResultCode.equalsIgnoreCase(IP_ACCESS_DENIED)) {
					_oASelectAuthenticationLogger.log(new Object[] {
						MODULE, sUserId, htAuthSPResponse.get("client_ip"), sOrganization, sAppID, "denied", sResultCode
					});
					throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
				}

				StringBuffer sbError = new StringBuffer("AuthSP returned errorcode: ");
				sbError.append(sResultCode);
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			_oASelectAuthenticationLogger.log(new Object[] {
				MODULE, sUserId, htAuthSPResponse.get("client_ip"), sOrganization, sAppID, "granted"
			});
			htResponse.put("rid", sRid);
			htResponse.put("authsp_type", "ip");
			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectAuthSPException e) {
			htResponse.put("result", e.getMessage());
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not verify authentication response due to internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}
}
