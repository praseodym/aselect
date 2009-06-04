/*
 * Created on 6-aug-2007
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package org.aselect.server.authspprotocol.handler;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthSPException;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;

/**
 * The DigidAuthSPHandler. <br>
 * <br>
 * <b>Description:</b><br>
 * The DigidAuthSPHandler communicates with the DigiD AuthSP by using redirects.
 * <br>
 * <br>
 * <b>Concurrency issues:</b> <br> - <br>
 * 
 * @author Atos Origin
 */
public class DigidAuthSPHandler implements IAuthSPProtocolHandler
{
	private final static String MODULE = "DigidAuthSPHandler";
	private ASelectConfigManager _configManager;
	private SessionManager _sessionManager;
	private ASelectSystemLogger _systemLogger;
	private ASelectAuthenticationLogger _authenticationLogger;
	private IClientCommunicator _oClientCommunicator;

	private String _sAuthSPId;
	private String _sAuthSPUrl;
	private String _sASelectAuthSPServerId;
	private String _sDefaultBetrouwbaarheidsNiveau;

	private HashMap<String, String> _htBetrouwbaarheidsNiveaus;
	private HashMap<String, String> _htSharedSecrets;

	/**
	 * Initializes the DigidAuthSPHandler. <br>
	 * Resolves the following config items:<br> - The DigidAuthSP id<br> - The
	 * url to the authsp (from the resource)<br> - The server id from the
	 * A-Select main config<br>
	 * <br>
	 * <br>
	 * 
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object,
	 *      java.lang.Object)
	 */
	public void init(Object oAuthSPConfig, Object oAuthSPResource)
		throws ASelectAuthSPException
	{
		String sMethod = "init";

		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			_authenticationLogger = ASelectAuthenticationLogger.getHandle();
			_configManager = ASelectConfigManager.getHandle();
			_sessionManager = SessionManager.getHandle();

			_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");
			try {
				_sAuthSPId = _configManager.getParam(oAuthSPConfig, "id");
			}
			catch (Exception e) {
				throw new ASelectAuthSPException("No valid 'id' config item found in authsp section", e);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + _sAuthSPId);

			try {
				_sAuthSPUrl = _configManager.getParam(oAuthSPResource, "url");
			}
			catch (Exception e) {
				StringBuffer sbFailed = new StringBuffer("No valid 'url' config item found in resource section of authsp with id='");
				sbFailed.append(_sAuthSPId).append("'");
				throw new ASelectAuthSPException(sbFailed.toString(), e);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "AuthSPUrl=" + _sAuthSPUrl);

			try {
				_sDefaultBetrouwbaarheidsNiveau = _configManager.getParam(oAuthSPConfig, "default_betrouwbaarheidsniveau");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config item 'default_shared_secret' found in 'authsp' section", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sASelectAuthSPServerId = _configManager.getParam(oAuthSPConfig, "server_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config item 'server_id' found in 'authsp' section", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "ServerId=" + _sASelectAuthSPServerId);

			// Presuming : always use the RawCommunicator
//			_oClientCommunicator = new RawCommunicator(_systemLogger);
			// 20090407, Bauke: no longer presuming
			_oClientCommunicator = Tools.initClientCommunicator(ASelectConfigManager.getHandle(), _systemLogger, oAuthSPConfig);

			Object oBetrouwbaarheidsNiveaus = null;
			try {
				oBetrouwbaarheidsNiveaus = _configManager.getSection(oAuthSPConfig, "betrouwbaarheidsniveaus");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'betrouwbaarheidsniveaus' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			Object oBetrouwbaarheidsNiveau = null;
			try {
				oBetrouwbaarheidsNiveau = _configManager.getSection(oBetrouwbaarheidsNiveaus, "betrouwbaarheidsniveau");
			}
			catch (ASelectConfigException e) {
				_systemLogger
						.log(Level.WARNING, MODULE, sMethod, "No config section 'betrouwbaarheidsniveau' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			_htBetrouwbaarheidsNiveaus = new HashMap<String, String>();
			_htSharedSecrets = new HashMap<String, String>();

			while (oBetrouwbaarheidsNiveau != null) {
				loadBetrouwbaarheidsNiveau(oBetrouwbaarheidsNiveau);
				oBetrouwbaarheidsNiveau = _configManager.getNextSection(oBetrouwbaarheidsNiveau);
			}

		}
		catch (ASelectAuthSPException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	private void loadBetrouwbaarheidsNiveau(Object oBetrouwbaarheidsNiveau)
		throws ASelectException
	{
		String sMethod = "loadBetrouwbaarheidsNiveau()";

		String sNiveau;
		try {
			sNiveau = _configManager.getParam(oBetrouwbaarheidsNiveau, "id");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No attribute 'id' in config section 'betrouwbaarheidsniveau' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		String sApplication;
		try {
			sApplication = _configManager.getParam(oBetrouwbaarheidsNiveau, "application");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No section 'application' in config section 'betrouwbaarheidsniveau' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		String sSharedSecret;
		try {
			sSharedSecret = _configManager.getParam(oBetrouwbaarheidsNiveau, "shared_secret");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No section 'shared_secret' in config section 'betrouwbaarheidsniveau' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "BetrouwbaarheidsNiveau: '" + sNiveau + "', Application: '"
				+ sApplication + "', Shared secret: '" + sSharedSecret.substring(0, 6) + "...'");
		_htBetrouwbaarheidsNiveaus.put(sNiveau, sApplication);
		_htSharedSecrets.put(sNiveau, sSharedSecret);
	}

	/**
	 * Sends an authentication request to the authsp. <br>
	 * The response must contain the following parameters:<br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">name</td>
	 * <td style="" bgcolor="#EEEEFF"> value</td>
	 * <td style="" bgcolor="#EEEEFF">encoded</td>
	 * </tr>
	 * <tr>
	 * <td>as_url</td>
	 * <td>A-Select Server url</td>
	 * <td>yes</td>
	 * </tr>
	 * <tr>
	 * <td>rid</td>
	 * <td>A-Select Server request id</td>
	 * <td>no</td>
	 * </tr>
	 * <tr>
	 * <td>uid</td>
	 * <td>A-Select Server user ID</td>
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
	 * </table> <br>
	 * <br>
	 * 
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#computeAuthenticationRequest(java.lang.String)
	 */
	@SuppressWarnings("unchecked")
	public HashMap computeAuthenticationRequest(String sRid)
	{
		String sMethod = "computeAuthenticationRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		HashMap htMethodResponse = new HashMap();
		htMethodResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		try {
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				StringBuffer sbBuffer = new StringBuffer("Could not fetch session context for rid: ");
				sbBuffer.append(sRid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htSessionContext="+htSessionContext);
			
			// De appId wordt bepaald adhv de hoogte van het gewenste betrouwbaarheidsniveau
			// Deze zit in de sessioncontext
			// 20090110, Bauke changed requested_betrouwbaarheidsniveau  to required_level
			String sBetrouwbaarheidsNiveau = (String) htSessionContext.get("required_level");
			Integer intLevel = (Integer) htSessionContext.get("level");
			String sAppId;
			String sSharedSecret;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "requested required_level="+sBetrouwbaarheidsNiveau+
					" level="+intLevel+" default level="+_sDefaultBetrouwbaarheidsNiveau);
			if (sBetrouwbaarheidsNiveau == null || sBetrouwbaarheidsNiveau.equals("empty")) {
				// if betrouwbaarheidsniveau was not specified, we use the default.
				sBetrouwbaarheidsNiveau = _sDefaultBetrouwbaarheidsNiveau;
			}
			sAppId = _htBetrouwbaarheidsNiveaus.get(sBetrouwbaarheidsNiveau);
			sSharedSecret = _htSharedSecrets.get(sBetrouwbaarheidsNiveau);
			if (sAppId == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No <application> found for level="+sBetrouwbaarheidsNiveau);
				throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
			}
			if (sSharedSecret == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No <betrouwbaarheidsniveau> found for level="+sBetrouwbaarheidsNiveau);
				throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
			}

			//String sAppUrl = (String) htSessionContext.get("my_url") + "?local_rid=" + sRid + "&authsp=" + _sAuthSPId;
			String _sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);
			String sAppUrl = _sServerUrl + "?local_rid=" + sRid + "&authsp=" + _sAuthSPId;
			String sASelectServerId = _sASelectAuthSPServerId;
			String sASelectServerUrl = _sAuthSPUrl;

			HashMap htRequest = new HashMap();
			htRequest.put("request", "authenticate");
			htRequest.put("app_id", sAppId);
			htRequest.put("app_url", sAppUrl);
			htRequest.put("shared_secret", sSharedSecret);
			htRequest.put("a-select-server", sASelectServerId);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Send to DigiD="+sASelectServerUrl+" req="+hashtable2CGIMessage(htRequest));

			HashMap htResponse = null;
			try {
				htResponse = _oClientCommunicator.sendMessage(htRequest, sASelectServerUrl);
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not send authentication request to: "
						+ sASelectServerUrl);
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Result=" + htResponse);
			// This is what we may get from DigiD:
			// Response={rid=120127592091747E2EEBC3F0AA366, as_url=https://as-demo.digid.nl/aselectserver/server?request=login1,
			//           result_code=0000, a-select-server=digidasdemo1}

			String sResultCode = (String)htResponse.get("result_code");
			if (!sResultCode.equals("0000")) {
				throw new Exception("Bad result from DigiD");

				/*htResponse.put("organization", "DigiDDemo");
				htResponse.put("rid", "120127592091747E2EEBC3F0AA366");
				htResponse.put("a-select-server", "digidasdemo1");
				htResponse.put("as_url", "https://as-demo.digid.nl/aselectserver/server?request=login1");
				htResponse.put("organization", "DigiDDemo");
				htResponse.put("result_code", "0000");*/
				
				// We regain control at:
				// https://my.idp.nl/aselectserver/server?local_rid=4A83AB89E64B6A20&authsp=DigidAuthSP&
				//   rid=120127592091747E2EEBC3F0AA366&a-select-server=digidasdemo1&aselect_credentials=7C664...
				}

			sASelectServerUrl = (String) htResponse.get("as_url");
			String sDigidRid = (String) htResponse.get("rid");

			// TODO Waarom een update??, er is niets gewijzigd
			//_sessionManager.updateSession(sRid, htSessionContext);

			// redirect with A-Select request=login1
			StringBuffer sbRedirect = new StringBuffer(sASelectServerUrl);
			sbRedirect.append("&rid=");
			sbRedirect.append(sDigidRid);
			sbRedirect.append("&a-select-server=");
			sbRedirect.append(sASelectServerId);

			htMethodResponse.put("redirect_url", sbRedirect.toString());
			htMethodResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectAuthSPException e) {
			htMethodResponse.put("result", e.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not authenticate", e);
			htMethodResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htMethodResponse;
	}

	@SuppressWarnings("unchecked")
	public HashMap verifyAuthenticationResponse(HashMap htResponse)
	{
		String sMethod = "verifyAuthenticationResponse()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		HashMap<String, String> result = new HashMap<String, String>();
		String resultCode = Errors.ERROR_ASELECT_INTERNAL_ERROR;

		try {
			String sLocalRid = (String) htResponse.get("local_rid");
			String sDigidRid = (String) htResponse.get("rid");
			String credentials = (String) htResponse.get("aselect_credentials");

			// To determine which shared secret to use, we need to know the
			// 'betrouwbaarheidsniveau'. This is stored in the session,
			// which we can get via the local_rid. If its not found, we use
			// the default betrouwbaarheidsniveau to determine the shared
			// secret
			String sReqLevel = _sDefaultBetrouwbaarheidsNiveau;
			String sharedSecret = _htSharedSecrets.get(_sDefaultBetrouwbaarheidsNiveau);
			SessionManager sessionManager = SessionManager.getHandle();
			if (sessionManager.containsKey(sLocalRid)) {
				HashMap sessionContext = sessionManager.getSessionContext(sLocalRid);
				// 20090110, Bauke changed requested_betrouwbaarheidsniveau  to required_level
				sReqLevel = (String) sessionContext.get("required_level");
				Integer intLevel = (Integer)sessionContext.get("level");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "required_level="+sReqLevel+" level="+intLevel);
				if (sReqLevel == null || sReqLevel.equals("empty"))
					sReqLevel = _sDefaultBetrouwbaarheidsNiveau;
				sharedSecret = _htSharedSecrets.get(sReqLevel);
			}

			HashMap reqParams = new HashMap();
			reqParams.put("request", "verify_credentials");
			reqParams.put("a-select-server", _sASelectAuthSPServerId);
			reqParams.put("rid", sDigidRid);
			reqParams.put("aselect_credentials", credentials);
			reqParams.put("shared_secret", sharedSecret);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "sendMessage to " + _sAuthSPUrl + " request=" + reqParams);
			HashMap response = null;
			try {
				response = _oClientCommunicator.sendMessage(reqParams, _sAuthSPUrl);
			}
			catch (ASelectCommunicationException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not send authentication request to: "+_sAuthSPUrl);
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Response=" + response);
			
			// DigiD should respond with:
			// Response={organization=DigiDDemo, laatst_ingelogd=1201183703000, betrouwbaarheidsniveau=10, asp=NAVWW1,
			//   asp_level=10, result_code=0000, a-select-server=digidasdemo1, uid=923005716, app_id=ABCDE.my_org.nl,
			//   app_level=5, tgt_exp_time=1201304729377, rid=120127592091747E2EEBC3F0AA366}

			resultCode = (String) response.get("result_code");
			String sServerId = (String) response.get("a-select-server");
			String sUid = (String) response.get("uid");
			String sBetrouwbaarheidsniveau = (String) response.get("betrouwbaarheidsniveau");
			String sRid = (String) response.get("rid");
			String sOrganization = (String) response.get("organization");
			String sAppID = (String) response.get("app_id");
			//if ("950000528".equals(sUid))  // Bauke: testing levels
			//		sBetrouwbaarheidsniveau = "20";
			//
			// Also match sBetrouwbaarheidsniveau against the requested level
			//
			Integer reqLevel = -1, digidLevel = -1;
			if (sBetrouwbaarheidsniveau != null) {
				digidLevel = Integer.parseInt(sBetrouwbaarheidsniveau);
				reqLevel = Integer.parseInt(sReqLevel);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "digidLevel="+digidLevel+
						" reqLevel="+sReqLevel+":"+reqLevel);
				if (digidLevel < reqLevel) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "DIGID LEVEL NOT HIGH ENOUGH (config error)");
					throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
				}
			}
			
			if ((resultCode != null) && (sUid != null) && (sServerId != null && sBetrouwbaarheidsniveau != null)
					&& (sRid != null) && (sServerId.equals(_sASelectAuthSPServerId)) && (sRid.equals(sDigidRid))
					&& (digidLevel >= reqLevel)
					&& (resultCode.equals(Errors.ERROR_ASELECT_SUCCESS))) {
				result.put("rid", sLocalRid);
				result.put("uid", sUid);
				// Bauke: not sure which one it should be: user_id / uid 
				result.put("user_id", sUid);
				result.put("betrouwbaarheidsniveau", sBetrouwbaarheidsniveau);
				resultCode = Errors.ERROR_ASELECT_SUCCESS;
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, htResponse.get("client_ip"), sOrganization, sAppID, "granted"
				});
			}
			else {
				result.put("rid", sLocalRid);
				resultCode = ("0040".equals(resultCode))? Errors.ERROR_ASELECT_SERVER_CANCEL:
								Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, htResponse.get("client_ip"), sOrganization, sAppID, "denied"
				});
			}
			result.put("result", resultCode);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "result=" + resultCode);
		}
		catch (ASelectException e) {
			if (((String) result.get("result")).equals(Errors.ERROR_ASELECT_SUCCESS)) {
				result.put("result", e.getMessage());  // Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
		}
		return result;
	}

	private String hashtable2CGIMessage(HashMap htInput)
		throws UnsupportedEncodingException
	{
		StringBuffer sbBuffer = new StringBuffer();
		Set keys = htInput.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
		//Enumeration enumKeys = htInput.keys();
		//boolean bStop = !enumKeys.hasMoreElements(); // more elements?
		//while (!bStop) {
		//	String sKey = (String) enumKeys.nextElement();
			Object oValue = htInput.get(sKey);
			if (oValue instanceof String) {
				sbBuffer.append(sKey);
				sbBuffer.append("=");
				// URL encode value
				String sValue = URLEncoder.encode((String) oValue, "UTF-8");
				sbBuffer.append(sValue);
			}
			else if (oValue instanceof String[]) {
				String[] strArr = (String[]) oValue;
				for (int i = 0; i < strArr.length; i++) {
					sbBuffer.append(sKey).append("%5B%5D");
					sbBuffer.append("=");
					String sValue = URLEncoder.encode(strArr[i], "UTF-8");
					sbBuffer.append(sValue);
					if (i < strArr.length - 1)
						sbBuffer.append("&");
				}
			}

			//if (enumKeys.hasMoreElements()) {
			// Append extra '&' after every parameter.
			sbBuffer.append("&");
			//}
		}
		int len = sbBuffer.length();
		return sbBuffer.substring(0, (len>0)? len-1: len);
//		return sbBuffer.toString();
	}
}
