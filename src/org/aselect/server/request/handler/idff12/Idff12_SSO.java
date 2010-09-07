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
 *
 * @author Bauke Hiemstra - www.anoigo.nl
 * 
 * Version 1.0 - 14-11-2007
 */
package org.aselect.server.request.handler.idff12;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.*;
import org.aselect.server.request.handler.saml11.common.AssertionSessionManager;
import org.aselect.server.utils.Utils;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.*;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLSubject;
import org.opensaml.artifact.*;

//
// Handles Liberty Alliance ID-FF step 5 - Identity Provider
// Process AuthnRequest
//
public class Idff12_SSO extends ProtoRequestHandler
{
	public final static String MODULE = "Idff12_SSO";
	public final static String SESSION_ID_PREFIX = "idff12_";
	public final static String RETURN_SUFFIX = "_return";
	private final static String COOKIENAME = "idff12_idp";

	private String _sTemplate = null;
	private AssertionSessionManager _oAssertionSessionManager;
	private IClientCommunicator _oClientCommunicator;
	private HashMap _htApplications;
	public String _sASelectServerID;
	private String _sProviderId;
	public String _sMyAppId;
	private String _sIstsUrl;

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#getSessionIdPrefix()
	 */
	protected String getSessionIdPrefix()
	{
		return SESSION_ID_PREFIX;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#useConfigToCreateSamlBuilder()
	 */
	protected boolean useConfigToCreateSamlBuilder()
	{
		return true;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";
		try {
			super.init(oServletConfig, oConfig);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Idff12_SSO.init()");

			_oClientCommunicator = initClientCommunicator(oConfig);
			_sProviderId = ASelectConfigManager.getSimpleParam(oConfig, "provider_id", true);
			_sIstsUrl = ASelectConfigManager.getSimpleParam(oConfig, "ists_url", true);

			_sMyAppId = ASelectConfigManager.getParamFromSection(oConfig, "application", "id", true);
			_sTemplate = readTemplateFromConfig(oConfig, "template");

			_vIdPUrls = new Vector(); // Vector will contain 'url' key values
			_htIdPs = new HashMap(); // contains url->id as a <key> -> <value> pair
			getTableFromConfig(oConfig, _vIdPUrls, _htIdPs, "identity_providers", "idp", "url",/*->*/"id", true,
					true);

			// Retrieve List of: ProviderId's <--> SP Assertion Consumer URL's
			_htApplications = new HashMap();
			Object oProviders = null;
			try {
				oProviders = _configManager.getSection(oConfig, "service_providers");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'service_providers' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			Object oProvider = null;
			try {
				oProvider = _configManager.getSection(oProviders, "sp");
			}
			catch (ASelectConfigException e) {
				_systemLogger
						.log(
								Level.CONFIG,
								MODULE,
								sMethod,
								"No config item 'provider' in section 'providers' found, not using any application id to provider id mapping",
								e);
			}

			while (oProvider != null) {
				String sProviderID = null;
				try {
					sProviderID = _configManager.getParam(oProvider, "id");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No config item 'id' found in 'provider' section", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				String sAssertUrl = null;
				try {
					sAssertUrl = _configManager.getParam(oProvider, "url");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No config item 'app_id' found in 'provider' section", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				if (_htApplications.containsKey(sProviderID)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Configured provider id isn't unique: "
							+ sProviderID);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}
				_htApplications.put(sProviderID, sAssertUrl);

				oProvider = _configManager.getNextSection(oProvider);
			}
			// ProviderId's retrieved

			try {
				Object oASelect = _configManager.getSection(null, "aselect");
				_sASelectServerID = _configManager.getParam(oASelect, "server_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config item 'server_id' found in 'aselect' section", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			// From XSAML11RequestHandler
			Object oStorageManager = null;
			try {
				oStorageManager = _configManager.getSection(oConfig, "storagemanager", "id=assertions");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config section 'storagemanager' with 'id=assertions' found", e);
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			try {
				_oAssertionSessionManager = AssertionSessionManager.getHandle();
				_oAssertionSessionManager.init(oStorageManager);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "AssertionSessionManager=" + _oAssertionSessionManager);
			}
			catch (ASelectException e) {
				_systemLogger
						.log(Level.WARNING, MODULE, sMethod, "AssertionSessionManager could not be initialized", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
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

	// Symlabs says:
	// http://www.anoigo.nl:8080/aselectserver/server/idff_sso?
	// RequestID=RC7MARr3cJmdxkFSdeT21&MajorVersion=1&MinorVersion=2&
	// IssueInstant=2007-05-29T17:06:05Z&
	// ProviderID=https://sp.symspdemo.com:8780/sp.xml&
	// NameIDPolicy=federated&IsPassive=false&
	// ProtocolProfile=http://projectliberty.org/profiles/brws-art&
	// SigAlg=http://www.w3.org/2000/09/xmldsig#rsa-sha1&
	// Signature=i3GkJi0P0cFqSIsJapjkls60ABl...=
	// RelayState is optional!
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.IRequestHandler#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		HashMap htTgtContext = null;
		HashMap htIdffSession = null;
		String sSerAttributes = null;
		String sRid = null, sTgt = null;
		String sUrlRid = request.getParameter("rid");
		String sPathInfo = request.getPathInfo();
		String sServer = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "SSO PATH=" + sPathInfo + " " + request.getMethod() + " "
				+ request.getQueryString());

		HashMap htCredentials = getASelectCredentials(request);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "getAselectCredentials: sUrlRid=" + sUrlRid + " Credentials="
				+ htCredentials);

		if (htCredentials != null && !htCredentials.isEmpty()) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Credentials present");
			sRid = (String) htCredentials.get("rid");
			sServer = (String) htCredentials.get("a-select-server");

			if (sRid != null && sServer != null) {
				if (sUrlRid == null)
					sUrlRid = sRid;
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Rid/Server present");
				sTgt = (String) htCredentials.get("tgt");
				sSerAttributes = (String) htCredentials.get("attributes");

				htTgtContext = _tgtManager.getTGT(sTgt);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "getTGT htTgtContext=" + htTgtContext
						+ ", htAttributes=" + sSerAttributes);

				// Idff session is used to store the Caller's Assertion consumerURL and RelayState
				htIdffSession = retrieveSessionDataFromRid(request, SESSION_ID_PREFIX);

				if (sPathInfo.endsWith(RETURN_SUFFIX) && htIdffSession == null) {
					// The Idff session is only needed upon return
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Empty getSessionContext response");
					htTgtContext = null; // force login
				}
			}
		}

		String sRelayState = null, sProviderID = null, sAssertUrl = null;
		String sRequestID = null;
		String sReqMethod = request.getMethod();
		if (sReqMethod != null && sReqMethod.equals("GET")) {
			sRelayState = request.getParameter("RelayState");
			sProviderID = request.getParameter("ProviderID");
			if (sProviderID == null) // try Oracle glitch
				sProviderID = request.getParameter("providerid");
			sRequestID = request.getParameter("RequestID");
		}
		else if (sReqMethod != null && sReqMethod.equals("POST")) {
			String sLareq = request.getParameter("LAREQ");
			if (sLareq != null) {
				String sAuthnRequest = new String(Base64Codec.decode(sLareq));
				if (sAuthnRequest != null) {
					sProviderID = Tools.extractFromXml(sAuthnRequest, "lib:ProviderID", true);
					sRelayState = Tools.extractFromXml(sAuthnRequest, "lib:RelayState", true);
					sRequestID = Tools.extractFromXml(sAuthnRequest, "lib:RequestID", true);
				}
			}
		}
		if (htIdffSession == null || !sPathInfo.endsWith(RETURN_SUFFIX)) {
			htIdffSession = new HashMap();
			if (sProviderID != null)
				htIdffSession.put("libProviderID", sProviderID);
			if (sRequestID != null)
				htIdffSession.put("libRequestID", sRequestID);
			if (sRelayState != null)
				htIdffSession.put("libRelayState", sRelayState);
			sAssertUrl = (String) _htApplications.get(sProviderID);
			if (sAssertUrl == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unknown Provider ID: " + sProviderID);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			if (sAssertUrl != null)
				htIdffSession.put("libAssertUrl", sAssertUrl);
		}

		try {
			if (htTgtContext == null) { // Login required
				_systemLogger.log(Level.INFO, MODULE, sMethod, "LOGIN required");
				//
				// ---- Step 1 ---- Just got in, see where the user must beidentified
				// IDP Single Sign-On Service
				// Get the AuthnRequest(), can be GET or POST
				// Example:
				/*
				 * <lib:AuthnRequest RequestID="RPCUk2ll+GVz+t1lLURp51oFvJXk" MajorVersion="1" MinorVersion="2"
				 * consent="urn:liberty:consent:obtained" IssueInstant="2001-12-17T21:42:4Z"
				 * xmlns:lib="urn:liberty:iff:2003-08"> <ds:Signature> ... </ds:Signature>
				 * <lib:ProviderID>http://ServiceProvider.com</lib:ProviderID>
				 * <lib:NameIDPolicy>federate</lib:NameIDPolicy> <lib:ForceAuthn>false</lib:ForceAuthn>
				 * <lib:IsPassive>false</lib:IsPassive>
				 * <lib:ProtocolProfile>http://projectliberty.org/profiles/brws-art</lib:ProtocolProfile>
				 * <lib:RequestAuthnContext>
				 * <lib:AuthnContextClassRef>http://projectliberty.org/schemas/authctx/classes/
				 * Password-ProtectedTransport</lib:AuthnContextClassRef>
				 * <lib:AuthnContextComparison>exact</lib:AuthnContextComparison> </lib:RequestAuthnContext>
				 * <lib:RelayState>R0lGODlhcgGSALMAAAQCAEMmCZtuMFQxDS8b</lib:RelayState> </lib:AuthnRequest>
				 */
				// Analyze the ID-FF parameters: ProviderID and RelayState
				// Check mandatory information
				if (sProviderID == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "AuthnRequest: Missing parameter 'ProviderID'");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				if (sAssertUrl == null) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "AuthnRequest: No mapping found for ProviderID: "
							+ sProviderID);
					sAssertUrl = sProviderID;
				}
				// if (sRelayState == null) {
				// _systemLogger.log(Level.WARNING, MODULE, sMethod,"AuthnRequest: Missing parameter 'RelayState'");
				// throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				// }
				_systemLogger.log(Level.INFO, MODULE, sMethod, "sProviderId=" + sProviderID + " sRelayState="
						+ sRelayState);
				// End of parameter handling

				String sASelectURL = _sServerUrl; // extractAselectServerUrl(request);

				// Set the return address
				if (sPathInfo == null)
					sPathInfo = "/idff_sso";
				if (sRelayState == null) {
					sRelayState = sASelectURL + sPathInfo + RETURN_SUFFIX;
				}

				// Start an authenticate request
				htTgtContext = performAuthenticateRequest(sASelectURL, sPathInfo, RETURN_SUFFIX, _sMyAppId, true,
						_oClientCommunicator);

				sRid = (String) htTgtContext.get("rid");
				storeSessionDataWithRid(response, htIdffSession, SESSION_ID_PREFIX, sRid);

				// Let the user make his choice
				// The cookie contains the previous choice
				String sSelectedRedirectUrl = HandlerTools.getCookieValue(request, COOKIENAME, _systemLogger);
				if (sSelectedRedirectUrl != null && !_vIdPUrls.contains(sSelectedRedirectUrl)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid '" + COOKIENAME
							+ "' cookie, unknown IdP: " + sSelectedRedirectUrl);
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				String sActionUrl = sASelectURL + _sIstsUrl;
				_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT_ists=" + sActionUrl + " RelayState="
						+ sRelayState + " SelectedRedirectUrl=" + sSelectedRedirectUrl);
				handleShowForm(_sTemplate, sSelectedRedirectUrl, sActionUrl, sRelayState, _sProviderId, null,
						sASelectURL, sRid, _sASelectServerID, response);
				return new RequestState(null);
			}

			// ---- Step 2 ---- Back from identification or already logged in
			// Returned from login1, should have aselect_credentials, rid, a-select-server
			// This only code works if we arrive here from another aselect server
			//
			if (htTgtContext != null && sSerAttributes != null) {
				htTgtContext.put("attributes", sSerAttributes);
				_tgtManager.updateTGT(sTgt, htTgtContext);
			}

			// Store with the newest issued Rid
			storeSessionDataWithRid(response, htIdffSession, SESSION_ID_PREFIX, sRid);

			byte[] bSourceId = Util.generateSourceId(_sProviderId);
			SAMLArtifactType0003 oSAMLArtifact = new SAMLArtifactType0003(bSourceId);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "OK, Artifact: SourceIdUrl=" + _sProviderId + " Artifact="
					+ oSAMLArtifact);

			// Taken from XSAML11RequestHandler:
			// Create and store the SAML Assertion
			String sUid = (String) htTgtContext.get("uid");
			if (sUid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'uid' found");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "sUid=" + sUid);

			String sIP = request.getRemoteAddr();
			String sHost = request.getRemoteHost();
			sProviderID = (String) htIdffSession.get("libProviderID");
			sRequestID = (String) htIdffSession.get("libRequestID");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "createSAMLAssertion, sIP=" + sIP + ", sHost=" + sHost
					+ ", htResponse=" + htTgtContext);

			// htCredentials should have a key "attributes" containing the serialized attributes of the user
			SAMLAssertion oSAMLAssertion = _saml11Builder.createSAMLAssertionFromCredentials(sUid, sRequestID,
					null/* sNameIdFormat */, sIP, sHost, SAMLSubject.CONF_ARTIFACT, _sProviderId /* sProviderID */,
					null/* audience */, htCredentials);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "oSAMLAssertion=" + oSAMLAssertion);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "putAssertion, Artifact=" + oSAMLArtifact);
			_oAssertionSessionManager.putAssertion((org.opensaml.artifact.Artifact) oSAMLArtifact, oSAMLAssertion);

			// Redirect to the SP Assertion Consumer URL, pass Artifact
			// and the RelayState (contains the Resource URL)
			sRelayState = (String) htIdffSession.get("libRelayState");
			String sBase64 = Base64Codec.encode(oSAMLArtifact.getBytes());
			// _systemLogger.log(Level.INFO, MODULE, sMethod, "Base64=" + sBase64);

			sAssertUrl = (String) htIdffSession.get("libAssertUrl");
			if (sAssertUrl == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'libAssertUrl' found in ID-FF session");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			sAssertUrl += "?SAMLart=" + URLEncoder.encode(sBase64, "UTF-8");
			if (sRelayState != null)
				sAssertUrl += "&RelayState=" + URLEncoder.encode(sRelayState, "UTF-8");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT 2Assert=" + sAssertUrl);
			response.sendRedirect(sAssertUrl);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return new RequestState(null);
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#serializeTheseAttributes(java.util.HashMap)
	 */
	public String serializeTheseAttributes(HashMap htAttribs)
		throws ASelectException
	{
		String sMethod = "serializeTheseAttributes";
		
		String sSerializedAttributes = Utils.serializeAttributes(htAttribs);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "sSerializedAttributes=" + sSerializedAttributes);
		return sSerializedAttributes;
	}
}
