package org.aselect.server.request.handler.xsaml20.idp;

import java.io.PrintWriter;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.util.XMLHelper;

/**
 * IdP SLO Service
 * Single Logout entry using HTTP-Redirect
 */
// Example configuration
// <handler id="saml20_slo"
//    class="org.aselect.server.request.handler.xsaml20.idp.Xsaml20_SLO_Redirect"
//    target="/saml20_slo.*" >
// </handler>
//
public class Xsaml20_SLO_Redirect extends Saml20_BrowserHandler
{
    private final static String MODULE = "Xsaml20_SLO_Redirect";
//	private final static String SESSION_ID_PREFIX = "saml20_";
	private final String LOGOUTREQUEST = "LogoutRequest";

	private boolean _bTryRedirectLogoutFirst = true;
	private int _iRedirectLogoutTimeout = 30;
	
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init()";

		super.init(oServletConfig, oConfig);

		String sTryRedirect = HandlerTools.getSimpleParam(oConfig, "try_redirect_logout_first", false);
		if (sTryRedirect != null && !sTryRedirect.equals("true"))
			_bTryRedirectLogoutFirst = false;

		try {
			_iRedirectLogoutTimeout = new Integer(_configManager.getParam(oConfig, "redirect_logout_timeout")).intValue();
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_logout_timeout' found in 'handler' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * send a LogoutRequests to one of the other involved SPs TO: De
	 * federatie-idp vernietigd de lokale serversessie en clientcookie. De
	 * federatie-idp verwijderd de PIP-sessie en kijkt in eigen sessietabel voor
	 * overige bestaande sessie. Federatie-idp stuurt gebruiker naar de
	 * logoutservice van de eerstvolgende SP samen met een SAML-logoutrequest.
	 * This other SP will respond with an artifact, which will be resolved in
	 * the idp artifactResolver. There it will look for even more SPs and
	 * initiate communication with them. If there are no more other SPs a logout
	 * response will be sent to the original initiating SP
	 */
	protected void handleSpecificSaml20Request(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
					SignableSAMLObject samlMessage)
	throws ASelectException
	{
		String sMethod = "handleSpecificSaml20Request";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		try {
			LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "received SAMLRequest: \n"
							+ XMLHelper.prettyPrintXML(logoutRequest.getDOM()));

			Response errorResponse = validateLogoutRequest(logoutRequest, httpRequest);
			if (errorResponse != null) {
				String errorMessage = "Something wrong in SAML communication";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
				PrintWriter pwOut = httpResponse.getWriter();
				pwOut.write(errorMessage);
				return;
			}

			// Now the message is OK
			String initiatingSP = logoutRequest.getIssuer().getValue();

/*			// retrieve the sso session for this user
			SSOSessionManager ssoSessionManager = SSOSessionManager.getHandle();
			UserSsoSession ssoSession = ssoSessionManager.getSsoSession(uid);

			// Remove initiating SP
			ssoSession.removeServiceProvider(initiatingSP);
			// Store the initiating SP as initiatingSP for future reference
			ssoSession.setLogoutInitiator(initiatingSP);
			// overwrite the session (needed for database storage)
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Removed initiatingSP="+initiatingSP+
					" new session="+ssoSession);
			ssoSessionManager.putSsoSession(ssoSession);

			// Remove the TGT, extract ID from session
			TGTManager tgtManager = TGTManager.getHandle();
			String tgtId = ssoSession.getTgtId();

			if (tgtManager.containsKey(tgtId)) {
				tgtManager.remove(tgtId);
			}*/
			
			// Delete the IdP client cookie
	        String sCookieDomain = _configManager.getCookieDomain();
	        HandlerTools.delCookieValue(httpResponse, "aselect_credentials", sCookieDomain, _systemLogger);
			// NOTE: cookie GOES, TGT STAYS in admin!!
			
	        logoutNextSessionSP(httpRequest, httpResponse, logoutRequest, initiatingSP,
						_bTryRedirectLogoutFirst, _iRedirectLogoutTimeout);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	// TODO kijken waar allemaal op gevalideerd kan/moet worden
	private Response validateLogoutRequest(LogoutRequest logoutRequest, HttpServletRequest httpRequest)
		throws ASelectException
	{
		String sMethod = "validateLogoutRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		Response errorResponse = null;
		String sInResponseTo = logoutRequest.getID(); // Is required in SAMLsyntax
		String sDestination = logoutRequest.getDestination();
		String sStatusCode = "";
		String sStatusMessage = "";
		if (sDestination == null) {
			sDestination = "UnkownDestination";
			sStatusCode = StatusCode.INVALID_ATTR_NAME_VALUE_URI;
			sStatusMessage = "The 'Destination' attribute found in element LogoutRequest of SAML message was null";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage);
			return errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
		}
		if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(logoutRequest)) {
			sStatusCode = StatusCode.REQUEST_DENIED_URI;
			sStatusMessage = "Time interval in element LogoutRequest not valid";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage);
			return errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
		}
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, sMethod + " successful");
		return errorResponse;
	}
    
	public Issuer retrieveIssuer(String elementName, SignableSAMLObject samlMessage)
    {
	    if (elementName.equals(LOGOUTREQUEST)) {
			LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
			return logoutRequest.getIssuer();
		}
		return null;
    }
}