package org.aselect.server.request.handler.saml20.idp.authentication;

import java.io.PrintWriter;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml20.common.LogoutRequestSender;
import org.aselect.server.request.handler.saml20.common.LogoutResponseSender;
import org.aselect.server.request.handler.saml20.common.NodeHelper;
import org.aselect.server.request.handler.saml20.common.SamlHistoryManager;
import org.aselect.server.request.handler.saml20.common.SignatureUtil;
import org.aselect.server.request.handler.saml20.idp.metadata.MetaDataManagerIDP;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class LogoutResponseHandler extends AbstractRequestHandler
{

	private static final String MODULE = "LogoutResponseHandler";

	private final String LOGOUTRESPONSE = "LogoutResponse";

	private String _sServerUrl;

	private boolean _bVerifySignature = true;

	public void destroy()
	{
	}

	/**
	 * Init for class LogoutResponseHandler. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig.
	 * @param oConfig
	 *            Object.
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		super.init(oServletConfig, oConfig);
		String sMethod = "init()";
		Object oASelect = null;
		try {
			oASelect = _configManager.getSection(null, "aselect");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'aselect' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		try {
			_sServerUrl = _configManager.getParam(oASelect, "redirect_url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'server_url' found in 'aselect' section",
					e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		String sVerifySignature = null;
		try {
			sVerifySignature = _configManager.getParam(oConfig, "verify_signature");
		}
		catch (Exception e) {
			if (sVerifySignature != null) {
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		if (sVerifySignature != null && sVerifySignature.equalsIgnoreCase("false")) {
			_bVerifySignature = false;
		}
	}

	/**
	 * Process Logout response. <br>
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @throws ASelectException
	 *             If process of Logout response fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		if (request.getParameter("SAMLResponse") != null) {
			handleSAMLResponse(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + request.getQueryString()
					+ " is not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		return null;
	}

	private void handleSAMLResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
		throws ASelectException
	{
		String sMethod = "handleSAMLResponse()";

		try {
			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(httpRequest));

			HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
			decoder.decode(messageContext);

			SignableSAMLObject samlMessage = (SignableSAMLObject) messageContext.getInboundSAMLMessage();
			_systemLogger.log(Level.INFO, MODULE, sMethod, XMLHelper.prettyPrintXML(samlMessage.getDOM()));

			String elementName = samlMessage.getElementQName().getLocalPart();

			// The SAMLRequest must be signed, if not the message can't be trusted
			// and a responsemessage is send to the browser
			if (!SignatureUtil.isSigned(httpRequest)) {
				String errorMessage = "SAML message must be signed.";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
				PrintWriter pwOut = httpResponse.getWriter();
				pwOut.write(errorMessage);
				return;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML message IS signed.");

			// The signing must be correct, if not the message can't be
			// trusted
			// and a responsemessage is send to the browser

			// First we must detect which public key must be used
			// The alias of the publickey is equal to the appId and the
			// appId is retrieved by
			// the Issuer, which is the server_url

			Issuer issuer;
			if (elementName.equals(LOGOUTRESPONSE)) {
				LogoutResponse logoutResponse = (LogoutResponse) samlMessage;
				issuer = logoutResponse.getIssuer();
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage:\r\n"
						+ XMLHelper.prettyPrintXML(samlMessage.getDOM()) + "\r\nis not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			if (issuer == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "LogoutResponse did not contain <Issuer> element");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			String sEntityId = issuer.getValue();
			MetaDataManagerIDP metadataManager = MetaDataManagerIDP.getHandle();
			PublicKey publicKey = metadataManager.getSigningKey(sEntityId);
			if (publicKey == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "PublicKey for entityId: " + sEntityId
						+ " not found.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Found PublicKey for entityId: " + sEntityId);

			if (_bVerifySignature) {
				if (!SignatureUtil.verifySignature(publicKey, httpRequest)) {
					String errorMessage = "Signing of SAML message is not correct.";
					_systemLogger.log(Level.INFO, MODULE, sMethod, errorMessage);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					PrintWriter pwOut = httpResponse.getWriter();
					pwOut.write(errorMessage);
					return;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Signature is correct.");

			}
			else {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No verification on Signature.");
			}

			if (elementName.equals(LOGOUTRESPONSE)) {
				handleLogoutResponse(httpRequest, httpResponse, (LogoutResponse) samlMessage);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage:\r\n"
						+ XMLHelper.prettyPrintXML(samlMessage.getDOM()) + "\r\nis not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	private void handleLogoutResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			LogoutResponse logoutResponse)
		throws ASelectException
	{
		String sMethod = "handleLogoutResponse()";

		// Ik heb nu een logoutresponse ontvangen. Deze was succesvol. Haal
		// deze uit de lijst met betrokken sps. Kijk of er nog andere sps in
		// zitten en stuur hier indien nodig ook logout requests naartoe.
		// als de lijst met betrokken sps nu leeg is, stuur dan een
		// logoutresponse naar de initierende sp.

		// wat ik nu nog nodig heb is om welker gebruiker het ook alweer gaat!
		// dit staat niet in het ontvangen logoutresponse bericht. De gebruiker
		// wordt momenteel als "uid" parameter met het request meegegeven. Dit
		// wordt later evt. de credentials van de gebruiker

		// check if the logoutResponse was successful
		String status = logoutResponse.getStatus().getStatusCode().getValue();
		if (!status.equals(StatusCode.SUCCESS_URI)) {
			// not much we can do about it, we continue logging out
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "LogoutResponse indicates no succes: StatusCode="
					+ status);
		}

		// determine which user belongs to this response
		String inResponseTo = logoutResponse.getInResponseTo();
		Element element = (Element) SamlHistoryManager.getHandle().get(inResponseTo);

		XMLObject o = null;
		try {
			o = new NodeHelper().unmarshallElement(element);
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error while unmarshalling " + element, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		if (!(o instanceof LogoutRequest)) {
			// we really did expect a logoutrequest here
			String msg = "LogoutRequest expected from SamlMessageHistory but received: " + o.getClass();
			_systemLogger.log(Level.INFO, MODULE, sMethod, msg);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		LogoutRequest originalLogoutRequest = (LogoutRequest) o;
		String uid = originalLogoutRequest.getNameID().getValue();

		SSOSessionManager sessionManager = SSOSessionManager.getHandle();
		UserSsoSession ssoSession = sessionManager.getSsoSession(uid);

		String serviceProvider = logoutResponse.getIssuer().getValue();
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Just received LogoutResponse from " + serviceProvider);
		ssoSession.removeServiceProvider(serviceProvider);
		// overwrite the session (needed for database storage)
		sessionManager.putSsoSession(ssoSession);
		List<ServiceProvider> serviceProvidersList = ssoSession.getServiceProviders();
		Iterator<ServiceProvider> it = serviceProvidersList.iterator();
		// are there still other SPs involved?
		if (it.hasNext()) {
			// get the next SP and log it out
			ServiceProvider sp = it.next();
			String serviceProviderUrl = sp.getServiceProviderUrl();

			// metadata
			MetaDataManagerIDP metadataManager = MetaDataManagerIDP.getHandle();
			String url = metadataManager.getLocation(serviceProviderUrl,
					SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);

			// remove it from the list with involved SPs
			ssoSession.removeServiceProvider(sp.getServiceProviderUrl());
			// overwrite the session (needed for database storage)
			sessionManager.putSsoSession(ssoSession);
			LogoutRequestSender sender = new LogoutRequestSender();
			sender.sendLogoutRequest(url, _sServerUrl, uid, httpRequest, httpResponse, "federation initiated logout");
			return;
		}
		// als er geen andere sps meer betrokken zijn: stuur een
		// logoutresponse naar initierende sp
		String initiatingSP = ssoSession.getLogoutInitiator();
		sessionManager.delSsoSession(uid);
		sendLogoutResponse(initiatingSP, originalLogoutRequest.getID(), httpRequest, httpResponse);
	}

	private void sendLogoutResponse(String initiatingSP, String inResponseTo, HttpServletRequest httpRequest,
			HttpServletResponse httpResponse)
		throws ASelectException
	{

		String statusCode = StatusCode.SUCCESS_URI;

		String logoutResponseLocation = null; // get from metadata
		MetaDataManagerIDP metadataManager = MetaDataManagerIDP.getHandle();
		logoutResponseLocation = metadataManager.getResponseLocation(initiatingSP,
				SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		if (logoutResponseLocation == null) {
			// If there is no ResponseLocation we use Location instead
			logoutResponseLocation = metadataManager.getLocation(initiatingSP,
					SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		}

		LogoutResponseSender sender = new LogoutResponseSender();
		sender.sendLogoutResponse(logoutResponseLocation, _sServerUrl, statusCode, inResponseTo, httpRequest,
				httpResponse);
	}
}
