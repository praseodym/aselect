package org.aselect.server.request.handler.saml20.idp.authentication;

import java.io.BufferedInputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.URLEncoder;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml20.common.LogoutResponseBuilder;
import org.aselect.server.request.handler.saml20.common.NodeHelper;
import org.aselect.server.request.handler.saml20.common.SOAPManager;
import org.aselect.server.request.handler.saml20.common.Utils;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public class LogoutRequestHandler extends AbstractRequestHandler
{
	private final static String MODULE = "LogoutRequestHandler";

	private static final String SOAP_TYPE = "text/xml";

	private SystemLogger _oSystemLogger = _systemLogger;

	private String _sRedirectUrl;

	private static final String LOGOUTREQUEST = "LogoutRequest";

	/**
	 * Init for class LogoutRequestHandler. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig.
	 * @param oHandlerConfig
	 *            Object.
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		super.init(oServletConfig, oHandlerConfig);
		_oSystemLogger = _systemLogger;

		try {
			ConfigManager oConfigManager = ASelectConfigManager.getHandle();
			Object aselectSection = oConfigManager.getSection(null, "aselect");
			_sRedirectUrl = _configManager.getParam(aselectSection, "redirect_url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_url' found in 'aselect' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Process logout request. <br>
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @throws ASelectException
	 *             If processing of logout request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String _sMethod = "process";
		String sContentType = request.getContentType();
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Process Logout request, content="+sContentType);
		
		if (sContentType != null && sContentType.startsWith(SOAP_TYPE)) {
			// its a logoutrequest in SOAP
			handleSOAPLogoutRequest(request, response);
		}
		return null;
	}

	private void handleSOAPLogoutRequest(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "handleSOAPLogoutRequest";
		try {
			ServletInputStream input = request.getInputStream();
			BufferedInputStream bis = new BufferedInputStream(input);
			char b = (char) bis.read();
			StringBuffer sb = new StringBuffer();
			while (bis.available() != 0) {
				sb.append(b);
				b = (char) bis.read();
			}
			String sReceivedSoap = sb.toString();
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Received: " + sb);
			
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(sReceivedSoap);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			NodeHelper nodeHelper = new NodeHelper();
			Node eltArtifactResolve = nodeHelper.getNode(elementReceivedSoap, LOGOUTREQUEST);

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);

			LogoutRequest logoutRequest = (LogoutRequest) unmarshaller.unmarshall((Element) eltArtifactResolve);

			// vernietig locale sessie
			String uid = logoutRequest.getNameID().getValue();
			Issuer issuer = logoutRequest.getIssuer();
			String sp = issuer.getValue();
			removeSessionFromFederation(uid, sp);

			// stuur via SOAP een logoutResponse
			String returnUrl = logoutRequest.getIssuer().getValue();
			String requestId = logoutRequest.getID();

			// creeer logoutResponse
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Send Logout Response to: " + returnUrl);
			String statusCode = StatusCode.SUCCESS_URI;

			LogoutResponse logoutResponse = new LogoutResponseBuilder().buildLogoutResponse(_sRedirectUrl, statusCode,
					requestId);

			SOAPManager soapManager = new SOAPManager();
			Envelope envelope = soapManager.buildSOAPMessage(logoutResponse);
			Element envelopeElem = nodeHelper.marshallMessage(envelope);
			PrintWriter writer = response.getWriter();
			writer.write(URLEncoder.encode(XMLHelper.nodeToString(envelopeElem), "UTF-8"));

		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/*
	 * Deze methode haalt de sp's op uit de tgt manager als de sp die meegegeven
	 * wordt de laatste is kill de volledige tgt en anders haal alleen de
	 * meegeleverde sp uit de lijst van sp's
	 */
	/**
	 * Remove the session from federation. <br>
	 * 
	 * @param uid
	 *            String with user id.
	 * @param serviceProvider
	 *            String with SP-id.
	 * @throws ASelectException
	 *             If remove session fails.
	 */
	public void removeSessionFromFederation(String uid, String serviceProvider)
		throws ASelectException
	{
		String _sMethod = "removeSessionFromFederation";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - UID=" + uid + " Remove SP=" + serviceProvider);
		TGTManager tgtManager = TGTManager.getHandle();
		String credentials = null;

		SSOSessionManager ssoSessionManager = SSOSessionManager.getHandle();
		UserSsoSession ssoSession = ssoSessionManager.getSsoSession(uid);
		List<ServiceProvider> spList = ssoSession.getServiceProviders();
		credentials = ssoSession.getTgtId();
		/*
		 * Check is there are more sp's if not then remove whole tgt else check
		 * is sp is the first in the active list
		 */
		String sCred = (credentials.length() > 30) ? credentials.substring(0, 30) + "..." : credentials;
		if (spList.size() > 1) {
			for (ServiceProvider sp : spList) {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - Multiple SP's Url="
						+ sp.getServiceProviderUrl());
				if (sp.getServiceProviderUrl().equals(serviceProvider)) {
					if (tgtManager.containsKey(credentials)) {
						_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - Remove SP="
								+ sp.getServiceProviderUrl() + "for TGT=" + sCred);
						ssoSession.removeServiceProvider(sp.getServiceProviderUrl());
						// overwrite the session (needed for database storage)
						ssoSessionManager.putSsoSession(ssoSession);
						break;
					}
				}
			}
		}
		else if (spList.size() == 1) {
			if (tgtManager.containsKey(credentials)) {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - One SP, Remove TGT=" + sCred + " and uid="+uid);
				tgtManager.remove(credentials);
				ssoSessionManager.remove(uid);
				// TODO: could kill SLOTimer task for 'credentials' at this point
			}
			else {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - One SP, but no TGT found");
				ssoSessionManager.remove(uid);
				// TODO: could kill SLOTimer task for 'credentials' at this point
			}
		}
		else {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDP - List of SP's is empty");
		}

	}

	public void destroy()
	{
	}
}
