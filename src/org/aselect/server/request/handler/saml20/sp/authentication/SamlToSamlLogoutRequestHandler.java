package org.aselect.server.request.handler.saml20.sp.authentication;

import java.io.BufferedInputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.URLEncoder;
import java.security.PublicKey;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml20.common.LogoutResponseBuilder;
import org.aselect.server.request.handler.saml20.common.LogoutResponseSender;
import org.aselect.server.request.handler.saml20.common.NodeHelper;
import org.aselect.server.request.handler.saml20.common.SOAPManager;
import org.aselect.server.request.handler.saml20.common.SignatureUtil;
import org.aselect.server.request.handler.saml20.sp.metadata.MetaDataManagerSP;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.tgt.saml20.SpTGTIssuer;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public class SamlToSamlLogoutRequestHandler extends AbstractRequestHandler
{
	private final static String MODULE = "SamlToSamlLogoutRequestHandler";

	private static final String LOGOUTREQUEST = "LogoutRequest";

	private static final String SOAP_TYPE = "text/xml";

	private String _sServerUrl;

	private boolean _bVerifySignature = true;

	/**
	 * Init for class SamlToSamlLogoutRequestHandler. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig
	 * @param oHandlerConfig
	 *            Object
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		super.init(oServletConfig, oHandlerConfig);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		try {
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException e) {
			_systemLogger
					.log(Level.WARNING, MODULE, sMethod, "There is a problem initializing the OpenSAML library", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		try {
			Object aselect = _configManager.getSection(null, "aselect");
			_sServerUrl = _configManager.getParam(aselect, "redirect_url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_url' found in 'aselect' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		String sVerifySignature = null;
		try {
			sVerifySignature = _configManager.getParam(oHandlerConfig, "verify_signature");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'verify_signature' found in 'handler' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		if (sVerifySignature != null && sVerifySignature.equalsIgnoreCase("false")) {
			_bVerifySignature = false;
		}
	}

	/**
	 * Dit is stap 7 van SLO. We hebben zojuist een saml LogoutRequest ontvangen
	 * en gaan deze nu verwerken. Dit houdt in: We loggen de gebruiker hier uit
	 * en maken hier melding van naar de federatie idp. Dit doen we door een
	 * artifact aan te maken met daarin het LogoutResponse. Dit artifact zal
	 * later door de federatie idp worden resolved.
	 */
	/**
	 * Process logout request. <br>
	 * 
	 * @param request
	 *            HttpServletRequest
	 * @param response
	 *            HttpServletResponse
	 * @throws ASelectException
	 *             If processing of logout request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");
		if (request.getParameter("SAMLRequest") != null) {
			handleSAMLRequest(request, response);
		}
		else if (request.getContentType().startsWith(SOAP_TYPE)) {
			// its a logoutrequest in SOAP
			handleSOAPLogoutRequest(request, response);
		}
		else {
			// it was not SOAP either
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + request.getQueryString()
					+ " is not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
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

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received Soap:\n" + sReceivedSoap);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(sReceivedSoap);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			NodeHelper nodeHelper = new NodeHelper();
			Node eltLogoutRequest = nodeHelper.getNode(elementReceivedSoap, LOGOUTREQUEST);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutRequest:\n"
					+ XMLHelper.nodeToString(eltLogoutRequest));

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltLogoutRequest);

			LogoutRequest logoutRequest = (LogoutRequest) unmarshaller.unmarshall((Element) eltLogoutRequest);

			// Destroy local session
			String uid = logoutRequest.getNameID().getValue();
			String tgtId = null;
			try {
				tgtId = UserToTgtMapper.getTgtId(uid);
				TGTManager tgtManager = TGTManager.getHandle();
				if (tgtManager.containsKey(tgtId)) {
					tgtManager.remove(tgtId);
				}
			}
			catch (ASelectStorageException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			}

			// overwriting the client cookie will not work here since we are
			// on the backchannel

			// stuur via SOAP een logoutResponse
			String returnUrl = logoutRequest.getIssuer().getValue();

			// creeer logoutResponse
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Send Logout Response to: " + returnUrl);
			String statusCode = StatusCode.SUCCESS_URI;
			String myEntityId = _sServerUrl;
			LogoutResponse logoutResponse = new LogoutResponseBuilder().buildLogoutResponse(myEntityId, statusCode,
					logoutRequest.getID());

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

	private void handleSAMLRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
		throws ASelectException
	{
		String sMethod = "handleSAMLRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		try {
			// The SAMLRequest must be signed, if not the message can't be
			// trusted
			// and a responsemessage is send to the browser
			if (!SignatureUtil.isSigned(httpRequest)) {
				String errorMessage = "SAML message must be signed.";
				_systemLogger.log(Level.INFO, MODULE, sMethod, errorMessage);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
				PrintWriter pwOut = httpResponse.getWriter();
				pwOut.write(errorMessage);
				return;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML message IS signed.");

			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(httpRequest));

			HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
			decoder.decode(messageContext);

			SignableSAMLObject samlMessage = (SignableSAMLObject) messageContext.getInboundSAMLMessage();
			_systemLogger.log(Level.INFO, MODULE, sMethod, XMLHelper.prettyPrintXML(samlMessage.getDOM()));

			String elementName = samlMessage.getElementQName().getLocalPart();

			// get the issuer
			Issuer issuer;
			if (elementName.equals(LOGOUTREQUEST)) {
				LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
				issuer = logoutRequest.getIssuer();
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage: "
						+ XMLHelper.prettyPrintXML(samlMessage.getDOM()) + " is not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			String sEntityId = issuer.getValue();
			MetaDataManagerSP metadataManager = MetaDataManagerSP.getHandle();
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

			// now the signature is OK and the message can be processed
			// further

			if (elementName.equals(LOGOUTREQUEST)) {
				LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
				handleLogoutRequest(httpRequest, httpResponse, logoutRequest);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage: "
						+ XMLHelper.prettyPrintXML(samlMessage.getDOM()) + " is not recognized");
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

	/**
	 * TO: De aangesproken SP vernietigt de lokale serversessie en
	 * clientcookie.De SP redirect de gebruiker naar de federatie-idp
	 * logoutservice met een LogoutResponse
	 * 
	 * @param httpRequest
	 * @param httpResponse
	 * @param logoutRequest
	 * @throws ASelectException
	 */
	private void handleLogoutRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			LogoutRequest logoutRequest)
		throws ASelectException
	{
		String sMethod = "handleLogoutRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		// vernietig locale sessie
		String uid = logoutRequest.getNameID().getValue();
		String tgtId = null;
		try {
			tgtId = UserToTgtMapper.getTgtId(uid);
			TGTManager tgtManager = TGTManager.getHandle();
			if (tgtManager.containsKey(tgtId)) {
				tgtManager.remove(tgtId);
			}
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, e.getMessage());
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		// overwrite the client cookie
		Cookie cookie = new Cookie(SpTGTIssuer.COOKIE_NAME, "");
		cookie.setMaxAge(0);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Delete Cookie=" + SpTGTIssuer.COOKIE_NAME);
		httpResponse.addCookie(cookie);

		// redirect de gebruiker naar de federatie-idp logoutservice met een
		// artifact
		String issuer = logoutRequest.getIssuer().getValue();

		// creeer logoutResponse
		String statusCode = StatusCode.SUCCESS_URI;
		String myEntityId = _sServerUrl;

		MetaDataManagerSP metadataManager = MetaDataManagerSP.getHandle();
		String logoutResponseLocation = metadataManager.getResponseLocation(issuer,
				SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		if (logoutResponseLocation == null) {
			// if responselocation does not exist, use location
			logoutResponseLocation = metadataManager.getLocation(issuer,
					SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		}
		LogoutResponseSender sender = new LogoutResponseSender();
		sender.sendLogoutResponse(logoutResponseLocation, myEntityId, statusCode, logoutRequest.getID(), httpRequest,
				httpResponse);

	}

	public void destroy()
	{
	}

}
