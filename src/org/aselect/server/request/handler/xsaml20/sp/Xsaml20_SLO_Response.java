package org.aselect.server.request.handler.xsaml20.sp;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.security.PublicKey;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.config.Version;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.Saml20_RedirectDecoder;
import org.aselect.server.request.handler.xsaml20.SamlHistoryManager;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.idp.MetaDataManagerIdp;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.opensaml.Configuration;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

//
// SP
// Accept LogoutResponse
// Either Soap or Redirect
//
public class Xsaml20_SLO_Response extends Saml20_BaseHandler
{
	private static final String MODULE = "Xsaml20_SLO_Response";
	private static final String SOAP_TYPE = "text/xml";
	private final String LOGOUTRESPONSE = "LogoutResponse";

//	private boolean _bVerifySignature = true;  // RH, 20080602, o, this is don by Saml20_BaseHandler now
    private String _sFriendlyName = "";
    private String _sLogoutResultPage = "";

	public void destroy()
	{
	}

	/**
	 * Init for class Xsaml20_SLO_Response. <br>
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
		String sMethod = "init()";
		super.init(oServletConfig, oConfig);
		
		try {
			Object aselect = _configManager.getSection(null, "aselect");
			_sFriendlyName = _configManager.getParam(aselect, "organization_friendly_name");
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'organization_friendly_name' found in handler section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

	    _sLogoutResultPage = _configManager.loadHTMLTemplate(_configManager.getWorkingdir(), "logoutresult.html");    
	    _sLogoutResultPage = Utils.replaceString(_sLogoutResultPage, "[version]", Version.getVersion());
	    _sLogoutResultPage = Utils.replaceString(_sLogoutResultPage, "[organization_friendly]", _sFriendlyName);
	}

	/**
	 * Process Logout response. <br>
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @throws ASelectException
	 *             If process logout response fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		if (request.getParameter("SAMLResponse") != null) {
			handleRedirectLogoutResponse(request, response);
		}
		else if (request.getContentType() != null && request.getContentType().startsWith(SOAP_TYPE)) {
			// It's a Soap logoutrequest
			handleSOAPLogoutResponse(request, response);
		}
		else {
			throw new ASelectException("Xsaml20_SLO_Response.process() expected SOAP message," +
					" or a request with SAMLResponse parameter");
		}
		return null;
	}

	private void handleRedirectLogoutResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
	throws ASelectException
	{
		String sMethod = "handleRedirectLogoutResponse()";

		try {
			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(httpRequest));

			Saml20_RedirectDecoder decoder = new Saml20_RedirectDecoder();
			decoder.decode(messageContext);

			SignableSAMLObject samlMessage = (SignableSAMLObject) messageContext.getInboundSAMLMessage();
			_systemLogger.log(Level.INFO, MODULE, sMethod, XMLHelper.prettyPrintXML(samlMessage.getDOM()));

			String elementName = samlMessage.getElementQName().getLocalPart();

			// First we must detect which public key must be used
			// The alias of the publickey is equal to the appId and the
			// appId is retrieved by the Issuer, which is the server_url
			Issuer issuer;
			if (elementName.equals(LOGOUTRESPONSE)) {
				LogoutResponse logoutResponse = (LogoutResponse) samlMessage;
				issuer = logoutResponse.getIssuer();
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage: "
						+ XMLHelper.prettyPrintXML(samlMessage.getDOM()) + " is not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			if (issuer == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "LogoutResponse did not contain <Issuer> element");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do logoutResponse signature verification=" + is_bVerifySignature());
			if (is_bVerifySignature()) {
				// The SAMLRequest must be signed, if not the message can't be trusted
				// and a response message will be sent to the browser
				if (!SamlTools.isSigned(httpRequest)) {
					String errorMessage = "SAML message must be signed.";
					// TODO Why do we send return message here and throw
					// exception in all other cases?
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					PrintWriter pwOut = httpResponse.getWriter();
					pwOut.write(errorMessage);
					return;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML message IS signed.");
				
				String sEntityId = issuer.getValue();
				MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
				PublicKey publicKey = metadataManager.getSigningKey(sEntityId);
				if (publicKey == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "PublicKey for entityId: " + sEntityId
							+ " not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found PublicKey for entityId: " + sEntityId);
				if (!SamlTools.verifySignature(publicKey, httpRequest)) {
					String errorMessage = "Signing of SAML message is not correct.";
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					PrintWriter pwOut = httpResponse.getWriter();
					pwOut.write(errorMessage);
					return;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Signature is correct.");
			}

			if (elementName.equals(LOGOUTRESPONSE)) {
				handleLogoutResponse(httpRequest, httpResponse, (LogoutResponse) samlMessage);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage was not recognized");
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
			LogoutResponse response)
	{
		String sMethod = "handleLogoutResponse";
		String statusCode = response.getStatus().getStatusCode().getValue();
		String resultCode = null;
		
		if (statusCode.equals(StatusCode.SUCCESS_URI)) {
			resultCode = Errors.ERROR_ASELECT_SUCCESS;
		}
		else {
			resultCode = Errors.ERROR_ASELECT_INTERNAL_ERROR;
		}

		// Standard A-Select mechanisme is here:
		// But it needs a TGT to present its info
		//String sLoggedOutForm = _configManager.getForm("loggedout");
        //sLoggedOutForm = _configManager.updateTemplate(sLoggedOutForm, htTGTContext);
        //pwOut.println(sLoggedOutForm);

		String sRelayState = httpRequest.getParameter("RelayState");
		if (sRelayState != null && !"".equals(sRelayState)) {
			// Redirect to the url in sRelayState
			String sAmpQuest = (sRelayState.indexOf('?') >= 0) ? "&": "?"; 
			String url = sRelayState + sAmpQuest + "result_code=" + resultCode;
			try {
				httpResponse.sendRedirect(url);
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			}
		}
		else {
			PrintWriter pwOut = null;
			try {
				String sHtmlPage = Utils.replaceString(_sLogoutResultPage, "[result_code]", resultCode);
				pwOut = httpResponse.getWriter();
			    httpResponse.setContentType("text/html");
	            pwOut.println(sHtmlPage);
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			}
			finally {
	            if (pwOut != null) {
	                pwOut.close();
	            }
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Logout Succeeded");
	}

	private void handleSOAPLogoutResponse(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "handleSOAPLogoutResponse";
		try {
			/*
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
			 */
			String sReceivedSoap = Tools.stream2string(request.getInputStream()); // RH, 20080715, n
			
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(sReceivedSoap);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			Node logoutResponseNode = SamlTools.getNode(elementReceivedSoap, LOGOUTRESPONSE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutResponse:\n"
					+ XMLHelper.nodeToString(logoutResponseNode));

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) logoutResponseNode);

			LogoutResponse logoutResponse = (LogoutResponse) unmarshaller.unmarshall((Element) logoutResponseNode);
			StatusCode statusCode = logoutResponse.getStatus().getStatusCode();

			// Check signature of logoutResponse
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do logoutResponse signature verification=" + is_bVerifySignature());
			String initiatingSP = logoutResponse.getIssuer().getValue();
			if (is_bVerifySignature()) {
// Let it just generate an AselectException!!
//				String logoutRequestIssuer = ( logoutRequest.getIssuer() == null ||	// avoid nullpointers
//						logoutRequest.getIssuer().getValue() == null ||
//						"".equals(logoutRequest.getIssuer().getValue()) ) ? null : 
//							logoutRequest.getIssuer().getValue();	// else value from message
				MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
				PublicKey pkey = metadataManager.getSigningKey(initiatingSP);
				if (pkey == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "PublicKey for entityId: " + initiatingSP
							+ " not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found PublicKey for entityId: " + initiatingSP);
				if (checkSignature(logoutResponse, pkey )) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "logoutResponse was signed OK");
				}
				else {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "logoutResponse was NOT signed OK");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);  // Kick 'm out
				}
			}
			
			// determine for which user this logoutResponse was anyway!
			String inResponseTo = logoutResponse.getInResponseTo();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "inResponseTo="+inResponseTo+" statusCode="+statusCode.getValue());
			Element element = (Element) SamlHistoryManager.getHandle().get(inResponseTo);
			XMLObject o = null;
			try {
				o = SamlTools.unmarshallElement(element);
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
			String sNameID = originalLogoutRequest.getNameID().getValue();

			// not much we can or have to do here except log the status
			if (StatusCode.SUCCESS_URI.equals(statusCode.getValue())) { // log succes
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Successful logout for " + sNameID);
			}
			else { // log failure
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Logout for " + sNameID + " returned statusCode = "
						+ statusCode.getValue());
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}
}
