/*
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
package org.aselect.server.request.handler.xsaml20.sp;

import java.io.PrintWriter;
import java.io.StringReader;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.Saml20_RedirectDecoder;
import org.aselect.server.request.handler.xsaml20.SamlHistoryManager;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
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
	private static final String MODULE = "sp.Xsaml20_SLO_Response";
	private static final String SOAP_TYPE = "text/xml";
	private final String LOGOUTRESPONSE = "LogoutResponse";

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	@Override
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
		String sMethod = "init";
		super.init(oServletConfig, oConfig);
	}

	/**
	 * Process Logout response. <br>
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If process logout response fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		if (request.getParameter("SAMLResponse") != null) {
			handleRedirectLogoutResponse(request, response);
		}
		else if (request.getContentType() != null && request.getContentType().startsWith(SOAP_TYPE)) {
			// It's a Soap logoutrequest
			handleSOAPLogoutResponse(request, response);
		}
		else {
			throw new ASelectException("Xsaml20_SLO_Response.process() expected SOAP message,"
					+ " or a request with SAMLResponse parameter");
		}
		return null;
	}

	/**
	 * Handle redirect logout response.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleRedirectLogoutResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
	throws ASelectException
	{
		String sMethod = "handleRedirectLogoutResponse";

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

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do logoutResponse signature verification="
					+ is_bVerifySignature());
			if (is_bVerifySignature()) {
				// The SAMLRequest must be signed, if not the message can't be trusted
				// and a response message will be sent to the browser
				if (!SamlTools.isSigned(httpRequest)) {
					String errorMessage = "SAML message must be signed.";
					// RM_60_01
					// exception in all other cases?
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					PrintWriter pwOut = httpResponse.getWriter();
					pwOut.write(errorMessage);
					return;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML message IS signed.");

				String sEntityId = issuer.getValue();
				MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
				PublicKey publicKey = metadataManager.getSigningKeyFromMetadata(sEntityId);
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
			handleLogoutResponse(httpRequest, httpResponse, (LogoutResponse) samlMessage);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	// This response is arriving from the IdP.
	// TgT is still present, response must be sent to our SP party or application
	/**
	 * Handle logout response.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @param response
	 *            the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogoutResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			LogoutResponse response)
	throws ASelectException
	{
		String sMethod = "handleLogoutResponse";
		TGTManager tgtManager = TGTManager.getHandle();
		
		String resultCode = Errors.ERROR_ASELECT_INTERNAL_ERROR;	// backward compatibility
		String statusCode = response.getStatus().getStatusCode().getValue();
//		String resultCode = (statusCode.equals(StatusCode.SUCCESS_URI)) ? Errors.ERROR_ASELECT_SUCCESS
//				: Errors.ERROR_ASELECT_INTERNAL_ERROR;
		if ( (StatusCode.SUCCESS_URI).equals(statusCode) ) {
			resultCode = Errors.ERROR_ASELECT_SUCCESS;
		} else {
			String sErrorSubCode = null;
			if ( response.getStatus().getStatusCode().getStatusCode() != null) {	// Get the subcode
				sErrorSubCode = SamlTools.mapStatus(response.getStatus().getStatusCode().getStatusCode().getValue());
				_systemLogger.log(Level.FINER, MODULE, sMethod, "ErrorSubcode: " + sErrorSubCode);

			}
			StatusMessage statMsg = response.getStatus().getStatusMessage();
			if (statMsg != null) {
				resultCode = statMsg.getMessage();
				_systemLogger.log(Level.FINER, MODULE, sMethod, "StatusMessage found: " + resultCode);

			} else {
				if (sErrorSubCode != null && !"".equals(sErrorSubCode)) {
					resultCode = sErrorSubCode;
				}
			}
		}

		String sTgT = response.getInResponseTo(); // hopefully contains the TgT
		if (sTgT.startsWith("_"))
			sTgT = sTgT.substring(1);
		HashMap htTGTContext = tgtManager.getTGT(sTgT);
		String sIdP = (htTGTContext == null) ? null : (String) htTGTContext.get("SendIdPLogout");

		// RM_60_02
		String sReturnUrl = (htTGTContext == null) ? null : (String) htTGTContext.get("RelayState");
		if (sIdP == null || sReturnUrl == null) {
			sReturnUrl = httpRequest.getParameter("RelayState"); // fall back mechanism
		}

		// Remove the TgT
		if (htTGTContext != null)
			tgtManager.remove(sTgT);

		finishLogoutActions(httpResponse, resultCode, sReturnUrl);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Logout Succeeded");
	}

	/**
	 * Handle soap logout response.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleSOAPLogoutResponse(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "handleSOAPLogoutResponse";
		try {
			/*
			 * ServletInputStream input = request.getInputStream(); BufferedInputStream bis = new
			 * BufferedInputStream(input); char b = (char) bis.read(); StringBuffer sb = new StringBuffer(); while
			 * (bis.available() != 0) { sb.append(b); b = (char) bis.read(); } String sReceivedSoap = sb.toString();
			 * _systemLogger.log(Level.INFO, MODULE, sMethod, "Received Soap:\n" + sReceivedSoap);
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
			UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) logoutResponseNode);

			LogoutResponse logoutResponse = (LogoutResponse) unmarshaller.unmarshall((Element) logoutResponseNode);
			StatusCode statusCode = logoutResponse.getStatus().getStatusCode();

			// Check signature of logoutResponse
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do logoutResponse signature verification="
					+ is_bVerifySignature());
			String initiatingSP = logoutResponse.getIssuer().getValue();
			if (is_bVerifySignature()) {
				// Bauke, 20091008: changed from MetaDataManagerIdp to ...Sp
				MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
				PublicKey pkey = metadataManager.getSigningKeyFromMetadata(initiatingSP);
				if (pkey == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "PublicKey for entityId: " + initiatingSP
							+ " not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found PublicKey for entityId: " + initiatingSP);
				if (checkSignature(logoutResponse, pkey)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "logoutResponse was signed OK");
				}
				else {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "logoutResponse was NOT signed OK");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST); // Kick 'm out
				}
			}

			// determine for which user this logoutResponse was anyway!
			String inResponseTo = logoutResponse.getInResponseTo();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "inResponseTo=" + inResponseTo + " statusCode="
					+ statusCode.getValue());
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
