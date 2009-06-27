package org.aselect.server.request.handler.xsaml20.sp;

import java.io.StringReader;
import java.security.PublicKey;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.SoapManager;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
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

//
// SP Soap Logout Request Handler
// Handles IdP requests using Soap
//
public class Xsaml20_SLO_Soap extends Saml20_BaseHandler
{
	private final static String MODULE = "Xsaml20_SLO_Soap";
	private static final String LOGOUTREQUEST = "LogoutRequest";
	//private static final String CONTENT_TYPE = "text/xml; charset=utf-8";
	private static final String SOAP_TYPE = "text/xml";

	/**
	 * Init for class Xsaml20_SLO_Soap. <br>
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
		super.init(oServletConfig, oHandlerConfig);
	}

	/**
	 * Dit is stap 7 van SLO. We hebben zojuist een saml LogoutRequest ontvangen
	 * en gaan deze nu verwerken. Dit houdt in: We loggen de gebruiker hier uit
	 * en maken hier melding van naar de federatie idp.
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
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		if (request.getContentType().startsWith(SOAP_TYPE)) {
			handleSOAPLogoutRequest(request, response);
		}
		else {
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
			*/
			String sReceivedSoap = Tools.stream2string(request.getInputStream()); // RH, 20080715, n
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received Soap LogoutRequest:\n" + sReceivedSoap);

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();

			StringReader stringReader = new StringReader(sReceivedSoap);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);
			Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
			Node eltLogoutRequest = SamlTools.getNode(elementReceivedSoap, LOGOUTREQUEST);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutRequest:\n"
					+ XMLHelper.nodeToString(eltLogoutRequest));

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltLogoutRequest);

			LogoutRequest logoutRequest = (LogoutRequest) unmarshaller.unmarshall((Element) eltLogoutRequest);


			MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
			String sASelectServerUrl = metadataManager.getLocation(_sServerUrl,
					LogoutRequest.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_SOAP11_BINDING_URI);
			String logoutRequestIssuer = ( logoutRequest.getIssuer() == null ||  // avoid nullpointers
					logoutRequest.getIssuer().getValue() == null ||
					"".equals(logoutRequest.getIssuer().getValue()) ) ? sASelectServerUrl : // if not in message, use value retrieved from metadata
						logoutRequest.getIssuer().getValue();	// else value from message

			_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutRequest Resolution at " +
					sASelectServerUrl );
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do logoutRequest signature verification=" + is_bVerifySignature());
			if (is_bVerifySignature()) {
				// Check signature of LogoutRequest
				PublicKey pkey = metadataManager.getSigningKey(logoutRequestIssuer);
				if (pkey == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "PublicKey for entityId: " + logoutRequestIssuer
							+ " not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}

//				if (checkSignature(logoutRequest,pkey)) { // We don't need the redirection anymore
				if (SamlTools.checkSignature(logoutRequest,pkey)) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutRequest was signed OK");
				}
				else {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutRequest was NOT signed OK");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);  // Kick 'm out
				}
			}

			// Signature is ok, Destroy local session
			// but first check time interval validity
			if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(logoutRequest)) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "LogoutRequest time interval was NOT valid");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);  // Kick 'm out
			}
			
			String sNameID = logoutRequest.getNameID().getValue();
			int found = removeTgtByNameID(sNameID);
			if (found == 0) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "NO TGT FOUND");
			}

			// Overwriting the client cookie will not work here since the backchannel is used

			// Send a LogoutResponse using SOAP
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Send Logout Response to: " + logoutRequestIssuer);
			String statusCode = StatusCode.SUCCESS_URI;
			String myEntityId = _sServerUrl;
			LogoutResponse logoutResponse = SamlTools.buildLogoutResponse(myEntityId, statusCode,
											logoutRequest.getID());

			// always sign the logoutResponse
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the logoutResponse >======" );
			logoutResponse = (LogoutResponse)sign(logoutResponse);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the logoutResponse ======<" );

			SoapManager soapManager = new SoapManager();
			Envelope envelope = soapManager.buildSOAPMessage(logoutResponse);
			Element envelopeElem = SamlTools.marshallMessage(envelope);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Writing SOAP message:\n"+XMLHelper.nodeToString(envelopeElem));

			// Bauke 20081112: used same code for all Soap messages
			// Remy: 20081113: Move this code to HandlerTools for uniformity
			SamlTools.sendSOAPResponse(response, XMLHelper.nodeToString(envelopeElem));
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	public void destroy()
	{
	}
}
