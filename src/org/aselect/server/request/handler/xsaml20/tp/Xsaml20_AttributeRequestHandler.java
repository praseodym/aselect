/**
 * 
 */
package org.aselect.server.request.handler.xsaml20.tp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.URLDecoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.Utils;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * @author RH Handles HTTP SAML20TGTRequest, verifies signature of requester Generates and returns TGT attributes
 *         Request must contain a (base64 encoded) "token" reference in the "token" query attribute A TGT will be
 *         fetched (if existent) and the requested attributes will be returned Requested attributes can be supplied in a
 *         multi valued "attributes" query-attribute Attributes will be returned in a (base64) encoded header? (Still to
 *         decide) SAMPLE aselect.xml <handler id="saml20_attribute_http_request"
 *         class="org.aselect.server.request.handler.xsaml20.tp.Xsaml20_AttributeRequestHandler"
 *         target="/saml20_attribute_http_request.*" > <verify_signature>true</verify_signature> <!-- not yet
 *         implemented --> </handler>
 */

// RM_61_01
public class Xsaml20_AttributeRequestHandler extends Saml20_BaseHandler
{

	// RM_61_02
	// RM_61_03
	// RM_61_04
	private static final String PARM_NAME_SAMLREQUEST = "SAMLRequest";// only SAMLRequest=attributestatement is
	// supported so far
	private static final String PARM_NAME_ENCODING = "encoding"; // only encoding=base64 is supported yet
	// private static final String PARM_NAME_URLENCODING = "urlencoding"; // urlencoding=true will urldecode the request
	private static final String PARM_NAME_CREATETGT = "createtgt"; // createtgt=true will set a TGT
	private static final String PARM_NAME_TOKEN = "token"; // base64 encoded samltoken or transientid (if samltoken,
	// must be an Assertion)
	private static final String PARM_NAME_ATRRIBUTES = "attributes"; // requested attributes as comma seperated
	// (url)list
	// private static final String PARM_NAME_UID = "uid"; // uid=<some_id> must be present if createtgt=true
	// private static final String PARM_NAME_REQUESTSIGNING = "requestsigning"; // requestsigning ==true will sign the
	// requested assertion
	// private static final String PARM_VALUE_TOKENREQUEST = "tokenrequest";
	private static final String PARM_VALUE_ATRRIBUTESTATEMENT = "attributestatement";
	private static final String PARM_VALUE_TRANSIENT = "transientid";
	private static final String PARM_VALUE_ENCODING_BASE64 = "base64";

	private static final String TGT_NAMEID_KEY = "name_id"; // Is hard-coded in TGTManger

	private final static String MODULE = "tp.Xsaml20_AttributeRequestHandler";
	// private XMLObjectBuilderFactory _oBuilderFactory;

	private String encoding = null; // encoding stype we want to receive in the response
	private String samlrequest = null; // samltype we want returned (e.g. "attributestatement")
	// private String createtgt = null; // "true" or "false"
	private String urlencoding = null; // "true" or "false"

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";

		try {
			super.init(oServletConfig, oConfig);
		}
		catch (ASelectException e) { // pass to caller
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "TokenRequest");

		// _oBuilderFactory = Configuration.getBuilderFactory();

	}

	/*
	 * (non-Javadoc)
	 * @see org.aselect.server.request.handler.IRequestHandler#process(javax.servlet.http.HttpServletRequest,
	 * javax.servlet.http.HttpServletResponse)
	 */
	public RequestState process(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		// SUGGEST allow for direct transient ID handling
		String sMethod = "process";
		String sPathInfo = servletRequest.getPathInfo();
		PrintWriter pwOut = null;
		
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "==== Path=" + sPathInfo + " TokenRequestQuery: "
				+ servletRequest.getQueryString());
		samlrequest = servletRequest.getParameter(PARM_NAME_SAMLREQUEST);
		if (samlrequest == null) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Request: " + servletRequest.getQueryString()
					+ " is not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		// Check if we support the requested encoding
		encoding = servletRequest.getParameter(PARM_NAME_ENCODING);
		if (encoding != null && !PARM_VALUE_ENCODING_BASE64.equalsIgnoreCase(encoding)) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Requested encoding: " + encoding + " not supported");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		// createtgt = request.getParameter(PARM_NAME_CREATETGT);

		try {
			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);
			// RM_61_05
			handleAttributeRequest(servletRequest, servletResponse, pwOut);
		}
		catch (IOException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage());
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return new RequestState(null);

	}

	// For now we use SAML URI Binding (which is simple but not very safe!)
	// RM_61_06
	/**
	 * Handle attribute request.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void handleAttributeRequest(HttpServletRequest request, HttpServletResponse response, PrintWriter pwOut)
	throws IOException, ASelectException
	{
		String sMethod = "handleAttributeRequest";

		String[] atts = request.getParameterValues(PARM_NAME_ATRRIBUTES);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "attributes=" + atts);
		for (int i = 0; i < atts.length; i++) {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "attributes[" + i + "]=" + atts[i]);
		}

		// RM_61_07
		// For now we only allow one request at the time, we take the first that comes up
		String returnstring = null;
		String subject = null;
		if (PARM_VALUE_ATRRIBUTESTATEMENT.equalsIgnoreCase(samlrequest)
				|| PARM_VALUE_TRANSIENT.equalsIgnoreCase(samlrequest)) {

			String token = request.getParameter(PARM_NAME_TOKEN);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "SAML token received:" + token);
			if ("true".equalsIgnoreCase(urlencoding)) {
				// We received de token URLEncoded so we URLDecode
				token = URLDecoder.decode(token, "UTF-8");
			}

			if (PARM_VALUE_ENCODING_BASE64.equalsIgnoreCase(request.getParameter(PARM_NAME_ENCODING))) {
				BASE64Decoder b64dec = new BASE64Decoder();
				byte[] tokenArray = b64dec.decodeBuffer(token);
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				baos.write(tokenArray);
				token = baos.toString("UTF-8"); // We should have gotten UTF-8 formatted strings
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "decoded token received:" + token);

			if (PARM_VALUE_ATRRIBUTESTATEMENT.equalsIgnoreCase(samlrequest)) {

				// String issuer = _sServerUrl;
				// RM_61_08
				// RM_61_09
				// Assertion ass = createAttributeStatementAssertion(parms, issuer, subject,
				// "true".equalsIgnoreCase(sign));
				// returnstring = XMLHelper.prettyPrintXML(ass.getDOM());

				Assertion assertion = createAssertion(token);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Assertion created");

				ASelectConfigManager _oASelectConfigManager = ASelectConfigManager.getHandle();
				String _sKeystoreName = new StringBuffer(_oASelectConfigManager.getWorkingdir()).append(File.separator)
						.append("keystores").append(File.separator).append("aselect.keystore").toString();
				KeyStore ks = null;
				try {
					ks = KeyStore.getInstance("JKS");
					ks.load(new FileInputStream(new File(_sKeystoreName)), "changeit".toCharArray());
					// ks.load(new FileInputStream(new File(_sKeystoreName)), null);
				}
				catch (KeyStoreException e) {
					e.printStackTrace();
				}
				catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				}
				catch (CertificateException e) {
					e.printStackTrace();
				}
				if (assertion.isSigned()) {
					// if (!SamlTools.checkSignature(assertion, getPublicKey(ks, "fippg"))) {
					if (!SamlTools.checkSignature(assertion, _configManager.getDefaultCertificate().getPublicKey())) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Signature not valid!");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					else {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Signature is valid!");
					}
				}
				subject = assertion.getSubject().getNameID().getValue();
			}
			else {
				subject = token;
			}

			TGTManager tgtm = TGTManager.getHandle();
			HashMap ht = tgtm.getTGT(subject);
			StringBuffer sb = new StringBuffer();
			_systemLogger.log(Level.FINER, MODULE, sMethod, "ht:" + ht);
			// RM_61_10
			if (atts != null && ht != null && !ht.isEmpty()) {
				for (int i = 0; i < atts.length; i++) {
					// RM_61_11
					if (ht.containsKey(atts[i])) {
						// Code to RFC822 header quoted strings
						sb.append("\"").append(atts[i]).append('=').append(ht.get(atts[i]).toString()).append("\"")
								.append(',');
						// sb.append("\"").append(MimeUtility.encodeText(atts[i])).append('=').
						// append(MimeUtility.encodeText(ht.get(atts[i]).toString())).append("\"").append(',');
						_systemLogger
								.log(Level.FINEST, MODULE, sMethod, "attributes to return so far:" + (sb.toString()));
					}
				}
				int j = 0;
				if ((j = sb.lastIndexOf(",")) >= 0)
					sb.deleteCharAt(j); // remove last ","
			}
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "TGT values retrieved:" + (sb.toString()));
			returnstring = sb.toString();
		}
		else if (PARM_VALUE_TRANSIENT.equalsIgnoreCase(samlrequest)) {

		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + samlrequest + " is not supported");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		response.setContentType("text/RFC822-Headers");  // overwrite type from prepareForHtmlOutput()
		// Add returnstring also as custom header "atrributes"
		response.setHeader("X-" + PARM_NAME_ATRRIBUTES, returnstring);
		pwOut.write(returnstring);
		// Caller closes pwOut
	}

	/**
	 * Creates the assertion.
	 * 
	 * @param token
	 *            the token
	 * @return the assertion
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings( {
		"unchecked"
	})
	private Assertion createAssertion(String token)
	throws ASelectException
	{

		String sMethod = "createAssertion";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Creating the Assertion");

		Assertion assertion = null;

		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		DocumentBuilder builder;
		try {
			builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(token);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedAssertion = builder.parse(inputSource);
			Element elementReceivedAssertion = docReceivedAssertion.getDocumentElement();

			_systemLogger.log(Level.FINER, MODULE, sMethod, "unmarhalling DOM:"
					+ XMLHelper.prettyPrintXML(elementReceivedAssertion));
			assertion = unmarshallAssertion(elementReceivedAssertion);
		}
		catch (ParserConfigurationException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not configure the parser");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		catch (SAXException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not parse the assertion");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		catch (IOException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "IO error handling the assertion");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		catch (UnmarshallingException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not unmarshall the assertion");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		return assertion;
	}

	/**
	 * Unmarshall assertion.
	 * 
	 * @param ass
	 *            the ass
	 * @return the assertion
	 * @throws ASelectException
	 *             the a select exception
	 * @throws UnmarshallingException
	 *             the unmarshalling exception
	 */
	private Assertion unmarshallAssertion(Element ass)
	throws ASelectException, UnmarshallingException
	{
		String sMethod = "unmarshallAssertion";

		// Unmarshall to the SAMLmessage
		UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = factory.getUnmarshaller(ass);

		Assertion assertion = (Assertion) unmarshaller.unmarshall(ass);

		return assertion;
	}

	/**
	 * Unmarshall attribute statement.
	 * 
	 * @param ass
	 *            the ass
	 * @return the attribute statement
	 * @throws ASelectException
	 *             the a select exception
	 * @throws UnmarshallingException
	 *             the unmarshalling exception
	 */
	private AttributeStatement unmarshallAttributeStatement(Element ass)
	throws ASelectException, UnmarshallingException
	{
		String sMethod = "unmarshallAssertion";

		// Unmarshall to the SAMLmessage
		UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = factory.getUnmarshaller(ass);

		AttributeStatement assertion = (AttributeStatement) unmarshaller.unmarshall(ass);

		return assertion;
	}

	/**
	 * Gets the public key.
	 * 
	 * @param keystore
	 *            the keystore
	 * @param alias
	 *            the alias
	 * @return the public key
	 */
	public PublicKey getPublicKey(KeyStore keystore, String alias)
	{
		java.security.cert.Certificate cert;
		ASelectConfigManager _oASelectConfigManager = ASelectConfigManager.getHandle();
		cert = _oASelectConfigManager.getDefaultCertificate();
		// Get public key
		PublicKey publicKey = cert.getPublicKey();
		return publicKey;
	}
}
