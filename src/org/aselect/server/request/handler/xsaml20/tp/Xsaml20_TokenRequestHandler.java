/**
 * 
 */
package org.aselect.server.request.handler.xsaml20.tp;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Encoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.util.XMLHelper;

/**
 * @author RH
 * Handles HTTP SAML20TokenRequest, verifies signature of requester Generates and returns a SAMLAssertion
 * containing (optional) attributes provided in the request. Request must contain a "uid" reference. This "uid"
 * will NOT be returned in the SAMLAssertion A new unique identifier will be generated and returned in the
 * SAMLAssertion (subject) (Optionally) a TGT will be set with this "uid" and newly generated identifier for
 * later reference SAMPLE aselect.xml
 * <handler id="saml20_token_http_request"
 *	class="org.aselect.server.request.handler.xsaml20.tp.Xsaml20_TokenRequestHandler"
 *	target="/saml20_token_http_request.*" >
 *	<verify_signature>true</verify_signature>
 * </handler>
 */
// RM_62_01
public class Xsaml20_TokenRequestHandler extends Saml20_BaseHandler
{

	// RM_62_02
	// change query parameters to more unique values (e.q. 'anoigorequest_encoding=base64')
	// or even better, put them as parameters in de aselect.xml config file
	private static final String PARM_NAME_SAMLREQUEST = "SAMLRequest";// only SAMLRequest=attributestatement is
	// supported so far
	private static final String PARM_NAME_ENCODING = "encoding"; // only encoding=base64 is supported yet
	private static final String PARM_NAME_URLENCODING = "urlencoding"; // urlencoding=true will urlencode the result
	private static final String PARM_NAME_CREATETGT = "createtgt"; // createtgt=true will set a TGT
	private static final String PARM_NAME_UID = "uid"; // uid=<some_id> must be present if createtgt=true
	private static final String PARM_NAME_REQUESTSIGNING = "requestsigning"; // requestsigning ==true will sign the
	// requested assertion
	// private static final String PARM_VALUE_TOKENREQUEST = "tokenrequest";
	private static final String PARM_VALUE_ATRRIBUTESTATEMENT = "attributestatement";
	private static final String PARM_VALUE_ENCODING_BASE64 = "base64";

	private static final String TGT_NAMEID_KEY = "name_id"; // Is hard-coded in TGTManger

	private final static String MODULE = "tp.Xsaml20_TokenRequestHandler";
	private XMLObjectBuilderFactory _oBuilderFactory;

	private String encoding = null; // encoding stype we want to receive in the response
	private String samlrequest = null; // samltype we want returned (e.g. "attributestatement")
	private String createtgt = null; // "true" or "false"
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

		_oBuilderFactory = Configuration.getBuilderFactory();

	}

	/*
	 * (non-Javadoc)
	 * @see org.aselect.server.request.handler.IRequestHandler#process(javax.servlet.http.HttpServletRequest,
	 * javax.servlet.http.HttpServletResponse)
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process";
		String sPathInfo = request.getPathInfo();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== Path=" + sPathInfo + " TokenRequestQuery: "
				+ request.getQueryString());
		samlrequest = request.getParameter(PARM_NAME_SAMLREQUEST);
		if (samlrequest == null) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Request: " + request.getQueryString()
					+ " is not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		// Check if we support the requested encoding
		encoding = request.getParameter(PARM_NAME_ENCODING);
		if (encoding != null && !PARM_VALUE_ENCODING_BASE64.equalsIgnoreCase(encoding)) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Requested encoding: " + encoding + " not supported");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		createtgt = request.getParameter(PARM_NAME_CREATETGT);
		urlencoding = request.getParameter(PARM_NAME_URLENCODING);

		try {
			// RM_62_03
			handleTokenRequest(request, response);
		}
		catch (IOException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage());
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return new RequestState(null);
	}

	// For now we use SAML URI Binding (which is simple but not very safe!)
	// RM_62_04
	/**
	 * Handle token request.
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
	protected void handleTokenRequest(HttpServletRequest request, HttpServletResponse response)
	throws IOException, ASelectException
	{
		String sMethod = "handleTokenRequest";

		response.setHeader("Pragma", "no-cache");
		response.setHeader("Cache-Control", "no-cache, no-store");
		PrintWriter pwOut = response.getWriter();
		HashMap parms = new HashMap();
		parms.putAll(request.getParameterMap());
		// RM_62_05
		// For now we only allow one request at the time, we take the first that comes up
		String returnstring = null;
		if (PARM_VALUE_ATRRIBUTESTATEMENT.equalsIgnoreCase(samlrequest)) {
			parms.remove(PARM_NAME_SAMLREQUEST); // we do not want the SAMLRequest returned as attribute in the
			// assertion
			parms.remove(PARM_NAME_ENCODING); // we do not want the encoding returned as attribute in the assertion
			parms.remove(PARM_NAME_CREATETGT); // we do not want the createtgt returned as attribute in the assertion
			String issuer = _sServerUrl;
			// RM_62_06
			String subject = "myTansientID"; // for test only
			if (createtgt != null && createtgt.equalsIgnoreCase("true")) {
				// RM_62_07
				String uid = request.getParameter(PARM_NAME_UID);
				if (uid == null || "".equals(uid)) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "For setting TGT a uid is required");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				parms.remove(PARM_NAME_UID); // we do not want the uid returned as attribute in the assertion
				TGTManager tgtm = TGTManager.getHandle();
				// copy (map) the HashMap to the HashMap
				HashMap ht = new HashMap(parms);
				ht.put(TGT_NAMEID_KEY, uid);
				subject = tgtm.createTGT(ht);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "TGT created:" + subject);
			}
			String sign = request.getParameter(PARM_NAME_REQUESTSIGNING);
			Assertion ass = HandlerTools.createAttributeStatementAssertion(parms, issuer, subject, "true".equalsIgnoreCase(sign));
			// returnstring = XMLHelper.prettyPrintXML(ass.getDOM()); // better not do this if you have signed the
			// message!
			returnstring = XMLHelper.nodeToString(ass.getDOM());
		}
		// RM_62_08
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + samlrequest + " is not supported");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		if (PARM_VALUE_ENCODING_BASE64.equalsIgnoreCase(request.getParameter(PARM_NAME_ENCODING))) {
			// response.setContentType("text/RFC822-Headers");
			// response.setContentType("text/plain");
			response.setContentType("application/octet-stream");

			BASE64Encoder b64enc = new BASE64Encoder();
			returnstring = b64enc.encode(returnstring.getBytes("UTF-8"));
		}
		else {
			response.setContentType("application/samlassertion+xml");
		}
		if ("true".equalsIgnoreCase(urlencoding)) {
			returnstring = URLEncoder.encode(returnstring, "UTF-8");
			response.setContentType("application/x-www-form-urlencoded");
		}
		pwOut.write(returnstring);
		pwOut.close();
	}
}
