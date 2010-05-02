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
package org.aselect.server.request.handler.xsaml20;

import java.io.IOException;

import java.io.PrintWriter;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.request.handler.ProtoRequestHandler;
import org.aselect.server.request.handler.xsaml20.sp.MetaDataManagerSp;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Utils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

//
//
public abstract class Saml20_BaseHandler extends ProtoRequestHandler
{
	private final static String MODULE = "Saml20_BaseHandler";

	// RH, 20080602
	// We (Bauke and I) decided that default should be NOT to verify
	// SAML2 says it SHOULD be signed, therefore it's advisable to activate it in the configuration
	private boolean _bVerifySignature = false;
	private boolean _bVerifyInterval = false; // Checking of Saml2 NotBefore and NotOnOrAfter
	private Long maxNotBefore = null; // relaxation period before NotBefore, validity period will be extended with this
	// value (seconds)
	// if null value is not specified in aselect.xml
	private Long maxNotOnOrAfter = null;
	// relaxation period after NotOnOrAfter, validity period will be extended with this value (seconds)
	// if null value is not specified in aselect.xml

	/**
	 * Init for class Saml20_BaseHandler. <br>
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
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Saml Bootstrap");
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "OpenSAML library could not be initialized", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Bootstrap done");

		String sVerifySignature = ASelectConfigManager.getSimpleParam(oHandlerConfig, "verify_signature", false);
		if ("true".equalsIgnoreCase(sVerifySignature)) {
			set_bVerifySignature(true);
		}
		String sIntervalInterval = ASelectConfigManager.getSimpleParam(oHandlerConfig, "verify_interval", false);
		if ("true".equalsIgnoreCase(sIntervalInterval)) {
			set_b_VerifyInterval(true);
		}

		String sMaxNotBefore = ASelectConfigManager.getSimpleParam(oHandlerConfig, "max_notbefore", false);
		if (sMaxNotBefore != null) {
			setMaxNotBefore(new Long(Long.parseLong(sMaxNotBefore) * 1000));
		}
		String sMaxNotOnOrAfter = ASelectConfigManager.getSimpleParam(oHandlerConfig, "max_notonorafter", false);
		if (sMaxNotOnOrAfter != null) {
			setMaxNotOnOrAfter(new Long(Long.parseLong(sMaxNotOnOrAfter) * 1000));
		}
	}

	// Unfortunately, sNameID is not equal to our tgtID (it's the Federation's)
	// So we have to search all TGT's (for now a very inefficient implementation) TODO
	/**
	 * Removes the tgt by name id.
	 * 
	 * @param sNameID
	 *            the s name id
	 * @return the int
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 */
	protected int removeTgtByNameID(String sNameID)
		throws ASelectStorageException
	{
		String sMethod = "removeByNameID";
		TGTManager tgtManager = TGTManager.getHandle();
		HashMap allTgts = tgtManager.getAll();

		// For all TGT's
		int found = 0;
		Set keys = allTgts.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
			// for (Enumeration<String> e = allTgts.keys(); e.hasMoreElements();) {
			// String sKey = e.nextElement();
			HashMap htTGTContext = (HashMap) tgtManager.get(sKey);
			String tgtNameID = (String) htTGTContext.get("name_id");
			if (sNameID.equals(tgtNameID)) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Remove TGT=" + Utils.firstPartOf(sKey, 30));
				tgtManager.remove(sKey);
				found = 1;
				break;
			}
		}
		return found;
	}

	/**
	 * Send logout to id p.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @param sTgT
	 *            the s tg t
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param sIssuer
	 *            the s issuer
	 * @param sLogoutReturnUrl
	 *            the s logout return url
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void sendLogoutToIdP(HttpServletRequest request, HttpServletResponse response, String sTgT,
			HashMap htTGTContext, String sIssuer, String sLogoutReturnUrl)
		throws ASelectException
	{
		String sMethod = "sendLogoutToIdP";
		// String sAuthspType = (String)htTGTContext.get("authsp_type");
		// if (sAuthspType != null && sAuthspType.equals("saml20")) {
		// Send a saml LogoutRequest to the federation idp
		LogoutRequestSender logoutRequestSender = new LogoutRequestSender();
		String sNameID = (String) htTGTContext.get("name_id");

		// metadata
		String sFederationUrl = (String) htTGTContext.get("federation_url");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Logout to IdP=" + sFederationUrl + " returnUrl="
				+ sLogoutReturnUrl);
		// if (sFederationUrl == null) sFederationUrl = _sFederationUrl; // xxx for now
		MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
		String url = metadataManager.getLocation(sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,
				SAMLConstants.SAML2_REDIRECT_BINDING_URI);

		if (url != null) {
			logoutRequestSender.sendLogoutRequest(request, response, sTgT, url, sIssuer/* issuer */, sNameID,
					"urn:oasis:names:tc:SAML:2.0:logout:user", sLogoutReturnUrl);
		}
		else {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "No IdP SingleLogoutService");
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}
		// }
		// else
		// _systemLogger.log(Level.INFO, MODULE, sMethod, "authsp_type != saml20");
	}

	/**
	 * Finish logout actions.
	 * 
	 * @param httpResponse
	 *            the http response
	 * @param resultCode
	 *            the result code
	 * @param sReturnUrl
	 *            the s return url
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void finishLogoutActions(HttpServletResponse httpResponse, String resultCode, String sReturnUrl)
		throws ASelectException
	{
		String sMethod = "finishLogoutActions";
		String sLogoutResultPage = "";

		// And inform the caller or user
		if (sReturnUrl != null && !"".equals(sReturnUrl)) {
			// Redirect to the "RelayState" url
			String sAmpQuest = (sReturnUrl.indexOf('?') >= 0) ? "&" : "?";
			String url = sReturnUrl + sAmpQuest + "result_code=" + resultCode;
			try {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + url);
				httpResponse.sendRedirect(url);
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			}
		}
		else {
			PrintWriter pwOut = null;
			try {
				sLogoutResultPage = _configManager.loadHTMLTemplate(_configManager.getWorkingdir(), "logoutresult",
						_sUserLanguage, _sUserCountry);
				sLogoutResultPage = Utils.replaceString(sLogoutResultPage, "[version]", Version.getVersion());
				sLogoutResultPage = Utils.replaceString(sLogoutResultPage, "[organization_friendly]", _sFriendlyName);
				String sHtmlPage = Utils.replaceString(sLogoutResultPage, "[result_code]", resultCode);
				pwOut = httpResponse.getWriter();
				httpResponse.setContentType("text/html");
				pwOut.println(sHtmlPage);
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
			finally {
				if (pwOut != null) {
					pwOut.close();
				}
			}
		}
	}

	/**
	 * Process logout request. <br>
	 * 
	 * @throws ASelectException
	 *             If processing of logout request fails.
	 */
	// public abstract RequestState process(HttpServletRequest request, HttpServletResponse response)
	// throws ASelectException;
	/*
	 * { String sMethod = "process()"; return null; }
	 */

	@Override
	public void destroy()
	{
	}

	/**
	 * Checks if is _b verify signature.
	 * 
	 * @return true, if is _b verify signature
	 */
	public synchronized boolean is_bVerifySignature()
	{
		return _bVerifySignature;
	}

	/**
	 * Sets the _b verify signature.
	 * 
	 * @param verifySignature
	 *            the new _b verify signature
	 */
	public synchronized void set_bVerifySignature(boolean verifySignature)
	{
		_bVerifySignature = verifySignature;
	}

	/**
	 * Checks if is _b verify interval.
	 * 
	 * @return true, if is _b verify interval
	 */
	public synchronized boolean is_bVerifyInterval()
	{
		return _bVerifyInterval;
	}

	/**
	 * Sets the _b_ verify interval.
	 * 
	 * @param verifyInterval
	 *            the new _b_ verify interval
	 */
	public synchronized void set_b_VerifyInterval(boolean verifyInterval)
	{
		_bVerifyInterval = verifyInterval;
	}

	/**
	 * Gets the max not before.
	 * 
	 * @return the max not before
	 */
	public synchronized Long getMaxNotBefore()
	{
		return maxNotBefore;
	}

	/**
	 * Sets the max not before.
	 * 
	 * @param maxNotBefore
	 *            the new max not before
	 */
	public synchronized void setMaxNotBefore(Long maxNotBefore)
	{
		this.maxNotBefore = maxNotBefore;
	}

	/**
	 * Gets the max not on or after.
	 * 
	 * @return the max not on or after
	 */
	public synchronized Long getMaxNotOnOrAfter()
	{
		return maxNotOnOrAfter;
	}

	/**
	 * Sets the max not on or after.
	 * 
	 * @param maxNotOnOrAfter
	 *            the new max not on or after
	 */
	public synchronized void setMaxNotOnOrAfter(Long maxNotOnOrAfter)
	{
		this.maxNotOnOrAfter = maxNotOnOrAfter;
	}

	/**
	 * Extract XML object from document string as present in a HTTP POST request
	 * 
	 * @param docReceived
	 *            the doc received
	 * @return the authz decision query
	 * @throws ASelectException
	 *             the ASelect exception
	 */
	protected XMLObject extractXmlObject(String docReceived, String sXmlType)
	throws ASelectException
	{
		String _sMethod = "handleSAMLRequest";
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "Process SAML message:\n" + docReceived);
		XMLObject authzDecisionQuery = null;
		try {
			// Build XML Document
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(docReceived);
			InputSource inputSource = new InputSource(stringReader);
			Document parsedDocument = builder.parse(inputSource);
			_systemLogger.log(Level.INFO, MODULE, _sMethod, "parsedDocument=" + parsedDocument);
	
			// Get AuthzDecision object
			Element elementReceived = parsedDocument.getDocumentElement();
			Node eltAuthzDecision = SamlTools.getNode(elementReceived, sXmlType);
	
			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltAuthzDecision);
			authzDecisionQuery = unmarshaller.unmarshall((Element) eltAuthzDecision);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to process SAML message", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return authzDecisionQuery;
	}
}
