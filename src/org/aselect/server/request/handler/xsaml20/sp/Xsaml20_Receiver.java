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

import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.Audit;
import org.joda.time.DateTime;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLHelper;

public class Xsaml20_Receiver extends Saml20_BrowserHandler
{
	private final static String MODULE = "Xsaml20_Receiver";
	private final String ACCEPTREQUEST = "Response";

	private String _sMyAppId = null;
	private String _sResponseID = null;

	HashMap<String, String> _htKnownApplications = new HashMap<String, String>(); // contains the know application id's
	
	/**
	 * Initializes the request handler
	 *  
	 * @param oServletConfig
	 *            the o servlet config
	 * @param oHandlerConfig
	 *            the o handler config
	 * @throws ASelectException
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
		throws ASelectException
	{
		String sMethod = "init()";

		try {
			super.init(oServletConfig, oHandlerConfig);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		
		try {
			_sMyAppId = _configManager.getParam(oHandlerConfig, "app_id");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'app_id' found", e);
		}
		_htKnownApplications = ASelectConfigManager.getTableFromConfig(oHandlerConfig, _htKnownApplications, 
				"applications", "application", "id", null, true/* mandatory */, false/* unique values */);
	}

	/**
	 * Overrides the default.
	 * 
	 * @param request
	 *            - HttpServletRequest
	 * @param response
	 *            - HttpServletResponse
	 * @return RequestState
	 * @throws ASelectException
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process()";
		String sPathInfo = request.getPathInfo();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== Path=" + sPathInfo + " RequestQuery: "	+ request.getQueryString());
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request received === Path=" + sPathInfo+
				" Locale="+request.getLocale().getLanguage()+" Method="+request.getMethod());

		// 20100331, Bauke: added HTTP POST support
		if (request.getParameter("SAMLRequest") != null || "POST".equals(request.getMethod())) {
			handleSAMLMessage(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + request.getQueryString()+ " is not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request handled ");
		return new RequestState(null);
	}
	
	/**
	 * Handle specific saml20 request.
	 * Overrides the abstract method called in handleSAMLMessage().
	 * 
	 * @param httpRequest
	 *            the HTTP request
	 * @param httpResponse
	 *            the HTTP response
	 * @param samlMessage
	 *            the saml message to be handled
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	protected void handleSpecificSaml20Request(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
						SignableSAMLObject samlMessage, String sRelayState)
	throws ASelectException
	{
		String sMethod = "handleSpecificSaml20Request " + Thread.currentThread().getId();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "PathInfo="+httpRequest.getPathInfo());

		try {
			Assertion assertObj = (Assertion)samlMessage;
			//HandlerTools.marshallAssertion(assertObj, true);  // debugging
			
			//Issuer oIssuer = assertObj.getIssuer();
			Subject oSubject = assertObj.getSubject();
			String sNameId = oSubject.getNameID().getValue();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "NameID="+sNameId);
			
			AuthnStatement oAuthn = assertObj.getAuthnStatements().get(0);
			AuthnContext oContext = oAuthn.getAuthnContext();
			AuthnContextClassRef oClassRef = oContext.getAuthnContextClassRef();
			String sClassRef = oClassRef.getAuthnContextClassRef();
			String sSecLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(sClassRef, _systemLogger);
			String sDNSName = oAuthn.getSubjectLocality().getDNSName();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "ClassRef="+sClassRef+" level="+sSecLevel);
			
			// The Assertion signature was checked in the Saml20_BrowserHandler already
			// _sResponseID holds the requested application, check it against the known applications
			String sFound = _htKnownApplications.get(_sResponseID);
			if (sFound == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unknow application: " + _sResponseID);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			
			Conditions oCond = assertObj.getConditions();
			DateTime oDateTime = oCond.getNotOnOrAfter();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Nooa="+oDateTime.toString()+" VerifyInterval="+is_bVerifyInterval());
			if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(assertObj)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Bad validity interval");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			
			// Get the Attribute statement and retrieve the attributes from it
			HashMap htAttributes = new HashMap();
			htAttributes.put("uid", sNameId);
			htAttributes.put("sel_level", sSecLevel);
			AttributeStatement attrStatement = assertObj.getAttributeStatements().get(0);
			List<Attribute> lAttr = attrStatement.getAttributes();
			for (int i=0; i<lAttr.size(); i++) {
				Attribute attr = lAttr.get(i);
				List<XMLObject> aValues = attr.getAttributeValues();
				XSString obj = (XSString)aValues.get(0);
				htAttributes.put(attr.getName(), obj.getValue());
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Attr "+attr.getName()+"="+obj.getValue());
			}
			
			// Create a ticket with attributes and set a cookie
			String sTgt = createContextAndIssueTGT(httpResponse, null, _sMyServerId, _sASelectOrganization, _sMyAppId, null, htAttributes);

			// and redirect the user to the destination url
			_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT to "+_sResponseID);
			httpResponse.sendRedirect(_sResponseID);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, XMLHelper.prettyPrintXML(samlMessage.getDOM()));
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> SAML Response handled");
	}

	/**
	 * Override of the default supplied by Saml20_BrowserHandler
	 * Extract the part we're interested in from the 'samlMessage'
	 * Also retrieve the Issuer from the message and set _oSamlIssuer accordingly
	 * 
	 * @param samlMessage - the complete incoming message
	 * @return - the interesting part of the message
	 * @throws ASelectException
	 */
	protected SignableSAMLObject extractSamlObject(SignableSAMLObject samlMessage)
	throws ASelectException
	{
		String sMethod = "extractSamlObject";
		
		// Extract the "Assertion" from the message
		Response response = (Response)samlMessage;
		response.getDestination();
		_sResponseID = response.getID();
		Assertion assertObj = response.getAssertions().get(0);  // pointer in samlMessage
		//HandlerTools.marshallAssertion(assertObj, true);  // debugging
		
		set_SamlIssuer(assertObj.getIssuer());
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Response ID="+_sResponseID+" issuer="+get_SamlIssuer().getValue()); 
		return (SignableSAMLObject) assertObj;
	}

	/**
	 * Override ProtoRequestHandler version to use signing key from Application
	 * 
	 * @param sEntityId - to retrieve key for
	 * @return - the public key
	 * @throws ASelectException
	 */
	public PublicKey retrievePublicSigningKey(String sEntityId)
	throws ASelectException
	{
		String sMethod = "retrievePublicSigningKey";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Get Application Key for: "+sEntityId);
		return ApplicationManager.getHandle().getSigningKey(sEntityId);
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler#retrieveIssuer(java.lang.String, org.opensaml.common.SignableSAMLObject)
	 */
	public Issuer retrieveIssuer(String elementName, SignableSAMLObject samlMessage)
	{
		Assertion assertObj = (Assertion)samlMessage;
		return assertObj.getIssuer();
	}
	
	/**
	 * Tell caller the XML type we want recognized
	 * Overrides the abstract method called in handleSAMLMessage().
	 * 
	 * @return
	 *		the XML type
	 */
	protected String retrieveXmlType()
	{
		return ACCEPTREQUEST;
	}
	}