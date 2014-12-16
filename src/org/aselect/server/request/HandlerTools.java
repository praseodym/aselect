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
package org.aselect.server.request;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Level;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Node;

/*
 * Generic Tools for all Handler routines
 * 
 * 20100228, Bauke: moved all copies of (de)serializeAttributes to HandlerTools
 */
public class HandlerTools
{
	final static String MODULE = "HandlerTools";

	// This code can be used to set HttpOnly (not supported by Java Cookies)
	/**
	 * Put cookie value.
	 * 
	 * @param response
	 *            the response
	 * @param sCookieName
	 *            the cookie name
	 * @param sCookieValue
	 *            the cookie value
	 * @param sCookieDomain
	 *            the cookie domain
	 * @param sCookiePath
	 *            the cookie path
	 * @param iAge
	 *            the age
	 * @param httpOnly
	 *            the http only flag
	 * @param logger
	 *            the logger
	 */
	public static void putCookieValue(HttpServletResponse response, String sCookieName, String sCookieValue,
			String sCookieDomain, String sCookiePath, int iAge, int httpOnly, ASelectSystemLogger logger)
	{
		String sMethod = "putCookieValue";
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		if (response == null) {
			logger.log(Level.WARNING, MODULE, sMethod, "No servletResponse to set cookie "+sCookieName);
			return;
		}

		String addedSecurity = _configManager.getAddedSecurity();
		if (sCookiePath == null)
			sCookiePath = _configManager.getCookiePath();

		String sValue = sCookieName + "=" + sCookieValue;
		if (sCookieDomain != null)
			sValue += "; Domain=" + sCookieDomain;
		sValue += "; Version=1; Path=" + sCookiePath; // was: "/aselectserver/server";
		// if (iAge != -1) sValue += "; expires=<date>"
		// format: Wdy, DD-Mon-YYYY HH:MM:SS GMT, e.g.: Fri, 31-Dec-2010, 23:59:59 GMT

		if (iAge >= 0)
			sValue += "; Max-Age=" + iAge;

		if (addedSecurity != null && addedSecurity.contains("cookies") && httpOnly == 1) {
				sValue += "; Secure; HttpOnly";
		}
		logger.log(Level.INFO, MODULE, sMethod, "Add Cookie, Header: " + sValue);
		
		//response.setHeader("Set-Cookie", sValue);
		// 20121029, Bauke: It must be possible to have multiple "Set-Cookie" headers! Therefore use addHeader().
		response.addHeader("Set-Cookie", sValue);
	}

	/**
	 * Del cookie value.
	 * 
	 * @param response
	 *            the response
	 * @param sCookieName
	 *            the s cookie name
	 * @param sCookieDomain
	 *            the s cookie domain
	 * @param logger
	 *            the logger
	 */
	public static void delCookieValue(HttpServletResponse response, String sCookieName,
				String sCookieDomain, String sCookiePath, ASelectSystemLogger logger)
	{
		String sMethod = "delCookieValue";
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		if (response == null) {
			logger.log(Level.WARNING, MODULE, sMethod, "No servletResponse to set cookie "+sCookieName);
			return;
		}

		Cookie cookie = new Cookie(sCookieName, "_deleted_");
		if (sCookieDomain != null)
			cookie.setDomain(sCookieDomain);
		if (!Utils.hasValue(sCookiePath))
			sCookiePath = _configManager.getCookiePath();
		cookie.setPath(sCookiePath); // was: "/aselectserver/server");
		cookie.setMaxAge(0);
		logger.log(Level.INFO, MODULE, sMethod, "Delete Cookie="+sCookieName+" Domain="+sCookieDomain+" Path="+sCookiePath);
		response.addCookie(cookie);
	}

	// Bauke: added
	/**
	 * Gets the cookie value.
	 * 
	 * @param request
	 *            the request
	 * @param sName
	 *            the s name
	 * @param logger
	 *            the logger
	 * @return the cookie value
	 */
	public static String getCookieValue(HttpServletRequest request, String sName, ASelectSystemLogger logger)
	{
		String sMethod = "getCookieValue";
		String sReturnValue = null;
		
		if (request == null) {
			logger.log(Level.WARNING, MODULE, sMethod, "No servletRequest to retrieve cookie "+sName);
			return null;
		}
		Cookie oCookie[] = request.getCookies();
		if (oCookie == null)
			return null;
		for (int i = 0; i < oCookie.length; i++) {
			String sCookieName = oCookie[i].getName();
			if (logger != null) { // allow for null logger
				logger.log(Level.FINEST, MODULE, sMethod, "Get "+sName+" try="+sCookieName);
			}
			if (sCookieName.equals(sName)) {
				String sCookieValue = oCookie[i].getValue();
				// remove '"' surrounding the cookie if applicable
				int iLength = sCookieName.length();
				if (sCookieName.charAt(0) == '"' && sCookieName.charAt(iLength - 1) == '"') {
					sCookieName = sCookieName.substring(1, iLength - 1);
				}
				if (logger != null) {// allow for null logger
					logger.log(Level.FINE, MODULE, sMethod, sCookieName + "=" + sCookieValue);
				}
				sReturnValue = sCookieValue;
				break;
			}
		}
		return sReturnValue;
	}

	/**
	 * @throws ASelectException
	 */
	public static void setRequestorFriendlyCookie(HttpServletResponse servletResponse, HashMap sessionContext, ASelectSystemLogger systemLogger)
	throws ASelectException
	{
		ASelectConfigManager configManager = ASelectConfigManager.getHandle();
		if (sessionContext == null)
			return;
	
		String sStatus = (String)sessionContext.get("status");
		String sAppId = (String)sessionContext.get("app_id");
		if (/*"del".equals(sStatus) &&*/ Utils.hasValue(sAppId)) {
			String sUF = ApplicationManager.getHandle().getFriendlyName(sAppId);
			HandlerTools.setEncryptedCookie(servletResponse, "requestor_friendly_name", sUF, configManager.getCookieDomain(), -1/*age*/, systemLogger);
		}
	}
	
	/**
	 * Sets an encrypted cookie.
	 * 
	 * @param servletResponse
	 *            the servlet response
	 * @param sCookieName
	 *            the cookie name
	 * @param sCookieValue
	 *            the cookie value
	 * @param sCookieDomain
	 *            the cookie domain
	 * @param systemLogger
	 *            the systemlogger
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static void setEncryptedCookie(HttpServletResponse servletResponse,
			String sCookieName, String sCookieValue, String sCookieDomain, int iAge, ASelectSystemLogger systemLogger)
	throws ASelectException
	{
		String sMethod = "setEncryptedCookie";
		CryptoEngine _cryptoEngine = CryptoEngine.getHandle();

		systemLogger.log(Level.FINER, MODULE, sMethod, "Encrypt cookie="+sCookieName+", value="+sCookieValue);
		if (servletResponse == null) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "No servletResponse to set cookie");
			return;
		}
		if (!Utils.hasValue(sCookieValue)) {
			systemLogger.log(Level.FINER, MODULE, sMethod, "No cookie value given for "+sCookieName);
			return;
		}
		sCookieValue = _cryptoEngine.encryptData(sCookieValue.getBytes());

		HandlerTools.putCookieValue(servletResponse, sCookieName, sCookieValue,
				sCookieDomain, null/*default path*/, iAge/*5 years*/, 1/*httpOnly*/, systemLogger);
	}

	/**
	 * Gets the encrypted cookie.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param sCookieName
	 *            the cookie name
	 * @param systemLogger
	 *            the system logger
	 * @return the string
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static String getEncryptedCookie(HttpServletRequest servletRequest, String sCookieName, ASelectSystemLogger systemLogger)
	throws ASelectException
	{
		String sMethod = "getEncryptedCookie";
		if (servletRequest == null) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "No servletRequest to retrieve cookie");
			return null;
		}
		CryptoEngine _cryptoEngine = CryptoEngine.getHandle();
		String sCookieValue = HandlerTools.getCookieValue(servletRequest, sCookieName, systemLogger);
		if (!Utils.hasValue(sCookieValue))
			return null;
		
		byte[] baBytes = _cryptoEngine.decryptData(sCookieValue);
		sCookieValue = new String(baBytes);
		systemLogger.log(Level.FINER, MODULE, sMethod, "Decrypt="+sCookieValue);
		return sCookieValue;
	}

	/**
	 * Log cookies.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param logger
	 *            the logger
	 */
	public static void logCookies(HttpServletRequest servletRequest, ASelectSystemLogger logger)
	{
		String sMethod = "logCookies";
		Cookie[] aCookies = servletRequest.getCookies();
		if (aCookies == null) {
			logger.log(Level.FINER, MODULE, sMethod, "No Cookies");
			return;
		}

		for (int i = 0; i < aCookies.length; i++) {
			logger.log(Level.INFO, MODULE, sMethod, "Cookie " + aCookies[i].getName() + "=" + aCookies[i].getValue()
					+ ", Path=" + aCookies[i].getPath() + ", Domain=" + aCookies[i].getDomain() + ", Age="
					+ aCookies[i].getMaxAge());
		}
	}

	/**
	 * Creates the attribute statement assertion.
	 * 
	 * @param parms
	 *            the parms
	 * @param sIssuer
	 *            the issuer
	 * @param sSubject
	 *            the subject
	 * @param sign
	 *            sign the assertion?
	 * @return the assertion
	 * @throws ASelectException
	 */
	@SuppressWarnings( {
		"unchecked"
	})
	public static Assertion createAttributeStatementAssertion(Map parms, String sIssuer, String sSubject, boolean sign)
	throws ASelectException
	{
		String sMethod = "createAttributeStatementAssertion";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		XMLObjectBuilderFactory _oBuilderFactory;
		_oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory();

		systemLogger.log(Level.INFO, MODULE, sMethod, "Issuer="+sIssuer+" Subject="+sSubject);
		XMLObjectBuilder stringBuilder = _oBuilderFactory.getBuilder(XSString.TYPE_NAME);

		SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) _oBuilderFactory
				.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);

		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) _oBuilderFactory
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

		Assertion assertion = assertionBuilder.buildObject();
		assertion.setVersion(SAMLVersion.VERSION_20);

		SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) _oBuilderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameID = nameIDBuilder.buildObject();
		nameID.setFormat(NameIDType.TRANSIENT); // was PERSISTENT
		nameID.setNameQualifier(sIssuer);
		nameID.setValue(sSubject);
		
		systemLogger.log(Level.INFO, MODULE, sMethod, nameID.getValue());
		SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) _oBuilderFactory
				.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject subject = subjectBuilder.buildObject();
		subject.setNameID(nameID);

		SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) _oBuilderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
		assertionIssuer.setFormat(NameIDType.ENTITY);
		assertionIssuer.setValue(sIssuer);

		assertion.setIssuer(assertionIssuer);
		assertion.setSubject(subject);
		DateTime tStamp = new DateTime();
		assertion.setIssueInstant(tStamp);
		try {
			assertion.setID(SamlTools.generateIdentifier(systemLogger, MODULE));
		}
		catch (ASelectException ase) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "failed to build SAML response", ase);
		}

		AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

		SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) _oBuilderFactory
				.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

		Iterator itr = parms.keySet().iterator();
		systemLogger.log(Level.INFO, MODULE, sMethod, "Start iterating through parameters");
		while (itr.hasNext()) {
			String parmName = (String) itr.next();

			// Bauke, 20081202 replaced, cannot convert parms.get() to a String[]
			Object oValue = parms.get(parmName);
			if (!(oValue instanceof String)) {
				systemLogger.log(Level.INFO, MODULE, sMethod, "Skip, not a String: "+parmName);
				continue;
			}
			String sValue = (String)parms.get(parmName);
			systemLogger.log(Level.FINER, MODULE, sMethod, "parm:" + parmName + " has value:" + sValue);
			Attribute attribute = attributeBuilder.buildObject();
			attribute.setName(parmName);
			XSString attributeValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
					XSString.TYPE_NAME);
			attributeValue.setValue(sValue);
			attribute.getAttributeValues().add(attributeValue);

			attributeStatement.getAttributes().add(attribute);
		}
		systemLogger.log(Level.INFO, MODULE, sMethod, "Finalizing the assertion building, sign="+sign);
		assertion.getAttributeStatements().add(attributeStatement);
		assertion = marshallAssertion(assertion, false);
		if (sign) {
			systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the final Assertion >======");
			assertion = (Assertion)SamlTools.signSamlObject(assertion);
			systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the Assertion ======<" + assertion);
		}

		// // Only for testing
		// if (!SamlTools.checkSignature(assertion, _configManager.getDefaultCertificate().getPublicKey()) ) {
		// _systemLogger.log(Level.INFO, MODULE, sMethod, "Signing verification says signature NOT valid ?!?" );
		// } else {
		// _systemLogger.log(Level.INFO, MODULE, sMethod, "Signing verification says signature is valid!" );
		// }
		return assertion;
	}

	
	
	
	/**
	 * Creates the authn + attribute statement assertion.
	 * 
	 * @param parms
	 *            the (optional) attribute name/value pairs
	 * @param sIssuer
	 *            the issuer
	 * @param sSubject
	 *            the subject
	 * @param sign
	 *            sign the assertion?
	 * @return the assertion
	 * @throws ASelectException
	 */
	@SuppressWarnings( {
		"unchecked"
	})
	public static Assertion createAuthnStatementAttributeStatementAssertion(Map parms, String sIssuer, String sSubject, boolean sign)
	throws ASelectException
	{
		String sMethod = "createAuthnStatmeentAttributeStatementAssertion";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		XMLObjectBuilderFactory _oBuilderFactory;
		_oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory();

		systemLogger.log(Level.INFO, MODULE, sMethod, "Issuer="+sIssuer+" Subject="+sSubject);
		XMLObjectBuilder stringBuilder = _oBuilderFactory.getBuilder(XSString.TYPE_NAME);

		SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) _oBuilderFactory
				.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);

		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) _oBuilderFactory
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

		Assertion assertion = assertionBuilder.buildObject();
		assertion.setVersion(SAMLVersion.VERSION_20);

		SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) _oBuilderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameID = nameIDBuilder.buildObject();
//		nameID.setFormat(NameIDType.TRANSIENT);
//		nameID.setNameQualifier(sIssuer);
		nameID.setValue(sSubject);
		
		SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) _oBuilderFactory
		.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_SENDER_VOUCHES);

		
		
		systemLogger.log(Level.INFO, MODULE, sMethod, nameID.getValue());
		SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) _oBuilderFactory
				.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject subject = subjectBuilder.buildObject();
		subject.setNameID(nameID);
		subject.getSubjectConfirmations().add(subjectConfirmation);


		SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) _oBuilderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
		assertionIssuer.setFormat(NameIDType.ENTITY);
		assertionIssuer.setValue(sIssuer);

		assertion.setIssuer(assertionIssuer);
		assertion.setSubject(subject);
		DateTime tStamp = new DateTime();
		assertion.setIssueInstant(tStamp);
		try {
			assertion.setID(SamlTools.generateIdentifier(systemLogger, MODULE));
		}
		catch (ASelectException ase) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "failed to build SAML response", ase);
		}

		// ---- AuthenticationContext
		SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) _oBuilderFactory
				.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
		
		// "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
		String sAutnContextClassRefURI = "PasswordProtectedTransport";// Make this a parameter
		authnContextClassRef.setAuthnContextClassRef(sAutnContextClassRefURI);

		SAMLObjectBuilder<AuthenticatingAuthority> authenticatingAuthorityBuilder = (SAMLObjectBuilder<AuthenticatingAuthority>) _oBuilderFactory
				.getBuilder(AuthenticatingAuthority.DEFAULT_ELEMENT_NAME);
		AuthenticatingAuthority authenticatingAuthority = authenticatingAuthorityBuilder.buildObject();
		String  sAuthenticatingAuthority = "DIGID-BURGER";// Make this a parameter
		authenticatingAuthority.setURI(sAuthenticatingAuthority);
		
		
		SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) _oBuilderFactory
				.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
		AuthnContext authnContext = authnContextBuilder.buildObject();
		authnContext.setAuthnContextClassRef(authnContextClassRef);
		authnContext.getAuthenticatingAuthorities().add(authenticatingAuthority);

		SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) _oBuilderFactory
				.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
		AuthnStatement authnStatement = authnStatementBuilder.buildObject();
		authnStatement.setAuthnInstant(tStamp);

		authnStatement.setAuthnContext(authnContext);

		
		assertion.getAuthnStatements().add(authnStatement);

		
		if ( parms != null && !parms.isEmpty() ) {	// only add attributeStatement if there are any attributes
			
			AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
	
			SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) _oBuilderFactory
					.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
	
			Iterator itr = parms.keySet().iterator();
			systemLogger.log(Level.INFO, MODULE, sMethod, "Start iterating through parameters");
			while (itr.hasNext()) {
				String parmName = (String) itr.next();
	
				Object oValue = parms.get(parmName);
				if (!(oValue instanceof String)) {
					systemLogger.log(Level.INFO, MODULE, sMethod, "Skip, not a String: "+parmName);
					continue;
				}
				String sValue = (String)parms.get(parmName);
				systemLogger.log(Level.FINER, MODULE, sMethod, "parm:" + parmName + " has value:" + sValue);
				Attribute attribute = attributeBuilder.buildObject();
				attribute.setName(parmName);
				XSString attributeValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
						XSString.TYPE_NAME);
				attributeValue.setValue(sValue);
				attribute.getAttributeValues().add(attributeValue);
	
				attributeStatement.getAttributes().add(attribute);
			}
			assertion.getAttributeStatements().add(attributeStatement);
		}

		systemLogger.log(Level.INFO, MODULE, sMethod, "Finalizing the assertion building, sign="+sign);
		assertion = marshallAssertion(assertion, false);
		if (sign) {
			systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the final Assertion >======");
//			assertion = (Assertion)SamlTools.signSamlObject(assertion);
			assertion = (Assertion)SamlTools.signSamlObject(assertion, null, true, true); // sha1 default algorithm
			systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the Assertion ======<" + assertion);
		}

		return assertion;
	}

	
	
	/**
	 * Marshall assertion.
	 * 
	 * @param assertion
	 *            the assertion
	 * @return the assertion
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static Assertion marshallAssertion(Assertion assertion, boolean doLog)
	throws ASelectException
	{
		String sMethod = "marshallAssertion";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(assertion);
		try {
			Node node = marshaller.marshall(assertion);
			if (doLog) {
				String msg = XMLHelper.prettyPrintXML(node);
				systemLogger.log(Level.INFO, MODULE, sMethod, msg);
			}
		}
		catch (MarshallingException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return assertion;
	}

	/**
	 * Create a signed and base64 encoded Saml Token
	 * containing the attributes present in htAttributes.
	 * 
	 * @param sIssuer
	 *            the issuer
	 * @param sTgt
	 *            the tgt
	 * @param htAttributes
	 *            the attributes
	 * @return the attribute token
	 * @throws ASelectException
	 */
	public static String createAttributeToken(String sIssuer, String sTgt, HashMap htAttributes)
	throws ASelectException
	{
		String sMethod = "createAttributeToken";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();

		Assertion samlAssert = HandlerTools.createAttributeStatementAssertion(htAttributes, sIssuer/* Issuer */,
				sTgt/* Subject */, true/* sign */);
		String sAssertion = XMLHelper.nodeToString(samlAssert.getDOM());
		systemLogger.log(Level.INFO, MODULE, sMethod, "Assertion=" + sAssertion);

		try {
			byte[] bBase64Assertion = sAssertion.getBytes("UTF-8");
			BASE64Encoder b64enc = new BASE64Encoder();
			return b64enc.encode(bBase64Assertion);
		}
		catch (UnsupportedEncodingException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}
	
	
	/*
	 * 
	 */
		/**
		 * @param keyfile	full path to keyfile that contains client certificate
		 * @param keyfilePw	password for the keystore
		 * @return	sslsocketfactory or null if creation failed 
		 * @throws GeneralSecurityException
		 * @throws IOException
		 * 
		 * Override this method if you need a non-default sslsocketfactory
		 * or set  the security property "ssl.SocketFactory.provider"
		 */
		public static SSLSocketFactory createSSLSocketFactory(String keyfile, String keyfilePw) throws GeneralSecurityException, IOException {
		    /*
		     * Set up a key manager for client authentication
		     * if asked by the server.  Use the implementation's
		     * default TrustStore and secureRandom routines.
		     */
		    SSLSocketFactory factory = null;
			SSLContext ctx;
			KeyManagerFactory kmf;
			KeyStore ks;
			
			if (keyfile == null || "".equals(keyfile.trim()) ) {
				return null;
			}
			char[] passphrase = keyfilePw.toCharArray();

			ctx = SSLContext.getInstance("TLS");
			kmf = KeyManagerFactory.getInstance("SunX509");
			ks = KeyStore.getInstance("JKS");

			ks.load(new FileInputStream(keyfile), passphrase);

			kmf.init(ks, passphrase);
			ctx.init(kmf.getKeyManagers(), null, null);

			factory = ctx.getSocketFactory();

			return factory;
			
		}

	
}
