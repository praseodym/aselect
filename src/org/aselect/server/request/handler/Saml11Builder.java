/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 *
 * @author Bauke Hiemstra - www.anoigo.nl
 * 
 * Version 1.0 - 14-11-2007
 */
package org.aselect.server.request.handler;


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.opensaml.*;
import org.w3c.dom.Node;

//
//
//
public class Saml11Builder
{
	final String MODULE = "SAML11Builder";
	private ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
	private TGTManager _oTGTManager = TGTManager.getHandle();

	private String _sAttributeNamespace = "";
	private boolean _bSendAttributeStatement = false;
	private long _lAssertionExpireTime = 0;
	private String _sASelectServerID = "";
	private String SESSION_ID_PREFIX = "";

	/**
	 * Instantiates a new saml11 builder.
	 */
	public Saml11Builder() {
	}

	/**
	 * Instantiates a new saml11 builder.
	 * 
	 * @param nameSpace
	 *            the name space
	 * @param sendAttr
	 *            the send attr
	 * @param expTime
	 *            the exp time
	 * @param serverID
	 *            the server id
	 * @param sesPrefix
	 *            the ses prefix
	 */
	public Saml11Builder(String nameSpace, boolean sendAttr, long expTime, String serverID, String sesPrefix) {
		_sAttributeNamespace = nameSpace;
		_bSendAttributeStatement = sendAttr;
		_lAssertionExpireTime = expTime;
		_sASelectServerID = serverID;
		SESSION_ID_PREFIX = sesPrefix;
	}

	/**
	 * Creates the assertion from string.
	 * 
	 * @param s
	 *            the s
	 * @return the sAML assertion
	 * @throws SAMLException
	 *             the SAML exception
	 */
	public SAMLAssertion createAssertionFromString(String s)
	throws SAMLException
	{
		_systemLogger.log(Level.WARNING, MODULE, "createAssertionFromString", "Assert=" + s);
		InputStream i = new ByteArrayInputStream(s.getBytes());
		SAMLAssertion p = new SAMLAssertion(i);
		return p;
	}

	/**
	 * Creates the saml assertion from credentials.
	 * 
	 * @param sUid
	 *            the s uid
	 * @param sRequestID
	 *            the s request id
	 * @param sNameIdFormat
	 *            the s name id format
	 * @param sIP
	 *            the s ip
	 * @param sHost
	 *            the s host
	 * @param sConfirmationMethod
	 *            the s confirmation method
	 * @param sProviderId
	 *            the s provider id
	 * @param sAudience
	 *            the s audience
	 * @param htInfo
	 *            the ht info
	 * @return the sAML assertion
	 * @throws ASelectException
	 *             the a select exception
	 */
	public SAMLAssertion createSAMLAssertionFromCredentials(String sUid, String sRequestID, String sNameIdFormat,
			String sIP, String sHost, String sConfirmationMethod, String sProviderId, String sAudience, HashMap htInfo)
	throws ASelectException
	{
		String sMethod = "createSAMLAssertion";
		HashMap htAttributes = null;
		try {
			String sAuthSPID = (String) htInfo.get("authsp");
			if (sAuthSPID == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'authsp' item in response from 'verify_credentials'");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			String sAppID = (String) htInfo.get("app_id");
			if (sAppID == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'app_id' item in response from 'verify_credentials'");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "genAUTH sAuthSPID=" + sAuthSPID + " sAppID" + sAppID);
			String sAttributes = (String) htInfo.get("attributes");
			if (sAttributes != null) {
				htAttributes = org.aselect.server.utils.Utils.deserializeAttributes(sAttributes);
			}
			else {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No parameter 'attributes' found");
				htAttributes = new HashMap();
				htAttributes.put("uid", sUid);
				htAttributes.put("authsp", sAuthSPID);
				htAttributes.put("app_id", sAppID);
				String sPar = (String) htInfo.get("betrouwbaarheidsniveau");
				if (sPar != null) htAttributes.put("betrouwbaarheidsniveau", sPar);
			}

			// The real work!
			SAMLAssertion oSAMLAssertion = createMySAMLAssertion(sProviderId, sUid, sNameIdFormat, sIP, sHost,
					sConfirmationMethod, sAudience, htAttributes);

			if (sRequestID != null) {
				// Add InResponseTo="<sRequestID>"
				// _systemLogger.log(Level.INFO, MODULE, sMethod, "Generated Assertion="+oSAMLAssertion);
				Node n = oSAMLAssertion.toDOM();
				Tools.addAttributeToElement(n, _systemLogger, "Assertion", "InResponseTo", sRequestID);
				// _systemLogger.log(Level.INFO, MODULE, sMethod, "Modified Assertion="+oSAMLAssertion);
			}

			// stores all SAML information to build SAML queries in the TGT Manager storage
			storeSessionInformation(sUid, sProviderId, sAppID, sAuthSPID, htAttributes);
			return oSAMLAssertion;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAssertion", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Creates the my saml assertion.
	 * 
	 * @param sProviderId
	 *            the s provider id
	 * @param sUid
	 *            the s uid
	 * @param sNameIdFormat
	 *            the s name id format
	 * @param sIP
	 *            the s ip
	 * @param sHost
	 *            the s host
	 * @param sConfirmationMethod
	 *            the s confirmation method
	 * @param sAudience
	 *            the s audience
	 * @param htAttributes
	 *            the ht attributes
	 * @return the sAML assertion
	 * @throws ASelectException
	 *             the a select exception
	 * @throws SAMLException
	 *             the SAML exception
	 */
	public SAMLAssertion createMySAMLAssertion(String sProviderId, String sUid, String sNameIdFormat, String sIP,
			String sHost, String sConfirmationMethod, String sAudience, HashMap htAttributes)
	throws ASelectException, SAMLException
	{
		String sMethod = "createMySAMLAssertion";
		Date dCurrent = new Date();
		Vector vSAMLStatements = new Vector();

		SAMLAuthenticationStatement oSAMLAuthenticationStatement = generateSAMLAuthenticationStatement(sUid,
				sNameIdFormat, sIP, sHost, dCurrent, sConfirmationMethod);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML oSAMLAuthenticationStatement="
				+ oSAMLAuthenticationStatement);
		if (oSAMLAuthenticationStatement != null)
			vSAMLStatements.add(oSAMLAuthenticationStatement);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML htAttributes=" + htAttributes);
		if (_bSendAttributeStatement) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "sUid=" + sUid);
			SAMLAttributeStatement oSAMLAttributeStatement = generateSAMLAttributeStatement(sUid, sNameIdFormat,
					htAttributes);
			// _systemLogger.log(Level.INFO, MODULE, sMethod, "oSAMLAttributeStatement="+oSAMLAttributeStatement);
			if (oSAMLAttributeStatement != null)
				vSAMLStatements.add(oSAMLAttributeStatement);
		}
		Date dExpire = new Date(System.currentTimeMillis() + _lAssertionExpireTime);

		SAMLAudienceRestrictionCondition oAudienceRestr = null;
		Vector vConditions = null;
		if (sAudience != null && !sAudience.equals("")) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML sAudience=" + sAudience);
			oAudienceRestr = new SAMLAudienceRestrictionCondition();
			oAudienceRestr.addAudience(sAudience);
			vConditions = new Vector();
			vConditions.add(oAudienceRestr);
		}
		SAMLAssertion oSAMLAssertion = new SAMLAssertion(sProviderId, // Issuer: Our (IdP) Id
				dCurrent, // Valid from
				dExpire, // Valid until
				vConditions, // Audience condition
				null, // Advice(s)
				vSAMLStatements // Contained statements
		);
		return oSAMLAssertion;
	}

	/**
	 * Generate saml authentication statement.
	 * 
	 * @param sUid
	 *            the s uid
	 * @param sNameIdFormat
	 *            the s name id format
	 * @param sIP
	 *            the s ip
	 * @param sHost
	 *            the s host
	 * @param dCurrent
	 *            the d current
	 * @param sConfirmationMethod
	 *            the s confirmation method
	 * @return the sAML authentication statement
	 * @throws ASelectException
	 *             the a select exception
	 */
	private SAMLAuthenticationStatement generateSAMLAuthenticationStatement(String sUid, String sNameIdFormat,
			String sIP, String sHost, Date dCurrent, String sConfirmationMethod)
	throws ASelectException
	{
		String sMethod = "generateSAMLAuthenticationStatement";
		SAMLAuthenticationStatement oSAMLAuthenticationStatement = null;
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "IDENT Uid=" + sUid + " ServerID=" + _sASelectServerID);
			SAMLNameIdentifier oSAMLNameIdentifier = new SAMLNameIdentifier(sUid, null/* qualifier */, // _sASelectServerID,
					(sNameIdFormat == null) ? SAMLNameIdentifier.FORMAT_UNSPECIFIED : sNameIdFormat);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SUBJECT oSAMLNameIdentifier=" + oSAMLNameIdentifier);

			SAMLSubject oSAMLSubject = new SAMLSubject(oSAMLNameIdentifier, null, null, null);
			oSAMLSubject.addConfirmationMethod(SAMLSubject.CONF_BEARER); // sConfirmationMethod
			_systemLogger.log(Level.INFO, MODULE, sMethod, "AUTH oSAMLSubject=" + oSAMLSubject);

			oSAMLAuthenticationStatement = new SAMLAuthenticationStatement(oSAMLSubject, // The subject
					sConfirmationMethod, // SAMLAuthenticationStatement.AuthenticationMethod_Password, // Authentication
					// method
					dCurrent, // Issue instant
					null, // sIP, // The subject's IP
					null, // sHost, // The subject's hostname
					null); // Authority bindings
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAuthenticationStatement", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return oSAMLAuthenticationStatement;
	}

	/**
	 * Generate saml attribute statement.
	 * 
	 * @param sUid
	 *            the s uid
	 * @param sNameIdFormat
	 *            the s name id format
	 * @param htAttributes
	 *            the ht attributes
	 * @return the sAML attribute statement
	 * @throws ASelectException
	 *             the a select exception
	 */
	private SAMLAttributeStatement generateSAMLAttributeStatement(String sUid, String sNameIdFormat,
			HashMap htAttributes)
	throws ASelectException
	{
		String sMethod = "generateSAMLAttributeStatement";
		SAMLAttributeStatement oSAMLAttributeStatement = null;
		SAMLAttribute oSAMLAttribute = null;
		try {
			Vector vAttributes = new Vector();
			Set keys = htAttributes.keySet();
			for (Object s : keys) {
				String sKey = (String) s;

				// Enumeration enumAttributeNames = htAttributes.keys();
				// while (enumAttributeNames.hasMoreElements())
				// {
				// String sKey = (String)enumAttributeNames.nextElement();
				Object oValue = htAttributes.get(sKey);
				oSAMLAttribute = createSAMLAttribute(sKey, oValue, _sAttributeNamespace);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Attr Key=" + sKey + ", oValue=" + oValue); // +", oSAMLAttribute="+oSAMLAttribute);
				// RM_37_01
				if (!sKey.equals("DiscoveryResourceOffering"))
					vAttributes.add(oSAMLAttribute);
			}
			// Make ADFS happy?
			oSAMLAttribute = createSAMLAttribute("Group", "ClaimAppMapping", "http://schemas.xmlsoap.org/claims");
			vAttributes.add(oSAMLAttribute);

			SAMLNameIdentifier oSAMLNameIdentifier = new SAMLNameIdentifier(sUid, null/* qualifier: _sASelectServerID */,
					(sNameIdFormat == null) ? SAMLNameIdentifier.FORMAT_UNSPECIFIED : sNameIdFormat);

			SAMLSubject oSAMLSubject = new SAMLSubject(oSAMLNameIdentifier, null, null, null);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "oSAMLSubject=" + oSAMLSubject);
			oSAMLAttributeStatement = new SAMLAttributeStatement(oSAMLSubject, vAttributes);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "oSAMLAttributeStatement=" + oSAMLAttributeStatement);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAttributeStatement", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return oSAMLAttributeStatement;
	}

	/**
	 * Store session information.
	 * 
	 * @param sUid
	 *            the s uid
	 * @param sProviderId
	 *            the s provider id
	 * @param sAppID
	 *            the s app id
	 * @param sAuthSPID
	 *            the s auth spid
	 * @param htAttributes
	 *            the ht attributes
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void storeSessionInformation(String sUid, String sProviderId, String sAppID, String sAuthSPID, HashMap htAttributes)
	throws ASelectException
	{
		String sMethod = "storeSessionInformation";
		try {
			String sSAMLID = SESSION_ID_PREFIX + sUid;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SAMLID=" + sSAMLID);

			HashMap htSAMLTGT = null;
			if (!_oTGTManager.containsKey(sSAMLID)) {
				htSAMLTGT = new HashMap();
				if (sProviderId != null && sAppID != null) {
					HashMap htResources = new HashMap();
					htResources.put(sProviderId, sAppID);
					htSAMLTGT.put("resources", htResources);
				}

				if (sAuthSPID != null) {
					Vector vAuthSPs = new Vector();
					vAuthSPs.add(sAuthSPID);
					htSAMLTGT.put("authsps", vAuthSPs);
				}

				if (sProviderId != null && htAttributes != null) {
					// store authentication information in session
					// put attribute collection in TGTManager with id=saml11_[A-Select_username]

					HashMap htAttribs = new HashMap();
					htAttribs.put(sProviderId, htAttributes);
					htSAMLTGT.put("attributes", htAttribs);
				}
				_oTGTManager.put(sSAMLID, htSAMLTGT);
			}
			else {
				htSAMLTGT = _oTGTManager.getTGT(sSAMLID);

				if (sProviderId != null && sAppID != null) {
					HashMap htResources = (HashMap) htSAMLTGT.get("resources");
					htResources.put(sProviderId, sAppID);
					htSAMLTGT.put("resources", htResources);
				}

				if (sAuthSPID != null) {
					Vector vTGTAuthSPs = (Vector) htSAMLTGT.get("authsps");
					vTGTAuthSPs.add(sAuthSPID);
					htSAMLTGT.put("authsps", vTGTAuthSPs);
				}

				if (sProviderId != null && htAttributes != null) {
					HashMap htAttribs = (HashMap) htSAMLTGT.get("attributes");
					if (htAttribs != null) {
						HashMap htAppIDAttribs = null;
						if ((htAppIDAttribs = (HashMap) htAttribs.get(sProviderId)) == null) {
							htAttribs.put(sProviderId, htAttributes);
						}
						else {
							htAppIDAttribs.putAll(htAttributes);
							htAttribs.put(sProviderId, htAppIDAttribs);
						}
						htSAMLTGT.put("attributes", htAttribs);
					}
				}
				_oTGTManager.updateTGT(sSAMLID, htSAMLTGT);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAssertion", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	// RM_37_02
	/**
	 * Creates the saml attribute.
	 * 
	 * @param sName
	 *            the s name
	 * @param oValue
	 *            the o value
	 * @param sNameSpace
	 *            the s name space
	 * @return the sAML attribute
	 * @throws ASelectException
	 *             the a select exception
	 */
	private SAMLAttribute createSAMLAttribute(String sName, Object oValue, String sNameSpace)
	throws ASelectException
	{
		String sMethod = "generateSAMLAttribute";
		SAMLAttribute oSAMLAttribute = new SAMLAttribute();

		try {
			oSAMLAttribute.setNamespace(sNameSpace);
			oSAMLAttribute.setName(sName);

			if (oValue instanceof Vector) {
				Vector vValue = (Vector) oValue;
				Enumeration enumValues = vValue.elements();
				while (enumValues.hasMoreElements())
					oSAMLAttribute.addValue(enumValues.nextElement());
			}
			else
				oSAMLAttribute.addValue(oValue);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create a SAML attribute object", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return oSAMLAttribute;
	}
}
