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
 */

/* 
 * $Id: AbstractWebSSOProfile.java,v 1.5 2006/05/03 10:11:08 tom Exp $ 
 */

package org.aselect.server.request.handler.saml11.websso;


import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLSubject;

/**
 * Abstract class implementing the basic functionality of a WebSSO profile handler. <br>
 * <br>
 * <b>Description:</b><br>
 * Reads default configuration and contains functionality for SAMLAssertion generation. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public abstract class AbstractWebSSOProfile implements IWebSSOProfile
{
	protected final static String SESSION_ID_PREFIX = "saml11_";

	protected ASelectSystemLogger _systemLogger;
	protected ASelectConfigManager _configManager;
	protected long _lAssertionExpireTime;
	protected SessionManager _oSessionManager;
	protected TGTManager _oTGTManager;
	protected String _sASelectServerID;
	private String _sAttributeNamespace;
	private boolean _bSendAttributeStatement;

	private final static String MODULE = "AbstractWebSSOProfile";
	private String _sID;

	/**
	 * Initializes the default functionality for a WebSSO profile Handler. <br/>
	 * <br/>
	 * <b>Description:</b><br>
	 * <li>Sets class variables with a protective scope</li> <li>Reads the A-Select Server id from A-Select Server basic
	 * configuration</li> <li>Reads the 'id' config item from the 'profile' config section of the WebSSO Profile handler
	 * config</li> <br>
	 * <br>
	 * 
	 * @param oConfig
	 *            the o config
	 * @param lAssertionExpireTime
	 *            the l assertion expire time
	 * @param sAttributeNamespace
	 *            the s attribute namespace
	 * @param bSendAttributeStatement
	 *            the b send attribute statement
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.saml11.websso.IWebSSOProfile#init(java.lang.Object, long,
	 *      java.lang.String, boolean)
	 */
	public void init(Object oConfig, long lAssertionExpireTime, String sAttributeNamespace,
			boolean bSendAttributeStatement)
	throws ASelectException
	{
		String sMethod = "init()";
		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			_configManager = ASelectConfigManager.getHandle();
			_lAssertionExpireTime = lAssertionExpireTime;
			_oSessionManager = SessionManager.getHandle();
			_oTGTManager = TGTManager.getHandle();
			_sAttributeNamespace = sAttributeNamespace;
			_bSendAttributeStatement = bSendAttributeStatement;

			try {
				_sID = _configManager.getParam(oConfig, "id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'id' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			Object oASelect = null;
			try {
				oASelect = _configManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'aselect' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sASelectServerID = _configManager.getParam(oASelect, "server_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config item 'server_id' in section 'aselect' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

	}

	/**
	 * Returns the configured profile id <br>
	 * <br>
	 * .
	 * 
	 * @return the ID
	 * @see org.aselect.server.request.handler.saml11.websso.IWebSSOProfile#getID()
	 */
	public String getID()
	{
		return _sID;
	}

	/**
	 * Process.
	 * 
	 * @param htInfo
	 *            the ht info
	 * @param response
	 *            the response
	 * @param sIP
	 *            the s ip
	 * @param sHost
	 *            the s host
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.saml11.websso.IWebSSOProfile#process(java.util.HashMap,
	 *      javax.servlet.http.HttpServletResponse, java.lang.String, java.lang.String)
	 */
	abstract public void process(HashMap htInfo, HttpServletResponse response, String sIP, String sHost)
	throws ASelectException;

	/**
	 * Destroy.
	 * 
	 * @see org.aselect.server.request.handler.saml11.websso.IWebSSOProfile#destroy()
	 */
	abstract public void destroy();

	/**
	 * Creates a SAMLAssertion object. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Reads the following configuration:<br/>
	 * &lt;profile id='[id]' class='[class]'&gt;<br/>
	 * &nbsp;...<br/>
	 * &lt;/profile&gt;<br/>
	 * <li><b>id</b> - the unique id of the web sso handler</li> <li><b>class</b> - the physical web sso handler class</li>
	 * <br/>
	 * <br/>
	 * <li>Creates a SAMLAssertion object containing the authentication statement and (if available) attribute statement
	 * </li> <li>Creates SAMLAuthenticationStatement</li> <li>Creates SAMLAttributeStatement if attributes are available
	 * </li> <li>Stores SAML information needed for queries in the A-Select TGT Manager</li> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>sUid != null</li> <li>sProviderId != null</li> <li>htInfo != null</li> <li>sConfirmationMethod != null</li> <br/>
	 * <br/>
	 * <code>htInfo</code> must contain the following items:<br/>
	 * <li>authsp</li> <li>app_id</li> <li>attributes</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sUid
	 *            the A-Select user id of the requestor
	 * @param sProviderId
	 *            the providerId that is requested
	 * @param htInfo
	 *            HashMap containing user information
	 * @param sIP
	 *            the client IP address
	 * @param sHost
	 *            the Host representation of the client IP address
	 * @param sConfirmationMethod
	 *            the SAML Confirmation Method that must be used when creating a SAML Authentication statement
	 * @param sIdp
	 *            the s idp
	 * @return the requested SAMLAssertion object
	 * @throws ASelectException
	 *             if creation fails
	 */
	protected SAMLAssertion createSAMLAssertion(String sUid, String sProviderId, HashMap htInfo, String sIP,
			String sHost, String sConfirmationMethod, String sIdp)
	throws ASelectException
	{
		String sMethod = "createSAMLAssertion()";
		SAMLAssertion oSAMLAssertion = null;
		SAMLAttributeStatement oSAMLAttributeStatement = null;
		SAMLAuthenticationStatement oSAMLAuthenticationStatement = null;
		Date dCurrent = new Date();
		Vector vSAMLStatements = new Vector();
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

			oSAMLAuthenticationStatement = generateSAMLAuthenticationStatement(sUid, sIP, sHost, dCurrent,
					sConfirmationMethod, sIdp);
			vSAMLStatements.add(oSAMLAuthenticationStatement);

			String sAttributes = (String) htInfo.get("attributes");
			if (sAttributes == null) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No parameter 'attributes' found");
			}
			else {
				htAttributes = org.aselect.server.utils.Utils.deserializeAttributes(sAttributes);
				if (_bSendAttributeStatement) {
					oSAMLAttributeStatement = generateSAMLAttributeStatement(sUid, htAttributes);
					vSAMLStatements.add(oSAMLAttributeStatement);
				}
			}

			Date dExpire = new Date(System.currentTimeMillis() + _lAssertionExpireTime);

			oSAMLAssertion = new SAMLAssertion(sIdp, // _sASelectServerID, // Our (IdP) Id
					dCurrent, // Valid from
					dExpire, // Valid until
					null,
					// RM_34_01
					null, // Advice(s)
					vSAMLStatements // Contained statements
			);

			// stores all SAML information to build SAML queries in the TGT Manager storage
			storeSessionInformation(sUid, sProviderId, sAppID, sAuthSPID, htAttributes);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAssertion", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return oSAMLAssertion;
	}

	/**
	 * Stores SAML user information in the TGT Manager. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Stores information needed for SAML Queries. <br/>
	 * <br/>
	 * Creates or updates a session with session id saml_[A-Select User ID] and the following information:<br/>
	 * <table border='1'>
	 * <tr>
	 * <th>key</th>
	 * <th>value</th>
	 * </tr>
	 * <tr>
	 * <td>resources</td>
	 * <td><b><i>resources HashMap</b></i></td>
	 * </tr>
	 * <tr>
	 * <td>authsps</td>
	 * <td>authsp_id</td>
	 * </tr>
	 * <tr>
	 * <td>attributes</td>
	 * <td><b><i>attributes / application HashMap</b> </i></td>
	 * </tr>
	 * </table>
	 * <br/>
	 * <b><i>resources HashMap</b></i>
	 * <table border='1'>
	 * <tr>
	 * <th>key</th>
	 * <th>value</th>
	 * </tr>
	 * <tr>
	 * <td>providerId</td>
	 * <td>app_id</td>
	 * </tr>
	 * </table>
	 * <br/>
	 * <b><i>attributes / application HashMap</b></i>
	 * <table border='1'>
	 * <tr>
	 * <th>key</th>
	 * <th>value</th>
	 * </tr>
	 * <tr>
	 * <td>app_id</td>
	 * <td><b><i>attributes HashMap</b></i></td>
	 * </tr>
	 * </table>
	 * <br/>
	 * <b><i>attributes HashMap</b></i>
	 * <table border='1'>
	 * <tr>
	 * <th>key</th>
	 * <th>value</th>
	 * </tr>
	 * <tr>
	 * <td>attribute name</td>
	 * <td>attribute value</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>sUid != null</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sUid
	 *            A-Select user id
	 * @param sProviderId
	 *            requested providerId
	 * @param sAppID
	 *            A-Select app_id
	 * @param sAuthSPID
	 *            A-Select authsp_id
	 * @param htAttributes
	 *            HashMap containing the user attributes
	 * @throws ASelectException
	 *             if session information could not be stored
	 */
	private void storeSessionInformation(String sUid, String sProviderId, String sAppID, String sAuthSPID,
			HashMap htAttributes)
	throws ASelectException
	{
		String sMethod = "storeAttributesSession()";
		try {
			String sSAMLID = SESSION_ID_PREFIX + sUid;

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

	/**
	 * Generates a SAML Authentication Statement. <br/>
	 * 
	 * @param sUid
	 *            A-Select user id
	 * @param sIP
	 *            client IP
	 * @param sHost
	 *            client Host name
	 * @param dCurrent
	 *            current time as Date object
	 * @param sConfirmationMethod
	 *            SAML Confirmation Method
	 * @param sIdp
	 *            the s idp
	 * @return the created SAMLAuthenticationStatement
	 * @throws ASelectException
	 *             if generation fails
	 */
	private SAMLAuthenticationStatement generateSAMLAuthenticationStatement(String sUid, String sIP, String sHost,
			Date dCurrent, String sConfirmationMethod, String sIdp)

	throws ASelectException
	{
		String sMethod = "generateSAMLAuthenticationStatement()";
		SAMLAuthenticationStatement oSAMLAuthenticationStatement = null;
		try {

			SAMLNameIdentifier oSAMLNameIdentifier = new SAMLNameIdentifier(sUid, sIdp,
					SAMLNameIdentifier.FORMAT_UNSPECIFIED);

			/**
			 * AuthN is finished. Now create an assertion. Step 1: construct the subject, i.e. who/what is this
			 * assertion about? A subject consists of a NameIdentifier (id's the principal) and at least one
			 * SubjectConfirmationMethod that tells the SP how to authenticate (confirm) the subject. With Browser/POST,
			 * this method is always "bearer", meaning the bearer of the assertion, which is the principal itself, is
			 * confirming its own identity.
			 */

			SAMLSubject oSAMLSubject = new SAMLSubject(oSAMLNameIdentifier, null, null, null);
			oSAMLSubject.addConfirmationMethod(sConfirmationMethod);

			/**
			 * Step 2: construct the authentication statement. It contains the subject we've just created, an
			 * authentication instant (which we simply set to "now"), the IP of the subject
			 */

			oSAMLAuthenticationStatement = new SAMLAuthenticationStatement(oSAMLSubject, // The subject
					dCurrent, // Authn instant
					sIP, // The subject's IP
					sHost, // The subject's hostname
					null); // Authority bindings

		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAuthenticationStatement", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return oSAMLAuthenticationStatement;
	}

	/**
	 * Generates a SAML 1.1 Attribute statement <br>
	 * <br>
	 * 
	 * @param sUid
	 *            A-Select user id
	 * @param htAttributes
	 *            HashMap containing attributes with key=[attribute name] value=[attribute value]
	 * @return the created SAMLAttributeStatement
	 * @throws ASelectException
	 *             if generation fails
	 */
	private SAMLAttributeStatement generateSAMLAttributeStatement(String sUid, HashMap htAttributes)
	throws ASelectException
	{
		String sMethod = "generateSAMLAttributeStatement()";
		SAMLAttributeStatement oSAMLAttributeStatement = null;
		try {
			Vector vAttributes = new Vector();
			Set keys = htAttributes.keySet();
			for (Object s : keys) {
				String sKey = (String) s;
				// Enumeration enumAttributeNames = htAttributes.keys();
				// while(enumAttributeNames.hasMoreElements())
				// {
				// String sKey = (String)enumAttributeNames.nextElement();
				Object oValue = htAttributes.get(sKey);
				SAMLAttribute oSAMLAttribute = createSAMLAttribute(sKey, oValue);
				vAttributes.add(oSAMLAttribute);
			}

			SAMLNameIdentifier oSAMLNameIdentifier = new SAMLNameIdentifier(sUid, _sASelectServerID,
					SAMLNameIdentifier.FORMAT_UNSPECIFIED);

			SAMLSubject oSAMLSubject = new SAMLSubject(oSAMLNameIdentifier, null, null, null);
			oSAMLAttributeStatement = new SAMLAttributeStatement(oSAMLSubject, vAttributes);

		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAttributeStatement", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return oSAMLAttributeStatement;
	}

	/**
	 * Creates a SAMLAttribute object. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a SAMLAttribute object, using the supplied name and value (must be of type String or Vector).<br/>
	 * Sets the attribute namespace, to the configured one. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * sName != null<br/>
	 * oValue != null <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sName
	 *            attribute name
	 * @param oValue
	 *            attribute value (String or Vector)
	 * @return SAMLAttribute containing the complete attribute
	 * @throws ASelectException
	 *             if creation fails
	 */
	private SAMLAttribute createSAMLAttribute(String sName, Object oValue)
	throws ASelectException
	{
		String sMethod = "generateSAMLAttribute()";
		SAMLAttribute oSAMLAttribute = new SAMLAttribute();

		try {
			oSAMLAttribute.setNamespace(_sAttributeNamespace);
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
