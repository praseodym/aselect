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
 * $Id: BrowserArtifact.java,v 1.9 2006/05/03 10:11:08 tom Exp $ 
 */
package org.aselect.server.request.handler.saml11.websso.profile;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.handler.saml11.common.AssertionSessionManager;
import org.aselect.server.request.handler.saml11.websso.AbstractWebSSOProfile;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLSubject;
import org.opensaml.artifact.SAMLArtifact;
import org.opensaml.artifact.SAMLArtifactType0001;
import org.opensaml.artifact.SAMLArtifactType0002;
import org.opensaml.artifact.URI;
import org.opensaml.artifact.Util;

// TODO: Auto-generated Javadoc
/**
 * Browser/Artifact websso profile. <br>
 * <br>
 * <b>Description:</b><br>
 * Sends a SAML Browser/Artifact response. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class BrowserArtifact extends AbstractWebSSOProfile
{
	private final static String MODULE = "BrowserArtifact";
	private final static String ARTIFACTTYPE = "1"; // must be 1, because 2 needs config
	private int _iArtifactType;
	private String _sSourceLocation;
	private AssertionSessionManager _oAssertionSessionManager;
	private String _sIssuer;

	/**
	 * Initializes the Browser/Artifact SAML 1.1 web sso profile handler. <br>
	 * <br>
	 * <b>Description:</b><br>
	 * Reads the following configuration:<br/>
	 * <br/>
	 * &lt;profile artifact=[artifact_id] ...&gt;<br/>
	 * &nbsp;&lt;artifact id='[id]' type='[type]'/&gt;<br/>
	 * &nbsp;&lt;artifact id='[id]' type='[type]'&gt;<br/>
	 * &nbsp;&nbsp;&lt;sourcelocation&gt;[sourcelocation]&lt;/sourcelocation&gt;<br/>
	 * &nbsp;&lt;/artifact&gt;<br/>
	 * &lt;/profile&gt;<br/>
	 * <br/>
	 * <ul>
	 * <li><b>artifact_id</b> - alias to the artifact that will be used</li>
	 * <li><b>id</b> - alias to the artifact that will be used</li>
	 * <li><b>type</b> (optional) - the Artifact type, must be '1' or '2'. If not configured '1' will be used</li>
	 * <li><b>sourcelocation</b> - the sourcelocation that will be used when creating the Artifact</li>
	 * </ul>
	 * <br>
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
	@Override
	public void init(Object oConfig, long lAssertionExpireTime, String sAttributeNamespace,
			boolean bSendAttributeStatement)
		throws ASelectException
	{
		String sMethod = "init()";
		try {
			_oAssertionSessionManager = AssertionSessionManager.getHandle();

			super.init(oConfig, lAssertionExpireTime, sAttributeNamespace, bSendAttributeStatement);

			String sArtifact = null;
			try {
				sArtifact = _configManager.getParam(oConfig, "artifact");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'artifact' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			Object oArtifact = null;
			try {
				oArtifact = _configManager.getSection(oConfig, "artifact", "id=" + sArtifact);
			}
			catch (ASelectConfigException e) {
				StringBuffer sbError = new StringBuffer("No config section 'artifact' found with id='");
				sbError.append(sArtifact);
				sbError.append("'");

				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			String sArtifactType = null;
			try {
				sArtifactType = _configManager.getParam(oArtifact, "type");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No config item 'type' in section 'artifact' found, using default type: " + ARTIFACTTYPE, e);
				sArtifactType = ARTIFACTTYPE;
			}

			try {
				_iArtifactType = Integer.parseInt(sArtifactType);
			}
			catch (NumberFormatException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Config item 'type' in section 'artifact' isn't a number: " + sArtifactType, e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			if (_iArtifactType != 1 && _iArtifactType != 2) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Config item 'type' in section 'artifact' must be '1' or '2', not: " + _iArtifactType);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			if (_iArtifactType == 2) {
				try {
					_sSourceLocation = _configManager.getParam(oArtifact, "sourcelocation");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No config item 'sourcelocation' in section 'artifact' found", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
			}
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Using artifact type: " + _iArtifactType);

			try { // added 1.5.4
				_sIssuer = _configManager.getParam(oConfig, "issuer");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'issuer' found", e);
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
	 * Sends the SAML 1.1 Browser/Artifact response. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The <code>htInfo</code> contains the response parameters of the <code>verify_credentials</code> request.<br/>
	 * Uses the following parameters from htInfo:<br/>
	 * <li>rid</li> <li>uid</li> <br/>
	 * <br/>
	 * <li>The session will be retrieved</li> <li>The SAML Browser/Artifact will be created , (optional) attribute
	 * assertion</li> <li>A SAML Assertion will be created and put in the Assertion session manager</li> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>htInfo != null</li> <li>response != null</li> <br/>
	 * The following information will not be used: <li>sIP</li> <li>sHost</li> <br/>
	 * <br/>
	 * Session must contain the following items:<br/>
	 * <li>shire</li> <li>target</li> <li>providerId</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * <br>
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
	@Override
	public void process(HashMap htInfo, HttpServletResponse response, String sIP, String sHost)
		throws ASelectException
	{
		String sMethod = "process()";
		SAMLArtifact oSAMLArtifact = null;
		try {
			String sRID = (String) htInfo.get("rid");
			if (sRID == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'rid' found");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			// TODO this is also done in the SAML11RequestHandler.process() (Martijn)
			HashMap htSession = _oSessionManager.getSessionContext(SESSION_ID_PREFIX + sRID);
			if (htSession == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No SAML Session available for rid: " + sRID);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			String sShire = (String) htSession.get("shire");
			if (sShire == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'shire' found in session");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			String sTarget = (String) htSession.get("target");
			if (sTarget == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'target' found in session");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			String sProviderId = (String) htSession.get("providerId");
			if (sProviderId == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'providerId' found in session");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			// added 1.5.4
			String sIdp = _sIssuer;
			if (sIdp == null) {
				sIdp = (String) htInfo.get("organization");
				if (sIdp == null) {
					_systemLogger.log(Level.FINE, MODULE, sMethod,
							"No parameter 'organization' found in result from verify_credentials");
					// throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
					sIdp = _sASelectServerID;
				}
			}
			sIdp = URLEncoder.encode(sIdp, "UTF-8");
			sIdp = sIdp.replaceAll("\\+", "%20");
			// end of 1.5.4

			String sConfirmationMethod = null;
			if (_iArtifactType == 1) {
				byte[] bSourceId = Util.generateSourceId(_sASelectServerID);
				oSAMLArtifact = new SAMLArtifactType0001(bSourceId);
				sConfirmationMethod = SAMLSubject.CONF_ARTIFACT;
			}
			else if (_iArtifactType == 2) {
				URI oURI = new URI(_sSourceLocation);
				oSAMLArtifact = new SAMLArtifactType0002(oURI);
				sConfirmationMethod = SAMLSubject.CONF_ARTIFACT;
			}

			if (_oAssertionSessionManager.containsKey(oSAMLArtifact)) {
				_systemLogger
						.log(Level.WARNING, MODULE, sMethod, "Artifact already exists in Artifact Session Manager");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			String sUid = (String) htInfo.get("uid");
			if (sUid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'uid' found");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			SAMLAssertion oSAMLAssertion = createSAMLAssertion(sUid, sProviderId, htInfo, sIP, sHost,
					sConfirmationMethod, sIdp);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Storing SAML assertion: " + oSAMLAssertion.toString());

			_oAssertionSessionManager.putAssertion(oSAMLArtifact, oSAMLAssertion);

			send(response, oSAMLArtifact, sShire, sTarget);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

	}

	/**
	 * Clear class variables from memory <br>
	 * <br>
	 * .
	 * 
	 * @see org.aselect.server.request.handler.saml11.websso.IWebSSOProfile#destroy()
	 */
	@Override
	public void destroy()
	{
		// do nothing
	}

	/**
	 * Sends a SAML 1.1 Browser/Artifact response. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The following redirect will be created:<br>
	 * <code>[shire]?TARGET=[target]&SAMLart=[samlart]</code><br/>
	 * <li><b>shire</b> - shire URL</li> <li><b>target</b> - URL encoded 'TARGET' parameter</li> <li><b>samlart</b> -
	 * URL encoded 'SAMLart' parameter</li> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>response != null</li> <li>oSAMLArtifact != null</li> <li>sShire != null</li> <li>sTarget != null</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param response
	 *            HttpServletResponse were the redirect will be sent
	 * @param oSAMLArtifact
	 *            SAMLArtifact containing the requested artifact assertion
	 * @param sShire
	 *            the url of the redirect
	 * @param sTarget
	 *            the target parameter from the request
	 * @throws ASelectException
	 *             URLEncoding fails or redirect couldn't be sent
	 */
	private void send(HttpServletResponse response, SAMLArtifact oSAMLArtifact, String sShire, String sTarget)
		throws ASelectException
	{
		String sMethod = "send()";
		try {
			StringBuffer sbRedirect = new StringBuffer();
			sbRedirect.append(sShire);
			sbRedirect.append("?TARGET=");
			sbRedirect.append(URLEncoder.encode(sTarget, "UTF-8"));

			// TODO: There can be more then one SAMLart in the redirect, maybe this must be supported in the future
			// (Martijn)
			sbRedirect.append("&SAMLart=");
			sbRedirect.append(URLEncoder.encode(oSAMLArtifact.encode(), "UTF-8"));

			StringBuffer sbFiner = new StringBuffer("Sending to '");
			sbFiner.append(sShire);
			sbFiner.append("' SAML Artifact message:\r\n");
			sbFiner.append(oSAMLArtifact.toString());

			_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIR " + sbFiner.toString());

			response.sendRedirect(sbRedirect.toString());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not send SAML Artifact", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

}
