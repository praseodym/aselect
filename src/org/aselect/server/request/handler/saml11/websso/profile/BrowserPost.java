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
 * $Id: BrowserPost.java,v 1.7 2006/05/03 10:11:08 tom Exp $ 
 */
package org.aselect.server.request.handler.saml11.websso.profile;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xml.security.signature.XMLSignature;
import org.aselect.server.request.handler.saml11.websso.AbstractWebSSOProfile;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Base64Codec;
import org.aselect.system.utils.Utils;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLSubject;


/**
 * Browser/Post websso profile. <br>
 * <br>
 * <b>Description:</b><br>
 * Sends a SAML Browser/Post response. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class BrowserPost extends AbstractWebSSOProfile
{
	private final static String MODULE = "BrowserPost";
	//private String _sTemplate;
	private String _sTemplateName = null;
	private String _sIssuer;

	/**
	 * Initializes the Browser/Post SAML 1.1 web sso profile handler. <br>
	 * <br>
	 * <b>Description:</b><br>
	 * Reads the following configuration:<br/>
	 * <br/>
	 * &lt;profile&gt;<br/>
	 * &lt;template&gt;[template]&lt;/template&gt;<br/>
	 * &lt;/profile&gt;<br/>
	 * <ul>
	 * <li><b>template</b> - file name of the Browser/Post template, the file must be located in
	 * [working_dir]/aselectserver/conf/html/</li>
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
		String sMethod = "init";
		try {
			super.init(oConfig, lAssertionExpireTime, sAttributeNamespace, bSendAttributeStatement);

			try {
				_sTemplateName = _configManager.getParam(oConfig, "template");
				Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(), null/*language*/,
						_sTemplateName, null, null/*friendly_name*/, null/*version*/);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'template' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			// added 1.5.4
			try {
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
	 * Sends the SAML 1.1 Browser/Post response. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The <code>htInfo</code> contains the response parameters of the <code>verify_credentials</code> request.<br/>
	 * Uses the following parameters from htInfo:<br/>
	 * <li>rid</li> <li>uid</li> <br/>
	 * <br/>
	 * <li>The session will be retrieved</li> <li>The SAML Browser/Post will be created, with Authentication Assertion ,
	 * (optional) attribute assertion</li> <li>The SAML response will be signed with the default A-Select Server private
	 * key</li> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>htInfo != null</li> <li>response != null</li> <br/>
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
	public void process(HashMap htInfo, HttpServletRequest request, HttpServletResponse response, String sIP, String sHost)
	throws ASelectException
	{
		String sMethod = "process";
		try {
			String sRID = (String) htInfo.get("rid");
			if (sRID == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'rid' found");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			// RM_36_01
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

			String sUid = (String) htInfo.get("uid");
			if (sUid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'uid' found");
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

			SAMLAssertion oSAMLAssertion = createSAMLAssertion(sUid, sProviderId, htInfo, sIP, sHost,
					SAMLSubject.CONF_BEARER, sIdp);

			Vector vSAMLAssertions = new Vector();
			vSAMLAssertions.add(oSAMLAssertion);

			SAMLResponse oSAMLResponse = new SAMLResponse(null, sShire, vSAMLAssertions, null);

			Vector vCertificatesToInclude = new Vector();
			vCertificatesToInclude.add(_configManager.getDefaultCertificate());
			oSAMLResponse.sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, _configManager.getDefaultPrivateKey(),
					vCertificatesToInclude);

			sendBrowserResponse(request, response, oSAMLResponse, sShire, sTarget);
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
	 * Clears class variables from memory. <br>
	 * <br>
	 * 
	 * @see org.aselect.server.request.handler.saml11.websso.AbstractWebSSOProfile#destroy()
	 */
	@Override
	public void destroy()
	{
		// does nothing
	}

	/**
	 * Sends the SAML 1.1 Browser/Post response by showing a form according to the configured template. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Replaces the following tags in the Browser/Post template:<br>
	 * <li>[action]</li> <li>[target]</li> <li>[samlresponse]</li> <br/>
	 * <br/>
	 * <li>Creates the output page</li> <li>The SAML Output message will be Base64 encoded</li> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>response != null</li> <li>oSAMLResponse != null</li> <li>sAction != null</li> <li>sTarget != null</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param servletResponse
	 *            HttpServletResponse were the page will be shown
	 * @param oSAMLResponse
	 *            Containing the SAML Assertions
	 * @param sAction
	 *            the shire value
	 * @param sTarget
	 *            the target value
	 * @throws ASelectException
	 *             if the page could not be displayed or the Base64 encoding fails
	 */
	private void sendBrowserResponse(HttpServletRequest servletRequest, HttpServletResponse servletResponse, SAMLResponse oSAMLResponse, String sAction, String sTarget)
	throws ASelectException
	{
		String sMethod = "send";
		PrintWriter pwOut = null;
		try {
			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

			String sHTMLResponse = Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(),
					null/*language*/, _sTemplateName, null, null/*friendly_name*/, null/*version*/);

			sHTMLResponse = Utils.replaceString(sHTMLResponse, "[action]", sAction);
			sHTMLResponse = Utils.replaceString(sHTMLResponse, "[target]", sTarget);

			String sSAMLResponse = oSAMLResponse.toString();

			StringBuffer sbFine = new StringBuffer("Sending Browser/Post to '");
			sbFine.append(sAction);
			_systemLogger.log(Level.FINE, MODULE, sMethod, sbFine.toString());

			StringBuffer sbFiner = new StringBuffer("SAML Browser/Post response message:\r\n");
			sbFiner.append(sSAMLResponse);
			_systemLogger.log(Level.FINER, MODULE, sMethod, sbFiner.toString());

			String sSAMLResponseBase64 = Base64Codec.encode(sSAMLResponse.getBytes("ASCII"));
			sHTMLResponse = Utils.replaceString(sHTMLResponse, "[samlresponse]", sSAMLResponseBase64);

			pwOut.print(sHTMLResponse);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not send SAMLResponse", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			if (pwOut != null)
				pwOut.close();
		}
	}
}
