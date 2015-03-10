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
package org.aselect.server.request.handler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.regex.Pattern;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.Version;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.RequestState;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * IDPF RequestHandler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class serves as a an IDP first generic request handler 
 *  It handles generic authentication requests
 *  Requests a rid from the aselectserver and sends of the user to authenticate 
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>IDPFHandler</code> implementation for a single request. <br>
 * 
 * @author Remy Hanswijk
 */
public class IDPFHandler extends ProtoRequestHandler
{
	private final static String MODULE = "IDPFHandler";
	private String idpfEndpointUrl =  null;

	private String _sMyServerID = null;
	private String appID = null;
	private String sharedSecret = null;
	private String defaultUID = null;
	private String elected_uid_attributename = null;
	private String passed_credentials_attributename = null;
	private String aselectServerURL = null;
	private String endpointurl = null;
	
	private String _sPostTemplate = null;
	private String secretKey = null;
	// if we want to use other signing key than de default privatekey
	private String authsp4Signing = null;

	/* @param oServletConfig
	 *            the o servlet config
	 * @param oConfig
	 *            the o config
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";

		try {
			super.init(oServletConfig, oConfig);
			Object oASelect = null;
			try {
				oASelect = _configManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not find 'aselect' config section in config file", e);
				throw e;
			}

			try {
				_sMyServerID = _configManager.getParam(oASelect, "server_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'server_id' config parameter in 'aselect' config section", e);
				throw e;
			}
			try {
				aselectServerURL = _configManager.getParam(oASelect, "redirect_url");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'server_id' config parameter in 'redirect_url' config section", e);
				throw e;
			}

			try {
				idpfEndpointUrl = _configManager.getParam(oConfig, "idpfendpointurl");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'ists' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				appID = _configManager.getParam(oConfig, "application");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'application' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
						
			try {
				sharedSecret = _configManager.getParam(oConfig, "shared_secret");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'shared_secret' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

//			try {
//				verifySignature = _configManager.getParam(oConfig, "verify_signature");
//			}
//			catch (ASelectConfigException e) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'verify_signature' found", e);
//				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
//			}
			
			try {
				defaultUID = _configManager.getParam(oConfig, "uid");
			}
			catch (ASelectConfigException e) {
				defaultUID = "siam_user";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'uid' found, using default: " + defaultUID);
			}

			try {
				elected_uid_attributename = _configManager.getParam(oConfig, "elected_uid_attributename");
			}
			catch (ASelectConfigException e) {
				elected_uid_attributename = "uid";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'elected_uid_attributename' found, using default: " + elected_uid_attributename);
			}

			try {
				passed_credentials_attributename = _configManager.getParam(oConfig, "passed_credentials_attributename");
			}
			catch (ASelectConfigException e) {
				passed_credentials_attributename = "ssoCredentials";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'passed_credentials_attributename' found, using default: " + passed_credentials_attributename);
			}
			
			try {
				endpointurl = _configManager.getParam(oConfig, "applicationendpointurl");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'applicationendpointurl' found");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			
//			try {
//				endpointsigning = _configManager.getParam(oConfig, "applicationendpointsigning");
//			}
//			catch (ASelectConfigException e) {
//				endpointsigning = "sha1";	// set default to sha1
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'applicationendpointsigning' found, using default: " + endpointsigning , e);
//			}
			
			try {
				setPostTemplate(_configManager.getParam(oConfig, "post_template"));
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'post_template' found", e);
			}
			try {
				setSecretKey(_configManager.getParam(oConfig, "secretkey"));
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'secretkey' found", e);
			}

			try {
				setAuthsp4Signing(_configManager.getParam(oConfig, "authsp4signing"));
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'authsp4signing' found", e);
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
	 * Process incoming request.<br>
	 * 
	 * @param servletRequest
	 *            HttpServletRequest.
	 * @param servletResponse
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If processing of  data request fails.
	 */
	public RequestState process(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{		
		String sMethod = "process";
		String uid = defaultUID;
		String extractedAselect_credentials = null;
	    
    	extractedAselect_credentials = servletRequest.getParameter("aselect_credentials");

    	if (extractedAselect_credentials == null) {	// For now we don't care about previous authentication, let aselect handle that
	    	
	    	// authenticate to the aselect server
    		String ridReqURL = aselectServerURL;
    		String ridSharedSecret = sharedSecret;
    		String ridAselectServer = _sMyServerID;
    		String ridrequest= "authenticate";
    		String ridAppURL =  getIdpfEndpointUrl();
    		
//		   		String ridCheckSignature = verifySignature; 
    		
    		String ridResponse = "";
    		// Send data 
    		BufferedReader in = null;
    		try { 
	    		//Construct request data 
	    		String ridURL = ridReqURL + "?" + "shared_secret=" + URLEncoder.encode(ridSharedSecret, "UTF-8") +
	    				"&a-select-server=" + URLEncoder.encode(ridAselectServer, "UTF-8") +
	    				"&request=" + URLEncoder.encode(ridrequest, "UTF-8") +
	    				"&uid=" + URLEncoder.encode(uid, "UTF-8") +
	    				 // RM_30_01
	    				"&app_url=" + URLEncoder.encode(ridAppURL, "UTF-8") +
//			    				"&check-signature=" + URLEncoder.encode(ridCheckSignature, "UTF-8") +
	    				"&app_id=" + URLEncoder.encode(appID, "UTF-8");
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Requesting rid through: " + ridURL);

    			URL url = new URL(ridURL); 
    			
    			in = new BufferedReader(new InputStreamReader(url.openStream()));

    			String inputLine = null;
    			while ((inputLine = in.readLine()) != null) {
    				ridResponse += inputLine;
    			}
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Requesting rid response: " + ridResponse);
    		}
    		catch (Exception e) { 	
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not retrieve rid from aselectserver: " + ridAselectServer);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
    		}
    		finally {
    			if (in != null)
					try {
						in.close();
					}
					catch (IOException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close stream to aselectserver : " + ridAselectServer);
					}
    		}

    		String extractedRid = ridResponse.replaceFirst(".*rid=([^&]*).*$", "$1");
			_systemLogger.log(Level.FINER, MODULE, sMethod, "rid retrieved: " + extractedRid);

			_htSessionContext = _oSessionManager.getSessionContext(extractedRid);
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found for RID: " + extractedRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			_htSessionContext = setupSessionContext(_htSessionContext);

			String javaxSessionid = servletRequest.getSession().getId();
			_systemLogger.log(Level.FINER, MODULE, sMethod, "idpfsessionid: " +javaxSessionid);

			_htSessionContext.put("idpfsessionid", javaxSessionid);
			
			_oSessionManager.updateSession(extractedRid, _htSessionContext);
			
    		String loginrequest= "login1";

    		//Construct request data 
    		String redirectURL = null;
			try {
				redirectURL = ridReqURL + "?" + 
						"request=" + URLEncoder.encode(loginrequest, "UTF-8") +
						"&a-select-server=" + URLEncoder.encode(ridAselectServer, "UTF-8") +
						"&rid=" + extractedRid;
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Requesting login through redirect with redirectURL: " + redirectURL);
				
	    		servletResponse.sendRedirect(redirectURL);
			}
			catch (UnsupportedEncodingException e1) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e1);
			}
			catch (IOException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not redirect to: " + redirectURL);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
			}
	    }
    	else {	// This should be a return from the aselect server
    		// This should be the aselectserver response
    		
    		// check the session for validity
			String javaxSessionid = servletRequest.getSession().getId();
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "javaxSessionid: " +javaxSessionid);

			String org_javaxSessionid = (String)_htSessionContext.get("idpfsessionid");
			if (!javaxSessionid.equals(org_javaxSessionid)) { 
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid sessionid found");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Handle the aselectserver response");
			
			String finalResult  = verify_credentials(servletRequest, extractedAselect_credentials);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "finalResult after verify_credentials: " + finalResult);
			
    		String extractedAttributes = finalResult.replaceFirst(".*attributes=([^&]*).*$", "$1");
    		String extractedResultCode = finalResult.replaceFirst(".*result_code=([^&]*).*$", "$1");

    		String urlDecodedAttributes = null;;
    		String decodedAttributes = null;
			try {
				urlDecodedAttributes = URLDecoder.decode(extractedAttributes, "UTF-8");
	    		decodedAttributes = URLDecoder.decode(new String(org.apache.commons.codec.binary.Base64.decodeBase64(urlDecodedAttributes.getBytes())), "UTF-8");
	    		String attribs[] = decodedAttributes.split("&");
	    		for (int i=0;i<attribs.length;i++) {
					_systemLogger.log(Level.FINER, MODULE, sMethod, "Retrieved attribute from aselectserver: " + attribs[i]);
	    		}
			}
			catch (UnsupportedEncodingException e2) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLDecode from UTF-8, this should not happen!");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e2);
			}
	    	
	        String userSelectedClaimedId =  null;
//	        userSelectedId =  finalResult.replaceFirst(".*uid=([^&]*).*$", "$1");
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieved uid from aselect query string (userSelectedId): " + userSelectedId);

//	        userSelectedClaimedId =  decodedAttributes.replaceFirst(".*uid=([^&]*).*$", "$1");
	        userSelectedClaimedId =  decodedAttributes.replaceFirst(".*" + Pattern.quote(elected_uid_attributename) + "=([^&]*).*$", "$1");	// configurable passed_uid
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Retrieved: " +elected_uid_attributename + " (elected_uid_attributename) from aselect attributes: " + userSelectedClaimedId);
	        
	        Boolean authenticatedAndApproved = false;
	        try {
	        	authenticatedAndApproved = Boolean.valueOf(Integer.parseInt(extractedResultCode) == 0);
	        } catch (NumberFormatException nfe ) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Resultcode from aselectserver was non-numeric: " + extractedResultCode);
	        }

	        if (authenticatedAndApproved) {
				// If authenticatedAndApproved then send off the user with either POST or GET
	        	// (Only POST for now)
	    		if (getPostTemplate() != null) {
	    			String sSelectForm = Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(), null, getPostTemplate(),
	    					_sUserLanguage, _configManager.getOrgFriendlyName(), Version.getVersion());
	    			
	    			String sInputs = generatePostForm(userSelectedClaimedId);

	    			// Keep logging short:
	    			_systemLogger.log(Level.FINER, MODULE, sMethod, "Template="+getPostTemplate()+" sInputs="+sInputs+" ...");

	    			handlePostForm(sSelectForm, getEndpointurl(), sInputs, servletRequest, servletResponse);
	    		}
	    		else {	// for now we only allow POST
	    			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No POST template found");
	    			throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
	    		}	

	        } else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not aythenticate user, authentication failed with resultcode: " + extractedResultCode);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_USER_NOT_ALLOWED);
	        }
	        
	    }
		return null;
	}

	/**
	 * @param userSelectedClaimedId
	 * @return
	 * @throws ASelectException
	 */
	private String generatePostForm(String userSelectedClaimedId)
	throws ASelectException
	{
		String a = String.valueOf(CryptoEngine.nextRandomInt());	// some random number
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		// We might have to put in some time zone info here if other party is in another timezone (or use UTC)
		String b = formatter.format(new Date());	// generate currenttime in format "yyyy-MM-dd HH:mm:ss"
		String c = userSelectedClaimedId;
		String d = a + "," + b + "," + c;
		String ssoCredentials = generateInlogindicatie(d, getSecretKey(), getAuthsp4Signing());
		String sInputs = buildHtmlInput(passed_credentials_attributename,  ssoCredentials);
		return sInputs;
	}

	/**
	 * @param sMethod
	 */
	protected HashMap setupSessionContext(HashMap htSessionContext)
	{
		String sMethod = "setupSessionContext";

		
		return htSessionContext;
	}

	/**
	 * @param request
	 * @param extracted_credentials
	 * @param sMethod
	 * @param extractedAselect_credentials
	 * @return 
	 * @throws ASelectCommunicationException
	 */
	private String verify_credentials(HttpServletRequest request, String extracted_credentials)
	throws ASelectCommunicationException
	{
		String sMethod = "verify_credentials";
		// This could be done by getting request parametermap
		String queryData = request.getQueryString();
		String extractedRid = queryData.replaceFirst(".*rid=([^&]*).*$", "$1");
		String finalReqURL = aselectServerURL;
		String finalReqSharedSecret = sharedSecret;
		String finalReqAselectServer = _sMyServerID;
		String finalReqrequest= "verify_credentials";
		
		//Construct request data
		String finalRequestURL = null;
		try {
			finalRequestURL = finalReqURL + "?" + "shared_secret=" + URLEncoder.encode(finalReqSharedSecret, "UTF-8") +
					"&a-select-server=" + URLEncoder.encode(finalReqAselectServer, "UTF-8") +
					"&request=" + URLEncoder.encode(finalReqrequest, "UTF-8") +
					"&aselect_credentials=" + extracted_credentials +
//								"&check-signature=" + URLEncoder.encode(ridCheckSignature, "UTF-8") +
					"&rid=" + extractedRid;
		}
		catch (UnsupportedEncodingException e3) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e3);
		}
		String finalResult = "";

		//Send data
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieving attributes through: " + finalRequestURL);

		BufferedReader in = null;
		try { 
			URL url = new URL(finalRequestURL); 
			
			in = new BufferedReader(
					new InputStreamReader(
							url.openStream()));

			String inputLine = null;
			while ((inputLine = in.readLine()) != null) {
				finalResult += inputLine;
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Retrieved attributes in: " + finalResult);

		} catch (Exception e) { 	
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not retrieve attributes from aselectserver: " + finalReqAselectServer);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
		} finally {
			if (in != null)
				try {
					in.close();
				}
				catch (IOException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close stream to aselectserver : " + finalReqAselectServer);
				}
		}
		return finalResult;
	}

	public String generateInlogindicatie(String d, String secretKey) throws ASelectException
	{
		return generateInlogindicatie(d, secretKey, null);
	}
	
	public String generateInlogindicatie(String d, String secretKey, String authsp4singing) throws ASelectException
	{
		CryptoEngine c = CryptoEngine.getHandle();
		String signature = c.generateSignature(authsp4singing, d);
		String inlogindicatie = c.generate3DES( d + "," + signature, secretKey );

		return inlogindicatie;

	}

	public void destroy()
	{
	}

	public synchronized String getIdpfEndpointUrl()
	{
		return idpfEndpointUrl;
	}

	public synchronized void setIdpfEndpointUrl(String idpfEndpointUrl)
	{
		this.idpfEndpointUrl = idpfEndpointUrl;
	}

	public synchronized String getEndpointurl()
	{
		return endpointurl;
	}

	public synchronized void setEndpointurl(String endpointurl)
	{
		this.endpointurl = endpointurl;
	}

	
	public synchronized String getPostTemplate()
	{
		return _sPostTemplate;
	}
	public synchronized void setPostTemplate(String sPostTemplate)
	{
		_sPostTemplate = sPostTemplate;
	}


	public String getSecretKey()
	{
		return secretKey;
	}

	public void setSecretKey(String secretKey)
	{
		this.secretKey = secretKey;
	}

	public synchronized String getAuthsp4Signing()
	{
		return authsp4Signing;
	}

	public synchronized void setAuthsp4Signing(String authsp4Signing)
	{
		this.authsp4Signing = authsp4Signing;
	}

}
