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
package org.aselect.server.request.handler.xsaml20.idp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.ProtoRequestHandler;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

/**
 * Saml20_IDPF RequestHandler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class serves as a an Saml20 IDP first generic request handler 
 *  It handles generic authentication requests
 *  Requests a rid from the aselectserver and sends of the user to authenticate 
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>Saml20_IDPF</code> implementation for a single request. <br>
 * 
 * @author Remy Hanswijk
 */
public class Xsaml20_IDPF extends ProtoRequestHandler
{
	private final static String MODULE = "Saml20_IDPF";
//	private String ists =  null;
	private String idpfEndpointUrl =  null;

	private String _sMyServerID = null;
	private String appID = null;
	private String sharedSecret = null;
	private String defaultUID = null;
	private String aselectServerURL = null;
	private String endpointsigning = null;
	private String endpointurl = null;
	private String endpointaudience = null;
	private String endpointaddkeyname = null;
	private String endpointaddcertificate = null;
	

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
		String sMethod = "init()";

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
			
			// RM_46_01
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
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'uid' found, using default: " + defaultUID , e);
			}

			try {
				endpointurl = _configManager.getParam(oConfig, "applicationendpointurl");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'applicationendpointurl' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				endpointsigning = _configManager.getParam(oConfig, "applicationendpointsigning");
			}
			catch (ASelectConfigException e) {
				endpointsigning = "sha1";	// set default to sha1
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'applicationendpointsigning' found, using default: " + endpointsigning , e);
			}
			
			try {
				endpointaudience = _configManager.getParam(oConfig, "applicationendpointaudience");
			}
			catch (ASelectConfigException e) {
				endpointaudience = "";	// set default to empty
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'applicationendpointaudience' found, using empty");
			}

			try {
				endpointaddkeyname = _configManager.getParam(oConfig, "applicationendpointaddkeyname");
				setEndpointaddkeyname( "true".equalsIgnoreCase(endpointaddkeyname) ? "true" :" false");
			}
			catch (ASelectConfigException e) {
				setEndpointaddkeyname("false");	// set default to false
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'applicationendpointaddkeyname' found, using: " + endpointaddkeyname);
			}

			try {
				endpointaddcertificate = _configManager.getParam(oConfig, "applicationendpointaddcertificate");
				setEndpointaddcertificate("true".equalsIgnoreCase(endpointaddcertificate) ? "true" :" false");
			}
			catch (ASelectConfigException e) {
				setEndpointaddcertificate("false");	// set default to false
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'applicationendpointaddcertificate' found, using: " + endpointaddcertificate);
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
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If processing of  data request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{		
		String sMethod = "process()";
		String uid = defaultUID;
		String extractedAselect_credentials = null;
		String consumer = null;
	    
    	extractedAselect_credentials = request.getParameter("aselect_credentials");

    	if (extractedAselect_credentials == null) {	// For now we don't care about previous authentication, let aselect handle that
    		// RM_46_02
    		consumer = request.getParameter("sp");
    		_systemLogger.log(Level.INFO, MODULE, sMethod, "Received an authenticate request with sp=: " + consumer);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Process an authenticate request for user: " + uid);
	    	
	    	// RM_46_03
	    	// authenticate to the aselect server
    		String ridReqURL = aselectServerURL;
    		String ridSharedSecret = sharedSecret;
    		String ridAselectServer = _sMyServerID;
    		String ridrequest= "authenticate";
//		    String ridAppURL = consumer;
    		String ridAppURL = idpfEndpointUrl;
    		
//		   	String ridCheckSignature = verifySignature; 
			// maybe also forced_userid ?
    		
    		String ridResponse = "";
    		// Send data 
    		BufferedReader in = null;
    		try { 
	    		//Construct request data 
	    		String ridURL = ridReqURL + "?" + "shared_secret=" + URLEncoder.encode(ridSharedSecret, "UTF-8") +
	    				"&a-select-server=" + URLEncoder.encode(ridAselectServer, "UTF-8") +
	    				"&request=" + URLEncoder.encode(ridrequest, "UTF-8") +
	    				"&uid=" + URLEncoder.encode(uid, "UTF-8") +
	    				 // RM_46_04
	    				"&app_url=" + URLEncoder.encode(ridAppURL , "UTF-8") +
//			    				"&check-signature=" + URLEncoder.encode(ridCheckSignature, "UTF-8") +
	    				"&app_id=" + URLEncoder.encode(appID, "UTF-8");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Requesting rid through: " + ridURL);

    			URL url = new URL(ridURL); 
    			
    			in = new BufferedReader(new InputStreamReader(url.openStream()));

    			String inputLine = null;
    			while ((inputLine = in.readLine()) != null) {
    				ridResponse += inputLine;
    			}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Requesting rid response: " + ridResponse);
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
    		//out.println("<br/>ridResponse=" + ridResponse); 

    		String extractedRid = ridResponse.replaceFirst(".*rid=([^&]*).*$", "$1");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "rid retrieved: " + extractedRid);

			_htSessionContext = _oSessionManager.getSessionContext(extractedRid);
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found for RID: " + extractedRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			// idpf (for now) only supports HTTP-POST binding
			_systemLogger.log(Level.INFO, MODULE, sMethod, "set sp_reqbinding: " + Saml20_Metadata.singleSignOnServiceBindingConstantPOST);
			_htSessionContext.put("sp_reqbinding", Saml20_Metadata.singleSignOnServiceBindingConstantPOST);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "set sp_assert_url: " +getEndpointurl());
			_htSessionContext.put("sp_assert_url", getEndpointurl());
			_systemLogger.log(Level.INFO, MODULE, sMethod, "set sp_reqsigning: " +getEndpointsigning());
			_htSessionContext.put("sp_reqsigning",getEndpointsigning());
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "set sp_audience: " +getEndpointaudience());
			_htSessionContext.put("sp_audience",getEndpointaudience());	// set sp_audience for audience restriction in saml post
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "set sp_addkeyname: " +getEndpointaddkeyname());
			_htSessionContext.put("sp_addkeyname",getEndpointaddkeyname());	// set sp_addkeyname for keyinfo in signature in samll post
			_systemLogger.log(Level.INFO, MODULE, sMethod, "set sp_addcertificate: " +getEndpointaddcertificate());
			_htSessionContext.put("sp_addcertificate",getEndpointaddcertificate());	// set sp_addcertificate for  keyinfo in signature in samll post
			
			_oSessionManager.updateSession(extractedRid, _htSessionContext);
			
    		String loginrequest= "login1";

    		//Construct request data 
    		String redirectURL = null;
			try {
				redirectURL = ridReqURL + "?" + 
						"request=" + URLEncoder.encode(loginrequest, "UTF-8") +
//								( consumer == null ? "" : "federation_url=" + URLEncoder.encode(consumer, "UTF-8")  )+
						"&a-select-server=" + URLEncoder.encode(ridAselectServer, "UTF-8") +
						"&rid=" + extractedRid;
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Requesting login through redirect with redirectURL: " + redirectURL);
				
	    		response.sendRedirect(redirectURL);
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
//		    //////////////////// this does not work yet, user will be redirected straight from the Xsaml20_SSO
    		// This should be the aselectserver response
    		// RM_46_05
	    	// handle the aselectserver response
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Handle the aselectserver response");
			
			String finalResult  = verify_credentials(request, extractedAselect_credentials);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "finalResult after verify_credentials: " + finalResult);
			
			// RM_46_06
			// RM_46_07
	    }
		return null;
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
		String sMethod = "verify_credentials()";
		// This could be done by getting request parametermap
		String queryData = request.getQueryString();
		String extractedRid = queryData.replaceFirst(".*rid=([^&]*).*$", "$1");
		String finalReqURL = aselectServerURL;
		String finalReqSharedSecret = sharedSecret;
		String finalReqAselectServer = _sMyServerID;
		String finalReqrequest= "verify_credentials";
//		    		String ridCheckSignature = verifySignature; // this does not help for verify_credentials if <applications>
//		    											// in aselect.xml has require_signing="true"
		
		//Construct request data
		// RM_46_08
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
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieved attributes in: " + finalResult);

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

	public synchronized String getEndpointsigning()
	{
		return endpointsigning;
	}

	public synchronized void setEndpointsigning(String endpointsigning)
	{
		this.endpointsigning = endpointsigning;
	}

	public synchronized String getEndpointurl()
	{
		return endpointurl;
	}

	public synchronized void setEndpointurl(String endpointurl)
	{
		this.endpointurl = endpointurl;
	}

	public synchronized String getEndpointaudience()
	{
		return endpointaudience;
	}

	public synchronized void setEndpointaudience(String endpointaudience)
	{
		this.endpointaudience = endpointaudience;
	}

	public synchronized String getEndpointaddkeyname()
	{
		return endpointaddkeyname;
	}

	public synchronized void setEndpointaddkeyname(String endpointaddkeyname)
	{
		this.endpointaddkeyname = endpointaddkeyname;
	}

	public synchronized String getEndpointaddcertificate()
	{
		return endpointaddcertificate;
	}

	public synchronized void setEndpointaddcertificate(String endpointaddcertificate)
	{
		this.endpointaddcertificate = endpointaddcertificate;
	}
}
