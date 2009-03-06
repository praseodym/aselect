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
 * $Id: SAML11RequestHandler.java,v 1.13 2006/05/03 10:11:08 tom Exp $ 
 */

package org.aselect.server.request.handler.saml11;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml11.common.AssertionSessionManager;
import org.aselect.server.request.handler.saml11.websso.IWebSSOProfile;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.communication.client.soap11.SOAP11Communicator;
import org.aselect.system.communication.client.soap12.SOAP12Communicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;

/**
 * SAML 1.1 SSO request handler.
 * <br><br>
 * <b>Description:</b><br>
 * Request handler for the following SAML 1.1 SSO Requests.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class SAML11RequestHandler extends AbstractRequestHandler
{
    private final static String MODULE = "SAML11RequestHandler";
    private final static String SESSION_ID_PREFIX = "saml11_";
    private IClientCommunicator _oClientCommunicator;
    private String _sDefaultWebSSOProfile;
    private HashMap<String,Object> _htWebSSOProfiles;
    private HashMap _htApplications;
    private AssertionSessionManager _oAssertionSessionManager;


    /**
     * Initializes the SAML 1.1 Request Handler.
     * <br><br>
     * <b>Description:</b><br>
     * Reads the following configuration:<br/><br/>
     * &lt;handler&gt;<br/>
     * &nbsp;&lt;clientcommunicator&gt;[clientcommunicator]&lt;/clientcommunicator&gt;<br/>
     * &nbsp;&lt;assertion expire='[expire]'&gt;<br/>
     * &nbsp;&lt;attribute namespace='[namespace]'&gt;<br/>
     * &nbsp;&lt;applications&gt;<br/>
     * &nbsp;&nbsp;&lt;application id='[id]' profile='[profile]'/&gt;<br/>
     * &nbsp;&nbsp;&nbsp;...<br/>
     * &nbsp;&lt;/applications&gt;<br/>
     * &nbsp;&lt;websso default='[default]'&gt;<br/>
     * &nbsp;&nbsp;...<br/>
     * &nbsp;&lt;/websso&gt;<br/>
     * &nbsp;&lt;storagemanager id='assertions'&gt;<br/>
     * &nbsp;&nbsp;...<br/>
     * &nbsp;&lt;/storagemanager&gt;<br/>
     * &lt;/handler&gt;<br/>
     * <br>
     * <ul>
     * <li><b>clientcommunicator</b> - Client communicator used for 
     * communicating to the A-Select Server for the verify_credentials request 
     * (raw/soap11/soap12)</li>
     * <li><b>expire</b> - The assertion expire time that must be used when 
     * creating new assertions</li>
     * <li><b>namespace</b> - The namespace that must be used when creating an 
     * attribute statement</li>
     * <li><b>id</b> - The A-Select app_id</li>
     * <li><b>profile</b> - The profile that must be used for the specified 
     * app_id</li>
     * <li><b>default</b> - The default web sso profile that will be used if an 
     * application isn't mapped to a profile</li>
     * <br/>
     * <li><b>storage manager</b> - The storage manager configuration is used by the A-Select Storage 
     * Manager from the A-Select System Package</li>
     * </ul>
     * <br><br>
     * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
     */
    public void init(ServletConfig oServletConfig, Object oConfig)
    	throws ASelectException
    {
        String sMethod = "init()";
        String sAttributeNamespace = null;
        long lAssertionExpireTime = -1;
        
        try
        {
            super.init(oServletConfig, oConfig);
            
            String sClientCommunicator = null;
            try
            {
                sClientCommunicator = _configManager.getParam(oConfig, "clientcommunicator");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config item 'clientcommunicator' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            Object oAssertion = null;
            try
            {
                oAssertion = _configManager.getSection(oConfig, "assertion");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config item 'expire' in 'assertion' section found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            String sAssertionExpireTime = null;
            try
            {
                sAssertionExpireTime = _configManager.getParam(oAssertion, "expire");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config item 'expire' in 'assertion' section found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }

            Object oAttribute = null;
            try
            {
                oAttribute = _configManager.getSection(oConfig, "attribute");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config section 'attribute' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            try
            {
                sAttributeNamespace = _configManager.getParam(oAttribute, "namespace");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config item 'namespace' in 'attribute' section found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            boolean bSendAttributeStatement = false;
            try
            {
                String sSendAttributeStatement = _configManager.getParam(oAttribute, "send_statement");
                StringBuffer sbConfig = new StringBuffer("Sending Attribute Statements directly in WebSSO response: ");
                
                if (sSendAttributeStatement.equalsIgnoreCase("TRUE"))
                {
                    sbConfig.append("enabled");
                    
                }
                else if (sSendAttributeStatement.equalsIgnoreCase("FALSE"))
                {
                    sbConfig.append("disabled");
                }
                else
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "Invalid config item 'send_statement' in 'attribute' section found, must be 'true' or 'false' not: " 
                        + sSendAttributeStatement);
                    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR);
                }
                _systemLogger.log(Level.CONFIG, MODULE, sMethod, sbConfig.toString());
                bSendAttributeStatement = new Boolean(sSendAttributeStatement).booleanValue();
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config item 'send_statement' in 'attribute' section found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            long lExpire = 0;
            try
            {
                lExpire = Long.parseLong(sAssertionExpireTime);
                lAssertionExpireTime = lExpire * 1000;
            }
            catch (NumberFormatException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "Config item 'expire' in 'assertion' section isn't a number: " + sAssertionExpireTime);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            if (lExpire < 1)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "Config item 'expire' in 'assertion' section must be higher than 0 and not: " + sAssertionExpireTime);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR);
            }
                  
            Object oWebSSO = null;
            try
            {
                oWebSSO = _configManager.getSection(oConfig, "websso");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config section 'websso' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            try
            {
                _sDefaultWebSSOProfile = _configManager.getParam(oWebSSO, "default");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config item 'default' in 'websso' section found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            Object oProfile = null;
            try
            {
                oProfile = _configManager.getSection(oWebSSO, "profile");
            }
            catch (ASelectConfigException e)
			{
			    _systemLogger.log(Level.WARNING, MODULE, sMethod
			        , "No config item 'class' in 'profile' section found", e);
			    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
            
            _htWebSSOProfiles = new HashMap();
            while (oProfile != null)
            {
                String sClass = null;
                try
                {
                    sClass = _configManager.getParam(oProfile, "class");
                }
                catch (ASelectConfigException e)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "No config item 'class' in 'profile' section found", e);
                    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
                }
                
                Class cProfile = null;
                IWebSSOProfile oWebSSOProfile = null;
                try
                {
	                cProfile = Class.forName(sClass);
	                oWebSSOProfile = (IWebSSOProfile)cProfile.newInstance();
                }
                catch (Exception e)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Not a correct 'IWebSSOProfile' class: " + sClass, e);
                    throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
                }
                
                oWebSSOProfile.init(oProfile, lAssertionExpireTime
                    , sAttributeNamespace, bSendAttributeStatement);
                if (_htWebSSOProfiles.containsKey(oWebSSOProfile.getID()))
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, "profile id is not unique: " + oWebSSOProfile.getID());
                    throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
                }
                _htWebSSOProfiles.put(oWebSSOProfile.getID(), oWebSSOProfile);
                
                oProfile = _configManager.getNextSection(oProfile);
            }
            
            Object oApplications = null;
            try
            {
                oApplications = _configManager.getSection(oConfig, "applications");
	        }
	        catch (ASelectConfigException e)
			{
			    _systemLogger.log(Level.WARNING, MODULE, sMethod
			        , "No config section 'applications' found", e);
			    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
	        
	        Object oApplication = null;
            try
            {
                oApplication = _configManager.getSection(oApplications, "application");
	        }
	        catch (ASelectConfigException e)
			{
			    _systemLogger.log(Level.WARNING, MODULE, sMethod
			        , "No config item 'application' in section 'applications' found", e);
			    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
	        
	        _htApplications = new HashMap();
            while (oApplication != null)
            {
                String sID = null;
                try
                {
                    sID = _configManager.getParam(oApplication, "id");
                }
                catch (ASelectConfigException e)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "No config item 'id' in 'application' section found", e);
                    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
                }
                
                String sProfile = null;
                try
                {
                    sProfile = _configManager.getParam(oApplication, "profile");
                }
                catch (ASelectConfigException e)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "No config item 'profile' in 'application' section found", e);
                    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
                }
                
                if (_htApplications.containsKey(sID))
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, "application id is not unique: " + sID);
                    throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
                }
                
                _htApplications.put(sID, sProfile);
                
                oApplication = _configManager.getNextSection(oApplication);
            }
                  
            Object oStorageManager = null;
            try
            {
                oStorageManager = _configManager.getSection(oConfig, "storagemanager", "id=assertions");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, 
                    "No config section 'storagemanager' with 'id=assertions' found", e);
                throw new ASelectStorageException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            try
            {
	            _oAssertionSessionManager = AssertionSessionManager.getHandle();
	            _oAssertionSessionManager.init(oStorageManager);
            }
            catch (ASelectException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "AssertionSessionManager could not be initialized", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            if (sClientCommunicator == null)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config item 'clientcommunicator' found");
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR);
            }
            
            if (sClientCommunicator.equalsIgnoreCase("soap11"))
            {
                _oClientCommunicator = new SOAP11Communicator("ASelect", _systemLogger);
            }
            else if (sClientCommunicator.equalsIgnoreCase("soap12"))
            {
                _oClientCommunicator = new SOAP12Communicator("ASelect", _systemLogger);
            }
            else if (sClientCommunicator.equalsIgnoreCase("raw"))
            {
                _oClientCommunicator = new RawCommunicator(_systemLogger);
            }
        }
        catch (ASelectException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }

    /**
     * Processes a SAML Web SSO request.
     * <br/><br/>
     * <li>Reads an A-Select <code>authenticate</code> response</li>
     * <li>Verifies if the following paramers are available in the response:
     * <ul>
     * <li>aselect_credentials</li>
     * <li>rid</li>
     * </ul>
     * </li>
     * <li>Sends an A-Select <code>verify_credentials</code> API call request to 
     * the A-Select Server</li>
     * <li>Reads the SAML session (with id: saml11_[rid]) created by the 
     * Shibboleth Authentication Profile</li>
     * <li>Processes the request with the correct websso profile handler for the 
     * specified application</li>
     * <br><br>
     * @see org.aselect.server.request.handler.AbstractRequestHandler#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public RequestState process(HttpServletRequest request, HttpServletResponse response) 
    	throws ASelectException
    {
        String sMethod = "process()";
        try
        {
            String sCredentials = request.getParameter("aselect_credentials");
            if (sCredentials == null)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No parameter 'aselect_credentials' in request");
    		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            String sRid = request.getParameter("rid");
            if (sRid == null)
    		{
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No parameter 'rid' in request");
    		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
    		}
            
            HashMap htResponse = handleVerifyCredentials(sCredentials, sRid, request);
            if (htResponse.isEmpty())
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No response after 'verify_credentials' call");
    		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            //retrieve session
            HashMap htAuthSession = _oSessionManager.getSessionContext(SESSION_ID_PREFIX + sRid);
            if (htAuthSession == null)
            {
                StringBuffer sbError = new StringBuffer("No SAML session found with id: ");
                sbError.append(SESSION_ID_PREFIX);
                sbError.append(sRid);
                
                _systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
                throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            String sAppID = (String)htAuthSession.get("app_id");
            String sProfile = null;
            if ((sProfile = (String)_htApplications.get(sAppID)) == null)
            {
                _systemLogger.log(Level.FINE, MODULE, sMethod
                    , "Using default WebSSOProfile, because there was no profile configured for app_id: " + sAppID);

                sProfile = _sDefaultWebSSOProfile;
            }
            
            IWebSSOProfile oWebSSOProfile = null;
            if ((oWebSSOProfile = (IWebSSOProfile)_htWebSSOProfiles.get(sProfile)) == null)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No WebSSOProfile found with id: " + sProfile);
    		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            String sIP = request.getRemoteAddr();
            String sHost = request.getRemoteHost();
            
            oWebSSOProfile.process(htResponse, response, sIP, sHost);
        }
        catch (ASelectException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod
                , "Could not process request", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        return new RequestState(null);
    }
    
    /**
     * Destroys all WebSSO profiles available in the <code>_htWebSSOProfiles
     * </code> HashMap and destroys the Assertion Session Manager singleton.
     * <br><br>
     * @see org.aselect.server.request.handler.IRequestHandler#destroy()
     */
    public void destroy()
    {
        if (_htWebSSOProfiles != null)
        {
    		for (Map.Entry<String, Object> entry : _htWebSSOProfiles.entrySet()) {
	            IWebSSOProfile oWebSSOProfile = (IWebSSOProfile)entry.getValue();
	            oWebSSOProfile.destroy();
    		}
/*	        Enumeration enumProfiles = _htWebSSOProfiles.elements();
	        while (enumProfiles.hasMoreElements())
	        {
	            IWebSSOProfile oWebSSOProfile = (IWebSSOProfile)enumProfiles.nextElement();
	            oWebSSOProfile.destroy();
	        }*/
        }   
        
        if (_oAssertionSessionManager != null)
            _oAssertionSessionManager.destroy();
    }

    /**
     * Sends a A-Select verify_credentials request.
     * <br><br>
     * @param sCredentials the A-Select credentials
     * @param sRid the A-Select rid
     * @param request the HttpServletRequest containing the request
     * @return HashMap containing the verify_credentials results
     * @throws ASelectException if communication fails
     */
    private HashMap handleVerifyCredentials(String sCredentials
        , String sRid
        , HttpServletRequest request)
    	throws ASelectException
    {
        String sMethod = "handleVerifyCredentials()";
        HashMap htRequest = new HashMap();
        HashMap htResponse = new HashMap();
        try
        {
            String sASelectID = request.getParameter("a-select-server");
    		if (sASelectID == null)
    		{
    		    _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No parameter 'a-select-server' in request");
    		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
    		}   		
    		
    		String sRequestURL = request.getRequestURL().toString();
			String sContextPath = request.getContextPath();
            String sServletPath = request.getServletPath();
            
            int iLocation = sRequestURL.indexOf(sContextPath);
            String sStartURL = sRequestURL.substring(0, iLocation);
            StringBuffer sbUrl = new StringBuffer(sStartURL);
            sbUrl.append(sContextPath);
            sbUrl.append(sServletPath);
			
    		htRequest.put("request", "verify_credentials");
    		htRequest.put("aselect_credentials", sCredentials);
    		htRequest.put("rid", sRid);
    		htRequest.put("a-select-server", sASelectID);
            if (ApplicationManager.getHandle().isSigningRequired()) {  // 1.5.4 added
                CryptoEngine.getHandle().signRequest(htRequest);
            }
    		htResponse = _oClientCommunicator.sendMessage(htRequest, sbUrl.toString());
    		
    		String sResultCode = (String)htResponse.get("result_code");
    		if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS))
    		{
    		    _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "A-Select Server returned error code: " + sResultCode);
    		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
    		}
    		return htResponse;
        }
        catch (ASelectException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod
                , "Could not send 'verify_credentials' request", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }

}
