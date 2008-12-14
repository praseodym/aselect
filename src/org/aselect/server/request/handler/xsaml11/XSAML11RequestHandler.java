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
package org.aselect.server.request.handler.xsaml11;

import java.net.URLEncoder;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.*;
import org.aselect.server.request.handler.saml11.common.AssertionSessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Utils;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLSubject;
import org.opensaml.artifact.SAMLArtifact;
import org.opensaml.artifact.SAMLArtifactType0001;
import org.opensaml.artifact.SAMLArtifactType0002;
import org.opensaml.artifact.Util;

//
// SAML 1.1 Browser Artifact profile
// The Inter-site Transfer Service - Source Site
//
public class XSAML11RequestHandler extends ProtoRequestHandler
{
    private final static String MODULE = "XSAML11RequestHandler";
    private final static String SESSION_ID_PREFIX = "xsaml11_"; // "xsaml11_"; FIXME Bauke

    private AssertionSessionManager _oAssertionSessionManager;
    private String _sSourceLocation = null;
    private String _sDestinationLocation = null;
	String _sProviderId = null;

	protected String getSessionIdPrefix() { return SESSION_ID_PREFIX; }
    protected boolean useConfigToCreateSamlBuilder() { return true; }

    /**
     * Initializes the Transfer SAML 1.1 Request Handler.
     */
    public void init(ServletConfig oServletConfig, Object oConfig)
    throws ASelectException
    {
        String sMethod = "init()";        
        try {
            super.init(oServletConfig, oConfig);
            
            String sClientCommunicator = null;
            try {
                sClientCommunicator = _configManager.getParam(oConfig, "clientcommunicator");
            }
            catch (ASelectConfigException e) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'clientcommunicator' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            if (sClientCommunicator == null) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'clientcommunicator' found");
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR);
            }
            
            try {
            	_sProviderId = _configManager.getParam(oConfig, "provider_id");
            }
            catch (ASelectConfigException e) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'provider_id' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            try {
            	_sSourceLocation = _configManager.getParam(oConfig, "sourcelocation");
            }
            catch (ASelectConfigException e) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'sourcelocation' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            try {
            	_sDestinationLocation = _configManager.getParam(oConfig, "destinationlocation");
            }
            catch (ASelectConfigException e) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'destinationlocation' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
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
            
            try {
	            _oAssertionSessionManager = AssertionSessionManager.getHandle();
	            _oAssertionSessionManager.init(oStorageManager);
            }
            catch (ASelectException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "AssertionSessionManager could not be initialized", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
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

    public RequestState process(HttpServletRequest request, HttpServletResponse response) 
   	throws ASelectException
    {
        String sMethod = "process()";
        _systemLogger.log(Level.INFO,MODULE,sMethod, "XSaml11 request="+request);
        try
        {
            Hashtable htResponse = getASelectCredentials(request);
            if (htResponse == null) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot get Aselect credentials (not logged in?)");
        		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);            
            }
            
			String sTarget = request.getParameter("TARGET");
			SAMLArtifact oSAMLArtifact = null;
			if (sTarget == null)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'TARGET' found in session");
    		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            _systemLogger.log(Level.INFO, MODULE, sMethod, "target="+sTarget);
			
			String sProviderId = _sProviderId;  // does not come from session
			if (sProviderId == null) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'providerId' found");
    		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
            }

			int _iArtifactType = 1;  // We only support type 1
			if (_iArtifactType == 1)
			{
	            byte[] bSourceId = Util.generateSourceId(_sASelectServerID);
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "sourceId="+bSourceId);
			    oSAMLArtifact = new SAMLArtifactType0001(bSourceId);
			}
			/*else if (_iArtifactType == 2)
			{
			    URI oURI = new URI(_sSourceLocation);  // communicate our SAML responder URI
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "_sSourceLocation="+_sSourceLocation);
			    oSAMLArtifact = new SAMLArtifactType0002(oURI);
			}*/
            _systemLogger.log(Level.INFO, MODULE, sMethod, "oSAMLArtifact="+oSAMLArtifact);
			
            // Create and store the SAML Assertion
            String sUid = (String)htResponse.get("uid");
            _systemLogger.log(Level.INFO, MODULE, sMethod, "sUid="+sUid);
            if (sUid == null) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'uid' found");
                throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            String sIP = request.getRemoteAddr();
            String sHost = request.getRemoteHost();
            _systemLogger.log(Level.INFO, MODULE, sMethod, "sIP="+sIP+", sHost="+sHost+", htResponse="+htResponse);
            SAMLAssertion oSAMLAssertion = _saml11Builder.createSAMLAssertionFromCredentials(
            		sUid, null, null, sIP, sHost, SAMLSubject.CONF_ARTIFACT, sProviderId, null/*audience*/, htResponse);
            _systemLogger.log(Level.INFO, MODULE, sMethod, "oSAMLAssertion="+oSAMLAssertion);
            			
			_oAssertionSessionManager.putAssertion(oSAMLArtifact, oSAMLAssertion);
			
			// Send the response (=redirect)
            _systemLogger.log(Level.INFO, MODULE, sMethod, "TARGET="+sTarget);
            send(response, oSAMLArtifact, _sDestinationLocation, sTarget);
        }
        catch (ASelectException e) {
            throw e;
        }
        catch (Exception e) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        return new RequestState(null);
    }

    private void send(HttpServletResponse response, SAMLArtifact oSAMLArtifact, String sRedirectUrl, String sTarget) 
    	throws ASelectException
    {
        String sMethod = "send()";
        try
        {
            StringBuffer sbRedirect = new StringBuffer();
            sbRedirect.append(sRedirectUrl);
            sbRedirect.append("?TARGET=");
            sbRedirect.append(URLEncoder.encode(sTarget, "UTF-8"));
            
            sbRedirect.append("&SAMLart=");
            sbRedirect.append(URLEncoder.encode(oSAMLArtifact.encode(), "UTF-8"));
            
            StringBuffer sbFiner = new StringBuffer("Sending to '");
            sbFiner.append(sRedirectUrl);
            sbFiner.append("' SAML Artifact message:");
            sbFiner.append(oSAMLArtifact.toString());
           
            _systemLogger.log(Level.INFO, MODULE, sMethod, "REDIR "+sbFiner.toString());                        
            response.sendRedirect(sbRedirect.toString());
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not send SAML Artifact", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }
    
    public String serializeTheseAttributes(Hashtable htAttribs)
    throws ASelectException
    {
        String sMethod = "serializeTheseAttributes()";
    	String sSerializedAttributes = _saml11Builder.serializeAttributes(htAttribs);
    	_systemLogger.log(Level.INFO, MODULE, sMethod, "sSerializedAttributes="+sSerializedAttributes);
    	return sSerializedAttributes;
    }
    
    public void destroy()
    {
        if (_oAssertionSessionManager != null)
            _oAssertionSessionManager.destroy();
    }
}
