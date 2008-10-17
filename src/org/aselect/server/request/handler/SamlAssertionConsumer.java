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
 * Generic SAML Assertion Consumer
 * Receive an Artifact, call an Artifact Resolver service to dereference the artifact
 * by using a SAML SOAP connection to send a <samlp:Request> and receive a <samlp:Response>.
 * Finally, process the SAML assertion and redirect the user to the requested resource
 */
package org.aselect.server.request.handler;

import java.util.Hashtable;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.saml11.common.AssertionSessionManager;
import org.aselect.server.session.SessionManager;
import org.aselect.system.communication.client.soap11.SOAP11Communicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.*;
import org.opensaml.*;
import org.opensaml.artifact.*;
import org.apache.xml.security.signature.XMLSignature;

//
//
public abstract class SamlAssertionConsumer extends ProtoRequestHandler
{
    final static String MODULE = "SamlAssertionConsumer";
    private SessionManager _sessionManager;
    private SAMLBinding _oSAMLBinding;
    private AssertionSessionManager _oAssertionSessionManager;
    private SOAP11Communicator _communicator;

    protected String _sMyServerId;
    protected String _sMyOrg;
    protected String _sMyAppId;
    protected String _sArtifactUrl = null;
    protected Hashtable _htIdPs = null;
    protected boolean _bCheckSigning = false;

    //
    public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
	    String sMethod = "init()";
	    try {
	        super.init(oServletConfig, oConfig);
            _systemLogger.log(Level.WARNING, MODULE, sMethod, "Specific initialization"); 
	        
	        _sessionManager = SessionManager.getHandle();
	        _oAssertionSessionManager = AssertionSessionManager.getHandle();
	        _oSAMLBinding = SAMLBindingFactory.getInstance(SAMLBinding.SOAP);
			String sCheckSigning = HandlerTools.getSimpleParam(oConfig, "check_signing", false);
			if (sCheckSigning != null && sCheckSigning.equals("true"))
				_bCheckSigning = true;
	
	        Object oASelect = null;
	        try {
	            oASelect = _configManager.getSection(null, "aselect");
            }
            catch(ASelectConfigException e) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, 
                    "Could not find 'aselect' config section in config file", e);
                throw e;
            }
            try {
                _sMyServerId = _configManager.getParam(oASelect, "server_id");
	        }
	        catch(ASelectConfigException e) {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, 
	                "Could not retrieve 'server_id' config parameter in 'aselect' config section",e);
	            throw e;
	        }
            try {
                _sMyOrg = _configManager.getParam(oASelect, "organization");
	        }
	        catch(ASelectConfigException e) {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, 
	                "Could not retrieve 'organization' config parameter in 'aselect' config section",e);
	            throw e;
	        }

	        Object oApplication = null;
	        try {
                oApplication = _configManager.getSection(oConfig, "application");
                _sMyAppId = _configManager.getParam(oApplication, "id");
	        }
	        catch(ASelectConfigException e) {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, 
	                "Could not retrieve 'id' parameter in 'application' config section",e);
	            throw e;
	        }
	    }
	    catch (ASelectException e) {
	        throw e;
	    }
	    catch (Exception e)
	    {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	}
    
    // Default implementation
    public String findArtifactUrl(String sArtifact)
    throws ASelectException
    {
    	return _sArtifactUrl;
    }

    //  Default implementation
    public String getRedirectUrl(HttpServletRequest request)
    {
        _systemLogger.log(Level.INFO, MODULE, "getRedirectUrl()", "Default impl. TARGET="+request.getParameter("TARGET"));
    	return request.getParameter("TARGET");
    }
    
    public RequestState process(HttpServletRequest request, HttpServletResponse response) 
   	throws ASelectException
    {
        String sMethod = "process()";        
        String sSessionId = null;
        String sTgt = null;
        String sRedirectUrl = getRedirectUrl(request);
        String sArtifact = request.getParameter("SAMLart");
        String sArtifactUrl;
        _systemLogger.log(Level.INFO,MODULE,sMethod, "Query="+request.getQueryString()+", RedirectUrl="+sRedirectUrl);
        if (sRedirectUrl == null) sRedirectUrl="no-application";
        
		sArtifactUrl = findArtifactUrl(sArtifact);
        _systemLogger.log(Level.INFO,MODULE,sMethod, "ArtifactURL="+sArtifactUrl);

        // Parse incoming artifact
        SAMLArtifactType0003 oParsedArtifact;
         try {
             SAMLArtifactType0003.Parser ap = new SAMLArtifactType0003.Parser();
             oParsedArtifact = (SAMLArtifactType0003)ap.parse(sArtifact);
        }
        catch (ArtifactParseException e) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not parse SAML Artifact", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        try {
            Vector vArt = new Vector();
            vArt.add(oParsedArtifact);
			SAMLRequest oSamlRequest = new SAMLRequest(vArt);
	        _systemLogger.log(Level.INFO,MODULE,sMethod, "ASSERT REQ oSamlRequest="+oSamlRequest);
	          
	        // Sign the assertion
			Vector vCertificatesToInclude = new Vector();
			vCertificatesToInclude.add(_configManager.getDefaultCertificate());
			
			_systemLogger.log(Level.INFO,MODULE,sMethod, "Sign");
			oSamlRequest.sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, 
								_configManager.getDefaultPrivateKey(), vCertificatesToInclude);
	        
	        // Send Artifact through the backchannel
	        String sSamlRequest = oSamlRequest.toString();
	        _systemLogger.log(Level.INFO,MODULE,sMethod, "ASSERT REQ oSamlRequest="+oSamlRequest);
            _communicator = new SOAP11Communicator("ASelectRequest", _systemLogger);
 
            String sResults = _communicator.sendStringMessage(sSamlRequest, sArtifactUrl);
            _systemLogger.log(Level.INFO,MODULE,sMethod, "ASSERT RESP sResults="+sResults); // sResults.substring(0, (len<30)?len:30));

            // Signature ok?
	        if (_bCheckSigning) {
	        	checkSignature(sResults);
	        }

            // Extract SAML response from the SOAP envelope
	        String sResponse = Tools.extractFromXml(sResults, "samlp:Response", false);
	        if (sResponse == null)
		        sResponse = Tools.extractFromXml(sResults, "Response", false);

	        String sAssertion = Tools.extractFromXml(sResponse, "saml:Assertion", true);
	        if (sAssertion == null)
		        sAssertion = Tools.extractFromXml(sResponse, "Assertion", true);

	        String sStatus = Tools.extractFromXml(sResponse, "samlp:Status", true);
	        if (sStatus == null)
		        sStatus = Tools.extractFromXml(sResponse, "Status", true);
	        _systemLogger.log(Level.INFO,MODULE,sMethod, "Status="+sStatus);
	        
	        if (sStatus != null && sAssertion != null && sStatus.contains("samlp:Success"))
	        {
		        // Create Response for the Browser (set cookie and redirect)
	        	// From: ApplicationAPIHandler.handleAuthenticateRequest()
	            Hashtable htSessionContext = new Hashtable();
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "sAppId="+_sMyAppId+ " sTarget="+sRedirectUrl+" _sMyOrg="+_sMyOrg);
	            htSessionContext.put("app_id", _sMyAppId);
	            htSessionContext.put("app_url", sRedirectUrl);
	            htSessionContext.put("organization", _sMyOrg);
	            htSessionContext.put("client_ip", request.getRemoteAddr()); // RH, 20080617, n
	            
	            //htSessionContext.put("level", intAppLevel);
	            sSessionId = _sessionManager.createSession(htSessionContext);
	            if (sSessionId == null) {
	                _systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to create session");
	                throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
	            }
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "SessionId="+sSessionId);
	            
	            // Add serialized attributes to the TgtContext
	            Hashtable htAttributes = extractUidAndAttributes(sAssertion);
				
	            // Create a TGT
				createContextAndIssueTGT(response, sSessionId, _sMyServerId, _sMyOrg, _sMyAppId, null, htAttributes);
	            
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "REDIR "+sRedirectUrl);
	            response.sendRedirect(sRedirectUrl.toString());
	        }
	        else {
	            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "SAMLRequest not successful");
	        }
        }
        catch (Exception e) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not retrieve SAMLResponse "+e.getClass(), e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        return new RequestState(null);
    }

    public String serializeTheseAttributes(Hashtable htAttribs)
    throws ASelectException
    {
    	return "";
    }
    
    // NOT USED
	private String getAttrFromSaml(String sName, String sAssertion)
	{
		String sMethod = "getAttrFromSaml";
		int nIdx = sAssertion.indexOf("AttributeName=\""+sName+"\"");
		String sUserId = null;
		if (nIdx >= 0)
			sUserId = Tools.extractFromXml(sAssertion.substring(nIdx), "AttributeValue", true);
		if (sUserId == null) {
		    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Attribute '"+sName+"' not found");
		    return null;
		}
		return sUserId;
	}
}
