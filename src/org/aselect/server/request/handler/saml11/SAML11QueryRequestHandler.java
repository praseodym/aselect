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
 * $Id: SAML11QueryRequestHandler.java,v 1.14 2006/05/03 10:11:08 tom Exp $ 
 */

package org.aselect.server.request.handler.saml11;

import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xml.security.signature.XMLSignature;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.opensaml.SAMLAction;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeDesignator;
import org.opensaml.SAMLAttributeQuery;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAuthenticationQuery;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLAuthorizationDecisionQuery;
import org.opensaml.SAMLAuthorizationDecisionStatement;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLBindingFactory;
import org.opensaml.SAMLDecision;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLSubject;
import org.opensaml.SAMLSubjectQuery;
import org.opensaml.SAMLSubjectStatement;

/**
 * SAML 1.1 Artifact request handler.
 * <br><br>
 * <b>Description:</b><br>
 * Request handler for the fowllowing SAML 1.1 Query Requests:
 * <ul>
 * <li>Authentication Query</li>
 * <li>Attribute Query</li>
 * <li>Authorization Decision Query</li>
 * </ul>
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class SAML11QueryRequestHandler extends AbstractRequestHandler
{
    private final static String MODULE = "SAMLQueryRequestHandler";
    private final static String SESSION_ID_PREFIX = "saml11_";
    private SAMLBinding _oSAMLBinding;
    private String _sASelectServerID;
    private String _sAttributeNamespace;
    private long _lAssertionExpireTime;
    private Hashtable _htAuthenticationMethods;
    private TGTManager _oTGTManager;
    
    /**
     * Initializes the SAML 1.1 Query Request Handler
     * <br/><br/>
     * <b>Description:</b><br/>
     * Reads the following configuration:<br/><br/>
     * &lt;handler&gt;<br/>
     * &nbsp;&lt;assertion expire='[expire]'/&gt;<br/>
     * &nbsp;&lt;attribute namespace='[namespace]'/&gt;<br/>
     * &nbsp;&lt;authentication_methods&gt;<br/>
     * &nbsp;&nbsp;&lt;identifier authsp_id='[authsp_id]' uri='[uri]'/&gt;<br/>
     * &nbsp;&lt;/authentication_methods&gt;<br/>
     * &lt;/handler&gt;<br/><br/>
     * <ul>
     * <li><b>expire</b> - The assertion expire time in seconds</li>
     * <li><b>namespace</b> - The attribute namespace</li>
     * <li><b>authsp_id</b> - The A-Select AuthSP ID</li>
     * <li><b>uri</b> - The authentication method namespace uri</li>
     * </ul>
     * <br/>
     * This function performs the following tasks:<br><br>
     * 1. Read the A-Select Server ID from the A-Select Server basic config<br/>
     * 2. Read the request handler configuration<br/><br>
     * <b>Note:</b> For every AuthSP configured in A-Select an identifier 
     * section must be configured
     * 
     * <br/><br/>
     * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
     */
    public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
	    String sMethod = "init()";
	    try
	    {
	        super.init(oServletConfig, oConfig);
	        
            _oTGTManager = TGTManager.getHandle();
	        _oSAMLBinding = SAMLBindingFactory.getInstance(SAMLBinding.SOAP);
            
            Object oASelect = null;
            try
            {
                oASelect = _configManager.getSection(null, "aselect");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'aselect' found", e);
                throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            try
            {
                _sASelectServerID = _configManager.getParam(oASelect, "server_id");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'server_id' in section 'aselect' found", e);
                throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
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
                _sAttributeNamespace = _configManager.getParam(oAttribute, "namespace");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config item 'namespace' in 'attribute' section found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            long lExpire = 0;
            try
            {
                lExpire = Long.parseLong(sAssertionExpireTime);
                _lAssertionExpireTime = lExpire * 1000;
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
            
            Object oAuthenticationMethods = null;
            try
            {
                oAuthenticationMethods = _configManager.getSection(oConfig, "authentication_methods");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config section 'authentication_methods' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            Object oIdentifier = null;
            try
            {
                oIdentifier = _configManager.getSection(oAuthenticationMethods, "identifier");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "Not one config section 'identifier' in section 'authentication_methods' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            _htAuthenticationMethods = new Hashtable();
            while (oIdentifier != null)
            {
                String sAuthSPID = null;
                try
                {
                    sAuthSPID = _configManager.getParam(oIdentifier, "authsp_id");
                }
                catch (ASelectConfigException e)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "No config item 'authsp_id' in section 'identifier' found", e);
                    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
                }
                
                String sURI = null;
                try
                {
                    sURI = _configManager.getParam(oIdentifier, "uri");
                }
                catch (ASelectConfigException e)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "No config item 'uri' in section 'identifier' found", e);
                    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
                }
                
                _htAuthenticationMethods.put(sAuthSPID, sURI);
                
                oIdentifier = _configManager.getNextSection(oIdentifier);
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
     * Processes a SAML message inside a SOAP message containing a SAML Subject 
     * Query request.
     * <br/><br/>
     * <ul>
     * <li>Parses the incoming request as SOAP/SAML message</li>
     * <li>Verifies if the SAML subject is valid</li>
     * <li>NameQualifier must be A-Select Server ID</li>
     * <li>NameIdentifier must be A-Select User ID</li>
     * <li>Retrieves the SAML session</li>
     * <li>Creates a SAMLResponse object by calling the correct method</li>
     * <li>Sends the SAMLResponse over SOAP</li>
     * </ul>
     * <br>
     * @see org.aselect.server.request.handler.AbstractRequestHandler#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public RequestState process(HttpServletRequest request, HttpServletResponse response) throws ASelectException
    {
        String sMethod = "process()";
        SAMLRequest oSAMLRequest = null;
        SAMLResponse oSAMLResponse = null;
        SAMLSubjectQuery oSAMLSubjectQuery = null;
        SAMLSubjectStatement oSAMLSubjectStatement = null;
        
        try
        {
            response.setContentType("text/xml");
            
            try
    	    {
    	        oSAMLRequest = _oSAMLBinding.receive(request ,1);
        	} 
    	    catch (SAMLException e) 
        	{
        	    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not parse SAML request with SOAP binding", e);
                throw e;
        	}   
            
            StringBuffer sbFiner = new StringBuffer("Retrieving SAML Query Request message:\r\n");
            sbFiner.append(oSAMLRequest.toString());
            _systemLogger.log(Level.FINER, MODULE, sMethod, sbFiner.toString());
    	    
//    	    if (!oSAMLRequest.isSigned())
//    	    {
//    	        _systemLogger.log(Level.WARNING, MODULE, sMethod, "Request isn't signed");
//        	    throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
//    	    }
                	    
            oSAMLSubjectQuery = (SAMLSubjectQuery)oSAMLRequest.getQuery();
    	    if (oSAMLSubjectQuery == null)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not find a SAML subject Query in request");
                throw new SAMLException(SAMLException.REQUESTER, "No SAML subject Query in request");
            }
            
    	    SAMLSubject oSAMLSubject = oSAMLSubjectQuery.getSubject();
            
            //verify if there is a confirmation method that is not SAMLSubject.CONF_BEARER
            boolean bFinish = false;
            Iterator iterCM = oSAMLSubject.getConfirmationMethods();
            while (iterCM.hasNext() && !bFinish)
            {
                String sConfirmationMethod = (String)iterCM.next();
                if (!sConfirmationMethod.equals(SAMLSubject.CONF_BEARER))
                    bFinish = true;
            }
            
            SAMLNameIdentifier oSAMLNameIdentifier = oSAMLSubject.getNameIdentifier();
            
            String sNameQualifier = oSAMLNameIdentifier.getNameQualifier();
            if (sNameQualifier == null)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "Wrong request, missing: name qualifier");
                throw new SAMLException(SAMLException.REQUESTER, "No name qualifier in request");
            }
            
            if (!sNameQualifier.equals(_sASelectServerID))
            {
                StringBuffer sbError = new StringBuffer("Wrong request, name qualifier is '");
                sbError.append(sNameQualifier);
                sbError.append("', but must be: ");
                sbError.append(_sASelectServerID);
                _systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
                throw new SAMLException(SAMLException.REQUESTER, "Wrong name qualifier in request");
            }
            
            String sNameIdentifier = oSAMLNameIdentifier.getName();
            if (sNameIdentifier == null)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "Wrong request, missing: name identifier");
                throw new SAMLException(SAMLException.REQUESTER, "No name identifier in request");
            }
            
            String sSAMLSessionID = SESSION_ID_PREFIX + sNameIdentifier;
            
            Hashtable htSAMLSession = _oTGTManager.getTGT(sSAMLSessionID);
            if (htSAMLSession == null)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No SAML session information found for name identifier: " + sNameIdentifier);
                throw new SAMLException(SAMLException.REQUESTER, "Unknown name identifier: " + sNameIdentifier);
            }
            
            long lExpireTime = _oTGTManager.getExpirationTime(sSAMLSessionID);
            if (lExpireTime <= System.currentTimeMillis())
            {
                //TGT verlopen
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "SAML session information expired for name identifier: " + sNameIdentifier);
                throw new SAMLException(SAMLException.REQUESTER, "A-Select TGT Expired");
            }
            
            String sShire = request.getRequestURL().toString();
            String sIP = request.getRemoteAddr();
            String sHost = request.getRemoteHost();
            
            if (oSAMLSubjectQuery instanceof SAMLAuthenticationQuery)
            {
                oSAMLSubjectStatement = handleAuthenticationQuery(htSAMLSession
                    , (SAMLAuthenticationQuery)oSAMLSubjectQuery
                    , sNameIdentifier
                    , lExpireTime
                    , sIP
                    , sHost);
            }
            else if (oSAMLSubjectQuery instanceof SAMLAttributeQuery)
            {
                oSAMLSubjectStatement = handleAttributeQuery(htSAMLSession
                    , (SAMLAttributeQuery)oSAMLSubjectQuery
                    , sNameIdentifier);
            }
            else if (oSAMLSubjectQuery instanceof SAMLAuthorizationDecisionQuery)
            {
                oSAMLSubjectStatement = handleAuthorizationDecisionQuery(htSAMLSession
                    , (SAMLAuthorizationDecisionQuery)oSAMLSubjectQuery
                    , sNameIdentifier);
            }
            
            oSAMLResponse = generateSAMLResponse(oSAMLRequest.getId(), sShire
                , oSAMLSubjectStatement);
            
            sbFiner = new StringBuffer("Sending SAML Query Response message:\r\n");
            sbFiner.append(oSAMLResponse.toString());
            _systemLogger.log(Level.FINER, MODULE, sMethod, sbFiner.toString());
            
            _oSAMLBinding.respond(response, oSAMLResponse, null);
        }
	    catch (SAMLException e)
	    {
	        respondError(response, oSAMLRequest, e);
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
     * Removes class variables from memory 
     * <br><br>
     * @see org.aselect.server.request.handler.AbstractRequestHandler#destroy()
     */
    public void destroy()
    {
        //do nothing
        
    }

    /**
     * Handles a SAML Authentication Query.
     * <br><br>
     * @param htSAMLSession Hashtable containing SAML Session information
     * @param oSAMLAuthenticationQuery SAML Subject Query object
     * @param sNameIdentifier A-Select User ID
     * @param lExpireTime SAML Authentication statement expiration time
     * @param sIP client IP address
     * @param sHost client Host name
     * @return SAMLSubjectStatement that can be sent to the requestor
     * @throws SAMLException if internal error occurred
     */
    private SAMLSubjectStatement handleAuthenticationQuery(Hashtable htSAMLSession
        , SAMLAuthenticationQuery oSAMLAuthenticationQuery
        , String sNameIdentifier
        , long lExpireTime
        , String sIP
        , String sHost)
        throws SAMLException
    {
        String sMethod = "handleAuthenticationQuery()";
        String sAuthSPID = null;
        String sAuthenticationMethod = null;
        SAMLAuthenticationStatement oSAMLAuthenticationStatement = null;
        try
        {
            Vector vAuthSPs = (Vector)htSAMLSession.get("authsps");
            if (vAuthSPs == null || vAuthSPs.isEmpty())
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid session for name identifier: " + sNameIdentifier);
                throw new SAMLException(SAMLException.REQUESTER, "Invalid session for name identifier: " + sNameIdentifier);
            }
            
            String sAuthMethod = oSAMLAuthenticationQuery.getAuthMethod();
            if (sAuthMethod != null)
            {
                //check if user is authenticated with an AuthSP that has configured AuthMethod == sAuthMethod
                Enumeration enumAuthSPIDs = _htAuthenticationMethods.keys();
                while (enumAuthSPIDs.hasMoreElements() && sAuthSPID == null)
                {
                    String sConfiguredAuthSPID = (String)enumAuthSPIDs.nextElement();
                    String sConfiguredAuthMethod = (String)_htAuthenticationMethods.get(sConfiguredAuthSPID);
                    if (sConfiguredAuthMethod.equals(sAuthMethod)
                        && vAuthSPs.contains(sConfiguredAuthSPID))
                    {
                        sAuthSPID = sConfiguredAuthSPID;
                        sAuthenticationMethod = sConfiguredAuthMethod;
                    }
                }
                
                if (sAuthSPID == null)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, "No AuthSP ID mapped to authentication method: " + sAuthMethod);
                    throw new SAMLException(SAMLException.REQUESTER, "Unknown Authentication Method");
                }
            }
            else
            {
                //last AuthSP id
                sAuthSPID = (String)vAuthSPs.lastElement();
                if (sAuthSPID == null)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid session for name identifier: " + sNameIdentifier);
                    throw new SAMLException(SAMLException.REQUESTER, "Invalid session for name identifier: " + sNameIdentifier);
                }
                
                sAuthenticationMethod = (String)_htAuthenticationMethods.get(sAuthSPID);
                if (sAuthenticationMethod == null)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "No authentication method configured for AuthSP ID: " + sAuthSPID);
                    throw new SAMLException(SAMLException.RESPONDER, "Internal error: invalid configuration");
                }
            }
              
            SAMLNameIdentifier oSAMLNameIdentifier = new SAMLNameIdentifier(sNameIdentifier, 
                _sASelectServerID, SAMLNameIdentifier.FORMAT_UNSPECIFIED);   
            
            SAMLSubject subject = new SAMLSubject(oSAMLNameIdentifier, null, null, null);               
            subject.addConfirmationMethod(SAMLSubject.CONF_BEARER);
            
            oSAMLAuthenticationStatement = new SAMLAuthenticationStatement(
                    subject,                // The subject 
                    new Date(lExpireTime),  // Authn instant
                    sIP,                    // The subject's IP
                    sHost,                  // The subject's hostname
                    null);                  // Authority bindings
           
        }
        catch (SAMLException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod
                , "Could not handle SAML Authentication Query", e);
            throw new SAMLException(SAMLException.RESPONDER, "Internal error", e);
        }
        return oSAMLAuthenticationStatement;
    }
    
    /**
     * Handles a SAML Attribute Query.
     * <br><br>
     * @param htSAMLSession Hashtable containing SAML Session information
     * @param oSAMLAttributeQuery SAML Subject Query object
     * @param sNameIdentifier A-Select User ID
     * @return SAMLSubjectStatement that can be sent to the requestor
     * @throws SAMLException if internal error occurred
     */
    private SAMLSubjectStatement handleAttributeQuery(Hashtable htSAMLSession
        , SAMLAttributeQuery oSAMLAttributeQuery
        , String sNameIdentifier)
        throws SAMLException
    {
        String sMethod = "handleAttributeQuery()";
        SAMLAttributeStatement oSAMLAttributeStatement = null;
        Hashtable htAppIDAttributes = null;
        
        try
        {
            Hashtable htAttributes = (Hashtable)htSAMLSession.get("attributes");
            if (htAttributes == null)
            {
                //no attributes found
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No attributes found for name identifier: " + sNameIdentifier);
                throw new SAMLException(SAMLException.REQUESTER, "No attributes found for name identifier: " + sNameIdentifier);
            }
            
            String sResource = oSAMLAttributeQuery.getResource();
            if (sResource != null)
            {
                if ((htAppIDAttributes = (Hashtable)htAttributes.get(sResource)) == null)
                {
                    StringBuffer sbError = new StringBuffer("Unknown resource (");
                    sbError.append(sResource);
                    sbError.append(") for name identifier: ");
                    sbError.append(sNameIdentifier);
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
                    throw new SAMLException(SAMLException.REQUESTER, "Unknown resource: " + sResource);
                }
            }
            else
            {
                htAppIDAttributes = new Hashtable();
                Enumeration enumAllAttributes = htAttributes.elements();
                while (enumAllAttributes.hasMoreElements())
                {
                    Hashtable htAttribs = (Hashtable)enumAllAttributes.nextElement();
                    htAppIDAttributes.putAll(htAttribs);
                }
            }
            
            Vector vRequestedAttributes = new Vector();
            Iterator iterDesignators = oSAMLAttributeQuery.getDesignators();
            if (!iterDesignators.hasNext())
            {
                Enumeration enumAppIDAttributes = htAppIDAttributes.keys();
                while (enumAppIDAttributes.hasMoreElements())
                {
                    String sAttributeName = (String)enumAppIDAttributes.nextElement();
                    Object oAttributeValue = htAppIDAttributes.get(sAttributeName);
                    SAMLAttribute oSAMLAttribute = createSAMLAttribute(sAttributeName, oAttributeValue); 
                    vRequestedAttributes.add(oSAMLAttribute);
                }
            }
            else
            {
                while (iterDesignators.hasNext())
                {
                    SAMLAttributeDesignator oSAMLAttributeDesignator = (SAMLAttributeDesignator)iterDesignators.next();
                    
                    String sAttributeName = oSAMLAttributeDesignator.getName();
                    if (!htAppIDAttributes.containsKey(sAttributeName))
                    {
                        StringBuffer sbError = new StringBuffer("Attribute '");
                        sbError.append(sAttributeName);
                        sbError.append("' not found for name identifier: ");
                        sbError.append(sNameIdentifier);
                        _systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
                    }
                    else
                    {
                        Object oAttributeValue = htAppIDAttributes.get(sAttributeName);
                        SAMLAttribute oSAMLAttribute = createSAMLAttribute(sAttributeName, oAttributeValue); 
                        vRequestedAttributes.add(oSAMLAttribute);
                    }
                }
            }
            if (vRequestedAttributes.isEmpty())
            {
                _systemLogger.log(Level.FINE, MODULE, sMethod, "Requested attributes not found for name identifier: " + sNameIdentifier);
                throw new SAMLException(SAMLException.REQUESTER, "Requested attributes not found for name identifier: " + sNameIdentifier);
            }
            
            SAMLNameIdentifier oSAMLNameIdentifier = new SAMLNameIdentifier(sNameIdentifier
                , _sASelectServerID
                , SAMLNameIdentifier.FORMAT_UNSPECIFIED);   
            
            //subject
            SAMLSubject oSAMLSubject = new SAMLSubject(oSAMLNameIdentifier, null, null, null);            
            
            //attribute statement
            oSAMLAttributeStatement = new SAMLAttributeStatement(oSAMLSubject
                , vRequestedAttributes);
        }
        catch (SAMLException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not handle SAML Attribute Query", e);
            throw new SAMLException(SAMLException.RESPONDER, "Internal error", e);
        }
        return oSAMLAttributeStatement;
    }
    
    /**
     * Handles a SAML Authorization Decision Query.
     * <br/>
     * If the requested resource is available SAMLDecision.INDETERMINATE will 
     * be returned in a SAML Response message. If the message is invalid, then 
     * SAMLDecision.DENY will be returned in a SAML Response message.
     * <br><br>
     * @param htSAMLSession Hashtable containing SAML Session information
     * @param oSAMLAuthorizationDecisionQuery SAML Subject Query object
     * @param sNameIdentifier A-Select User ID
     * @return SAMLSubjectStatement that can be sent to the requestor
     * @throws SAMLException if internal error occurred
     */
    private SAMLSubjectStatement handleAuthorizationDecisionQuery(Hashtable htSAMLSession
        , SAMLAuthorizationDecisionQuery oSAMLAuthorizationDecisionQuery
        , String sNameIdentifier)
        throws SAMLException
    {
        String sMethod = "handleAuthorizationDecisionQuery()";
        SAMLAuthorizationDecisionStatement oSAMLAuthorizationDecisionStatement = null;
        String sSAMLDecision = null;
        try
        {
            
            Hashtable htResources = (Hashtable)htSAMLSession.get("resources");
            if (htResources == null)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No resources found for name identifier: " + sNameIdentifier);
                throw new SAMLException(SAMLException.REQUESTER, "No resources found for name identifier: " + sNameIdentifier);
            }
            
            String sResource = oSAMLAuthorizationDecisionQuery.getResource();
            if (sResource == null)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No resource found in request for name identifier: " + sNameIdentifier);
                throw new SAMLException(SAMLException.REQUESTER, "No resource found in request");
            }
            
            Vector vSAMLActions = new Vector();
            Iterator iterActions = oSAMLAuthorizationDecisionQuery.getActions();
            while (iterActions.hasNext())
            {
                SAMLAction oSAMLAction = (SAMLAction)iterActions.next();   
                
                SAMLAction oNewSAMLAction = new SAMLAction(
                    oSAMLAction.getNamespace(), oSAMLAction.getData());
                
                vSAMLActions.add(oNewSAMLAction);
            }
            
            if (htResources.containsKey(sResource))
            {
                //Not implemented: Iterator iterEvidence = oSAMLAuthorizationDecisionQuery.getEvidence();
                //SAML message is correct, but we don't make any authorization desissions 
                sSAMLDecision = SAMLDecision.INDETERMINATE;
            }
            else
            {
                //we do know for sure that the user is denied for this resource, because he is unknown
                sSAMLDecision = SAMLDecision.DENY;
            }
            
            //build response
            SAMLNameIdentifier oSAMLNameIdentifier = new SAMLNameIdentifier(
                sNameIdentifier
                , _sASelectServerID
                , SAMLNameIdentifier.FORMAT_UNSPECIFIED);   
            
            //subject
            SAMLSubject oSAMLSubject = new SAMLSubject(oSAMLNameIdentifier, null
                , null, null);            
            
            //attribute statement
            oSAMLAuthorizationDecisionStatement 
                = new SAMLAuthorizationDecisionStatement(oSAMLSubject
                    , sResource, sSAMLDecision, vSAMLActions, null);
            
        }
        catch (SAMLException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod
                , "Could not handle SAML Authorization Decision Query", e);
            throw new SAMLException(SAMLException.RESPONDER, "Internal error", e);
        }
        return oSAMLAuthorizationDecisionStatement;
    }
    
    /**
     * Generates a SAML Response by the supplied shire and SAML Subject Statement
     * <br><br>
     * @param sInResponseTo InResponseTo must be same as RequestID
     * @param sShire recievement URI
     * @param oSAMLSubjectStatement that must be put in the SAML Assertion
     * @return SAMLResponse object
     * @throws SAMLException if SAML Response could not be created
     */
    private SAMLResponse generateSAMLResponse(String sInResponseTo, String sShire
        , SAMLSubjectStatement oSAMLSubjectStatement) 
        throws SAMLException
    {
        String sMethod = "generateSAMLResponse()";
        SAMLResponse oSAMLResponse = null;
        
        try
        {
            Vector vSAMLStatements = new Vector();
            vSAMLStatements.add(oSAMLSubjectStatement);
            
            Date dExpire = new Date(System.currentTimeMillis() + _lAssertionExpireTime);

            SAMLAssertion oSAMLAssertion = new SAMLAssertion(
                _sASelectServerID,          // Our (IdP) Id
                new Date(),                 // Valid from
                dExpire,                    // Valid until
                null,                       // TODO: add Audience condition
                null,                       // Advice(s)
                vSAMLStatements             // Contained statements
                );
            
            Vector vSAMLAssertions = new Vector();
            vSAMLAssertions.add(oSAMLAssertion);
            
            oSAMLResponse = new SAMLResponse(sInResponseTo, sShire
                , vSAMLAssertions, null);
            
            Vector vCertificatesToInclude = new Vector();
            vCertificatesToInclude.add(_configManager.getDefaultCertificate());
            oSAMLResponse.sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, 
                _configManager.getDefaultPrivateKey(),
                vCertificatesToInclude);
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create SAMLAttributeStatement", e);
            throw new SAMLException(SAMLException.RESPONDER, "Internal error", e);
        }
        
        return oSAMLResponse;
    }
    
    /**
     * Sends an error in a SAML message
     * @param response HttpServletResponse were to the response will be sent
     * @param oSAMLRequest SAMLRequest object, can be <code>null</code>
     * @param oSAMLException A SAML Exception object containing the error
     * @throws ASelectException if no SAML response could be sent
     */
    private void respondError(HttpServletResponse response
        , SAMLRequest oSAMLRequest
        , SAMLException oSAMLException)
        throws ASelectException
    {
        String sMethod = "respondError()";
        String sResponseId = null;
        try
        {
            if (oSAMLRequest != null)
                sResponseId = oSAMLRequest.getId();
            
            SAMLResponse oSAMLResponse = new SAMLResponse(sResponseId, null
                , null, oSAMLException);
            
            _oSAMLBinding.respond(response, oSAMLResponse, null);
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod
                , "Could not send failure over SAML binding", e);
            
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
                
        }
    }
    
    /**
     * Creates a SAMLAttribute object.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Creates a SAMLAttribute object, using the supplied name and value (must 
     * be of type String or Vector).<br/>
     * Sets the attribute namespace, to the configured one.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * sName != null<br/>
     * oValue != null
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sName attribute name
     * @param oValue attribute value (String or Vector)
     * @return SAMLAttribute containing the complete attribute
     * @throws ASelectException if creation fails
     */
    private SAMLAttribute createSAMLAttribute(String sName, Object oValue)
        throws ASelectException
    {
        String sMethod = "generateSAMLAttribute()";
        SAMLAttribute oSAMLAttribute = new SAMLAttribute();
        
        try
        {
            oSAMLAttribute.setNamespace(_sAttributeNamespace);
            oSAMLAttribute.setName(sName);
            
            if (oValue instanceof Vector)
            {
                Vector vValue = (Vector)oValue;
                Enumeration enumValues = vValue.elements();
                while(enumValues.hasMoreElements())
                    oSAMLAttribute.addValue(enumValues.nextElement());                                
            }
            else
                oSAMLAttribute.addValue(oValue);
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod
                , "Could not create a SAML attribute object", e);
            
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        
        return oSAMLAttribute;
    }

}
