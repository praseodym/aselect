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

import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xml.security.signature.XMLSignature;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.saml11.common.AssertionSessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLBindingFactory;
import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.artifact.*;
import org.w3c.dom.*;

//
// Generic SAML Artifact Resolver
// Receive <samlp:Request>
// Send <samlp:Response>
//
public abstract class SamlArtifactResolver extends ProtoRequestHandler
{
    private String MODULE = "SamlArtifactResolver";
    
    private SAMLBinding _oSAMLBinding;
    private AssertionSessionManager _oAssertionSessionManager;
//	private String _sProviderId;    
    
    public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
	    String sMethod = "init()";
	    try {
	        super.init(oServletConfig, oConfig);
	        _oAssertionSessionManager = AssertionSessionManager.getHandle();
	        _oSAMLBinding = SAMLBindingFactory.getInstance(SAMLBinding.SOAP);
//			_sProviderId = HandlerTools.getSimpleParam(oConfig, "provider_id", true);
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
        SAMLRequest oSAMLRequest = null;
        SAMLResponse oSAMLResponse = null;
        SAMLArtifact oSAMLArtifact = null;
        SAMLAssertion oSAMLAssertion = null;

        _systemLogger.log(Level.INFO,MODULE,sMethod, "ARTRES request="+request+
        		", Method="+request.getMethod()+", Url="+request.getRequestURL()+
        		", Type="+request.getContentType());
        try { 
            response.setContentType("text/xml");
            String sRequestUrl = request.getRequestURL().toString();
            _systemLogger.log(Level.INFO,MODULE,sMethod, "sRequestUrl="+sRequestUrl);

            // Read data from input stream, example input:
/*        	<?xml version="1.0" encoding="UTF-8"?>
        	<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        	<soap:Header/><soap:Body>
        	<samlp:Request xmlns="urn:oasis:names:tc:SAML:1.0:protocol"
        	 xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"
        	  xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        	  IssueInstant="2007-05-18T18:49:34.509Z" MajorVersion="1" MinorVersion="1"
        	  RequestID="_e63dcb72fb3cde38e64baa0eaf01a43d">
        	  <samlp:AssertionArtifact>AAOlm3kq8uJpt8B900hxPdw/0BvHmsgRIMgJH4i2U2JeaNmDO62lQJTf</samlp:AssertionArtifact>
        	</samlp:Request>
        	</soap:Body></soap:Envelope>
*/
/*			// Debugging:
        	int c;
        	String input;
            ServletInputStream in = request.getInputStream();
            for (input = "" ; ; ) {
                    c = in.read();
                    if (c < 0) break;
                    input = input + (char)c;
            }
            _systemLogger.log(Level.INFO,MODULE,sMethod, "input=\n["+input+"]");
*/
            try {
    	        oSAMLRequest = _oSAMLBinding.receive(request, 1);
        	} 
    	    catch (SAMLException e) {
        	    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not parse SAML request with SOAP binding", e);
                throw e;
        	}
            _systemLogger.log(Level.INFO,MODULE,sMethod, "RESOLVE IN oSAMLRequest="+oSAMLRequest);
                        
            Vector vSAMLAssertions = new Vector();
            Iterator iterArtifacts = oSAMLRequest.getArtifacts();
            while (iterArtifacts.hasNext())
            {
                oSAMLArtifact = (SAMLArtifact)iterArtifacts.next();
                _systemLogger.log(Level.INFO,MODULE,sMethod, "IN oSAMLArtifact="+oSAMLArtifact);
                
                Artifact art = (Artifact)oSAMLArtifact;
                oSAMLAssertion = _oAssertionSessionManager.getAssertion(art);
                if (oSAMLAssertion == null)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, "No SAML Assertion available for the supplied artifact");
                    throw new SAMLException(SAMLException.REQUESTER, "No SAML Assertion available for the supplied artifact");
                }
                _systemLogger.log(Level.INFO,MODULE,sMethod, "FOUND oSAMLAssertion="+oSAMLAssertion);
                
                long lNotBefore = oSAMLAssertion.getNotBefore().getTime();
                long lNotOnOrAfter = oSAMLAssertion.getNotOnOrAfter().getTime();
                long lCurrent = System.currentTimeMillis();
                if ((lCurrent > lNotBefore-60000) && (lCurrent <= lNotOnOrAfter))
                {
                    vSAMLAssertions.add(oSAMLAssertion);
                    //a SAMLAssertion may only be requested once 
                    _oAssertionSessionManager.remove(oSAMLArtifact);
                }
                else {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, "SAML Assertion expired");
                    throw new SAMLException(SAMLException.REQUESTER, "SAML Assertion expired");
                }
            }
			oSAMLResponse = new SAMLResponse(oSAMLRequest.getId() /*inResponseTo*/,
					null /*recipient*/, vSAMLAssertions, null);
            _systemLogger.log(Level.INFO,MODULE,sMethod, "SAMLRespone="+oSAMLResponse);

            Node n = oSAMLResponse.toDOM();
            // Add SessionIndex: goes in <saml:AuthenticationStatement ...>
            Tools.addAttributeToElement(n, _systemLogger, "AuthenticationStatement", "SessionIndex", Tools.getTimestamp());
            // Removed lib: before AuthenticationStatementType (Oracle)
            Tools.addAttributeToElement(n, _systemLogger, "AuthenticationStatement", "xsi:type", "AuthenticationStatementType");
            Tools.addAttributeToElement(n, _systemLogger, "Assertion", "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
            //Tools.addAttributeToElement(n, _systemLogger, "InResponseTo", "xmlns:xsi", oSAMLRequest.getId());
            
            // And sign
            Vector vCertificatesToInclude = new Vector();
			vCertificatesToInclude.add(_configManager.getDefaultCertificate());
			
            _systemLogger.log(Level.INFO,MODULE,sMethod, "Sign");
			oSAMLResponse.sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, 
				_configManager.getDefaultPrivateKey(), vCertificatesToInclude);
			
			String sSAMLResponse = oSAMLResponse.toString();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "RESOLVE OUT Response="+sSAMLResponse);
            
            _oSAMLBinding.respond(response, oSAMLResponse, null);
        }
        catch (SAMLException e) {
            respondError(response, oSAMLRequest, e);
        }
        catch (Exception e) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request ("+e.getClass()+")", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        return new RequestState(null);
    }
    
    private void respondError(HttpServletResponse response, SAMLRequest oSAMLRequest, SAMLException oSAMLException)
    throws ASelectException
    {
        String sMethod = "respondError()";
        String sResponseId = null;
        try {
            if (oSAMLRequest != null)
                sResponseId = oSAMLRequest.getId();
            
            SAMLResponse oSAMLResponse = new SAMLResponse(sResponseId, null, null, oSAMLException);
            _systemLogger.log(Level.INFO,MODULE,sMethod, "oSAMLResponse="+oSAMLResponse);
            _oSAMLBinding.respond(response, oSAMLResponse, null);
        }
        catch (Exception e) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not send failure over SAML binding", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }
}
