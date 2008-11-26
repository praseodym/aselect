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
package org.aselect.server.request.handler.wsfed;

import java.net.URLEncoder;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.*;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.opensaml.*;

//
// Resource Partner STS = SP
//
public class ResourceSTS extends ProtoRequestHandler
{
	public final static String MODULE = "ResourceSTS";
	private final static String RETURN_SUFFIX = "_return";
	private final static String SESSION_ID_PREFIX = "";  // 20081125 "wsfed_";
	private String _sProviderId;
	private String _sNameIdFormat;
	private String _sPostTemplate;
    protected boolean _bCheckSigning = false;

	protected String getSessionIdPrefix() { return SESSION_ID_PREFIX; }

	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
	    String sMethod = "init()";
	    try {
			super.init(oServletConfig, oConfig);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Specific init processing");

			_sProviderId = HandlerTools.getSimpleParam(oConfig, "provider_id", true);
			_sNameIdFormat = HandlerTools.getSimpleParam(oConfig, "nameid_format", true);
			_sPostTemplate = readTemplateFromConfig(oConfig, "post_template");
			String sCheckSigning = HandlerTools.getSimpleParam(oConfig, "check_signing", false);
			if (sCheckSigning != null && sCheckSigning.equals("true"))
				_bCheckSigning = true;
	    }
	    catch (ASelectException e) {  // Pass unchanged
	        throw e;
	    }
	    catch (Exception e) {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	}
	       
	//
	// Receive the Resource Challenge (Step 3)
	//
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
        String sMethod = "process()";
		String sPathInfo = request.getPathInfo();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Path="+sPathInfo);
		
		if (sPathInfo.endsWith(RETURN_SUFFIX)) {
			return processReturn(request, response);
		}
		
    	String sIdPUrl = request.getParameter("whr");
    	String sPwa = request.getParameter("wa");
    	String sPwreply = request.getParameter("wreply");  // protected resource
    	String sPwctx = request.getParameter("wctx");  // pass context unchanged
    	String sPwct = request.getParameter("wct");  // TODO: check
    	String sPwtrealm = request.getParameter("wtrealm");  // requestor's home realm

    	// Redirect to Requestor's IP/STS (Account Partner)
    	try {
	    	// Add a '?' after the selected IdP URL
	    	if (!sIdPUrl.endsWith("?"))
	            sIdPUrl = sIdPUrl + "?";
	    	
			String sASelectURL = _sServerUrl;  // extractAselectServerUrl(request);
			String sReplyTo = sASelectURL + sPathInfo + RETURN_SUFFIX;
			
	        StringBuffer sbRedirect = new StringBuffer(sIdPUrl);
	        sbRedirect.append("wa=").append(sPwa);
	        sbRedirect.append("&wct=").append(Tools.samlCurrentTime());  // new current time
	        sbRedirect.append("&wreply=").append(URLEncoder.encode(sReplyTo, "UTF-8"));
	        if (sPwctx != null) sbRedirect.append("&wctx=").append(URLEncoder.encode(sPwreply, "UTF-8"));
	        if (sPwtrealm != null) sbRedirect.append("&wtrealm=").append(URLEncoder.encode(sPwtrealm, "UTF-8"));
	   
	        // Redirect to Requestor's IP/STS (Step 4)
	        _systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT to IdP="+sbRedirect);
	        response.sendRedirect(sbRedirect.toString());
	    	return new RequestState(null);
    	}
	    //catch (ASelectException e) {  // Filter this one
	    //    throw e;
	    //}
	    catch (Exception e) {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	}

	//
	// Receive Requestor Token POST - Step 7
	//
	// <wst:RequestSecurityTokenResponse xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
	// <wst:RequestedSecurityToken><saml:Assertion AssertionID="_5f01741c-add2-40bb-b3f3-1214cd90700f" IssueInstant="2007-07-11T22:51:15Z" Issuer="urn:federation:adatum" MajorVersion="1" MinorVersion="1" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion">
	// <saml:Conditions NotBefore="2007-07-11T22:51:15Z" NotOnOrAfter="2007-07-11T23:51:15Z">
	// <saml:AudienceRestrictionCondition><saml:Audience>http://www.anoigo.nl/wsfed_sp.xml</saml:Audience></saml:AudienceRestrictionCondition>
	// </saml:Conditions>
	// <saml:Advice><adfs:CookieInfoHash xmlns:adfs="urn:microsoft:federation">sU1g1W6FUmfptr+fZiSmY8C6G9Q=</adfs:CookieInfoHash></saml:Advice>
	// <saml:AuthenticationStatement AuthenticationInstant="2007-07-11T22:51:15Z" AuthenticationMethod="urn:federation:authentication:windows">
	// <saml:Subject><saml:NameIdentifier Format="http://schemas.xmlsoap.org/claims/UPN">Administrator@adatum.com</saml:NameIdentifier></saml:Subject></saml:AuthenticationStatement>
	// <Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
	// <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI="#_5f01741c-add2-40bb-b3f3-1214cd90700f">
	// <Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
	// <DigestValue>iQPWzZVogkXf5BQJuxrP2BhDX8U=</DigestValue></Reference></SignedInfo><SignatureValue>C4E3IjEQDY5vitdajPa0NU2GfiSSQ0iw1Tk4X0Qe9dD1GBnviyS6Th9+J5DuunWXNY67HZnyM1NqeF4VLbTVgUAivpy8zqPnKfdj2h6+7RnzqPn/W0wdi6/sHyF8bMPOQGBOFkAKu1VQvdSzRZUUTTVBYmt+F6aUSUmSKPG5kVNvRHNzazwLCsVkQdYO896PTYb/xbYGOWguwpIX5zkuB0A7Mbr3ZCKscnU8v6ZXibiIpV24hVfAfcM47pruIOO5Txke9apTW6i5UIqUfa7eASiCMCt2dAsjiAVUpU0dRGOYCd8w5HzxwxU+vg0c89dntrRaASv2ShV2WQkPcHEq2A==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIC0DCCAbygAwIBAgIQxGk7HPuDb6pNm5nvOdF/3DAJBgUrDgMCHQUAMCgxJjAkBgNVBAMTHUZlZGVyYXRpb24gU2VydmVyIEFkZnNhY2NvdW50MB4XDTA3MDMyMDIxMjIzNFoXDTA4MDMyMDAzMjIzNFowKDEmMCQGA1UEAxMdRmVkZXJhdGlvbiBTZXJ2ZXIgQWRmc2FjY291bnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgHabNDtni0POjMHFp1vOLlH0wdgpvCCf2gXpCIOO9KLHVTAzsxrA68y56GV/Xxu1Ta3Sld1avzMZhqcEpY4+Ikw4cxAf9DWiQmycK/XwJr48+XQ6op0Gw+mjX1zC6e30hrFR+n4Xy5dACIQb44lSjyHnXosikW9CHjwbynOUuyCVcWXoPaLyaNKhntKahd1Z2l3XTrFHDORk6hIWPKaTSoHKbmyiVrt+292DL2V5fobX+oR7PgvDkhWFjkRCLadLBiwpPn7hXEPaNr9Qz55+pKh9dSyuw8yZhDRsGCA2q3GPv9Ww0FvsyiHQen9V33kDOUJMf3+5OLIj24jQbdLVHAgMBAAEwCQYFKw4DAh0FAAOCAQEAK39vJr1+eOQS0PbSgFPGuIFFZvYdZS9vgLofWL9Sm64Ry59aR4stnUErazfLVpS/yxk0mSadYOwKvXmdQQVyCyWq7BA6VoXk78+Si0bDf3Asx4vDa6Wf1V/JjCny07lxHAuxzqtuHSghY9yYG6Hd5xfUogTz5k4dSdpev6euNdV5+YpVFiryBB2lurCyWU2oyQja6l297wx8pYjCwxyTa0T6/maSHFSeQzuZ5heE+6yrVgOp4wsOuzF3YBpqDYwI/B984l1H9y9LzfzF/tRkkFG9KOpJja8dkZE8mum5WL+ElKgncqBJPk5LhOJmIVY0eGyJzMQhlSHTaiFutbG3Ag==</X509Certificate></X509Data></KeyInfo>
	// </Signature></saml:Assertion></wst:RequestedSecurityToken><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
	// <wsa:Address>http://www.anoigo.nl/wsfed_sp.xml</wsa:Address></wsa:EndpointReference>
	// </wsp:AppliesTo></wst:RequestSecurityTokenResponse>
	//
	public RequestState processReturn(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "processReturn()";
    	String sPwa = request.getParameter("wa");
    	String sPwresult = request.getParameter("wresult");
    	String sPwctx = request.getParameter("wctx");  // POST to this URL (the protected resource)
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Token IN: RequestorToken wresult=" + sPwresult + ", ReplyTo wctx="+sPwctx);
		
		// Return Resource Token, POST - Step 8
    	try {
    		// Check incoming token (signature, time)
            // Signature ok?
	        if (_bCheckSigning) {
	        	checkSignature(sPwresult);
	        }

    		Hashtable htAttributes = extractAllAttributes(sPwresult);
			String sUid = (String)htAttributes.get("digid_uid");
			if (sUid == null) sUid = (String)htAttributes.get("uid");
			if (sUid == null) sUid = (String)htAttributes.get("cn");
			if (sUid == null) {
				sUid = extractNameIdentifier(sPwresult);
			}
			if (sUid != null && htAttributes.get("uid") == null) {
				// We want at least the "uid" attribute
				htAttributes.put("uid", sUid);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htAttributes=" + htAttributes);
	
			String sAudience = null; // "urn:federation:treyresearch";
			//String sNameIdFormat = "http://schemas.xmlsoap.org/claims/UPN";
			//String sProviderId = "http://www.anoigo.nl/wsfed_sp.xml";
			String sRequestorToken = createRequestorToken(request, _sProviderId, sUid, _sNameIdFormat,
					sAudience, htAttributes, null);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Token OUT: RequestorToken=" + sRequestorToken);
			
			String sInputs = buildHtmlInput("wa", "wsignin1.0");
			sInputs += buildHtmlInput("wctx", sPwctx);
			sInputs += buildHtmlInput("wresult", Tools.htmlEncode(sRequestorToken));
			
			handlePostForm(_sPostTemplate, sPwctx, sInputs, response);			
	    	return new RequestState(null);
		}
		catch (SAMLException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "SAML Exception: ", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

    public String serializeTheseAttributes(Hashtable htAttribs)
    throws ASelectException
    {
    	return "";
    }

	public void destroy()
	{
	}
}
