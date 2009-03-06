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
package org.aselect.server.request.handler.idff12;

import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.*;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

//
//
public class Idff12_ISTS extends ProtoRequestHandler
{
    private final static String MODULE = "Idff12_ISTS";
    private final static String COOKIENAME = "idff12_idp";

    private String _sCookieDomain;
    public String _sTemplate = null;
    private String _sProviderId = null;
    private String _sOracleGlitch = null;

    protected String getSessionIdPrefix() { return ""; }
    protected boolean useConfigToCreateSamlBuilder() { return false; }

    public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
	    String sMethod = "init()";
	    try {
	        super.init(oServletConfig, oConfig);
	    }
	    catch (ASelectException e) {
	        throw e;
	    }
	    catch (Exception e) {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	       
		_sProviderId = Utils.getSimpleParam(oConfig, "provider_id", true);
		_sOracleGlitch = Utils.getSimpleParam(oConfig, "oracle_glitch", false);
		if (_sOracleGlitch != null)
    		_systemLogger.log(Level.INFO, MODULE, sMethod, "oracle_glitch=" + _sOracleGlitch);
        	
		_sCookieDomain = _configManager.getCookieDomain();
		//_sCookieDomain = Utils.getParamFromSection(oConfig, "cookie", "domain");
		//if (!_sCookieDomain.startsWith("."))
		//	_sCookieDomain = "." + _sCookieDomain;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Cookie domain is: " + _sCookieDomain);
	}

	public RequestState process(HttpServletRequest request, HttpServletResponse response)
    throws ASelectException
    {
        String sMethod = "process()";
        try {
    		String sRelayState = request.getParameter("RelayState");
            _systemLogger.log(Level.INFO, MODULE, sMethod, "ISTS RelayState="+sRelayState);
	        if (sRelayState == null) {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, "AuthnRequest: Missing parameter 'RelayState'");
                throw new ASelectException (Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
	        }
	        
	    	String sIdPUrl = request.getParameter("idp");
            // Transfer to the remote IdP
            handleSubmit(sIdPUrl, sRelayState, _sProviderId, response);
	    }
	    catch (ASelectException e) {
	        throw e;
	    }
	    catch (Exception e) {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	    return new RequestState(null);
	}

    private void handleSubmit(String sIdPUrl, String sRelayState, String sProviderId, HttpServletResponse response)
    throws ASelectException
    {
        String sMethod = "handleSubmit()";
        try {
        	// Store the current choice in a cookie
        	HandlerTools.putCookieValue(response, COOKIENAME, sIdPUrl, _sCookieDomain, -1, _systemLogger);
/*            Cookie oWAYFCookie = new Cookie(COOKIENAME, sIdPUrl);
            _systemLogger.log(Level.INFO, MODULE, sMethod, "Add Cookie: "+COOKIENAME+" Value="+sIdPUrl+
            		" CookieDomain="+_sCookieDomain);
            
            if (_sCookieDomain != null)
                oWAYFCookie.setDomain(_sCookieDomain);
            response.addCookie(oWAYFCookie);
            _systemLogger.log(Level.INFO, MODULE, sMethod, "Cookie("+COOKIENAME+") added");
*/                        
            //add a '?' char after the selected IdP URL
            if (!sIdPUrl.endsWith("?"))
                sIdPUrl = sIdPUrl + "?";
            
            // Generate a RequestID nonce
        	byte[] RequestID = new byte[20];
			CryptoEngine.nextRandomBytes(RequestID);
	        _systemLogger.log(Level.INFO, MODULE, sMethod, "RequestID="+Utils.toHexString(RequestID));

	        StringBuffer sbRedirect = new StringBuffer(sIdPUrl);
            sbRedirect.append("RequestID=").append(Utils.toHexString(RequestID));
            sbRedirect.append("&RelayState=").append(URLEncoder.encode(sRelayState, "UTF-8"));
            
            _systemLogger.log(Level.INFO, MODULE, sMethod, "IdPUrl="+sIdPUrl+"oracle_glitch="+_sOracleGlitch);
            String pidString = "&ProviderID=";
            if (_sOracleGlitch != null && sIdPUrl.contains(_sOracleGlitch))
            	pidString = "&providerid=";
            sbRedirect.append(pidString).append(URLEncoder.encode(sProviderId, "UTF-8"));
            sbRedirect.append("&IsPassive=false&NameIDPolicy=once&MajorVersion=1&MinorVersion=2");

            Date issueInstant = new Date();
            SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            String sIssueInstant = formatter.format(issueInstant);
            sbRedirect.append("&IssueInstant=").append(URLEncoder.encode(sIssueInstant, "UTF-8"));
            
            _systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT_target="+sbRedirect);
            response.sendRedirect(sbRedirect.toString());
        }
        catch (Exception e) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not handle form request", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }
}
