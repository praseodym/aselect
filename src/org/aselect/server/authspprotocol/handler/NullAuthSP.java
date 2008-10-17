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
 * $Id: NullAuthSP.java,v 1.20 2006/05/03 09:46:50 tom Exp $ 
 * 
 * Changelog:
 * $Log: NullAuthSP.java,v $
 * Revision 1.20  2006/05/03 09:46:50  tom
 * Removed Javadoc version
 *
 * Revision 1.19  2006/04/03 08:44:12  erwin
 * Changed signature checking (fixed bug #165)
 *
 * Revision 1.18  2005/09/08 13:06:53  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.17  2005/04/15 12:06:26  tom
 * Removed old logging statements
 *
 * Revision 1.16  2005/04/08 11:54:57  martijn
 * removed todo
 *
 * Revision 1.15  2005/04/01 14:17:41  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.14  2005/03/17 07:50:49  tom
 * Added IP to authentication log
 *
 * Revision 1.13  2005/03/16 13:15:10  martijn
 * changed todo
 *
 * Revision 1.12  2005/03/14 07:24:37  tom
 * Minor code style changes
 *
 * Revision 1.11  2005/03/10 16:16:40  tom
 * Added new Authentication Logger
 *
 * Revision 1.10  2005/03/10 08:17:01  tom
 * Added new Logger functionality
 *
 * Revision 1.9  2005/03/09 11:30:43  tom
 * Added final to the static variable String MODULE
 *
 * Revision 1.8  2005/03/09 09:23:23  erwin
 * Renamed and moved errors.
 *
 * Revision 1.7  2005/03/07 14:22:17  martijn
 * changed authentication log information
 *
 * Revision 1.6  2005/03/04 16:42:41  martijn
 * session expire failure handling bug fixed / authentication log information changed
 *
 * Revision 1.5  2005/03/04 16:24:09  tom
 * The NullAuthSP Handler now uses org.aselect.server.authspprotocol.IAuthSPProtocolHandler
 *
 * Revision 1.4  2005/03/04 09:08:17  martijn
 * added javadoc and renamed variables according to the coding style
 *
 * Revision 1.3  2005/03/04 08:44:21  martijn
 * added working version
 *
 * Revision 1.2  2005/03/03 14:40:10  martijn
 * created a working version
 *
 */

package org.aselect.server.authspprotocol.handler;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Hashtable;
import java.util.logging.Level;

import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthSPException;

/**
 * The Null AuthSP handler.
 * <br><br>
 * <b>Description:</b><br>
 * The Null AuthSP handler communicates with the Null AuthSP by using redirects. 
 * The Null AuthSP is only for testing perposes and may not be used as a real 
 * AuthSP in a production(live) environment 
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 */
public class NullAuthSP implements IAuthSPProtocolHandler
{
    /**
     * The name of this module, that is used in the system logging.
     */
    private final static String MODULE = "NullAuthSP";
    
    private final static String ERROR_NO_ERROR = "000";
    private final static String ERROR_ACCESS_DENIED = "800";
    
    /**
     * The A-Select config manager
     */
    private ASelectConfigManager _configManager;
    /**
     * The A-Select session manager
     */
    private SessionManager _sessionManager;
    /**
     * The A-Select crypto engine
     */
    private CryptoEngine _cryptoEngine;
    /**
     * The logger that logs system information
     */
    private ASelectSystemLogger _systemLogger;
    /**
     * The logger that logs authentication information
     */
    private ASelectAuthenticationLogger _authenticationLogger;
    /**
     * The AuthSP ID
     */
    private String _sAuthSP;
    /**
     * The url to the authsp
     */
    private String _sAuthSPUrl;
    /**
     * The A-Select Server server id
     */
    private String _sServerId;
    
    

    /**
     * Initializes the NullAuthSP handler.
     * <br>
     * Resolves the following config items:<br>
     * - The AuthSP id<br>
     * - The url to the authsp (from the resource)<br>
     * - The server id from the A-Select main config<br>
     * <br><br>
     * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
     */
    public void init(Object oAuthSPConfig, Object oAuthSPResource)
        throws ASelectAuthSPException
    {
        String sMethod = "init()";
        
        Object oASelectConfig = null;
        
        try
        {
            _systemLogger = ASelectSystemLogger.getHandle();
            _authenticationLogger = ASelectAuthenticationLogger.getHandle();
	        _configManager = ASelectConfigManager.getHandle();
	        _sessionManager = SessionManager.getHandle();
	        _cryptoEngine = CryptoEngine.getHandle();
	
	        try
	        {
	            _sAuthSP = _configManager.getParam(oAuthSPConfig, "id");
	        }
	        catch(Exception e)
	        {
	            throw new ASelectAuthSPException("No valid 'id' config item found in authsp section", e);
	        }
	        
	        try
	        {
	            _sAuthSPUrl = _configManager.getParam(oAuthSPResource, "url");
	        }
	        catch(Exception e)
	        {
	            StringBuffer sbFailed = new StringBuffer("No valid 'url' config item found in resource section of authsp with id='");
	            sbFailed.append(_sAuthSP);
	            sbFailed.append("'");
	            throw new ASelectAuthSPException(sbFailed.toString(), e);
	        }
	        
	        try
	        {
	            oASelectConfig = _configManager.getSection(null, "aselect");
	        }
	        catch(Exception e)
	        {
	            throw new ASelectAuthSPException("No main 'aselect' config section found", e);
	        }
	        
	        try
	        {
	            _sServerId = _configManager.getParam(oASelectConfig, "server_id");
	        }
	        catch(Exception e)
	        {
	            throw new ASelectAuthSPException("No valid 'server_id' config item found in main 'aselect' section", e);
	        }
        }
        catch(ASelectAuthSPException e)
        {
            _systemLogger.log(Level.WARNING, 
                MODULE, sMethod, "Could not initialize", e);
            throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
        }
        catch(Exception e)
        {
            _systemLogger.log(Level.SEVERE, 
                MODULE, sMethod, "Could not initialize", e);
            throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }

    /**
     * Sends an authentication request to the authsp.
     * <br>
     * The response must contain the following parameters:<br>
     * <table border="1" cellspacing="0" cellpadding="3">
     * <tr><td style="" bgcolor="#EEEEFF">name</td><td style="" bgcolor="#EEEEFF">
     * value</td><td style="" bgcolor="#EEEEFF">encoded</td></tr>
     * <tr><td>as_url</td><td>A-Select Server url</td><td>yes</td></tr>
     * <tr><td>rid</td><td>A-Select Server request id</td><td>no</td></tr>
     * <tr><td>uid</td><td>A-Select Server user ID</td><td>yes</td></tr>
     * <tr><td>a-select-server</td><td>A-Select Server ID</td><td>no</td></tr>
     * <tr><td>signature</td><td>signature of all paramaters in the above sequence</td><td>yes</td></tr>
     * </table>
     * <br><br>
     * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#computeAuthenticationRequest(java.lang.String)
     */
    public Hashtable computeAuthenticationRequest(String sRid)
    {
        String sMethod =  "computeAuthenticationRequest()";

        Hashtable htResponse = new Hashtable();
        htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

        try
        {
            Hashtable htSessionContext = _sessionManager.getSessionContext(sRid);
            if (htSessionContext == null)
            {
                StringBuffer sbBuffer = new StringBuffer("Could not fetch session context for rid: ");
                sbBuffer.append(sRid);
                _systemLogger.log(Level.WARNING,
                    MODULE, sMethod, sbBuffer.toString());

                throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
            }
            
            StringBuffer sbMyUrl = new StringBuffer((String)htSessionContext.get("my_url"));
            sbMyUrl.append("?authsp=").append(_sAuthSP);
            String sAsUrl = sbMyUrl.toString();
            
            Hashtable htAllowedAuthsps = (Hashtable)htSessionContext.get("allowed_user_authsps");
            if (htAllowedAuthsps == null)
            {
                _systemLogger.log(Level.WARNING, 
                    MODULE, sMethod, "allowed_user_authsps missing in session context");

                throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
            }
            String sUserId = (String)htAllowedAuthsps.get(_sAuthSP);
            if (sUserId == null)
            {
                _systemLogger.log(Level.WARNING, 
                    MODULE, sMethod, "missing NullAuthSP user attributes ");

                throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
            }
            
            String sCountry = (String)htSessionContext.get("country");
            if (sCountry == null || sCountry.trim().length() < 1)
            {
            	sCountry = null;
            }
            
            String sLanguage = (String)htSessionContext.get("language");
            if (sLanguage == null || sLanguage.trim().length() < 1)
            {
            	sLanguage = null;
            }
            
            StringBuffer sbSignature = new StringBuffer(sRid);
            sbSignature.append(sAsUrl);
            sbSignature.append(sUserId);
            sbSignature.append(_sServerId);
            
            if (sCountry != null)
                sbSignature.append(sCountry);
            
            if (sLanguage != null)
                sbSignature.append(sLanguage);

            String sSignature = _cryptoEngine.generateSignature(_sAuthSP, 
                sbSignature.toString());
            if (sSignature == null)
            {
                StringBuffer sbBuffer = new StringBuffer("Could not generate signature for authsp: ");
                sbBuffer.append(_sAuthSP);
                _systemLogger.log(Level.WARNING, 
                    MODULE, sMethod, sbBuffer.toString());

                throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
            }
            
            sSignature = URLEncoder.encode(sSignature, "UTF-8");
            sUserId = URLEncoder.encode(sUserId, "UTF-8");
            sAsUrl = URLEncoder.encode(sAsUrl, "UTF-8");

            StringBuffer sbRedirect = new StringBuffer(_sAuthSPUrl);
            sbRedirect.append("?as_url=").append(sAsUrl);
            sbRedirect.append("&rid=").append(sRid);
            sbRedirect.append("&uid=").append(sUserId);
            sbRedirect.append("&a-select-server=").append(_sServerId);
            
            if (sCountry != null)
                sbRedirect.append("&country=").append(sCountry);
            
            if (sLanguage != null)
                sbRedirect.append("&language=").append(sLanguage);
                        
            sbRedirect.append("&signature=").append(sSignature);
            
            htResponse.put("redirect_url", sbRedirect.toString());
            htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
        }
        catch (ASelectAuthSPException e)
        {
            htResponse.put("result", e.getMessage());
        }
        catch(Exception e)
        {
            _systemLogger.log(Level.SEVERE, 
                MODULE, sMethod, "Could not initialize", e);
            
            htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
        }
        
        return htResponse;
    }

    /**
     * Checks the response from the NullAuthSP.
     * <br>
     * The response must contain the following parameters:<br>
     * <table border="1" cellspacing="0" cellpadding="3">
     * <tr><td style="" bgcolor="#EEEEFF">name</td><td style="" bgcolor="#EEEEFF">
     * value</td><td style="" bgcolor="#EEEEFF">encoded</td></tr>
     * <tr><td>rid</td><td>A-Select Server request id</td><td>no</td></tr>
     * <tr><td>result_code</td><td>AuthSP result code</td><td>no</td></tr>
     * <tr><td>a-select-server</td><td>A-Select Server ID</td><td>no</td></tr>
     * <tr><td>signature</td><td>signature of all paramaters in the above sequence</td><td>yes</td></tr>
     * </table>
     * <br><br>
     * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#verifyAuthenticationResponse(java.util.Hashtable)
     */
    public Hashtable verifyAuthenticationResponse(Hashtable htAuthspResponse)
    {
        String sMethod = "verifyAuthenticationResponse()";

        String sUserId = null; 
        String sAppID = null;
        StringBuffer sbMessage = null;
        String sOrganization = null;
        String sLogResultCode = null;
        
        Hashtable htResponse = new Hashtable();
        htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

        try
        {
            String sRid = (String)htAuthspResponse.get("rid");
            String sAsUrl = (String)htAuthspResponse.get("my_url");
            String sResultCode = (String)htAuthspResponse.get("result_code");
            String sAsId = (String)htAuthspResponse.get("a-select-server");
            String sSignature = (String)htAuthspResponse.get("signature");

            if ((sRid == null) || (sResultCode == null) || (sSignature == null) || (sAsId == null))
            {
                _systemLogger.log(Level.WARNING, MODULE,
                    						sMethod, "Incorrect AuthSP response, missing one or more required parameters.");

                throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
            }
            
            
            StringBuffer sbAsUrl = new StringBuffer(sAsUrl);
            sbAsUrl.append("?authsp=");
            sbAsUrl.append(_sAuthSP);
            sAsUrl = sbAsUrl.toString();
            
            sSignature = URLDecoder.decode(sSignature, "UTF-8");
            StringBuffer sbSignature = new StringBuffer(sRid);
            sbSignature.append(sAsUrl);
            sbSignature.append(sResultCode);
            sbSignature.append(sAsId);

            if (!_cryptoEngine.verifySignature(_sAuthSP, sbSignature.toString(),sSignature))
            {
                _systemLogger.log(Level.WARNING, MODULE,
					sMethod, "Invalid signature in response from AuthSP");
                
                throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
            }
           
            Hashtable htSessionContext = _sessionManager.getSessionContext(sRid);
            if (htSessionContext == null)
            {
                _systemLogger.log(Level.WARNING, MODULE,
					sMethod, "Session expired -> SessionContext not available for rid: ");

                throw new ASelectAuthSPException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
            }
            
            sUserId = (String)htSessionContext.get("user_id");
            sAppID = (String)htSessionContext.get("app_id");
            
            //must be retrieved from the session, because it can be an remote organtization 
            sOrganization = (String)htSessionContext.get("organization");
            
             sbMessage = new StringBuffer(sOrganization);
            sbMessage.append(_sAuthSP).append(",");
            
            //check if user was authenticated successfully
            if (!sResultCode.equalsIgnoreCase(ERROR_NO_ERROR))
            {   
                if (sResultCode.equalsIgnoreCase(ERROR_ACCESS_DENIED))
	            {
                    _authenticationLogger.log(new Object[] {
									MODULE,
									sUserId,
									htAuthspResponse.get("client_ip"),
									sOrganization,
									sAppID,
									"denied"});
                   
                    throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
	            }
                
	            StringBuffer sbError = new StringBuffer("AuthSP returned errorcode: ");
	            sbError.append(sResultCode);
	            
                _systemLogger.log(Level.WARNING, MODULE,
					sMethod, sbError.toString());
	                        
	            throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
            }
            
            _authenticationLogger.log(new Object[] {
									MODULE,
									sUserId,
									htAuthspResponse.get("client_ip"),
									sOrganization,
									sAppID,
									"granted"});
            
            htResponse.put("rid", sRid);
            sLogResultCode = Errors.ERROR_ASELECT_SUCCESS;
            htResponse.put("result", sLogResultCode);
        }
        catch (ASelectAuthSPException e)
        {
            sLogResultCode =  e.getMessage();
            htResponse.put("result", e.getMessage());
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, 
                						MODULE,
                						sMethod,
                						"INTERNAL ERROR", 
                						e);
            sLogResultCode =  Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
            htResponse.put("result", sLogResultCode);
        }
        
        return htResponse;
    }
}

