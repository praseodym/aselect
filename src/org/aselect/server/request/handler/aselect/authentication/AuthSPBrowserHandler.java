/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license. See the included
 * LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE please contact SURFnet bv.
 * (http://www.surfnet.nl)
 */

/*
 * $Id: AuthSPBrowserHandler.java,v 1.2 2006/05/03 10:10:18 tom Exp $
 * 
 * Changelog: 
 * $Log: AuthSPBrowserHandler.java,v $
 * Revision 1.2  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.2  2006/02/08 08:07:34  martijn
 * getSession() renamed to getSessionContext()
 *
 * Revision 1.1  2006/01/13 08:40:26  martijn
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.13  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.12  2005/04/27 11:57:19  erwin
 * Fixed logging for unknown AuthSP and error in handling response.
 *
 * Revision 1.11  2005/04/06 08:58:12  martijn
 * code updates needed because of TGTIssuer code restyle
 *
 * Revision 1.10  2005/04/05 15:25:08  martijn
 * TGTIssuer.issueTGT() now only needs an optional old tgt and the printwriter isn't needed anymore
 *
 * Revision 1.9  2005/04/05 13:11:49  martijn
 * variable rename to coding standard
 *
 * Revision 1.8  2005/04/01 14:26:19  peter
 * cross aselect redesign
 *
 * Revision 1.7  2005/04/01 14:06:06  erwin
 * Added result_code check in handleError()
 *
 * Revision 1.6  2005/03/17 15:27:58  tom
 * Fixed javadoc
 *
 * Revision 1.5  2005/03/17 15:18:00  tom
 * Organized imports
 *
 * Revision 1.4  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.3  2005/03/17 07:58:43  erwin
 * The A-Select server ID is now set with the constructor,
 * instead of reading it from the configuration.
 *
 * Revision 1.2  2005/03/15 10:51:16  tom
 * - Added new Abstract class functionality
 * - Added Javadoc
 *
 * Revision 1.1  2005/03/15 08:21:58  tom
 * - Redesign of request handling
 *
 */

package org.aselect.server.request.handler.aselect.authentication;

import java.io.PrintWriter;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.AuthenticationLogger;
import org.aselect.system.sam.agent.SAMResource;

/**
 * This class handles cross-authentication requests coming
 * from a remote A-Select Server, except for the
 * <code>cross_login</code> request. 
 * It must be used as follows:
 * <br>
 * For each new incoming request, create a new 
 * <code>CrossASelectHandler</code> object and call either
 * the <code>handleCrossAuthenticateRequest()</code> or
 * the <code>handleCrossAuthenticateResponse()</code>, as
 * appropriate. 
 * <code>CrossASelectHandler</code> objects cannot be reused
 * due to concurrency issues. 

 * <br>
 * @author Alfa & Ariss
 * 
 * 
 * 14-11-2007 - Changes:
 * - Transfer PKI attributes Subject DN and Issuer DN to the context
 * 
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright UMC Nijmegen (http://www.umcn.nl)
 * 
 */
public class AuthSPBrowserHandler extends AbstractBrowserRequestHandler
{
    /**
     * Constructor for AuthSPBrowserHandler.
     * <br>
     * @param servletRequest The request.
     * @param servletResponse The response.
     * @param sMyServerId The A-Select Server ID.
     * @param sMyOrg The A-Select Server organisation.
     */
    public AuthSPBrowserHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
						String sMyServerId, String sMyOrg) {
		super(servletRequest, servletResponse, sMyServerId, sMyOrg);
		_sModule = "AuthSPBrowserHandler";
	}
    
    /**
	 * process authsp browser requests <br>
	 * <br>
	 * 
	 * @see org.aselect.server.request.handler.aselect.authentication.AbstractBrowserRequestHandler#processBrowserRequest(java.util.Hashtable,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter)
	 */
    public void processBrowserRequest(Hashtable htServiceRequest,
    					HttpServletResponse servletResponse, PrintWriter pwOut)
    throws ASelectException
    {
		String sRequest = (String) htServiceRequest.get("request");

		if (sRequest == null && _servletRequest.getParameter("authsp") != null) {
			handleAuthSPResponse(htServiceRequest, _servletResponse);
		}
		else if (sRequest.equals("error")) {
			handleError(htServiceRequest, _servletResponse);
		}
		else {
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}

    /**
	 * This function handles the AuthSP response and calls the correct AuthSP
	 * handler. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            Hashtable containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to the user
	 * @throws ASelectException
	 */
    private void handleAuthSPResponse(Hashtable htServiceRequest, HttpServletResponse servletResponse)
    throws ASelectException
    {
		String sMethod = "handleAuthSPResponse()";
		String sHandlerName = null;
		Object authSPsection = null;
		try {
			String sAsp = (String) htServiceRequest.get("authsp");
			IAuthSPProtocolHandler oProtocolHandler = null;

			try {
				authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"),
						"authsp", "id="	+ sAsp);
			}
			catch (ASelectException eA) {
				// Invalid AuthSP received
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid \"authsp\" received: " + sAsp, eA);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST, eA);
			}

			try {
				sHandlerName = _configManager.getParam(authSPsection, "handler");
			}
			catch (ASelectException eA) {
				// Invalid AuthSP received
				StringBuffer sbError = new StringBuffer("No handler configured for AuthSP '");
				sbError.append(sAsp);
				sbError.append("'");
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, sbError.toString(), eA);
				throw eA;
			}
			_systemLogger.log(Level.INFO, _sModule, sMethod, "AUTHSP authSPsection=" + authSPsection
					+ ", sHandlerName=" + sHandlerName);

			try {
				Class oClass = Class.forName(sHandlerName);
				oProtocolHandler = (IAuthSPProtocolHandler) oClass.newInstance();

				// get authsps config and retrieve active resource from SAMAgent
				String sResourceGroup = _configManager.getParam(authSPsection, "resourcegroup");
				SAMResource mySAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourceGroup);
				Object objAuthSPResource = mySAMResource.getAttributes();
				oProtocolHandler.init(authSPsection, objAuthSPResource);
			}
			catch (Exception e) {
				StringBuffer sbMessage = new StringBuffer("could not instantiate ");
				sbMessage.append(sHandlerName);

				_systemLogger.log(Level.SEVERE, _sModule, sMethod, sbMessage.toString(), e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

            // Let the AuthSP protocol handler verify the response from the AuthSP
            // htResponse will contain the result data
			_systemLogger.log(Level.INFO, _sModule, sMethod, "To AUTHSP, Request=" + htServiceRequest);
            Hashtable htResponse = oProtocolHandler.verifyAuthenticationResponse(htServiceRequest);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "From AUTHSP, Response=" + htResponse);

            String sResultCode = (String)htResponse.get("result");
            String sRid = (String) htResponse.get("rid");  // this is our own rid
			Hashtable htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Session not found, expired? rid="+sRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}

			// Saml20: Any errors must be reported back to the SP (so no Exception throwing in that case)
            String sIssuer = (String)htSessionContext.get("sp_issuer");
			if (sIssuer == null && !(sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)))
            {
				// Session can be killed. The user could not be authenticated.
                _systemLogger.log(Level.WARNING, _sModule, sMethod, "Error in response from authsp: " + sResultCode);     
                _sessionManager.killSession(sRid);
                throw new ASelectException(sResultCode);
            }
            // The user was authenticated successfully, or sp_issuer was present
            if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
            	htSessionContext.put("result_code", sResultCode);  // must be used by the tgt issuer
				_sessionManager.updateSession(sRid, htSessionContext);
            }
			
			// Some AuthSP's will return the authenticated userid as well (e.g. DigiD)
			// If they do, we'll have to copy it to our own Context
            Hashtable htAdditional = new Hashtable();
			String sUid = (String)htResponse.get("uid");
			if (sUid != null) {  // Saml20 code
				htSessionContext.put("user_id", sUid);
				String sSecLevel = (String)htResponse.get("betrouwbaarheidsniveau");
				if (sSecLevel != null) htSessionContext.put("assigned_betrouwbaarheidsniveau", sSecLevel);
				_sessionManager.updateSession(sRid, htSessionContext);

				if (sSecLevel != null) htAdditional.put("betrouwbaarheidsniveau", sSecLevel);
				String sAssertUrl = (String)htSessionContext.get("sp_assert_url");
	            if (sAssertUrl != null) htAdditional.put("sp_assert_url", sAssertUrl);  // saml20 addition
				String sSPRid = (String)htSessionContext.get("sp_rid");
	            if (sAssertUrl != null) htAdditional.put("sp_rid", sSPRid);  // saml20 addition
			}

			// Bauke: transfer PKI attributes to the Context
            String sSubjectDN = (String)htResponse.get("pki_subject_dn");
			if (sSubjectDN != null) htAdditional.put("pki_subject_dn", sSubjectDN);
            String sIssuerDN = (String)htResponse.get("pki_issuer_dn");
			if (sIssuerDN != null) htAdditional.put("pki_issuer_dn", sIssuerDN);
            String sSubjectId = (String)htResponse.get("pki_subject_id");
			if (sSubjectId != null) htAdditional.put("pki_subject_id", sSubjectId);
            String sSmsPhone = (String)htResponse.get("sms_phone");
			if (sSmsPhone != null) htAdditional.put("sms_phone", sSmsPhone);
            
            TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
            String sOldTGT = (String)htServiceRequest.get("aselect_credentials_tgt");
			String sCred = (String)htServiceRequest.get("aselect_credentials");
			if (sCred != null) htAdditional.put("asp_credentials", sCred);
            tgtIssuer.issueTGT(sRid, sAsp, htAdditional, servletResponse, sOldTGT);
        }
        catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
    }
    
    /**
	 * Abort an authentication attempt and redirect the user back to the
	 * application. The application will receive the error code specified in the
	 * API call. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            Hashtable containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to the user
	 * @throws ASelectException
	 */
    private void handleError(Hashtable htServiceRequest,
        HttpServletResponse servletResponse)
    throws ASelectException
    {
        String sMethod = "handleError()";
        AuthenticationLogger authenticationLogger = 
            ASelectAuthenticationLogger.getHandle();

        try
        {
            // Get parameter "rid"
            String sRid = (String)htServiceRequest.get("rid");
            if (sRid == null)
            {
                _systemLogger.log(Level.WARNING, _sModule, sMethod, 
                    "Invalid request: parameter 'rid' is missing.");
                throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }

            // Get parameter "result_code"
            String sResultCode = (String)htServiceRequest.get("result_code");
            if (sResultCode == null) //result_code missing
            {
                _systemLogger.log(Level.WARNING, _sModule, sMethod, 
                "Invalid request: Parameter 'result_code' is missing.");
                throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            if (sResultCode.length() != 4) //result_code invalid
            {
                _systemLogger.log(Level.WARNING, _sModule, sMethod, 
                "Invalid request: Parameter 'result_code' is not valid.");
                throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            try
            {
                Integer.parseInt(sResultCode);
            }
            catch(NumberFormatException eNF) //result_code not a number
            {
                _systemLogger.log(Level.WARNING, _sModule, sMethod, 
                "Invalid request: Parameter 'result_code' is not a number.");
                throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }

            // Get session context
            Hashtable htSessionContext = _sessionManager.getSessionContext(sRid);
            if (htSessionContext == null)
            {
                _systemLogger.log(Level.WARNING, _sModule, sMethod, 
                "Invalid request: invalid or unknown session.");
                throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
            }

            // Log cancel request
            String sAppId = (String)htSessionContext.get("app_id");
            String sUserId = (String)htSessionContext.get("user_id");
            authenticationLogger.log(new Object[] {
                						"Login", 
                						sUserId,
                						(String)htServiceRequest.get("client_ip"),
                						_sMyOrg,
                						sAppId,
                						"denied",
                						sResultCode});

            // Issue TGT
            TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
            tgtIssuer.issueErrorTGT(sRid, sResultCode, servletResponse);
        }
        catch (ASelectException ae)
        {
          throw ae;
        }
        catch (Exception e)
        {
            _systemLogger
            .log(
                Level.WARNING,
                _sModule,
                sMethod,
                "Internal error.",
                e);
            
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }
}

