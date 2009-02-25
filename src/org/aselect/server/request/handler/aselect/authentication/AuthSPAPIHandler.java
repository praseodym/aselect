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
 * $Id: AuthSPAPIHandler.java,v 1.2 2006/05/03 10:10:18 tom Exp $
 * 
 * Changelog: 
 * $Log: AuthSPAPIHandler.java,v $
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
 * Revision 1.8  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/09/07 13:35:55  erwin
 * Removed the URL.decode usage in the handleKillSessionRequest() method. (bug #95)
 *
 * Revision 1.6  2005/05/20 13:08:32  erwin
 * Fixed some minor bugs in Javadoc
 *
 * Revision 1.5  2005/05/02 14:15:12  peter
 * code-style
 *
 * Revision 1.4  2005/04/15 11:51:23  tom
 * Removed old logging statements
 *
 * Revision 1.3  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.2  2005/03/15 16:06:01  erwin
 * Moved redundant code to seperate methods and AbstractAPIRequestHandler.
 *
 * Revision 1.1  2005/03/15 08:21:52  tom
 * - Redesign of request handling
 *
 *
*/

package org.aselect.server.request.handler.aselect.authentication;

import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.session.SessionManager;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.communication.server.IOutputMessage;
import org.aselect.system.communication.server.IProtocolRequest;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;

/**
 * This class handles authentication responses and API calls
 * originating from an authsp. It must be used as follows:
 * <br>
 * For each new incoming request, create a new 
 * <code>AuthSPRequestHandler</code> object and call its
 * <code>handleRequest()</code> method.
 * <code>AuthSPRequestHandler</code> objects cannot be reused
 * due to concurrency issues. 
 * 
 * @author Alfa & Ariss
 * 
 * 
 */
public class AuthSPAPIHandler extends AbstractAPIRequestHandler
{

    private SessionManager _sessionManager;
    
    /**
     * Create new instance.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Calls {@link AbstractAPIRequestHandler#AbstractAPIRequestHandler(
     * RequestParser, HttpServletRequest, HttpServletResponse, String, String)}
     * and handles are obtained to relevant managers.
     * <br><br>
     * @param reqParser The request parser to be used.
     * @param servletRequest The request.
     * @param servletResponse The response.
     * @param sMyServerId The A-Select Server ID.
     * @param sMyOrg The A-Select Server organisation.
     * @throws ASelectCommunicationException If communication fails.
     */
    public AuthSPAPIHandler (RequestParser reqParser, 
		HttpServletRequest servletRequest, 
		HttpServletResponse servletResponse,
		String sMyServerId, 
		String sMyOrg)
    	throws ASelectCommunicationException
    {
        super(reqParser, servletRequest, servletResponse, sMyServerId, sMyOrg);
        _sModule = "AuthSPAPIHandler";
        _sessionManager = SessionManager.getHandle();   	        
    }
        
    /**
     * Start processing a request coming from an authsp.
     * <br><br>
     * @see org.aselect.server.request.handler.aselect.authentication.AbstractAPIRequestHandler#processAPIRequest(
     * 	org.aselect.system.communication.server.IProtocolRequest, 
     * 	org.aselect.system.communication.server.IInputMessage, 
     * 	org.aselect.system.communication.server.IOutputMessage)
     */
    public void processAPIRequest(
        IProtocolRequest oProtocolRequest, 
        IInputMessage oInputMessage, 
        IOutputMessage oOutputMessage) throws ASelectException
    {
        String sMethod = "processAPIRequest()";

        String sAPIRequest = null;
        try
        {
            sAPIRequest = oInputMessage.getParam("request");
        }
        catch(ASelectCommunicationException eAC)
        {
            _systemLogger.log(Level.WARNING, 
                _sModule, sMethod, "Unsupported API call",eAC);
            throw new ASelectCommunicationException(
                Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
        }  
        
        if (sAPIRequest.equals("kill_session"))
        {
            handleKillSessionRequest(oInputMessage, oOutputMessage);            
        }
        else
        {
            _systemLogger.log(Level.WARNING, _sModule, sMethod,
                "Unsupported API Call: " + sAPIRequest);
            
            throw new ASelectCommunicationException(
                Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
        }
    }

    /**
     * This function handles the <code>request=kill_session</code> call.
     * <br>
     * @param oInputMessage The input message.
     * @param oOutputMessage The output message.
     * @throws ASelectCommunicationException If proccessing fails.
     */
    private void handleKillSessionRequest(IInputMessage oInputMessage, 
		IOutputMessage oOutputMessage) throws ASelectCommunicationException
    {
        String sSessionId = null;
        String sSignature = null;
        String sAuthSP = null;
        HashMap htSessionContext;
        String sMethod = "handleKillSessionRequest()";

        try
        {
            sSessionId = oInputMessage.getParam("rid");
            sSignature = oInputMessage.getParam("signature");
            sAuthSP = oInputMessage.getParam("authsp");
        }
        catch(ASelectCommunicationException eAC)
        {
            _systemLogger.log(Level.WARNING, 
                						_sModule,
                						sMethod,
                						"Missing required parameters");            
            throw new ASelectCommunicationException(
                Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST, eAC);
        }

        if( !CryptoEngine.getHandle().verifySignature(sAuthSP,sSessionId, sSignature))
        {
            _systemLogger.log(Level.WARNING, 
				_sModule, sMethod, "AuthSP:" + sAuthSP+ " Invalid signature:"+sSignature);

            throw new ASelectCommunicationException(
                		Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
        }

        // check if session exists
        htSessionContext = _sessionManager.getSessionContext(sSessionId);
        if (htSessionContext == null)
        {
            _systemLogger.log(Level.WARNING, 
										_sModule,
										sMethod,
										"Invalid session: " + sSessionId);

            throw new ASelectCommunicationException(
                		Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
        }

        htSessionContext = null;
        _sessionManager.killSession(sSessionId);

        try
        {
            oOutputMessage.setParam("rid",sSessionId);
            oOutputMessage.setParam("result_code",Errors.ERROR_ASELECT_SUCCESS);
        }
        catch(ASelectCommunicationException eAC)
        {
            _systemLogger.log(Level.WARNING, _sModule, sMethod, 
                "Could not set response parameter",eAC);
            throw new ASelectCommunicationException(
                Errors.ERROR_ASELECT_INTERNAL_ERROR,eAC);
        }
    }
}
