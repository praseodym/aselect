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
 * $Id: IAuthSPProtocolHandler.java,v 1.4 2006/04/26 12:16:36 tom Exp $ 
 * 
 * Changelog:
 * $Log: IAuthSPProtocolHandler.java,v $
 * Revision 1.4  2006/04/26 12:16:36  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.3  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/03/10 10:10:52  erwin
 * Improved Javadoc
 *
 * Revision 1.1  2005/03/04 12:52:55  peter
 * renamed
 * naming convention, javadoc, code style
 *
 */

package org.aselect.server.authspprotocol;

import java.util.Hashtable;

import org.aselect.system.exception.ASelectAuthSPException;

/**
 * Interface that all AuthSP protocol handlers should implement.
 * <br><br>
 * <b>Description:</b><br>
 * Interface that all AuthSP protocol handlers should implement.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 *  
 */
public interface IAuthSPProtocolHandler
{
    /**
     * Initializes the AuthSP protocol handler.
     * <br>
     * <b>Description: </b> <br>
     * Initializes the AuthSP protocol handler with authsp handler specific
     * configuration and resources.
     * <br><br>
     * <b>Concurrency issues: </b> <br>
     * -
     * <br>
     * <b>Preconditions: </b> <br>
     * -
     * <br>
     * <b>Postconditions: </b> <br>
     * -
     * 
     * @param oAuthSPConfig
     * 			<code>Object</code> containing the authsp specific configuration.
     * @param oAuthSPResource
     * 			<code>Object</code> containing the authsp specific resource(s).
     * @throws ASelectAuthSPException
     * 			If initialization fails.
     */
    public void init(Object oAuthSPConfig, Object oAuthSPResource)
        throws ASelectAuthSPException;

    /**
     * Creation of an AuthSP specific redirect URL.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * The AuthSP handler should compute a redirect URL. In the response
     * hashtable the AuthSP handler shall place "result" to indicate the
     * processing result and "redirect_url" if everything is ok.
     * The <code>ASelectLoginHandler</code> will redirect the user to 
     * this URL.<br>
     * The created URL should contain AuthSP specific parameters.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sRid
     * 			Needed parameter in the redirect URL. Can also be used
     * to retrieve session information from the <code>SessionManager</code>.
     * @return <code>Hashtable</code> containing at least:
     * <ul>
     * 	<li><code>result</code></li>
     * 	<li><code>redirect_url</code></li>
     * </ul>
     */
    public Hashtable computeAuthenticationRequest(String sRid);
    
    /**
     * Verification of an AuthSP specific response.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * AuthSP redirects user back to <code>ASelectServer</code>
     * which will parse the response parameters in a <code>
     * Hashtable</code> to this function.
     * The AuthSP handler should verify the AuthSP specific parameters.
     * <br><br>
     * The AuthSP handler should verify the response from an AuthSP In the
     * response hashtable the AuthSP handler shall place "result" to indicate
     * the processing result and "rid" of the request if everything is ok
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param htResponse
     * 			<code>Hashtable</code> containing all parameters that were
     * 			received from the AuthSP. It should contain at least:
     * <ul>
     * <li><code>rid</code>
     * </ul>
     * @return <code>Hashtable</code> containing at least:
     * <ul>
     * <li><code>result</code>
     * <li><code>rid</code>
     * </ul>
     */
    public Hashtable verifyAuthenticationResponse(Hashtable htResponse);
}