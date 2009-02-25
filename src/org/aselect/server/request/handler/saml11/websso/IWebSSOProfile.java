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
 * $Id: IWebSSOProfile.java,v 1.4 2006/05/03 10:11:08 tom Exp $ 
 */
package org.aselect.server.request.handler.saml11.websso;

import java.util.HashMap;

import javax.servlet.http.HttpServletResponse;

import org.aselect.system.exception.ASelectException;

/**
 * Interface for SAML 1.1 websso profile reponse handlers.
 * <br><br>
 * <b>Description:</b><br>
 * Interface that describes the methods that a WebSSO Profile response handler 
 * class must implement
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public interface IWebSSOProfile
{
    /**
     * Initializes the profile handler.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Reads configuration and sets class variables to a default value
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
     * @param oConfig object containing the configuration used by the A-Select 
     * ConfigManager
     * @param lAssertionExpireTime the configured assertion expire time
     * @param sAttributeNamespace the configured attribute namespace that will 
     * be used for creating attributes
     * @param bSendAttributeStatement TRUE if the Attribute Statement must be 
     * send direclty
     * @throws ASelectException if initialization fails
     */
    public void init(Object oConfig, long lAssertionExpireTime
        , String sAttributeNamespace, boolean bSendAttributeStatement) 
    throws ASelectException;
    
    /**
     * processes a request and sends a websso response.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Sends a SAML 1.1 WebSSO response
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
     * @param htInfo containing the A-Select verify_credentials response items
     * @param response the HttpServletResponse were to the SAML response will be 
     * sent
     * @param sIP the client IP address
     * @param sHost the host representation of the clients IP address
     * @throws ASelectException if processing fails
     */
    public void process(HashMap htInfo, HttpServletResponse response
        , String sIP, String sHost) throws ASelectException;
    
    /**
     * Removes class variables from memory.
     * <br><br>
     */
    public void destroy();
    
    /**
     * Returns the value of the configured id parameter in the profile section.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * The ID must be unique.
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
     * @return String containing the profile class id
     */
    public String getID();
}
