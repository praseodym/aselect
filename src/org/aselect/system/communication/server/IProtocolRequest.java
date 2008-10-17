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
 * $Id: IProtocolRequest.java,v 1.3 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: IProtocolRequest.java,v $
 * Revision 1.3  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.2  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.1  2005/02/10 16:06:53  erwin
 * Refactor ProtocolRequest to IProtocolRequest.
 *
 *
 */
package org.aselect.system.communication.server;

import java.io.IOException;
import java.io.InputStream;

/**
 * Defines an interface to the request part of a protocol.
 * <br><br>
 * <b>Description:</b><br>
 * This interface contains methods to access data and control 
 * information of the request. 
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public interface IProtocolRequest
{

    /**
     * Returns the full name of the protocol used.
     * e.g. SOAP 1.2 over HTTP. 
     * @return the full name of the protocol
     */
    public String getProtocolName();
    
    /**
     * Returns the full URL to which the request was issued. 
     * @return the full URL of the target of the request.
     */
    public String getTarget();
    
    /**
     * Returns an <code>String</code> which contains the request its data.
     * @return The request data as String.
     */
    public String getMessage();

    /**
     * Get a property of the underlying protocol.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns the property value with the given name. 
     * For e.g. HTTP these properties are headers like "content-type".
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <code>sName</code> must contain a valid parameter name.
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sName The property name.
     * @return The propery value.
     */
    public String getProperty(String sName);

    /**
     * get the request its data.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns an <code>InputStream</code>, which contains the request its data.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * The returned <code>InputStream</code> should not be shared.
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @return <code>InputStream</code> from which the incomming message can 
     * be retrieved.
     * @throws IOException if <CODE>InputStream</CODE> 
     * can't be retrieved from the protocol.
     */
    public InputStream getInputStream() throws IOException;
    
    
}