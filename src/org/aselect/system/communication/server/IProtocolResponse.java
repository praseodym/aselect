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
 * $Id: IProtocolResponse.java,v 1.3 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: IProtocolResponse.java,v $
 * Revision 1.3  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.2  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.1  2005/02/10 16:07:12  erwin
 * Refactor ProtocolResponse to IProtocolResponse.
 *
 *
 */
package org.aselect.system.communication.server;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Defines an interface to the response part of a protocol.
 * <br><br>
 * <b>Description:</b><br>
 * This interface contains methods to modify and add data and 
 * control information to the response. 
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public interface IProtocolResponse
{
    /**
     * Set a property of the response protocol.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Sets a property in the response. 
     * For e.g. HTTP these properties are headers like 
     * "Content-type" or the status code.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <ul>
     * 	<li><code>sName</code> must contain a valid property name.</li>
     * 	<li><code>sValue</code> must contain a valid property value.</li>
     * </ul>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * The response contains the new property.
     * <br>
     * @param sName the name of the property that has to be set.
     * @param sValue the value that has to be set.
     */
    public void setProperty(String sName, String sValue);

    /**
     * Return an output stream.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns an output stream, which can be used to write the data to.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * The returned <code>OutputStream</code> should be used once.
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @return <code>OutputStream</code> to which the response 
     * message can be send.
     * @throws IOException if <CODE>OutputStream</CODE> can't be 
     * retrieved from the protocol
     */
    public OutputStream getOutputStream() throws IOException;
}