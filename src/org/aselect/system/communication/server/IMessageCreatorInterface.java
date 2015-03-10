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
 * $Id: IMessageCreatorInterface.java,v 1.3 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: IMessageCreatorInterface.java,v $
 * Revision 1.3  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.2  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.1  2005/02/10 16:09:13  erwin
 * Refactor MessageCreatorInterface to IMessageCreatorInterface
 *
 *
 */

package org.aselect.system.communication.server;

import org.aselect.system.exception.ASelectCommunicationException;

/**
 * Defines a common interface for a message creator. <br>
 * <br>
 * <b>Description: </b> <br>
 * The <code>IMessageCreatorInterface</code> is used to provide a bridge between implementation and interface. This
 * interface can be implemented for several protocols (e.g. SOAP) and can be used in a {@link Communicator}. <br>
 * <br>
 * For every protocol a new Creator must be created which implements this interface. The IMessageCreatorInterface
 * supplies only a method for initialisation <br>
 * <br>
 * The request is used to create an input message object. The response is used to create an output message with
 * corresponding properties (HTTP Headers) that can be sent back to the requester. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * Some implementations of the <code>IMessageCreatorInterface</code> can use none thread safe internal representations. <br>
 * 
 * @author Alfa & Ariss
 */
public interface IMessageCreatorInterface extends IInputMessage, IOutputMessage
{
	
	/**
	 * Initializes the message creator. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Specifies a common method for initializing a <code>IMessageCreatorInterface</code> implementation.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * Make sure <code>init()</code> is called once in the process. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li>oRequest must be a valid <code>IProtocolRequest</code></li>
	 * <li>oResponse must be a valid <code>IProtocolResponse</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b>
	 * <ul>
	 * <li>The <code>IMessageCreatorInterface</code> is succesfully initialized.</li>
	 * <li>The request data is succesfuly parsed to an input message.</li>
	 * </ul>
	 * 
	 * @param oRequest
	 *            The request to create an input message from.
	 * @param oResponse
	 *            The response to write the output message to.
	 * @return true - if initialization was succesfull.<br>
	 *         false - if initialization fails.
	 * @throws ASelectCommunicationException
	 *             if communication fails.
	 */
	public boolean soapInit(IProtocolRequest oRequest, IProtocolResponse oResponse)
	throws ASelectCommunicationException;

}