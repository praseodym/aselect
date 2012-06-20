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
 * $Id: IInputMessage.java,v 1.3 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: IInputMessage.java,v $
 * Revision 1.3  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.2  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.1  2005/02/10 16:05:48  erwin
 * Refactor InputMessage to IInputmessage.
 *
 *
 */
package org.aselect.system.communication.server;

import org.aselect.system.exception.ASelectCommunicationException;


/**
 * Defines a interface to a input message which can be used with A-Select. <br>
 * <br>
 * <b>Description:</b><br>
 * An <code>IInputMessage</code> can be used as an interface to the internal messages of the
 * {@link IMessageCreatorInterface}. This interface is provided to access the communication in a transparent manner. <br>
 * <br>
 * The <code>IInputMessage</code> interface only specifies methods for retrieving information from the message. An input
 * message is normally created from an inputstream. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public interface IInputMessage
{
	
	/**
	 * Get a Parameter value from this message. <br>
	 * <br>
	 * getParam( <b>Description:</b> <br>
	 * Returns a parameter value from the message. The parameters are name/value pairs; the name of the value must be
	 * specified. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sName</code> must contain a valid parameter name. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sName
	 *            The name of the parameter to return.
	 * @return The value of the queried parameter.
	 * @throws ASelectCommunicationException
	 *             If parameter retrieving fails.
	 */
	public String getParam(String sName)
	throws ASelectCommunicationException;

	/**
	 * RequestHandler.processVerifyCredentialsRequest Get array Parameter values from this message. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns an array of values from the parameter with the given name. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sName</code> must contain a valid parameter name. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sName
	 *            The name of the parameter to return.
	 * @return An array of all values belonging to the queried parameter.
	 * @throws ASelectCommunicationException
	 *             If parameter retrieving fails.
	 */
	public String[] getArray(String sName)
	throws ASelectCommunicationException;
}