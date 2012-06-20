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
 * $Id: IOutputMessage.java,v 1.3 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: IOutputMessage.java,v $
 * Revision 1.3  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.2  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.1  2005/02/10 16:06:16  erwin
 * Refactor OutputMessage to IOutputmessage.
 *
 *
 */
package org.aselect.system.communication.server;

import org.aselect.system.exception.ASelectCommunicationException;

/**
 * Defines a interface to a output message which can be used with A-Select. <br>
 * <br>
 * <b>Description:</b><br>
 * Defines an interface to a message that can be used with A-Select. An output message can be created step-by-step and
 * finally sent. <br>
 * <br>
 * <code>OutputMessage</code> can be used as a interface to the internal messages of the
 * {@link IMessageCreatorInterface}. This interface is provided to access the communication in a transparent manner. <br>
 * <br>
 * The OuputMessage interface only specifies methods for setting information in the output message. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public interface IOutputMessage
{
	
	/**
	 * Sets a parameter in the message. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new paremeter in the output. If the parameter does not yet exsist it is created. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <ul>
	 * <li><code>sName</code> must contain a valid parameter name.</li>
	 * <li><code>sValue</code> must contain a valid parameter value.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The ouput message contains the new parameter. <br>
	 * 
	 * @param sName
	 *            The name of the parameter
	 * @param sValue
	 *            The value of the parameter
	 * @return true - if parameter succesfully set otherwise false.
	 * @throws ASelectCommunicationException
	 *             If communication fails.
	 */
	public boolean setParam(String sName, String sValue)
	throws ASelectCommunicationException;

	// 20090310, Bauke: Added to support applications using the DigiD protocol to connect to the server
	// That protocol does not URL encode it's parameters
	/**
	 * Sets the param.
	 * 
	 * @param sName
	 *            the s name
	 * @param sValue
	 *            the s value
	 * @param doUrlEncode
	 *            encode the URL?
	 * @return true, if successful
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 */
	public boolean setParam(String sName, String sValue, boolean doUrlEncode)
	throws ASelectCommunicationException;
	
	// 20110112, Bauke: Make URL encoding configurable (by application)	
	public boolean isDoUrlEncode();
	public void setDoUrlEncode(boolean doUrlEncode);

	/**
	 * Sets a array parameter in the message. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Set an array parameter with the given name and values. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <ul>
	 * <li><code>sName</code> must contain a valid parameter name.</li>
	 * <li><code>saValues</code> must contain valid array parameter values.</li>
	 * </ul>
	 * <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The ouput message contains the new array parameter. <br>
	 * 
	 * @param sName
	 *            The name of the parameter
	 * @param saValues
	 *            The values of the parameter
	 * @return true - if parameter successfully set otherwise false.
	 * @throws ASelectCommunicationException
	 *             If communication fails.
	 */
	public boolean setParam(String sName, String[] saValues)
	throws ASelectCommunicationException;

	/**
	 * Sends this message. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Sends the output message. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * A message can only send once. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * The message should at least be initialized. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The message is send. <br>
	 * 
	 * @return true if send successfully, otherwise false.
	 * @throws ASelectCommunicationException
	 *             If communication fails.
	 */
	public boolean send()
	throws ASelectCommunicationException;

}