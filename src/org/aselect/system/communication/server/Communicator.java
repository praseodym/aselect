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
 * $Id: Communicator.java,v 1.4 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: Communicator.java,v $
 * Revision 1.4  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/02/10 16:10:10  erwin
 * Applied code style and Javadoc comment.
 *
 *
 */

package org.aselect.system.communication.server;

import org.aselect.system.exception.ASelectCommunicationException;

/**
 * Defines a communicator which can be used with A-Select. <br>
 * <br>
 * <b>Description: </b> <br>
 * Defines a communicator which can be used with A-Select. An inputmessage is normally created from an inputstream.
 * Interfaces to {@link IInputMessage}and {@link IOutputMessage}can be obtained by the get methods. <br>
 * <br>
 * <i>Note: The Communicator is part of the "Builder" design pattern that is used in the design of the A-Select server
 * communication package. It can be seen as the director of this pattern. The init method can be seen as the construct
 * method of the director. The message creator is the actual abstract builder and the setParam() method can be seen as a
 * build part method of the Builder. To protect the functionality of the builder, the builder is divided into several
 * interfaces like IInputMessage, IOutputMessage, and IMessageCreatorInterface. </i> <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * The used <code>IMessageCreatorInterface</code> can be a non threadsafe implementation. <br>
 * <br>
 * It is recommended to use one <code>Communicator</code> per communication flow. <br>
 * 
 * @author Alfa & Ariss
 */
public class Communicator
{
	/** The used message creator. */
	private IMessageCreatorInterface _oCreator;

	/**
	 * Creates a new instance of Communicator. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a new instance of Communicator which uses a <code>IMessageCreatorInterface</code> implementation. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * <code>oCreator</code> should be used in <u>one </u> <code>Communicator</code>.<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>oCreator</code> must be an uninitialized <code>IMessageCreatorInterface</code> implementation which is only
	 * used in this instance. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The message creator is set with <code>oCreator</code>.<br>
	 * 
	 * @param oCreator
	 *            The creator to be used to create messages.
	 */
	public Communicator(IMessageCreatorInterface oCreator) {
		_oCreator = oCreator;
	}

	/**
	 * Initializes the Communicator. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Initializes the used <code>IMessageCreatorInterface</code> implementation.
	 * 
	 * @param oRequest
	 *            The request to create the input message from.
	 * @param oResponse
	 *            The response to write the output message to.
	 * @return true - if initialisation was succesfull <br>
	 *         False - if initialisation fails.
	 * @throws ASelectCommunicationException
	 *             If communication fails.
	 * @see IMessageCreatorInterface#init(IProtocolRequest, IProtocolResponse)
	 */
	public boolean init(IProtocolRequest oRequest, IProtocolResponse oResponse)
		throws ASelectCommunicationException
	{
		return _oCreator.init(oRequest, oResponse);
	}

	/**
	 * Get input message. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Get the input message that was created during initialization. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>IInputMessage</code> can be a non threadsafe implementation. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <code>Communicator</code> must be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @return an interface to the created input message.
	 */
	public IInputMessage getInputMessage()
	{
		return _oCreator;
	}

	/**
	 * Get output message. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Get the output message to add parameters. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The returned <code>IOutputMessage</code> can be a non threadsafe implementation. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <code>Communicator</code> must be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @return an interface to the output message.
	 */
	public IOutputMessage getOutputMessage()
	{
		return _oCreator;
	}

	/**
	 * Sends the output message. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Calls the <code>send</code> of the used <code>IMessageCreatorInterface</code> implementation.
	 * 
	 * @return true id sent succesfull.
	 * @throws ASelectCommunicationException
	 *             If communciation fails.
	 * @see IMessageCreatorInterface#send()
	 */
	public boolean send()
		throws ASelectCommunicationException
	{
		// call the send from the Message Creator
		return _oCreator.send();
	}
}