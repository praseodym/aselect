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
 * $Id: IClientCommunicator.java,v 1.4 2006/05/03 09:29:19 tom Exp $ 
 * 
 * Changelog:
 * $Log: IClientCommunicator.java,v $
 * Revision 1.4  2006/05/03 09:29:19  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.1  2005/02/07 15:12:35  erwin
 * Renamed from ClientCommunicator.
 *
 * Revision 1.3  2005/02/01 16:28:21  erwin
 * Improved Javadoc comment
 *
 * Revision 1.2  2005/02/01 09:16:10  erwin
 * Improved code style. Added Javadoc comment.
 *
 */

package org.aselect.system.communication.client;

import java.util.HashMap;

import org.aselect.system.exception.ASelectCommunicationException;


/**
 * Interface for simple A-Select API communication. <br>
 * <br>
 * <b>Description: </b> <br>
 * Specifies a method for sending API calls to the A-Select server. <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - sendStringMessage() method added
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl)
 */
public interface IClientCommunicator
{
	
	/**
	 * Send an API call to the A-Select server. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a message from the given parameters and sends it to the given url. The response parameters are returned
	 * in a <code>hashtable</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * The returned {@link java.util.HashMap} is synchronized. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * <li><code>parameters</code> should contain valid A-Select parameters.</li>
	 * <li><code>target</code> must be a valid URL.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The <code>HashMap<code> which is returned contains A-Select response parameters.
	 * <br>
	 * 
	 * @param htParameters
	 *            The API call request parameters (<code>HashMap</code> with name/value pairs)
	 * @param sTarget
	 *            A <CODE>String</CODE> containing the target URL
	 * @return The response parameters of the API call in a <code>HashMap</code>
	 * @throws ASelectCommunicationException
	 *             If communication fails.
	 */
	public HashMap sendMessage(HashMap htParameters, String sTarget)
	throws ASelectCommunicationException;

	// Bauke: Added
	/**
	 * Send string message.
	 * 
	 * @param sParameters
	 *            the s parameters
	 * @param sTarget
	 *            the s target
	 * @return the string
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 */
	public String sendStringMessage(String sParameters, String sTarget)
	throws ASelectCommunicationException;
}