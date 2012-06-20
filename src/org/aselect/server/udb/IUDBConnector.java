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
 * $Id: IUDBConnector.java,v 1.4 2006/04/26 12:18:59 tom Exp $ 
 * 
 * Changelog:
 * $Log: IUDBConnector.java,v $
 * Revision 1.4  2006/04/26 12:18:59  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.3  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/04/29 11:39:00  erwin
 * Added isUserEnabled() and getUserAttributes()
 *
 * Revision 1.1  2005/02/28 09:26:07  martijn
 * changed all variable names to naming convention and added java documentation
 *
 */

package org.aselect.server.udb;

import java.util.HashMap;

import org.aselect.system.exception.ASelectUDBException;


/**
 * Interface to a A-Select UDB connector. <br>
 * <br>
 * <b>Description:</b><br>
 * Resolves a user profile by retrieving information from the user database. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public interface IUDBConnector
{
	
	/**
	 * Initializes the the IUDBConnector. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This usually entails:
	 * <ul>
	 * <li>Reading the configuration</li>
	 * <li>Openening a connection with a User Database.</li>
	 * <li>Testing the connection</li>
	 * </ul>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <i>oConfigSection</i> may not be <code>null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oConfigSection
	 *            containing the configuration section for this component
	 * @throws ASelectUDBException
	 *             if the component could not be initialized by missing config parameters or could not open a connection
	 */
	public void init(Object oConfigSection)
	throws ASelectUDBException;

	/**
	 * Returns the user profile stored in user database. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns a hashtable with the user's profile. The information returned is as follows: <br>
	 * <table border="1">
	 * <tr>
	 * <th><b>Item </b></th>
	 * <th><b>Value </b></th>
	 * </tr>
	 * <tr>
	 * <td><code>result_code</code></td>
	 * <td>Specifies an <code>Errors.NO_ERROR</code> for success or an relevant A-Select Error.</td>
	 * </tr>
	 * <tr>
	 * <td><code>user_authsps</code></td>
	 * <td>HashMap containing the AuthSP's that the user is registered for. <br>
	 * The hashtable contains an entry for each AuthSP and the value of the user attributes belonging to it.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <i>sUserId</i> may not be <code>null</code>. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sUserId
	 *            containing the user id by which the user is known in the user database
	 * @return a <code>HashMap</code> containing the user information (authsp information and result code)
	 */
	public HashMap getUserProfile(String sUserId);

	/**
	 * Check if the user is enabled for A-Select. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the value for A-Select enabled for the given user. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sUserId != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sUserId
	 *            the user to check.
	 * @return <code>true</code> if user is A-Select enabled, otherwise </code>false</code>.
	 * @throws ASelectUDBException
	 *             If retrieving information from UDB fails.
	 */
	public boolean isUserEnabled(String sUserId)
	throws ASelectUDBException;

	/**
	 * Retrieves the user attributes for the given user and AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Retrieves the user attributes for the given user and AuthSP. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>sUserId != null</code></li>
	 * <li><code>sAuthSPId != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sUserId
	 *            The user ID.
	 * @param sAuthSPId
	 *            The AuthSP ID
	 * @return The user attributes.
	 * @throws ASelectUDBException
	 *             If retrieving information from UDB fails.
	 */
	public String getUserAttributes(String sUserId, String sAuthSPId)
	throws ASelectUDBException;
}