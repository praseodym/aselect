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
 * $Id: ILDAPProtocolHandler.java,v 1.5 2006/05/03 10:06:47 tom Exp $ 
 *
 * Changelog:
 * $Log: ILDAPProtocolHandler.java,v $
 * Revision 1.5  2006/05/03 10:06:47  tom
 * Removed Javadoc version
 *
 * Revision 1.4  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/04/29 11:36:47  martijn
 * added full_uid support
 *
 * Revision 1.2  2005/03/29 13:47:24  martijn
 * config item port has been removed from the config, now using ldap://www.test.com:port instead
 *
 * Revision 1.1  2005/03/23 09:48:38  erwin
 * - Applied code style
 * - Added javadoc
 * - Improved error handling
 *
 *
 */

package org.aselect.authspserver.authsp.ldap;

import org.aselect.authspserver.log.AuthSPSystemLogger;


/**
 * Interface for a LDAP protocol handler. <br>
 * <br>
 * <b>Description: </b> <br>
 * Specifies methods which LDAP protocol handlers should implement. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public interface ILDAPProtocolHandler
{

	/**
	 * Initialize the <code>ILDAPProtocolHandler</code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The implementation of this method should perform all one-time functionality of the
	 * <code>ILDAPProtocolHandler</code>. e.g. Retrieving handles to important managers and reading basic configuration. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The <code>ILDAPProtocolHandler</code> is ready to authenticate.
	 * 
	 * @param sLDAPSUrl
	 *            The URl to the LDAP back-end.
	 * @param sDriver
	 *            The JNDI driver.
	 * @param sBaseDn
	 *            The Base DN.
	 * @param sUserDn
	 *            The user DN.
	 * @param bFullUid
	 *            True if the full uid must be sent to the backend
	 * @param sUid
	 *            The LDAP user name.
	 * @param sPrincipalDn
	 *            the principal DN.
	 * @param sPrincipalPwd
	 *            The principal password.
	 * @param systemLogger
	 *            The logger for system entries.
	 * @return true if initialisation is successful, otherwise false.
	 */
	public boolean init(String sLDAPSUrl, String sDriver, String sBaseDn, String sUserDn, boolean bFullUid,
			String sUid, String sPrincipalDn, String sPrincipalPwd, String sAttrAllowedLogins, String sAttrValidUntil, AuthSPSystemLogger systemLogger);

	/**
	 * Authenticate a user with LDAP. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Authenticate an user with a LDAP back-end.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <code>ILDAPProtocolHandler</code> must be initialised. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param sPassword
	 *            the password to validate.
	 * @return The authentication result code (as specified in {@link Errors}).
	 */
	public String authenticate(String sPassword);
}