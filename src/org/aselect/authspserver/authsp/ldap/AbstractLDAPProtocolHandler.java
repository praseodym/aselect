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
 * $Id: AbstractLDAPProtocolHandler.java,v 1.8 2006/05/03 10:06:47 tom Exp $ 
 *
 * Changelog:
 * $Log: AbstractLDAPProtocolHandler.java,v $
 * Revision 1.8  2006/05/03 10:06:47  tom
 * Removed Javadoc version
 *
 * Revision 1.7  2006/04/12 13:29:35  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.6.2.1  2006/04/12 06:08:09  jeroen
 * Fix in full uid check. Now also the index is checked > -1.
 *
 * Revision 1.6  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.5  2005/04/29 11:36:25  martijn
 * added full_uid support
 *
 * Revision 1.4  2005/03/29 13:47:24  martijn
 * config item port has been removed from the config, now using ldap://www.test.com:port instead
 *
 * Revision 1.3  2005/03/23 09:48:38  erwin
 * - Applied code style
 * - Added javadoc
 * - Improved error handling
 *
 * Revision 1.2  2005/02/04 10:12:40  leon
 * code restyle and license added
 *
 */

package org.aselect.authspserver.authsp.ldap;

import java.util.logging.Level;

import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.exception.ASelectException;

// TODO: Auto-generated Javadoc
/**
 * This class contains base functionality for LDAP AuthSP handlers. <br>
 * <br>
 * <b>Description: </b> <br>
 * Contains base configuration and initialisation functionality. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public abstract class AbstractLDAPProtocolHandler implements ILDAPProtocolHandler
{
	/** The module name */
	protected String _sModule = "AbstractLDAPProtocolHandler";

	/** The LDAP URL. */
	protected String _sLDAPUrl;
	/** The JNDI driver. */
	protected String _sDriver;
	/** The base DN. */
	protected String _sBaseDn;
	/** The user DN. */
	protected String _sUserDn;
	/** The user ID. */
	protected String _sUid;
	/** The princial DN */
	protected String _sPrincipalDn;
	/** The principal password. */
	protected String _sPrincipalPwd;
	/** The complete user ID. */
	protected boolean _bFullUid;

	/**
	 * The logger that logs system information
	 */
	protected AuthSPSystemLogger _systemLogger;

	/**
	 * Set the configuration items and the system logger. <br>
	 * <br>
	 * 
	 * @param sLDAPUrl
	 *            the s ldap url
	 * @param sDriver
	 *            the s driver
	 * @param sBaseDn
	 *            the s base dn
	 * @param sUserDn
	 *            the s user dn
	 * @param bFullUid
	 *            the b full uid
	 * @param sUid
	 *            the s uid
	 * @param sPrincipalDn
	 *            the s principal dn
	 * @param sPrincipalPwd
	 *            the s principal pwd
	 * @param systemLogger
	 *            the system logger
	 * @return true, if inits the
	 * @see org.aselect.authspserver.authsp.ldap.ILDAPProtocolHandler#init(java.lang.String, java.lang.String,
	 *      java.lang.String, java.lang.String, boolean, java.lang.String, java.lang.String, java.lang.String,
	 *      org.aselect.authspserver.log.AuthSPSystemLogger)
	 */
	public boolean init(String sLDAPUrl, String sDriver, String sBaseDn, String sUserDn, boolean bFullUid, String sUid,
			String sPrincipalDn, String sPrincipalPwd, AuthSPSystemLogger systemLogger)
	{
		_systemLogger = systemLogger;

		_sLDAPUrl = sLDAPUrl;
		_sDriver = sDriver;
		_sBaseDn = sBaseDn;
		_sUserDn = sUserDn;
		_sUid = sUid;
		_sPrincipalDn = sPrincipalDn;
		_sPrincipalPwd = sPrincipalPwd;
		_bFullUid = bFullUid;
		return true;
	}

	/**
	 * Authenticate a user using LDAP. <br>
	 * 
	 * @param sPassword
	 *            the s password
	 * @return the string
	 * @see org.aselect.authspserver.authsp.ldap.ILDAPProtocolHandler#authenticate(java.lang.String)
	 */
	public String authenticate(String sPassword)
	{
		String sMethod = "authenticate()";
		String sErrorCode = null;

		if (!_bFullUid) {
			int iIndex = _sUid.indexOf('@');
			if (iIndex > 0)
				_sUid = _sUid.substring(0, iIndex);
		}

		try {
			doBind(sPassword);
			sErrorCode = Errors.ERROR_LDAP_SUCCESS;
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not authenticate");
			sErrorCode = eAS.getMessage();
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not authenticate due to internal error", e);
			sErrorCode = Errors.ERROR_LDAP_INTERNAL_ERROR;
		}
		return sErrorCode;
	}

	/**
	 * Bind to the LDAP server using the user credentials. <br>
	 * 
	 * @param sPassword
	 *            The user password.
	 * @throws ASelectException
	 *             If user could not be authenticated.
	 */
	abstract protected void doBind(String sPassword)
		throws ASelectException;

}