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
 * $Id: LDAPSimpleProtocolHandler.java,v 1.10 2006/05/03 10:06:47 tom Exp $ 
 *
 * Changelog:
 * $Log: LDAPSimpleProtocolHandler.java,v $
 * Revision 1.10  2006/05/03 10:06:47  tom
 * Removed Javadoc version
 *
 * Revision 1.9  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.8  2005/04/29 11:38:47  martijn
 * fixed bugs in logging
 *
 * Revision 1.7  2005/03/29 13:47:24  martijn
 * config item port has been removed from the config, now using ldap://www.test.com:port instead
 *
 * Revision 1.6  2005/03/24 09:56:30  erwin
 * Fixed numberformat exception and problem with error handling
 *
 * Revision 1.5  2005/03/23 09:48:38  erwin
 * - Applied code style
 * - Added javadoc
 * - Improved error handling
 *
 * Revision 1.4  2005/03/14 12:15:17  martijn
 *
 * Revision 1.3  2005/02/04 10:12:40  leon
 * code restyle and license added
 *
 */
package org.aselect.authspserver.authsp.ldap;

import java.util.Hashtable;
import java.util.logging.Level;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.NoPermissionException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.aselect.system.exception.ASelectException;

/**
 * A basic LDAP protocol handler. <br>
 * <br>
 * <b>Description:</b><br>
 * Authenticates a user by binding to a LDAP server using the users credentials. The
 * <code>LDAPSimpleProtocolHandler</code> does not support SSL. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class LDAPSimpleProtocolHandler extends AbstractLDAPProtocolHandler
{	
	// Set the module name.
	public LDAPSimpleProtocolHandler()
	{
		_sModule = "LDAPSimpleProtocolHandler";
	}

	/**
	 * Tries to bind to the LDAP server using the users credentials. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * If no principal DN is known a simple binding is done, otherwise a subtree search. In this case the following
	 * steps are executed:
	 * <ol>
	 * <li>Bind to LDAP using security principal its DN & PWD</li>
	 * <li>Search for user its DN relative to base DN</li>
	 * <li>Bind using user credentials</li>
	 * </ol>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sPassword != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sPassword
	 *            the password
	 * @throws ASelectException
	 *             the aselect exception
	 * @see org.aselect.authspserver.authsp.ldap.AbstractLDAPProtocolHandler#doBind(java.lang.String)
	 */
	@Override
	protected void doBind(String sPassword)
	throws ASelectException
	{
		String sMethod = "doBind()";
		StringBuffer sbTemp = null;
		DirContext oDirContext = null;
		String sQuery = null;
		String sRelUserDn = null;
		NamingEnumeration enumSearchResults = null;

		Hashtable htEnvironment = new Hashtable();

		if (_sPrincipalDn.equals("")) {
			// If no principal DN is known, we do a simple binding
			htEnvironment.put(Context.PROVIDER_URL, _sLDAPUrl);
			htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver);
			htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");

			sbTemp = new StringBuffer(_sUserDn).append("=").append(_sUid);
			sbTemp.append(", ").append(_sBaseDn);
			htEnvironment.put(Context.SECURITY_PRINCIPAL, sbTemp.toString());
			htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);

			_systemLogger.log(Level.INFO, _sModule, sMethod, "BIND " + _sLDAPUrl + "_" + _sDriver + "_" + "simple1"
					+ "_" + sbTemp.toString());
			try {
				/////////////////////////////////////////////////////////////////////
				oDirContext = new InitialDirContext(htEnvironment);
			}
			catch (AuthenticationException e) {
				/*
				 * This exception is thrown when an authentication error occurs while accessing the naming or directory
				 * service. An authentication error can happen, for example, when the credentials supplied by the user
				 * program is invalid or otherwise fails to authenticate the user to the naming/directory service.
				 */
				StringBuffer sbFine = new StringBuffer("Could not authenticate user (invalid password): ");
				sbFine.append(_sUid);
				_systemLogger.log(Level.FINE, _sModule, sMethod, sbFine.toString());
				throw new ASelectException(Errors.ERROR_LDAP_INVALID_PASSWORD);
			}
			catch (CommunicationException eC) {
				/*
				 * This exception is thrown when the client is unable to communicate with the directory or naming
				 * service. The inability to communicate with the service might be a result of many factors, such as
				 * network partitioning, hardware or interface problems, failures on either the client or server side.
				 * This exception is meant to be used to capture such communication problems.
				 */
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "A communication error has occured", eC);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER, eC);
			}
			catch (NamingException eN) {
				// The initial directory context could not be created.
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "A naming error has occured", eN);
				throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR, eN);
			}

			try {
				oDirContext.close();
			}
			catch (Exception e) {
				sbTemp = new StringBuffer("Could not close connection to '");
				sbTemp.append(_sLDAPUrl);
				sbTemp.append("'");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), e);
			}
		}
		else { // otherwise we do a subtree search
			// Step 1: bind to LDAP using security principal's DN & PWD
			htEnvironment.put(Context.PROVIDER_URL, _sLDAPUrl);
			htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver); // USED TO BE: _sLDAPUrl);
			htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
			htEnvironment.put(Context.SECURITY_PRINCIPAL, _sPrincipalDn);
			htEnvironment.put(Context.SECURITY_CREDENTIALS, _sPrincipalPwd);

			_systemLogger.log(Level.INFO, _sModule, sMethod, "BIND " + _sLDAPUrl + "_" + _sDriver + "_" + "simple2"
					+ "_" + _sPrincipalDn + "_" + _sPrincipalPwd);
			try {
				oDirContext = new InitialDirContext(htEnvironment);
			}
			catch (AuthenticationException eA) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not bind to LDAP server", eA);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, eA);
			}
			catch (CommunicationException eC) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "An communication error has occured", eC);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER, eC);
			}
			catch (NamingException eN) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "An naming error has occured", eN);
				throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR, eN);
			}

			// DirContext creation using the principal DN succeeded
			// Step 2: search for user's DN relative to base DN
			sbTemp = new StringBuffer("(").append(_sUserDn).append("=").append(_sUid).append(")");
			sQuery = sbTemp.toString();

			SearchControls oScope = new SearchControls();
			oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);

			_systemLogger.log(Level.INFO, _sModule, sMethod, "SRCH " + _sBaseDn + "_" + sQuery + "_sub");
			try {
				enumSearchResults = oDirContext.search(_sBaseDn, sQuery, oScope);
			}
			catch (NamingException eN) {
				sbTemp = new StringBuffer("User '");
				sbTemp.append(_sUid);
				sbTemp.append("' is unknown");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eN);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
			}
			finally {
				try {
					if (oDirContext != null) {
						oDirContext.close();
						oDirContext = null;
					}
				}
				catch (Exception e) {
					sbTemp = new StringBuffer("Could not close connection with '");
					sbTemp.append(_sLDAPUrl);
					sbTemp.append("'");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), e);
				}
			}

			try {
				// Check if we got a result
				if (!enumSearchResults.hasMore()) {
					sbTemp = new StringBuffer("User '").append(_sUid);
					sbTemp.append("' not found during LDAP search. The filter was: '");
					sbTemp.append(sQuery).append("'.");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString());
					throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
				}

				SearchResult searchResult = (SearchResult) enumSearchResults.next();
				sRelUserDn = searchResult.getName();
				enumSearchResults.close();
				if (sRelUserDn == null) {
					sbTemp = new StringBuffer("No user DN was returned for '");
					sbTemp.append(_sUid).append("'.");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString());
					throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
				}
			}
			catch (NamingException eN) {
				sbTemp = new StringBuffer("failed to fetch profile of user '");
				sbTemp.append(_sUid);
				sbTemp.append("'");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eN);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
			}

			// Step 3: Bind using user's credentials
			sbTemp = new StringBuffer(sRelUserDn).append(",").append(_sBaseDn);

			htEnvironment = new Hashtable();
			htEnvironment.put(Context.PROVIDER_URL, _sLDAPUrl);
			htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver);
			htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
			htEnvironment.put(Context.SECURITY_PRINCIPAL, sbTemp.toString());
			htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);

			_systemLogger.log(Level.INFO, _sModule, sMethod, "USR_BIND " + _sLDAPUrl + "_" + _sDriver +
					"_" + "simple3"	+ "_" + sbTemp.toString());
			try {
				oDirContext = new InitialDirContext(htEnvironment);
				Attributes attr = oDirContext.getAttributes(sbTemp.toString());
				// Check for selfBlockedTime
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Attributes="+attr);
			}
			catch (NoPermissionException eP) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "No permission: expl=" + eP.getExplanation(), eP);
				throw new ASelectException(Errors.ERROR_LDAP_INVALID_PASSWORD, eP);
			}
			catch (AuthenticationException e) {
				StringBuffer sbFine = new StringBuffer("Could not authenticate user (invalid password): ").append(_sUid)
					.append(" expl="+e.getExplanation()).append(" cause="+e.getCause());
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbFine.toString());
				throw new ASelectException(Errors.ERROR_LDAP_INVALID_PASSWORD);
			}
			catch (CommunicationException eC) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "A communication error has occured: expl="+eC.getExplanation(), eC);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER, eC);
			}
			catch (NamingException eN) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "A naming error has occured: expl=" + eN.getExplanation(), eN);
				throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR, eN);
			}

			try {
				oDirContext.close();
			}
			catch (Exception e) {
				sbTemp = new StringBuffer("Could not close connection to '");
				sbTemp.append(_sLDAPUrl).append("'");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), e);
			}
		}
		//
	}
}
