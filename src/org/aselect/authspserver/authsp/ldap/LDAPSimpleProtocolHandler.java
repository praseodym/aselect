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
package org.aselect.authspserver.authsp.ldap;

import java.util.Date;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.NoPermissionException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

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
		//_systemLogger.log(Level.FINE, _sModule, "creator", "simple");
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
		String sMethod = "doBind";
		StringBuffer sbTemp = null;
		DirContext oDirContext = null, oPrincipalContext = null;
		String sQuery = null;
		String sRelUserDn = null;
		NamingEnumeration<SearchResult> enumSearchResults = null;
		Hashtable<String, String> htEnvironment = new Hashtable<String, String>();

		if (_sPrincipalDn.equals("")) {
			// If no principal DN is known, we do a simple binding
			htEnvironment.put(Context.PROVIDER_URL, _sLDAPUrl);
			htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver);
			htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");

			sbTemp = new StringBuffer(_sUserDn).append("=").append(_sUid);
			sbTemp.append(", ").append(_sBaseDn);
			htEnvironment.put(Context.SECURITY_PRINCIPAL, sbTemp.toString());
			htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);
			additionalSettings(htEnvironment);

			_systemLogger.log(Level.INFO, _sModule, sMethod, "USR_BIND " + _sLDAPUrl + "_" + _sDriver + "_" + "simple1"
					+ "_" + sbTemp.toString());
			try {
				oDirContext = new InitialDirContext(htEnvironment);
				// NOTE: the user may not have permissions to upd/del his own account
				// So, just forget it: checkAllowedLogins(sbTemp.toString(), oDirContext);
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
				 * The root cause can contain additional SSL error information.
				 */
				Throwable tRoot = eC.getRootCause();
				if (tRoot == null) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "A communication error has occurred", eC);
				}
				else {
					sbTemp = new StringBuffer("A communication error has occurred, root cause: \"");
					sbTemp.append(tRoot.getMessage()).append("\"");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eC);
				}
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER, eC);
			}
			catch (NamingException eN) {
				// The initial directory context could not be created.
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "A naming error has occurred", eN);
				throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR, eN);
			}
			finally {
				try {
					if (oDirContext != null)
						oDirContext.close();
				}
				catch (Exception e) {
					sbTemp = new StringBuffer("Could not close connection to '").append(_sLDAPUrl).append("'");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), e);
				}
			}
			return;
		}

		oDirContext = null;  // just to make sure
		try {
			// Otherwise we do a subtree search using the principal dn
			// Step 1: bind to LDAP using security principal's DN & PWD
			htEnvironment.put(Context.PROVIDER_URL, _sLDAPUrl);
			htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver); // USED TO BE: _sLDAPUrl);
			htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
			htEnvironment.put(Context.SECURITY_PRINCIPAL, _sPrincipalDn);
			htEnvironment.put(Context.SECURITY_CREDENTIALS, _sPrincipalPwd);
			additionalSettings(htEnvironment);
	
			_systemLogger.log(Level.INFO, _sModule, sMethod, "PRINCP_BIND " + _sLDAPUrl + "_" + _sDriver + "_" + "simple2"
					+ "_" + _sPrincipalDn + "_" + _sPrincipalPwd);
			try {
				oPrincipalContext = new InitialDirContext(htEnvironment);
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Principal login OK");
			}
			catch (AuthenticationException eA) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not bind to LDAP server", eA);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, eA);
			}
			catch (CommunicationException eC) {
				Throwable tRoot = eC.getRootCause();
				if (tRoot == null) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "A communication error has occurred", eC);
				}
				else {
					sbTemp = new StringBuffer("A communication error has occurred, root cause: \"");
					sbTemp.append(tRoot.getMessage()).append("\"");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eC);
				}
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER, eC);
			}
			catch (NamingException eN) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "An naming error has occurred", eN);
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
				enumSearchResults = oPrincipalContext.search(_sBaseDn, sQuery, oScope);
			}
			catch (NamingException eN) {
				sbTemp = new StringBuffer("User '").append(_sUid).append("' is unknown");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eN);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
			}
	
			try {  // Check if we got a result
				if (!enumSearchResults.hasMore()) {
					sbTemp = new StringBuffer("User '").append(_sUid);
					sbTemp.append("' not found during LDAP search. The filter was: '").append(sQuery).append("'.");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString());
					throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
				}
	
				SearchResult oSearchResult = (SearchResult) enumSearchResults.next();
				sRelUserDn = oSearchResult.getName();
				// prevent memory leaks in shaky LDAP implementations(154)
				enumSearchResults.close();
				if (sRelUserDn == null) {
					sbTemp = new StringBuffer("No user DN was returned for '").append(_sUid).append("'.");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString());
					throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
				}
			}
			catch (NamingException eN) {
				sbTemp = new StringBuffer("failed to fetch profile of user '").append(_sUid).append("'");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eN);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
			}
	
			// Step 3: Bind using the user's credentials
			sbTemp = new StringBuffer(sRelUserDn).append(",").append(_sBaseDn);
			htEnvironment = new Hashtable<String, String>();
			htEnvironment.put(Context.PROVIDER_URL, _sLDAPUrl);
			htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver);
			htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
			htEnvironment.put(Context.SECURITY_PRINCIPAL, sbTemp.toString());
			htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);
			additionalSettings(htEnvironment);
	
			_systemLogger.log(Level.INFO, _sModule, sMethod, "USR_BIND " + _sLDAPUrl + "_" + _sDriver +
					"_" + "simple3"	+ "_" + sbTemp.toString());
			try {
				oDirContext = new InitialDirContext(htEnvironment);
				// User login succeeded
				_systemLogger.log(Level.INFO, _sModule, sMethod, "User login OK");
				// The user may not have permissions to upd/del account, therefore use the Principal account
				int rc = checkAllowedLogins(sbTemp.toString(), oPrincipalContext);
				if (rc != 0) {
					_systemLogger.log(Level.INFO, _sModule, sMethod, "Account not OK, either no logins left, or login no longer valid");
					throw new ASelectException(Errors.ERROR_LDAP_INVALID_PASSWORD);
				}
			}
			catch (NoPermissionException eP) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "No permission: expl=" + eP.getExplanation(), eP);
				throw new ASelectException(Errors.ERROR_LDAP_INVALID_PASSWORD, eP);
			}
			catch (AuthenticationException e) {
				StringBuffer sbFine = new StringBuffer("Could not authenticate user (invalid password): ").append(_sUid)
									.append(" expl="+e.getExplanation()).append(" cause="+e.getCause());
				_systemLogger.log(Level.INFO, _sModule, sMethod, sbFine.toString());
				throw new ASelectException(Errors.ERROR_LDAP_INVALID_PASSWORD);
			}
			catch (CommunicationException eC) {
				Throwable tRoot = eC.getRootCause();
				if (tRoot == null) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "A communication error has occurred", eC);
				}
				else {
					sbTemp = new StringBuffer("A communication error has occurred, root cause: '");
					sbTemp.append(tRoot.getMessage()).append("'");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eC);
				}
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER, eC);
			}
			catch (NamingException eN) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "A naming error has occurred: expl=" + eN.getExplanation(), eN);
				throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR, eN);
			}
		}
		finally {
			try {
				if (oDirContext != null) oDirContext.close();
			}
			catch (Exception e) {
				sbTemp = new StringBuffer("Could not close connection to '").append(_sLDAPUrl).append("'");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), e);
			}
			try {
				if (oPrincipalContext != null) oPrincipalContext.close();
			}
			catch (Exception e) {
				sbTemp = new StringBuffer("Could not close connection to '").append(_sLDAPUrl).append("'");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), e);
			}
		}			
	}

	/**
	 * Check allowed logins.
	 * 
	 * @param sUserDN
	 *            the user's DN
	 * @param oDirContext
	 *            the directory context
	 * @return 0: ok, -1: not enough logins, or validity time has passed
	 * @throws NamingException
	 * @throws ASelectException
	 */
	private int checkAllowedLogins(String sUserDN, DirContext oDirContext)
	throws NamingException, ASelectException
	{
		final String sMethod = "checkAllowedLogins";
		int rc;
		
		Attributes attrs = oDirContext.getAttributes(sUserDN);
		_systemLogger.log(Level.INFO, _sModule, sMethod, "attr_valid_until="+_sAttrValidUntil+" attr_allowed_logins="+_sAttrAllowedLogins+" Attributes="+attrs);
		
		// Check validity time first
		if (Utils.hasValue(_sAttrValidUntil)) {
			String sValidUntil = getAttribute(attrs, _sAttrValidUntil);
			if (Utils.hasValue(sValidUntil)) {  // validity time was set
				long now = new Date().getTime();
				long validUntil = Long.valueOf(sValidUntil);
				_systemLogger.log(Level.INFO, _sModule, sMethod, "now="+now+" validUntil="+validUntil+" Seconds left: "+String.valueOf((validUntil-now)/1000));
				if (now > validUntil) {
					return -1;  // not OK
				}
			}
		}

		// Check number of allowed logins
		if (Utils.hasValue(_sAttrAllowedLogins)) {
			String sLoginsLeft = getAttribute(attrs, _sAttrAllowedLogins);
			if (Utils.hasValue(sLoginsLeft)) {
				int loginsLeft = Integer.valueOf(sLoginsLeft);
				_systemLogger.log(Level.INFO, _sModule, sMethod, "loginsLeft="+loginsLeft);
				loginsLeft--;
				if (loginsLeft <= 0) {
					// delete account
					rc = delLDAPEntry(oDirContext, sUserDN.toString());
				}
				else {
					Attributes newAttrs = new BasicAttributes();
					newAttrs.put(_sAttrAllowedLogins, String.valueOf(loginsLeft));
					// update account
					rc = updLDAPEntry(oDirContext, sUserDN.toString(), newAttrs);
				}
				if (rc < 0) {
					throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR);
				}
				return (loginsLeft >= 0)? 0: -1;
			}
		}
		return 0;  // OK
	}

	/**
	 * @param htEnvironment
	 */
	protected void additionalSettings(Hashtable<String, String> htEnvironment)
	{
		//_systemLogger.log(Level.FINE, _sModule, "additionalSettings", "simple");
	}
	
	/**
	 * Gets attribute 'name' from 'attrs'.
	 * 
	 * @param attrs
	 *            the attribute set
	 * @param name
	 *            the attribute name
	 * @return the requested attribute's value
	 */
    static public String getAttribute(Attributes attrs, String name)
	{
		try {
			return attrs.get(name).get().toString();
		}
		catch (Exception e) {
			return "";
		}
	}

    /**
	 * Upd ldap entry.
	 * Expect "cn=<value>" in 'cn' argument.
	 * 
	 * @param cn - the cn
	 * @param attrs - the attrs
	 * @param bDel - delete attribute?
	 * @return 0: success, -1: failure
	 */
    public int updLDAPEntry(DirContext ldapContext, String userDN, Attributes attrs)
    {
    	final String sMethod = "updLDAPEntry";

    	int mode = DirContext.REPLACE_ATTRIBUTE;
    	try {
    		_systemLogger.log(Level.FINE, _sModule, sMethod, "Upd: "+userDN+" mode="+mode);
    		ldapContext.modifyAttributes(userDN, mode, attrs);
		}
    	catch (NamingException e) {
    		_systemLogger.log(Level.FINE, _sModule, sMethod, "updLDAPentry("+userDN+") -> FAILED: "+e);
    		return -1;
		}
    	return 0;
    }

    /**
	 * Delete an LDAP entry.
	 * Expect "cn=<value>" in 'cn' argument.
	 * 
	 * @param cn
	 *            the cn of the entry
	 * @param subContainer
	 *            the sub container within the user Container
	 *            use null when entry is directly below the user Container
	 * @return result: 0 or -1
	 */
    public int delLDAPEntry(DirContext ldapContext, String userDN)
    {
    	final String sMethod = "delLDAPEntry";
    	
    	try {
    		_systemLogger.log(Level.FINE, _sModule, sMethod, "Del: "+userDN);
			ldapContext.destroySubcontext(userDN);
		}
    	catch (NamingException e) {
    		_systemLogger.log(Level.FINE, _sModule, sMethod, "delLDAPentry("+userDN+") -> FAILED: "+e);
    		return -1;
		}
    	return 0;
    }
}
