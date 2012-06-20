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
 * $Id: LDAPCRLHandler.java,v 1.3 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $log$
 *
 */
package org.aselect.authspserver.authsp.pki.crl.handler.ldap;

import java.io.ByteArrayInputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.aselect.authspserver.authsp.pki.Errors;
import org.aselect.authspserver.authsp.pki.crl.handler.ICRLHandler;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.exception.ASelectException;


/**
 * The LDAP CRL Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * This CRL Handler can handle CRL stored on LDAP Back-end. implements the ICRLHandler interface <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss
 */
public class LDAPCRLHandler implements ICRLHandler
{

	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "HttpCRLHandler";

	/** The logger that logs system information. */
	private AuthSPSystemLogger _systemLogger;

	/**
	 * initialize the LDAP CRL Handler <br>
	 * <br>
	 * .
	 * 
	 * @param oSystemLogger
	 *            the o system logger
	 * @see org.aselect.authspserver.authsp.pki.crl.handler.ICRLHandler#init(org.aselect.authspserver.log.AuthSPSystemLogger)
	 */
	public void init(AuthSPSystemLogger oSystemLogger)
	{
		_systemLogger = oSystemLogger;
	}

	/**
	 * Get The CRL from the given Location in LDAP. <br>
	 * <br>
	 * 
	 * @param URI
	 *            the uRI
	 * @return the CRL
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.authspserver.authsp.pki.crl.handler.ICRLHandler#getCRL(java.lang.String)
	 */
	public CRL getCRL(String URI)
	throws ASelectException
	{
		String sMethod = "getCRL()";
		CRL oCrl = null;
		CertificateFactory oCertificateFactory = null;
		LDAPURL oLdapUrl = null;
		Hashtable htContextEnv = null;
		DirContext oDirCtx = null;
		NamingEnumeration attributesEnumeration = null;

		try {
			oCertificateFactory = CertificateFactory.getInstance("X509");
		}
		catch (CertificateException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Internal error occured by creating instance of CertificateFactory", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}

		oLdapUrl = new LDAPURL(URI);
		// Set up the environment for creating the initial context
		htContextEnv = new Hashtable();
		htContextEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		htContextEnv.put(Context.PROVIDER_URL, oLdapUrl.getServerUrl());
		String[] saAttrIds = {
			oLdapUrl.getAttributes()
		};
		String sDn = oLdapUrl.getDn();

		try {
			// Create the initial context
			oDirCtx = new InitialDirContext(htContextEnv);
			Attributes oAttrs = oDirCtx.getAttributes(sDn, saAttrIds);
			attributesEnumeration = oAttrs.getAll();
			Attribute attr = (Attribute) attributesEnumeration.next();
			Object oCRL = attr.get();
			ByteArrayInputStream baInput = new ByteArrayInputStream((byte[]) oCRL);
			oCrl = oCertificateFactory.generateCRL(baInput);
		}
		catch (NamingException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Failed to retrieve attributes from LDAP Server: " + URI, e);
			throw new ASelectException(Errors.PKI_NO_CRL_FOUND_FOR_CA);
		}
		catch (CRLException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate CRL: " + URI, e);
			throw new ASelectException(Errors.PKI_NO_CRL_FOUND_FOR_CA);
		}
		finally { // prevent memory leaks (154)
			try {
				if (attributesEnumeration != null)
					attributesEnumeration.close();
				if (oDirCtx != null)
					oDirCtx.close();
			}
			catch (Exception e) {
			}
			;
		}
		return oCrl;
	}
}
