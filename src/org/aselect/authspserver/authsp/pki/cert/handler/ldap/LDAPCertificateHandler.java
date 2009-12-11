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
 * $Id: LDAPCertificateHandler.java,v 1.3 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $log$
 *
 */
package org.aselect.authspserver.authsp.pki.cert.handler.ldap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
import org.aselect.authspserver.authsp.pki.cert.handler.ICertificateHandler;
import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

// TODO: Auto-generated Javadoc
/**
 * The LDAP Certificate Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * This Certificate Handler retrieve certificates from a LDAP Back-end. implements the ICRLHandler interface <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss
 */
public class LDAPCertificateHandler implements ICertificateHandler
{
	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "LDAPCertificateHandler";

	/** The logger that logs system information. */
	private AuthSPSystemLogger _systemLogger;

	private String _sDriver = null;
	private String _sLdapMethod = null;
	private String _sUrl = null;
	private String _sBaseDn = null;
	private String _sCertificateAttrName = null;
	private String _sPrincipalDn = null;
	private String _sPrincipalPassword = null;
	private AuthSPConfigManager _oConfigManager;

	/**
	 * Initialize the LDAP Certificate Handler <br>
	 * <br>
	 * .
	 * 
	 * @param oSystemLogger
	 *            the o system logger
	 * @param oBackendConfig
	 *            the o backend config
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.authspserver.authsp.pki.cert.handler.ICertificateHandler#init(org.aselect.authspserver.log.AuthSPSystemLogger,
	 *      java.lang.Object)
	 */
	public void init(AuthSPSystemLogger oSystemLogger, Object oBackendConfig)
		throws ASelectException
	{
		String sMethod = "init()";
		_oConfigManager = AuthSPConfigManager.getHandle();
		_systemLogger = oSystemLogger;
		try {
			_sDriver = _oConfigManager.getParam(oBackendConfig, "driver");
			_sLdapMethod = _oConfigManager.getParam(oBackendConfig, "method");
			_sUrl = _oConfigManager.getParam(oBackendConfig, "url");
			_sBaseDn = _oConfigManager.getParam(oBackendConfig, "base_dn");
			_sCertificateAttrName = _oConfigManager.getParam(oBackendConfig, "cert_attribute_name");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize " + MODULE, e);
			throw e;
		}

		try {
			_sPrincipalDn = _oConfigManager.getParam(oBackendConfig, "principal_dn");
			_sPrincipalPassword = _oConfigManager.getParam(oBackendConfig, "principal_password");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "No principal name and password found: continue", e);
			// principal_dn and principal_password params may be
			// empty in the pki.xml configuration file,
			// so catch the ASelectConfigException and proceed.
		}
	}

	/**
	 * Returns the found certificates on the backend in a Keystore. <br>
	 * <br>
	 * 
	 * @param sSubjectDn
	 *            the s subject dn
	 * @return the certificates
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.authspserver.authsp.pki.cert.handler.ICertificateHandler#getCertificates(java.lang.String)
	 */
	public KeyStore getCertificates(String sSubjectDn)
		throws ASelectException
	{
		String sMethod = "getCertificates()";
		DirContext oDirCtx = null;
		NamingEnumeration oAttributesEnumeration = null;
		NamingEnumeration oCertEnumeration = null;
		CertificateFactory oCertificateFactory = null;

		KeyStore oCertKeystore = null;
		try {
			oCertKeystore = KeyStore.getInstance("JKS");
			oCertKeystore.load(null, null);
		}
		catch (KeyStoreException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Internal error occured by creating instance of JKS KeyStore", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}
		catch (NoSuchAlgorithmException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Internal error occured by creating instance of JKS KeyStore", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}
		catch (CertificateException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Internal error occured by creating instance of JKS KeyStore", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Internal error occured by creating instance of JKS KeyStore", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}

		Hashtable htContextEnv = new Hashtable();
		htContextEnv.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver);
		htContextEnv.put(Context.PROVIDER_URL, _sUrl);

		if (_sPrincipalDn != null || _sPrincipalPassword != null) {
			htContextEnv.put(Context.SECURITY_PRINCIPAL, _sPrincipalDn);
			htContextEnv.put(Context.SECURITY_CREDENTIALS, _sPrincipalPassword);
		}
		if (_sDriver == null || _sLdapMethod == null || _sUrl == null || _sBaseDn == null
				|| _sCertificateAttrName == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The necessary configuration is not complete");
			throw new ASelectConfigException(Errors.PKI_CONFIG_ERROR);
		}
		if (sSubjectDn == null || sSubjectDn.equalsIgnoreCase("")) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid PkiUserAttribute");
			throw new ASelectConfigException(Errors.PKI_CONFIG_ERROR);
		}
		if (_sLdapMethod.equalsIgnoreCase("ssl")) {
			htContextEnv.put(Context.SECURITY_PROTOCOL, "ssl");
		}
		try {
			oCertificateFactory = CertificateFactory.getInstance("X509");
			String[] saAttrIds = {
				_sCertificateAttrName
			};
			String sDn = sSubjectDn + "," + _sBaseDn;
			oDirCtx = new InitialDirContext(htContextEnv);
			Attributes oAttrs = oDirCtx.getAttributes(sDn, saAttrIds);
			oAttributesEnumeration = oAttrs.getAll();
			X509Certificate oX509Cert = null;
			int i = 0;
			while (oAttributesEnumeration.hasMoreElements()) {
				Attribute attr = (Attribute) oAttributesEnumeration.nextElement();
				oCertEnumeration = attr.getAll();
				while (oCertEnumeration.hasMoreElements()) {
					Object oCert = oCertEnumeration.next();
					ByteArrayInputStream baInput = new ByteArrayInputStream((byte[]) oCert);
					oX509Cert = (X509Certificate) oCertificateFactory.generateCertificate(baInput);
					String sAlias = "clientcert" + i;
					oCertKeystore.setCertificateEntry(sAlias, oX509Cert);
					i++;
				}
			}
		}
		catch (NamingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get certificates for: " + sSubjectDn, e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}
		catch (CertificateException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get certificates for: " + sSubjectDn, e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}
		catch (KeyStoreException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get certificates for: " + sSubjectDn, e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}
		finally { // prevent memory leaks (154)
			try {
				if (oAttributesEnumeration != null)
					oAttributesEnumeration.close();
				if (oCertEnumeration != null)
					oCertEnumeration.close();
				if (oDirCtx != null)
					oDirCtx.close();
			}
			catch (Exception e) {
			}
			;
		}
		return oCertKeystore;
	}
}
