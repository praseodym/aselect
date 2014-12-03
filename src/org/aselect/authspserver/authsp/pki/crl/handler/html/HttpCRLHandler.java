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
 * $Id: HttpCRLHandler.java,v 1.3 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $log$
 *
 */
package org.aselect.authspserver.authsp.pki.crl.handler.html;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.logging.Level;

import org.aselect.authspserver.authsp.pki.Errors;
import org.aselect.authspserver.authsp.pki.crl.handler.ICRLHandler;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.exception.ASelectException;


/**
 * The Http CRL Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * This CRL Handler can handle CRL stored on a webserver with the HTTP protocol. implements the ICRLHandler interface <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss
 */
public class HttpCRLHandler implements ICRLHandler
{

	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "HttpCRLHandler";

	/** The logger that logs system information. */
	private AuthSPSystemLogger _systemLogger;

	/**
	 * initialize the Http CRL Handler <br>
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
	 * Get The CRL from the given Location on the web. <br>
	 * <br>
	 * 
	 * @param sUri
	 *            the s uri
	 * @return the CRL
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.authspserver.authsp.pki.crl.handler.ICRLHandler#getCRL(java.lang.String)
	 */
	public CRL getCRL(String sUri)
	throws ASelectException
	{
		String sMethod = "getCRL";

		CertificateFactory cf = null;
		InputStream oConnectionInputStream = null;
		CRL crl = null;
		try {
			cf = CertificateFactory.getInstance("X509");
		}
		catch (CertificateException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Internal error occured by creating instance of CertificateFactory", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}
		try {
			URL oUrl = new URL(sUri);
			URLConnection con = oUrl.openConnection();
			oConnectionInputStream = con.getInputStream();
		}
		catch (MalformedURLException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, sUri, e);
			throw new ASelectException(Errors.PKI_CONFIG_ERROR);
		}
		catch (IOException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, sUri, e);
			throw new ASelectException(Errors.PKI_NO_CRL_FOUND_FOR_CA);
		}

		try {
			crl = cf.generateCRL(oConnectionInputStream);
		}
		catch (CRLException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate CRL: " + sUri, e);
			throw new ASelectException(Errors.PKI_NO_CRL_FOUND_FOR_CA);
		}
		return crl;
	}
}
