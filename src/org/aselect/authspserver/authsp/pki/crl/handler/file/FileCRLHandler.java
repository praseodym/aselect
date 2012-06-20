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
 * $Id: FileCRLHandler.java,v 1.3 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $log$
 *
 */
package org.aselect.authspserver.authsp.pki.crl.handler.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
 * The File CRL Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * This CRL Handler can handle CRL stored on the Local File System. implements the ICRLHandler interface <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss
 */
public class FileCRLHandler implements ICRLHandler
{

	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "FileCRLHandler";

	/** The logger that logs system information. */
	private AuthSPSystemLogger _systemLogger;

	/**
	 * initialize the File CRL Handler <br>
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
	 * Get The CRL from the given Location on the local file system. <br>
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
		String sMethod = "getCRL()";
		CertificateFactory oCertificateFactory = null;
		FileInputStream oFileInputStream = null;
		CRL crl = null;

		try {
			oCertificateFactory = CertificateFactory.getInstance("X509");
		}
		catch (CertificateException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Internal error occured by creating instance of CertificateFactory", e);
			throw new ASelectException(Errors.PKI_INTERNAL_SERVER_ERROR);
		}
		try {
			String sFileLocation = sUri.substring(7);
			File oCrlFile = new File(sFileLocation);
			oFileInputStream = new FileInputStream(oCrlFile);
		}
		catch (FileNotFoundException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, sUri, e);
			throw new ASelectException(Errors.PKI_CONFIG_ERROR);
		}
		try {
			crl = oCertificateFactory.generateCRL(oFileInputStream);
		}
		catch (CRLException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate CRL: " + sUri, e);
			throw new ASelectException(Errors.PKI_NO_CRL_FOUND_FOR_CA);
		}
		return crl;
	}
}
