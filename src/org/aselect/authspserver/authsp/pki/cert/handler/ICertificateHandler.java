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
 * $Id: ICertificateHandler.java,v 1.3 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $log$
 *
 */
package org.aselect.authspserver.authsp.pki.cert.handler;

import java.security.KeyStore;

//import org.aselect.authspserver.authsp.pki.exception.ASelectPKIServerException;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.exception.ASelectException;



/**
 * Certificate Handler Interface.
 * <br><br>
 * <b>Description:</b><br>
 * This interface includes all the functions a CRL Handler must include
 * to let it work with the PKI AuthSP.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * None
 * <br>
 * @author Alfa & Ariss
 * 
 */
public interface ICertificateHandler
{
	
	/**
	 * Initialize the Certificate Handler.
	 * <br>
	 * @param oSystemLogger the System Logger
	 * @param oBackendConfig the configuration of the used back-end
	 * @throws ASelectException
	 */
	public void init(AuthSPSystemLogger oSystemLogger, Object oBackendConfig) throws ASelectException;
	
	/**
	 * Get The Certificate(s) for the corresponding subjectDN.
	 * @param sSubjectDn
	 * @return a Keystore with the found certificate(s) 
	 * @throws ASelectException
	 */
	public KeyStore getCertificates(String sSubjectDn) 
			throws ASelectException;
}
