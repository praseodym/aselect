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
 * $Id: ICRLHandler.java,v 1.2 2005/07/25 10:53:25 peter Exp $ 
 *
 * Changelog:
 * $log$
 */
package org.aselect.authspserver.authsp.pki.crl.handler;

import java.security.cert.CRL;

import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.exception.ASelectException;

/**
 * The interface for a CRL Handler.
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
 * @version 1.0
 */
public interface ICRLHandler
{	
    
	/**
	 * Initialize the CRL Handler.
	 * <br><br>
	 * @param oSystemLogger The system logger
	 */
	public abstract void init(AuthSPSystemLogger oSystemLogger);
	
	/**
	 * get the CRL of the given location.
	 * <br><br>
	 * @param sUri The location of the CRL File
	 * @return a CRL File
	 * @throws ASelectException
	 */
	public abstract CRL getCRL(String sUri) throws ASelectException;
}
