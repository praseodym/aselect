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
 * $Id: AuthSPSAMAgent.java,v 1.3 2006/05/03 10:08:49 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthSPSAMAgent.java,v $
 * Revision 1.3  2006/05/03 10:08:49  tom
 * Removed Javadoc version
 *
 * Revision 1.2  2006/03/20 14:18:33  leon
 * SAM agent added for SessionManager
 *
 * Revision 1.1.2.1  2005/06/14 10:49:18  martijn
 * added AuthSP Attribute support
 *
 */

package org.aselect.authspserver.sam;

import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.sam.agent.SAMAgent;

// TODO: Auto-generated Javadoc
/**
 * A singleton class for the <code>SAMAgent</code>. <br>
 * <br>
 * <b>Description:</b><br>
 * A singleton class for the <code>SAMAgent</code> that is located in the org.aselect.system package. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class AuthSPSAMAgent extends SAMAgent
{
	/**
	 * The singleton instance of this object
	 */
	private static AuthSPSAMAgent oASelectSAMAgent;

	/**
	 * Constructor that has been made private for singleton purposes.
	 */
	private AuthSPSAMAgent() {
	}

	/**
	 * Method to return the instance of the <code>SAMAgent</code>. <br>
	 * 
	 * @return always the same <code>SAMAgent</code> object
	 */
	public static AuthSPSAMAgent getHandle()
	{
		if (oASelectSAMAgent == null)
			oASelectSAMAgent = new AuthSPSAMAgent();

		return oASelectSAMAgent;
	}

	/**
	 * Calls the initialize class of the super class <code>SAMAgent</code> with the A-Select config manager and the
	 * A-Select system logger. <br>
	 * 
	 * @throws ASelectSAMException
	 *             the a select sam exception
	 */
	public void init()
		throws ASelectSAMException
	{
		super.init(AuthSPConfigManager.getHandle(), AuthSPSystemLogger.getHandle());
	}

}