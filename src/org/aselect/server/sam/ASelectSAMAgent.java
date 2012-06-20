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
 * $Id: ASelectSAMAgent.java,v 1.7 2006/04/26 12:18:32 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectSAMAgent.java,v $
 * Revision 1.7  2006/04/26 12:18:32  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.6  2005/09/08 12:46:34  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.5  2005/03/10 16:46:00  erwin
 * Fixed typo
 *
 * Revision 1.4  2005/02/23 14:31:21  martijn
 * added javadoc
 *
 * Revision 1.3  2005/02/23 14:23:56  martijn
 * added java documentation and changed variable names
 *
 */

package org.aselect.server.sam;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.sam.agent.SAMAgent;

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
public class ASelectSAMAgent extends SAMAgent
{
	/**
	 * The singleton instance of this object
	 */
	private static ASelectSAMAgent oASelectSAMAgent;

	/**
	 * Constructor that has been made private for singleton purposes.
	 */
	private ASelectSAMAgent() {
	}

	/**
	 * Method to return the instance of the <code>SAMAgent</code>. <br>
	 * 
	 * @return always the same <code>SAMAgent</code> object
	 */
	public static ASelectSAMAgent getHandle()
	{
		if (oASelectSAMAgent == null)
			oASelectSAMAgent = new ASelectSAMAgent();

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
		super.init(ASelectConfigManager.getHandle(), ASelectSystemLogger.getHandle());
	}

}