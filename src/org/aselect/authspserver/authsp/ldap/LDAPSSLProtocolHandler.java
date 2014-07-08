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

import java.util.Hashtable;
import java.util.logging.Level;

import javax.naming.Context;

/**
 * A SSL LDAP protocol handler. <br>
 * <br>
 * <b>Description:</b><br>
 * Authenticates a user by binding to a (SSL) LDAP server using the users credentials. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 */
public class LDAPSSLProtocolHandler extends LDAPSimpleProtocolHandler
{
	// Set the module name.
	public LDAPSSLProtocolHandler()
	{
//		_systemLogger.log(Level.FINE, _sModule, "creator", "ssl");
		_sModule = "LDAPSSLProtocolHandler";
	}

	/**
	 * @param htEnvironment
	 */
	public void additionalSettings(Hashtable<String, String> htEnvironment)
	{
		_systemLogger.log(Level.FINE, _sModule, "additionalSettings", "ssl");
		htEnvironment.put(Context.SECURITY_PROTOCOL, "ssl");
	}
}
