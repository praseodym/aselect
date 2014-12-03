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
 * $Id: AuthSPConfigManager.java,v 1.7 2006/05/03 10:08:49 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthSPConfigManager.java,v $
 * Revision 1.7  2006/05/03 10:08:49  tom
 * Removed Javadoc version
 *
 * Revision 1.6  2005/09/08 12:47:54  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.5  2005/03/29 10:36:30  erwin
 * Added support for loading HTML templates and retrieving error messages.
 *
 * Revision 1.4  2005/03/11 13:27:07  erwin
 * Improved error handling.
 *
 * Revision 1.3  2005/03/08 14:12:51  tom
 * Javadoc: getHandle dit not contain a return value description
 *
 * Revision 1.2  2005/02/09 12:42:49  martijn
 * changed all variable names to naming convention and added javadoc
 *
 */
package org.aselect.authspserver.config;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Properties;
import java.util.logging.Level;

import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * The configuration manager for the A-Select AuthSP Server. <br>
 * <br>
 * <b>Description:</b><br>
 * A singleton configuration manager, containing the A-Select AuthSP Server configuration. It loads several settings in
 * memory during initialize. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class AuthSPConfigManager extends ConfigManager
{
	/** The name of this module, that is used in the system logging. */
	private final String MODULE = "AuthSPConfigManager";

	/** The static instance. */
	private static AuthSPConfigManager _oAuthSPConfigManager;

	/** The logger used for system logging */
	private AuthSPSystemLogger _systemLogger;

	/**
	 * Must be used to get an AuthSP ConfigManager instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new <code>AuthSPConfigManager</code> instance if it's still <code>null</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * Always the same instance of the config manager is returned, because it's singleton. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return handle to the AuthSPConfigManager
	 */
	public static AuthSPConfigManager getHandle()
	{
		if (_oAuthSPConfigManager == null)
			_oAuthSPConfigManager = new AuthSPConfigManager();

		return _oAuthSPConfigManager;
	}

	/**
	 * Retrieve error messsage from <code>Properties</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Retrieve the configured error message with the given key. <br>
	 * 
	 * @param sKey
	 *            The error code.
	 * @param pErrors
	 *            The error properties.
	 * @return The property if it exists, otherwise the key.
	 */
	public String getErrorMessage(String sModule, String sKey, Properties pErrors)
	{
		String sMethod = "getErrorMessage";

		String sMessage = null;
		try {
			sMessage = pErrors.getProperty(sKey).trim();
			if (sMessage == null)
				sMessage = "[" + sKey + "]";
		}
		catch (Exception e) {  // value was probably null so trim() function failed
			sMessage = "[" + sKey + "]";
		}
		_systemLogger.log(Level.INFO, sModule/*callers module*/, sMethod, "MSG["+sKey+"]->" + sMessage);
		return sMessage;
	}

	/**
	 * Must be private, so it can not be used. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Retrieves a handle to the AuthSP system logger. Must be private because <code>getHandle()</code> must be used to
	 * retrieve an instance. This is done for singleton purposes. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 */
	private AuthSPConfigManager()
	{
		_systemLogger = AuthSPSystemLogger.getHandle();
	}
}