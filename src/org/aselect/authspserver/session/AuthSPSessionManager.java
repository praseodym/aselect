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
 * $Id: AuthSPSessionManager.java,v 1.4 2006/05/03 10:08:49 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthSPSessionManager.java,v $
 * Revision 1.4  2006/05/03 10:08:49  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2006/03/20 14:42:42  martijn
 * removed unused code and restyled it like the A-Select Server session manager
 *
 * Revision 1.2  2006/03/20 14:18:11  leon
 * Sessionmanager added
 *
 * Revision 1.1.2.3  2005/06/16 12:38:52  martijn
 * added javadoc
 *
 * Revision 1.1.2.2  2005/06/15 11:53:36  martijn
 * added updateSession() and existSession()
 *
 * Revision 1.1.2.1  2005/06/14 10:49:18  martijn
 * added AuthSP Attribute support
 *
 */

package org.aselect.authspserver.session;

import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.authspserver.sam.AuthSPSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.storagemanager.StorageManager;

/**
 * A session manager for all AuthSP's. <br>
 * <br>
 * <b>Description:</b><br>
 * A singleton class that uses a <code>StorageManager</code> from the org.aselect.system package as backend. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class AuthSPSessionManager extends StorageManager
{
	/** The module name. */
	public static final String MODULE = "AuthSPSessionManager";
	private static AuthSPSessionManager _oAuthSPSessionManager;

	private AuthSPSystemLogger _systemLogger;
	private AuthSPConfigManager _configManager;

	/**
	 * Get a static handle to the <code>AuthSPSessionManager</code> instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if a static instance exists, otherwise it is created. This instance is returned. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * One instance of the <code>AuthSPSessionManager</code> exists. <br>
	 * 
	 * @return A handle to the <code>AuthSPSessionManager</code>.
	 */
	public static AuthSPSessionManager getHandle()
	{
		if (_oAuthSPSessionManager == null)
			_oAuthSPSessionManager = new AuthSPSessionManager();
		return _oAuthSPSessionManager;
	}

	/**
	 * Initializes the <code>AuthSPSessionManager</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Read configuration settings and initializes the components. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The instance variables and components are initialized. <br>
	 * 
	 * @throws ASelectException
	 *             if initialization fails
	 */
	public void init()
	throws ASelectException
	{
		String sMethod = "init()";
		try {
			_systemLogger = AuthSPSystemLogger.getHandle();
			_configManager = AuthSPConfigManager.getHandle();
			Object oSessionConfig = null;
			try {
				oSessionConfig = _configManager.getSection(null, "storagemanager", "id=session");
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'storagemanager' section with id='session' found in configuration", e);
				throw e;
			}

			super.init(oSessionConfig, _configManager, _systemLogger, AuthSPSAMAgent.getHandle());
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Session manager Successfully started.");
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Create a session with the supplied RID as ID. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The <code>htContext</code> variable contains the information that should be stored in the session. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>htSessionContext != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The given session is stored. <br>
	 * 
	 * @param sRid
	 *            The RID that is used as session ID
	 * @param htContext
	 *            The session context parameters in a <code>HashMap</code>.
	 * @throws ASelectException
	 *             if the session could not be created or already exists
	 */
	public void createSession(String sRid, HashMap htContext)
	throws ASelectException
	{
		String sMethod = "createSession()";
		try {
			/////////////////////////////////////////////////////
//			if (containsKey(sRid)) {	// RH, 20111121, o	
			if ( !create(sRid,htContext )) {	// RH, 20111121, n
				
				StringBuffer sbError = new StringBuffer("Session already exists: ");
				sbError.append(sRid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

//			put(sRid, htContext);	// RH, 20111121, o
		}
		catch (ASelectStorageException e) {
			if (e.getMessage().equals(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Maximum number of sessions reached", e);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_BUSY, e);
			}
			throw e;
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not create session with rid: ");
			sbError.append(sRid);
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Update a session context with the given information. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Overwrites the supplied session parameters in the context of the session with the given ID. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>sRid != null</code></li>
	 * <li><code>htExtendedContext != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The given session is updated with the new context. <br>
	 * 
	 * @param sRid
	 *            The ID of the session
	 * @param htExtendedContext
	 *            <code>HashMap</code> of the parameters in the session context that should be overwritten
	 * @throws ASelectException
	 *             if the session could not be updated
	 */
	/*public void updateSession_TestAndGet(String sRid, HashMap htExtendedContext)
	throws ASelectException
	{
		String sMethod = "updateSession_TestAndGet";
		try {
			if (!containsKey(sRid)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No sessions found with id: " + sRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_BUSY);
			}

			HashMap htOldContext = (HashMap) get(sRid);
			htOldContext.putAll(htExtendedContext);
			update(sRid, htOldContext);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not update session with rid: ");
			sbError.append(sRid);
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}*/
	
	/**
	 * Update a session context. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Updates the session context identified by the given ID in the session storage. <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>sSessionId != null</code></li>
	 * <li><code>htSessionContext != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The given session is stored with the new context. <br>
	 * <br>
	 * 
	 * @param sSessionId
	 *            The ID of the session.
	 * @param htSessionContext
	 *            The new session context.
	 * @return True if updating succeeds, otherwise false.
	 */
	public boolean updateSession(String sSessionId, HashMap htSessionContext)
	{
		String sMethod = "writeSession";
		boolean bReturn = false;
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SessionId=" + sSessionId);
			// 20120330, Bauke: Do not persist "status"
			String sStatus = (String)htSessionContext.get("status");
			htSessionContext.remove("status");
			update(sSessionId, htSessionContext); // insert or update
			if (sStatus != null) htSessionContext.put("status", sStatus);
			bReturn = true;
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not write session: " + sSessionId, e);
		}
		return bReturn;
	}

	/**
	 * Get the session context of a session. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Retrieve the session context (session parameters) belonging to the given session ID. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sSessionId != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sRid
	 *            The ID of the session.
	 * @return HashMap Containing the context of the session.
	 * @throws ASelectException
	 *             if the session oculd not be resolved.
	 */
	public HashMap getSessionContext(String sRid)
	throws ASelectException
	{
		String sMethod = "getSessionContext()";
		HashMap htContext = null;
		try {
			htContext = (HashMap)get(sRid);
		}
		catch (ASelectStorageException e) {
			StringBuffer sbError = new StringBuffer("Could not resolve session with rid: ");
			sbError.append(sRid);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString()+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return htContext;
	}

	/**
	 * Private constructor. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new storage manager and retrieves the system logger. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The storage manager is created.
	 */
	private AuthSPSessionManager() {
	}
}