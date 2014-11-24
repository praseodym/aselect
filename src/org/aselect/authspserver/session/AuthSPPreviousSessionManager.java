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
 * A session manager for Previous AuthSP. <br>
 * <br>
 * <b>Description:</b><br>
 * A singleton class that uses a <code>StorageManager</code> from the org.aselect.system package as backend. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 */
public class AuthSPPreviousSessionManager extends StorageManager
{
	/** The module name. */
	public static final String MODULE = "AuthSPPreviousSessionManager";
	private static AuthSPPreviousSessionManager _oAuthSPPreviousSessionManager;

	private AuthSPSystemLogger _systemLogger;
	private AuthSPConfigManager _configManager;

	/**
	 * Get a static handle to the <code>AuthSPPreviousSessionManager</code> instance. <br>
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
	 * One instance of the <code>AuthSPPreviousSessionManager</code> exists. <br>
	 * 
	 * @return A handle to the <code>AuthSPPreviousSessionManager</code>.
	 * @throws ASelectException 
	 */
	public static AuthSPPreviousSessionManager getHandle() throws ASelectException
	{
		if (_oAuthSPPreviousSessionManager == null) {
			_oAuthSPPreviousSessionManager = new AuthSPPreviousSessionManager();
			_oAuthSPPreviousSessionManager.init();
		}
		return _oAuthSPPreviousSessionManager;
	}

	/**
	 * Initializes the <code>AuthSPPreviousSessionManager</code>. <br>
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
		String sMethod = "init";
		try {
			_systemLogger = AuthSPSystemLogger.getHandle();
			_configManager = AuthSPConfigManager.getHandle();
			Object oSessionConfig = null;
			try {
				oSessionConfig = _configManager.getSection(null, "storagemanager", "id=previous_session");
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'storagemanager' section with id='previous_session' found in configuration", e);
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
	 * Create a session with the supplied sessionID as ID. <br>
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
	 * @param sessionID
	 *            The sessionID that is used as session ID
	 * @param htContext
	 *            The session context parameters in a <code>HashMap</code>.
	 * @throws ASelectException
	 *             if the session could not be created or already exists
	 */
	public void createSession(String sessionID, HashMap htContext)
	throws ASelectException
	{
		String sMethod = "createSession";
		try {
			/////////////////////////////////////////////////////
//			if (containsKey(sRid)) {	// RH, 20111121, o	
			if ( !create(sessionID,htContext )) {	// RH, 20111121, n
				
				StringBuffer sbError = new StringBuffer("Session already exists: ");
				sbError.append(sessionID);
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
			StringBuffer sbError = new StringBuffer("Could not create session with sessionID: ");
			sbError.append(sessionID);
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	
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
	 * @param sessionID
	 *            The ID of the session.
	 * @return HashMap Containing the context of the session.
	 * @throws ASelectException
	 *             if the session oculd not be resolved.
	 */
	public HashMap getSessionContext(String sessionID)
	throws ASelectException
	{
		String sMethod = "getSessionContext";
		HashMap htContext = null;
		try {
			htContext = (HashMap)get(sessionID);
		}
		catch (ASelectStorageException e) {
			StringBuffer sbError = new StringBuffer("Could not resolve session with rid: ");
			sbError.append(sessionID);
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
	private AuthSPPreviousSessionManager() {
	}
}