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
 * $Id: SessionManager.java,v 1.18 2006/04/26 12:18:32 tom Exp $ 
 * 
 * Changelog:
 * $Log: SessionManager.java,v $
 * Revision 1.18  2006/04/26 12:18:32  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.17  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.16.4.4  2006/02/08 08:04:14  martijn
 * javadoc typo
 *
 * Revision 1.16.4.3  2006/02/08 08:03:47  martijn
 * getSession() renamed to getSessionContext()
 *
 * Revision 1.16.4.2  2006/02/02 10:26:14  martijn
 * removed unused code
 *
 * Revision 1.16.4.1  2006/01/13 08:36:49  martijn
 * requesthandlers seperated from core
 *
 * Revision 1.16  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.15  2005/04/15 11:51:23  tom
 * Removed old logging statements
 *
 * Revision 1.14  2005/03/16 11:46:33  erwin
 * Fixed problem with SAM process time.
 *
 * Revision 1.13  2005/03/15 15:22:19  erwin
 * Create session now throws an ASelectException if server is busy.
 *
 * Revision 1.12  2005/03/14 13:03:05  erwin
 * Fixed problems with Admin monitor.
 *
 * Revision 1.11  2005/03/11 21:06:47  martijn
 * now using contains(key) instead of retrieving all objects with getAll() and doing the contains by hand
 *
 * Revision 1.10  2005/03/11 16:49:35  martijn
 * moved verifying if max sessions and tickets are reached to the storagemanager
 *
 * Revision 1.9  2005/03/10 15:12:00  erwin
 * Improved logging.
 *
 * Revision 1.8  2005/03/09 09:24:50  erwin
 * Renamed and moved errors.
 *
 * Revision 1.7  2005/03/08 13:01:17  remco
 * unnecessary randomize code removed
 *
 * Revision 1.6  2005/03/08 12:12:43  erwin
 * Applied code style, added Javadoc comment.
 *
 *
 */
package org.aselect.server.session;

import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.storagemanager.StorageManager;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;

/**
 * Manages A-Select Server sessions.
 * <br><br>
 * <b>Description:</b>
 * <br>
 * Provides methods for managing sessions:
 * <ul>
 * 	<li>Create a session</li>
 * 	<li>Kill a session</li>
 *  <li>Retrieve and update session contexts</li>
 * 	<li>Retrieve all session contexts</li>
 * </ul>
 * The session contexts are stored using a <code>StorageManager</code>.
 * <br><br>
 * <i>Note: This manager is implemented as a Singleton.</i>
 * <br><br> 
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class SessionManager extends StorageManager
{
	/** The module name. */
	public static final String MODULE = "SessionManager";

	/** The static instance. */
	private static SessionManager _oSessionManager;

	/** The number of session issued since startup. */
	private long _lSessionsCounter = 0;

	/** The last process time. */
	private long _lProcessTime;

	/** The logger for system log entries. */
	private SystemLogger _systemLogger;

	/**
	 * Initializes the <code>SessionManager</code>.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Read configuration settings and initializes the components.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The instance variables and components are initialized.
	 * <br>
	 * @throws ASelectException If initialization fails.
	 * @throws ASelectConfigException If one or more mandatory configuration 
	 * settings are missing or invalid.
	 */
	public void init()
		throws ASelectException, ASelectConfigException
	{
		String sMethod = "init()";
		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			ASelectConfigManager oConfigManager = ASelectConfigManager.getHandle();

			Object oSessionConfig = null;
			try {
				oSessionConfig = oConfigManager.getSection(null, "storagemanager", "id=session");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'storagemanager' section with id='session' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			super.init(oSessionConfig, oConfigManager, _systemLogger, ASelectSAMAgent.getHandle());

			//reset session counter
			_lSessionsCounter = 0;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Session manager Successfully started.");
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Returns a static handle to the <code>SessionManager</code> instance.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * <ul>
	 * <li>Checks if a static instance exists</li>
	 * <li>Otherwise create static instance</li>
	 * <li>Returns static instance</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * One instance of the <code>SessionManager</code> exists.
	 * <br>
	 * @return A static handle to the <code>SessionManager</code>.
	 */
	public static SessionManager getHandle()
	{
		if (_oSessionManager == null)
			_oSessionManager = new SessionManager();

		return _oSessionManager;
	}

	/**
	 * Destroy the <code>SessionManager</code>.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Destroys the storage manager by calling <code>super.destroy()</code>
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The <code>SessionManager</code> is destroyed.
	 */
	public void destroy()
	{
		super.destroy();
	}

	/**
	 * Create a unique session ID and stores the <code>htSessionContext</code> using this ID.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Stores the <code>htSessionContext</code> supplied by the caller under
	 * a unique generated session id of 8 bytes.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * <code>htSessionContext != null</code>
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The given session is stored.
	 * <br>
	 * @param htSessionContext The session context parameters in a 
	 * 	<code>HashMap</code>.
	 * @return The created session id.
	 * @throws ASelectException If server is busy.
	 */
	synchronized public String createSession(HashMap htSessionContext)
		throws ASelectException
	{
		String sMethod = "createSession";
		String sSessionId = null;

		try {
			byte[] baRandomBytes = new byte[8];

			CryptoEngine.nextRandomBytes(baRandomBytes);
			sSessionId = Utils.toHexString(baRandomBytes);
			while (containsKey(sSessionId)) {
				CryptoEngine.nextRandomBytes(baRandomBytes);
				sSessionId = Utils.toHexString(baRandomBytes);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Generated new sSessionId=" + sSessionId);
			}

			Tools.initializeSensorData(_systemLogger, htSessionContext);
			//_systemLogger.log(Level.INFO, MODULE, sMethod, "New SessionId=" + sSessionId);  // + ", htSessionContext="+htSessionContext);
			put(sSessionId, htSessionContext);  // always insert
			_lSessionsCounter++;
		}
		catch (ASelectStorageException e) {
			if (e.getMessage().equals(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Maximum number of sessions reached", e);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_BUSY, e);
			}
			throw e;
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create session", e);
			sSessionId = null; // reset session id
		}
		return sSessionId;
	}

	/**
	 * Stores a new session context using the supplied session ID.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Writes the new session context with the given ID in the storage.
	 * <br><br>
	 * Use this method also instead of 
	 * {@link SessionManager#updateSession(String, HashMap) }, if 
	 * the session allready exists. In this case this method is faster. 
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * 	<li><code>sSessionId != null</code></li>
	 * 	<li><code>htSessionContext != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The given session is stored with the new context.
	 * <br><br>
	 * @param sSessionId The ID of the session.
	 * @param htSessionContext The new session context.
	 * @return True if updating succeeds, otherwise false.
	 */
	public boolean writeSession(String sSessionId, HashMap htSessionContext)
	{
		String sMethod = "writeSession";
		boolean bReturn = false;
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SessionId=" + sSessionId);
			put(sSessionId, htSessionContext);  // insert or update
			bReturn = true;
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not write session: " + sSessionId, e);
		}
		return bReturn;
	}

	/**
	 * Update a session context.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Overwrites the new session context with the given ID in the storage.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * 	<li><code>sSessionId != null</code></li>
	 * 	<li><code>htSessionContext != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The given session is updated with the new context.
	 * <br>
	 * @param sSessionId The ID of the session.
	 * @param htSessionContext The new session context.
	 * @return True if updating succeeds, otherwise false.
	 */
	public boolean updateSession(String sSessionId, HashMap htSessionContext)
	{
		String sMethod = "updateSession";
		boolean bReturn = false;
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SessionId=" + sSessionId);
			if (containsKey(sSessionId)) {
				update(sSessionId, htSessionContext);
				bReturn = true;
			}
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not update session with id: " + sSessionId, e);
		}
		return bReturn;
	}

	/**
	 * Get the session context of a session.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Retrieve the session context (session parameters) belonging to the given
	 * session ID.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * <code>sSessionId != null</code>
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br>
	 * @param sSessionId The ID of the session.
	 * @return The session context as <code>HashMap</code>.
	 */
	public HashMap getSessionContext(String sSessionId)
	{
		String sMethod = "getSessionContext";
		HashMap htContext = null;
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SessionId=" + sSessionId);  // + ", Context=" + htContext);
			htContext = (HashMap)get(sSessionId);
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not find context for session with id: "
					+ sSessionId, e);
		}
		return htContext;
	}

	/**
	 * Kill a session.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Removes the session with the given ID from the storage manager.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * <code>sSessionId != null</code>
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The session is removed from storage.
	 * <br>
	 * @param sSessionId The ID of the session to be killed.
	 */
	public synchronized void killSession(String sSessionId)
	{
		String sMethod = "killSession";
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SessionId=" + sSessionId);
			// Retrieve session start time (timestamp) and calculate last processing time
			_lProcessTime = System.currentTimeMillis() - getTimestamp(sSessionId);
			// Remove session
			remove(sSessionId);
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not remove session with id: " + sSessionId, e);
		}
	}

	/**
	 * Retrieve the processing time.
	 * @return The processing time.
	 */
	public long getProcessingTime()
	{
		return _lProcessTime;
	}

	/**
	 * Retrieve the number of issued sessions since startup.
	 * @return The session counter.
	 */
	public long getCounter()
	{
		return _lSessionsCounter;
	}

	/**
	 * Private constructor.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Creates a new storage manager and retrieves the system logger.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The storage manager is created.
	 */
	private SessionManager()
	{
	}
}
