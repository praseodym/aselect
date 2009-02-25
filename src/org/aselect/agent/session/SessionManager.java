/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license. See the included
 * LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE please contact SURFnet bv.
 * (http://www.surfnet.nl)
 */

/*
 * $Id: SessionManager.java,v 1.11 2006/04/14 13:42:48 tom Exp $
 * 
 * Changelog: $Log: SessionManager.java,v $
 * Changelog: Revision 1.11  2006/04/14 13:42:48  tom
 * Changelog: QA: removed javadoc version tag, minor javadoc fixes
 * Changelog:
 * Changelog: Revision 1.10  2005/09/08 12:46:02  erwin
 * Changelog: Changed version number to 1.4.2
 * Changelog:
 * Changelog: Revision 1.9  2005/04/15 11:51:42  tom
 * Changelog: Removed old logging statements
 * Changelog:
 * Changelog: Revision 1.8  2005/03/14 10:09:07  erwin
 * Changelog: The ticket and session expiration and start
 * Changelog: time are now read from the ticket and session
 * Changelog: manager.
 * Changelog:
 * Changelog: Revision 1.7  2005/03/11 21:03:53  martijn
 * Changelog: config item max_sessions ihas been renamed to 'max' in storagemanager section with id='session'
 * Changelog:
 * Changelog: Revision 1.6  2005/03/11 16:49:35  martijn
 * Changelog: moved verifying if max sessions and tickets are reached to the storagemanager
 * Changelog:
 * Changelog: Revision 1.5  2005/03/08 13:40:36  erwin
 * Changelog: Improved comment.
 * Changelog:
 * Changelog: Revision 1.4  2005/03/03 17:24:19  erwin
 * Changelog: Applied code style, added javadoc comment.
 * Changelog: Changelog: Revision 1.3 2005/03/01
 * 14:08:34 martijn Changelog: fixed stop() method Changelog: Changelog:
 * Revision 1.2 2005/02/24 15:09:09 ali Changelog: Added IAgentEventListener
 * class and updates internal Javadoc. Changelog:
 */

package org.aselect.agent.session;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.agent.config.ASelectAgentConfigManager;
import org.aselect.agent.log.ASelectAgentSystemLogger;
import org.aselect.agent.sam.ASelectAgentSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.storagemanager.StorageManager;

/**
 * Manages A-Select Agent sessions.
 * <br><br>
 * <b>Description:</b><br>
 * Provides methods for managing sessions:
 * <ul>
 * 	<li>Create a session</li>
 *  <li>Update a session</li>
 * 	<li>Remove a sessions</li>
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
 */
public class SessionManager
{
	/** The MODULE name. */
	public static final String MODULE = "SessionManager";

	/** The static instance. */
	private static SessionManager _instance;

	/** The configuration. */
	private ASelectAgentConfigManager _oConfigManager;

	/** The session storage. */
	private StorageManager _oSessionTable;

	/** The random generator. */
	private SecureRandom _oRandomGenerator;

	/** The logger for system log entries. */
	private SystemLogger _systemLogger;

	/** number of sessions issued since startup. */
	private long _lSessionsCounter;

	/**
	 * Get a static handle to the <code>SessionManager</code> instance.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Checks if a static instance exists, otherwise it is created. This 
	 * instance is returned.
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
	 * One instance of the <code>SessionManager</code> exists.
	 * 
	 * @return A static handle to the <code>SessionManager</code>
	 */
	public static SessionManager getHandle()
	{
		if (_instance == null)
			_instance = new SessionManager();
		return _instance;
	}

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
	 * @return true if initialization succeeds, otherwise false.
	 */
	public boolean init()
	{
		String sMethod = "init()";

		try {
			_oConfigManager = ASelectAgentConfigManager.getHandle();

			_oSessionTable = new StorageManager();

			Object objSessionMngrConfig = null;
			try {
				objSessionMngrConfig = _oConfigManager.getSection(null, "storagemanager", "id=session");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod,
						"no storagemanager section with id=session declared in config file", e);
				return false;
			}

			_oSessionTable.init(objSessionMngrConfig, _oConfigManager, ASelectAgentSystemLogger.getHandle(),
					ASelectAgentSAMAgent.getHandle());

			//initilize Randomgenerator
			_oRandomGenerator = SecureRandom.getInstance("SHA1PRNG");
			_oRandomGenerator.setSeed(_oRandomGenerator.generateSeed(20));

			_lSessionsCounter = 0;

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully started");
			return true;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "exception: " + e.getMessage(), e);
		}
		return false;
	}

	/**
	 * Stop the <code>SessionManager</code>.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Destroys all current sessions.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * After this method is finished, no methods may be called 
	 * in other threads.
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The <code>SessionManager</code> has stopped.
	 * <br>
	 * 
	 */
	public void stop()
	{
		if (_oSessionTable != null)
			_oSessionTable.destroy();

		_systemLogger.log(Level.INFO, MODULE, "stop()", "Session manager stopped.");
	}

	/**
	 * Create a session.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Adds the given session context with the given ID to the storage.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * none.
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * 	<li><code>sSessionId != null</code></li>
	 * 	<li><code>htSessionContext != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The given session is stored.
	 * <br>
	 * @param sSessionId The id of the session. 
	 * @param htSessionContext The contents of the session (context).
	 * @return True if creation succeeds, otherwise false.
	 */
	public boolean createSession(String sSessionId, HashMap htSessionContext)
	{
		String sMethod = "createSession()";

		try {
			synchronized (_oSessionTable) {
				if (_oSessionTable.containsKey(sSessionId)) {
					return false;
				}
				try {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "New SessionId/Rid=" + sSessionId
							+ ", htSessionContext=" + htSessionContext);
					_oSessionTable.put(sSessionId, htSessionContext);
				}
				catch (ASelectStorageException e) {
					if (e.getMessage().equals(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED)) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Maximum number of sessions reached", e);
						return false;
					}
					throw e;
				}
				_lSessionsCounter++;
			}
			return true;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Exception: " + e.getMessage(), e);
		}
		return false;
	}

	/**
	 * Kill a session.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Removes the session with the given ID form the storage.
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
	 * @param sSessionId The ID of the session to be removed.
	 */
	public void killSession(String sSessionId)
	{
		try {
			synchronized (_oSessionTable) {
				_systemLogger.log(Level.INFO, MODULE, "killSession()", "Kill SessionId=" + sSessionId);
				_oSessionTable.remove(sSessionId);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, "killSession()", "Exception: " + e.getMessage(), e);
		}
	}

	/**
	 * Update a session context. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Overwrites the new session context with the given ID in the storage. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br> - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>sSessionId != null</code></li>
	 * <li><code>htSessionContext != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The given session is updated with the new context. <br>
	 * 
	 * @param sSessionId
	 *            The ID of the session.
	 * @param htSessionContext
	 *            The new session context.
	 * @return True if updating succeeds, otherwise false.
	 */
	public boolean updateSessionContext(String sSessionId, HashMap htSessionContext)
	{
		try {
			synchronized (_oSessionTable) {
				if (getSessionContext(sSessionId) != null) {
					_oSessionTable.update(sSessionId, htSessionContext);
				}
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, "updateSessionContext()", "Exception: " + e.getMessage(), e);
			return false;
		}
		return true;
	}

	/**  
	 * Get the number of issued sessions since startup.      
	 * @return The number of issued sessions.
	 */
	public long getSessionsCounter()
	{
		return _lSessionsCounter;
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
		HashMap htResponse = null;

		try {
			htResponse = (HashMap) _oSessionTable.get(sSessionId);
			_systemLogger.log(Level.INFO, MODULE, "getSessionContext()", "SessionId=" + sSessionId + ", Context="
					+ htResponse);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, "getSessionContext()", "Exception: " + e.getMessage());
		}

		return htResponse;
	}

	/**
	 * Retrieve all session contexts.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Retrieve all session contexts from the storage.
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
	 * -
	 * <br>
	 * @return All session contexts in a <code>HashMap</code>.
	 */
	public HashMap getSessionContexts()
	{
		HashMap htResponse = null;

		try {
			htResponse = _oSessionTable.getAll();
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, "getSessionContexts()", "Exception: " + e.getMessage(), e);
		}
		return htResponse;
	}

	/**
	 * Returns then session timeout.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Return the session timeout form the given session.
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
	 * @param sSessionId The session ID.
	 * @return The expiration time of the session.
	 * @throws ASelectStorageException If retrieving session timeout fails.
	 */
	public long getSessionTimeout(String sSessionId)
		throws ASelectStorageException
	{
		return _oSessionTable.getExpirationTime(sSessionId);
	}

	/**
	 * Private constructor.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * retrieves a handle to the system logger.  
	 * 
	 */
	private SessionManager() {
		_systemLogger = ASelectAgentSystemLogger.getHandle();
	}
}
