package org.aselect.server.request.handler.saml20.idp.authentication;

import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.storagemanager.StorageManager;
import org.aselect.server.request.handler.saml20.common.Utils;

/**
 * This class stores UserSsoSession to the configured storagemanager in a
 * key-value pair. The key is the userId, the value is the UserSsoSession.
 */
public class SSOSessionManager extends StorageManager
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "SSOSessionManager";

	/**
	 * The singleton instance of this object
	 */
	private static SSOSessionManager _oSsoSessionManager;

	/**
	 * The logger used for system logging
	 */
	private ASelectSystemLogger _systemLogger;

	/**
	 * Method to return an instance of the <code>SSOSessionManager</code>
	 * instead of using the constructor. <br>
	 * 
	 * @return always the same <code>SSOSessionManager</code> instance.
	 * @throws ASelectException
	 */
	public static SSOSessionManager getHandle()
		throws ASelectException
	{
		if (_oSsoSessionManager == null) {
			_oSsoSessionManager = new SSOSessionManager();
			_oSsoSessionManager.init();
		}
		return _oSsoSessionManager;
	}

	public void init()
		throws ASelectException
	{
		String sMethod = "init()";
		ASelectConfigManager oASelectConfigManager = null;
		Object oSsoSessionSection = null;

		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			oASelectConfigManager = ASelectConfigManager.getHandle();

			try {
				oSsoSessionSection = oASelectConfigManager.getSection(null, "storagemanager", "id=sso_session");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'storagemanager' config section found with id='sso_session'", e);
				throw e;
			}

			super.init(oSsoSessionSection, oASelectConfigManager, _systemLogger, ASelectSAMAgent.getHandle());
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully initialized SSO Session Manager");
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error initializing the SSO Session storage", e);
			throw e;
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger
					.log(Level.SEVERE, MODULE, sMethod, "Internal error while initializing SSO Session Manager", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * stores a user sso session. If there was no session stored for the user it
	 * stores the session with the user name as key and the session as value. If
	 * there already was a session stored with the user as key it gets
	 * overwritten
	 * 
	 * @param session
	 * @throws ASelectException
	 */
	public void putSsoSession(UserSsoSession session)
	throws ASelectException
	{
		String sMethod = "putSsoSession()";
		String sKey = session.getUserId();  // BETTER: getTgtId();

		if (session == null || sKey == null) {  // xxx session.getUserId() == null) {
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT);
		}
		try {
			// delSsoSession(session.getUserId()); // Bauke: was NOT overwritten??
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SESN User=" + session.getUserId()+
					" key="+Utils.firstPartOf(sKey));
			put(sKey, session);
		}
		catch (ASelectStorageException e) {
			if (e.getMessage().equals(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Maximum number of stored service providers reached", e);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_BUSY, e);
			}
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not store user sso session", e);
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Internal error while storing user sso session", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * retrieves the UserSsoSession for this user
	 * 
	 * @param sKey - the user for which to retrieve the session
	 * @return UserSsoSession
	 */
	public UserSsoSession getSsoSession(String sKey)
	{
		String sMethod = "getSsoSession()";

		UserSsoSession session = null;
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SESN Key=" + sKey);
			session = (UserSsoSession)get(sKey);
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "No sso session found for key=" + sKey, e);
		}
		return session;
	}

	/**
	 * Removes the user and its service providers from storage
	 * 
	 * @param sKey - the user to remove
	 */
	public void delSsoSession(String sKey)
	{
		String sMethod = "delSsoSession()";
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SESN Key=" + sKey);
			remove(sKey);
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot remove sso session for key=" + sKey, e);
		}
	}
}
