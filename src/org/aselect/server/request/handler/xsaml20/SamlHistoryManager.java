package org.aselect.server.request.handler.xsaml20;

import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.storagemanager.StorageManager;

/**
 * This class stores SAML messages that are being send, for future reference.
 * The messages are stored by their ID. The original message can be found by
 * looking for the in_response_to field in an incoming message. The SAML
 * messages are not stored as SAMLObjects because those are not Serializable.
 * The DOM is stored instead
 */
public class SamlHistoryManager extends StorageManager
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "SamlHistoryManager";

	/**
	 * The singleton instance of this object
	 */
	private static SamlHistoryManager _oSamlHistoryManager;

	/**
	 * The logger used for system logging
	 */
	private ASelectSystemLogger _systemLogger;

	/**
	 * Method to return an instance of the <code>TGTManager</code> instead of
	 * using the constructor. <br>
	 * 
	 * @return always the same <code>TGTManager</code> instance.
	 * @throws ASelectException
	 */
	public static SamlHistoryManager getHandle()
		throws ASelectException
	{
		if (_oSamlHistoryManager == null) {
			_oSamlHistoryManager = new SamlHistoryManager();
			_oSamlHistoryManager.init();
		}
		return _oSamlHistoryManager;
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
				oSsoSessionSection = oASelectConfigManager.getSection(null, "storagemanager", "id=saml_history");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'storagemanager' config section found with id='saml_history'", e);
				throw e;
			}

			super.init(oSsoSessionSection, oASelectConfigManager, _systemLogger, ASelectSAMAgent.getHandle());
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully initialized Saml History Manager");
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error initializing the Saml History Manager", e);
			throw e;
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error while initializing Saml History Manager", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

}
