package org.aselect.server.request.handler.xsaml20.sp;

import java.security.PublicKey;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.logging.Level;

import org.aselect.server.request.handler.xsaml20.SoapLogoutRequestSender;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;
import org.aselect.system.storagemanager.handler.MemoryStorageHandler;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.SingleLogoutService;

/*
 * NOTE: Code is identical to JDBCStorageHandlerTimeOut (except for class-names of course)
 */
public class MemoryStorageHandlerTimeOut extends MemoryStorageHandler
{
	private final static String MODULE = "MemoryStorageHandlerTimeOut";
	private TGTManager _oTGTManager;
	private ConfigManager _oConfigManager;
	private ASelectSystemLogger _oSystemLogger;
	private String _serverUrl;
	private String _sFederationUrl;
	private boolean _bVerifySignature = false; 	

	@Override
	public void init(Object oConfigSection, ConfigManager oConfigManager, SystemLogger systemLogger, SAMAgent oSAMAgent)
	throws ASelectStorageException
	{
		String sMethod = "init()";

		super.init(oConfigSection, oConfigManager, systemLogger, oSAMAgent);
		_oSystemLogger = (ASelectSystemLogger)systemLogger;
		_oConfigManager = oConfigManager;
		_oTGTManager = TGTManager.getHandle();
		systemLogger.log(Level.INFO, MODULE, sMethod, "ConfigManager="+oConfigManager+" ConfigSection="+oConfigSection);

		try {
			Object aselectSection = _oConfigManager.getSection(null, "aselect");
			_serverUrl = _oConfigManager.getParam(aselectSection, "redirect_url");
		}
		catch (ASelectConfigException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_url' found in 'aselect' section", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		try {
			Object aselectSection = _oConfigManager.getSection(null, "aselect");
			_sFederationUrl = _oConfigManager.getParam(aselectSection, "federation_url");
		}
		catch (ASelectConfigException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'federation_url' found in 'aselect' section", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		set_bVerifySignature(false);
		try {
            Object _oTicketSection = _oConfigManager.getSection(null, "storagemanager", "id=tgt");
			String sVerifySignature = _oConfigManager.getParam(_oTicketSection, "verify_signature");
			if ("true".equalsIgnoreCase(sVerifySignature)) {
				set_bVerifySignature(true);
			}
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "verify_signature = " + is_bVerifySignature());
		}
		catch (ASelectConfigException e) {
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "verify_signature not found, set to = " + is_bVerifySignature());
		}
	}

	// Bauke: replacement
	public void put(Object oKey, Object oValue, Long lTimestamp)
	throws ASelectStorageException
	{
		String _sMethod = "put";
		Hashtable htValue = (Hashtable)oValue;

		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "MSHT "+this.getClass());
		if (!_oTGTManager.containsKey(oKey) || htValue.get("createtime") == null) {
			long now = new Date().getTime();
			htValue.put("createtime", String.valueOf(now));
			htValue.put("sessionsynctime", String.valueOf(now));
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "ADD createtime/sessionsync/timestamp=" + now);
		}
		
		// Special hack to prevent that the Timestamp is updated when only the "sessionsynctime" is changed
		String upd = (String)htValue.get("updatetimestamp");
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "updatetimestamp="+upd);
		if (upd != null && upd.equals("no")) {
			lTimestamp = _oTGTManager.getTimestamp(oKey);
			htValue.remove("updatetimestamp");
		}
		super.put(oKey, oValue, lTimestamp);
	}

	@Override
	public void cleanup(Long lTimestamp)
	throws ASelectStorageException
	{
		String _sMethod = "cleanup";
		Long now = new Date().getTime();

		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "CLEANUP { lTimestamp=" + (lTimestamp-now)+" class="+this.getClass());
		determineTimeOut();
		// Only the TGT Manager should use this class, therefore do not call super.cleanup()
		//super.cleanup(lTimestamp);
		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "} CLEANUP");
	}

	// When the TGT is expired, we need to send a Soap Logout Request to the Federation
	@SuppressWarnings("unchecked")
	private void determineTimeOut()
	throws ASelectStorageException
	{
		String _sMethod = "determineTimeOut";

		Hashtable allTgts = new Hashtable();
		if (_oTGTManager != null) {
			allTgts = (Hashtable) _oTGTManager.getAll();
		}
		if (allTgts == null)
			return;
		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "SPTO _serverUrl=" + _serverUrl +
					" - TGT Count=" + allTgts.size());
		
		// For all TGT's
		for (Enumeration<String> e = allTgts.keys(); e.hasMoreElements();) {
			String key = e.nextElement();
			Hashtable htTGTContext = (Hashtable) _oTGTManager.get(key);
			String sNameID = (String)htTGTContext.get("name_id");
			String sSync = (String)htTGTContext.get("sessionsynctime");
			Long lastSync = Long.parseLong(sSync);
			Long expireTime = _oTGTManager.getExpirationTime(key);
			Long timeStamp = _oTGTManager.getTimestamp(key);
			Long now = new Date().getTime();

			String sKey = (key.length() > 30) ? key.substring(0, 30) + "..." : key;
			_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "SPTO - NameID=" + sNameID + 
					" TimeStamp="+(timeStamp-now)+" Left=" + (expireTime - now) + 
					" lastSync=" + (lastSync-now)+" Key=" + sKey);
			
			// Check Ticket Expiration
			if (now >= expireTime) {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SPTO Remove TGT and send Logout, Key=" + sKey);
				_oTGTManager.remove(key);
				sendLogoutToFederation(sNameID);
			}

			// Check Session Sync
			try {
				//String errorCode = Errors.ERROR_ASELECT_SUCCESS;
				Hashtable htResult = SessionSyncRequestSender.getSessionSyncParameters(_oSystemLogger);
				Long updateInterval = (Long)htResult.get("update_interval");
				//String samlMessageType = (String)htResult.get("message_type");
				//String federationUrl = (String)htResult.get("federation_url");
				
				// Since the last Session Sync also update the TGT's timestamp
				// also skip a few seconds after lastSync
				if (timeStamp > lastSync+10 && now >= lastSync + updateInterval) {
					// Perform a Session Sync to the Federation
					_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "SPTO Skip this SessionSync");
					//SessionSyncRequestSender ss_req = new SessionSyncRequestSender(_oSystemLogger,
					//			_sRedirectUrl, updateInterval, samlMessageType, federationUrl);
					//errorCode = ss_req.synchronizeSession(key, false, false);  // credentials not crypted, no tgt upgrade
					//if (errorCode != Errors.ERROR_ASELECT_SUCCESS) {
					//	_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "SPTO Session Sync FAILED");
					//	throw new ASelectStorageException(errorCode);
					//}
				}
			}
			catch (ASelectException ase) {
				throw new ASelectStorageException(ase.toString());
			}
		}
	}

	private boolean sendLogoutToFederation(String sNameID)
	throws ASelectStorageException
	{
		String _sMethod = "sendLogoutToFederation";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SPTO (" + _serverUrl + ") - NameID to timeout = " + sNameID);
		SoapLogoutRequestSender logout = new SoapLogoutRequestSender();
		String url = null;
		MetaDataManagerSp metadataManager = null;
		try {
			metadataManager = MetaDataManagerSp.getHandle();
			url = metadataManager.getLocation(_sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,
					SAMLConstants.SAML2_SOAP11_BINDING_URI);
		}
		catch (ASelectException e1) {
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		String issuerUrl = _serverUrl;
		PublicKey pkey = null;
		if (is_bVerifySignature()) {
			pkey = metadataManager.getSigningKey(_sFederationUrl);
			if (pkey == null || "".equals(pkey)) {
				_oSystemLogger.log(Level.SEVERE, MODULE, _sMethod, "No valid public key in metadata");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
		try {
			logout.sendSoapLogoutRequest(url, issuerUrl, sNameID, "urn:oasis:names:tc:SAML:2.0:logout:sp-timeout", pkey);
		}
		catch (ASelectException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "exception trying to send Logout message", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		return false;
	}

	public synchronized boolean is_bVerifySignature() {
		return _bVerifySignature;
	}
	public synchronized void set_bVerifySignature(boolean verifySignature) {
		_bVerifySignature = verifySignature;
	}
}
