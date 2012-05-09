/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.server.request.handler.xsaml20.idp;

import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import org.aselect.server.request.handler.xsaml20.ServiceProvider;
import org.aselect.server.request.handler.xsaml20.SoapLogoutRequestSender;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;
import org.aselect.system.storagemanager.handler.JDBCStorageHandler;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.SingleLogoutService;

/*
 * NOTE: Code is identical to MemoryStorageHandlerTimeOut (except for class-names of course).
 *       Though it is different from the sp-version.
 */
public class JDBCStorageHandlerTimeOut extends JDBCStorageHandler
{
	private final static String MODULE = "JDBCStorageHandlerTimeOut";
	private TGTManager _oTGTManager;
	private SystemLogger _oSystemLogger;
	private String timeOut;
	long timeOutTime = 0L;
	private String _serverUrl;
	private boolean _bVerifySignature = false;

	/* (non-Javadoc)
	 * @see org.aselect.system.storagemanager.handler.JDBCStorageHandler#init(java.lang.Object, org.aselect.system.configmanager.ConfigManager, org.aselect.system.logging.SystemLogger, org.aselect.system.sam.agent.SAMAgent)
	 */
	@Override
	public void init(Object oConfigSection, ConfigManager oConfigManager, SystemLogger systemLogger, SAMAgent oSAMAgent)
		throws ASelectStorageException
	{
		String sMethod = "init()";
		Object oTicketSection;

		super.init(oConfigSection, oConfigManager, systemLogger, oSAMAgent);
		_oSystemLogger = systemLogger;
		_oTGTManager = TGTManager.getHandle();

		// oConfigSection is null, so retrieve the section ourselves
		try {
			oTicketSection = oConfigManager.getSection(null, "storagemanager", "id=tgt");
		}
		catch (ASelectConfigException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid 'storagemanager' config section found with id='tgt'", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		try {
			Object aselectSection = oConfigManager.getSection(null, "aselect");
			_serverUrl = oConfigManager.getParam(aselectSection, "redirect_url");
		}
		catch (ASelectConfigException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_url' found in 'aselect' section", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		try {
			timeOut = oConfigManager.getParam(oTicketSection, "timeout");
			timeOutTime = Long.parseLong(timeOut);
			timeOutTime = timeOutTime * 1000;
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Absolute timeout on IDP = " + timeOutTime);
		}
		catch (ASelectConfigException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'timeout' found", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		set_bVerifySignature(false);
		try {
			String sVerifySignature = oConfigManager.getParam(oTicketSection, "verify_signature");
			if ("true".equalsIgnoreCase(sVerifySignature)) {
				set_bVerifySignature(true);
			}
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "verify_signature = " + is_bVerifySignature());
		}
		catch (ASelectConfigException e) {
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "verify_signature not found, set to = "
					+ is_bVerifySignature());
		}
	}

	// Bauke: added
	// "createtime" is used to implement the "Danish" logout
	// When now() > createtime + timeout-value -> Logout
	/* (non-Javadoc)
	 * @see org.aselect.system.storagemanager.handler.JDBCStorageHandler#put(java.lang.Object, java.lang.Object, java.lang.Long)
	 */
	@Override
	public void put(Object oKey, Object oValue, Long lTimestamp)
		throws ASelectStorageException
	{
		String _sMethod = "put";
		HashMap htValue = (HashMap) oValue;

		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Class=" + this.getClass());
		boolean hasKey = false;	// RH, 20111114, n
		// We'll use a small (not most beautiful) trick to speed up the "put" later on
//		if (!_oTGTManager.containsKey(oKey) || htValue.get("createtime") == null) {	// RH, 20111114, o
		if (!(hasKey =_oTGTManager.containsKey(oKey)) || htValue.get("createtime") == null) {	// RH, 20111114, n
			long now = new Date().getTime();
			htValue.put("createtime", String.valueOf(now));
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Added createtime=" + now);
		}
//		super.put(oKey, oValue, lTimestamp);	// RH, 20111114, o
		super.put(oKey, oValue, lTimestamp, hasKey ? UpdateMode.UPDATEFIRST : UpdateMode.INSERTFIRST);	// RH, 20111114, n
		
	}
	
	

	// Called from system.StorageManager: Cleaner.run()
	/* (non-Javadoc)
	 * @see org.aselect.system.storagemanager.handler.JDBCStorageHandler#cleanup(java.lang.Long)
	 */
	@Override
	public void cleanup(Long lTimestamp)
		throws ASelectStorageException
	{
		String _sMethod = "cleanup";
		long now = new Date().getTime();

		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "CLEANUP { lTimestamp=" + (lTimestamp - now) + " class="
				+ this.getClass());
		checkTimeoutCondition();
		// Only the TGT Manager should use this class, so no super.cleanup()
		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "} CLEANUP");
	}

	/**
	 * Check for sp's that need to be time out <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method checks if there are sp's that need to be timeout <br>
	 * .
	 * 
	 * @throws ASelectException
	 *             If check fails.
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 */
	@SuppressWarnings("unchecked")
	private void checkTimeoutCondition()
		throws ASelectStorageException
	{
		String _sMethod = "checkTimeoutCondition";
		long now = new Date().getTime();
		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "IDPTO now=" + now);

		HashMap allTgts = new HashMap();
		try {
			if (_oTGTManager != null) {
				allTgts = _oTGTManager.getAll();
			}
			if (allTgts == null)
				return;
			_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "IDPTO - TGT Count=" + allTgts.size());

			// For all TGT's
			Set keys = allTgts.keySet();
			for (Object s : keys) {
				String key = (String) s;
				// for (Enumeration<String> e = allTgts.keys(); e.hasMoreElements();) {
				// String key = e.nextElement();
				// Get TGT
				HashMap htTGTContext = (HashMap) _oTGTManager.get(key);
				String sNameID = (String) htTGTContext.get("name_id");
				Long lExpInterval = _oTGTManager.getExpirationTime(key) - _oTGTManager.getTimestamp(key);

				// Get the user's session
				UserSsoSession sso = (UserSsoSession) htTGTContext.get("sso_session");
				List<ServiceProvider> spList = sso.getServiceProviders();

				String sCreateTime = (String) htTGTContext.get("createtime");
				long lCreateTime = 0;
				try {
					lCreateTime = Long.parseLong(sCreateTime);
				}
				catch (Exception exc) {
					_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "CreateTime was not set");
				}
				boolean danishLogout = (now >= lCreateTime + timeOutTime);

				// debug
				_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "ExpInt=" + lExpInterval + " Timeout=" + timeOutTime
						+ " Create=" + (lCreateTime - now) + " Danish=" + danishLogout + " Initiator="
						+ sso.getLogoutInitiator());
				String sKey = (key.length() > 30) ? key.substring(0, 30) + "..." : key;
				for (ServiceProvider sp : spList) {
					_oSystemLogger.log(Level.FINER, MODULE, _sMethod, " IDPTO - NameID=" + sNameID + " key=" + sKey
							+ " LastSessionSync=" + (sp.getLastSessionSync() - now));
				}

				// For all SP's attached to this TGT
				for (ServiceProvider sp : spList) {
					long spLastSync = sp.getLastSessionSync();

					if (spLastSync == 0) {
						_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "CIO - lastsync was not set!");
						spLastSync = _oTGTManager.getTimestamp(key);
					}
					_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "IDPTO - ListSize=" + spList.size()
							+ ((danishLogout) ? " DANISH" : "") + ((spLastSync < now - lExpInterval) ? " EXPIRED" : "")
							+ " ExpInt=" + lExpInterval + " LastSync=" + (spLastSync - now) + " Left="
							+ (spLastSync + lExpInterval - now) + " SP=" + sp.getServiceProviderUrl());
					if (danishLogout || spLastSync < now - lExpInterval) { // was: timeLimitSp) {
						if (spList.size() == 1) {
							_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDPTO - Remove TGT Key=" + sKey);
							_oTGTManager.remove(key);
						}
						else {
							_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDPTO - Remove SP="
									+ sp.getServiceProviderUrl() + " from TGT Key=" + sKey);
							sso.removeServiceProvider(sp.getServiceProviderUrl());
							// Overwrite the TGT (needed for database storage)
							_oTGTManager.updateTGT(key, htTGTContext);
						}
						_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDPTO - Send Logout to SP="
								+ sp.getServiceProviderUrl());
						sendLogoutRequestToSp(sNameID, sp.getServiceProviderUrl());
					}
				}
			}
		}
		catch (ASelectException ex) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "IDPTO - Exception in checkSpTimeOut", ex);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Send Logout request to sp <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method sends a logout request to the sp that has to timeout <br>
	 * .
	 * 
	 * @param sNameID
	 *            String with the NameID
	 * @param urlSp
	 *            String where to send logout request
	 * @throws ASelectException
	 *             If send request fails.
	 */
	private void sendLogoutRequestToSp(String sNameID, String urlSp)
		throws ASelectException
	{
		String _sMethod = "sendLogOutRequest";
		SoapLogoutRequestSender requestSender = new SoapLogoutRequestSender();
		MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
		String url = metadataManager.getLocation(urlSp, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,
				SAMLConstants.SAML2_SOAP11_BINDING_URI);

		PublicKey pkey = null;
		if (is_bVerifySignature()) {
			pkey = metadataManager.getSigningKeyFromMetadata(urlSp);
			if (pkey == null || "".equals(pkey)) {
				_oSystemLogger.log(Level.SEVERE, MODULE, _sMethod, "No valid public key in metadata");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
		try {  // Sign with our private key!
			requestSender.sendSoapLogoutRequest(url, _serverUrl, sNameID, "urn:oasis:names:tc:SAML:2.0:logout:sp-timeout", pkey);
		}
		catch (ASelectException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "IDP - exception trying to send logout request", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Checks if is _b verify signature.
	 * 
	 * @return true, if is _b verify signature
	 */
	public synchronized boolean is_bVerifySignature()
	{
		return _bVerifySignature;
	}

	/**
	 * Sets the _b verify signature.
	 * 
	 * @param verifySignature
	 *            the new _b verify signature
	 */
	public synchronized void set_bVerifySignature(boolean verifySignature)
	{
		_bVerifySignature = verifySignature;
	}
}
