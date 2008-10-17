package org.aselect.server.request.handler.saml20.idp.authentication;

import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Level;

import org.aselect.server.request.handler.saml20.common.BackChannelLogoutRequestSender;
import org.aselect.server.request.handler.saml20.idp.metadata.MetaDataManagerIDP;
import org.aselect.server.tgt.TGTManager;
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

/**
 * MemoryStorageHandlerTimeOut. <br>
 * <br>
 * <b>Description:</b><br>
 * This class is used for timeout. <br>
 * <br>
 * <br>
 * <br>
 * 
 * @author Atos Origin
 */
public class MemoryStorageHandlerTimeOut extends MemoryStorageHandler
{
	private final static String MODULE = "MemoryStorageHandlerTimeOut";
	private TGTManager _oTGTManager;
	private SystemLogger _oSystemLogger;
	private String timeOut;
	long timeOutTime = 0L;
	private String _serverUrl;

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
        catch(ASelectConfigException e) {
            systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'storagemanager' config section found with id='tgt'", e);
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
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Timeout time on IDP = " + timeOutTime);
		}
		catch (ASelectConfigException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'timeout' found", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	// Bauke: added
	// "createtime" is used to implement the "Danish" logout
	// When now() > createtime + timeout-value -> Logout
	@Override
	public void put(Object oKey, Object oValue, Long lTimestamp)
		throws ASelectStorageException
	{
		String _sMethod = "put";
		Hashtable htValue = (Hashtable)oValue;

		if (!_oTGTManager.containsKey(oKey) || htValue.get("createtime") == null) {
			long now = new Date().getTime();
			htValue.put("createtime", String.valueOf(now));
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Added createtime=" + now);
		}
		super.put(oKey, oValue, lTimestamp);
	}

	// Called from system.StorageManager: Cleaner.run()
	@Override
	public void cleanup(Long lTimestamp)
		throws ASelectStorageException
	{
		String _sMethod = "cleanup";
		long now = new Date().getTime();

		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "CLEANUP { lTimestamp=" + (lTimestamp-now)+" class="+this.getClass());
		checkSpTimeOut();
		// Only the TGT Manager should use this class, so no super.cleanup()
		// super.cleanup(lTimestamp);
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "} CLEANUP");
	}

	/**
	 * Check for sp's that need to be time out <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method checks if there are sp's that need to be timeout <br>
	 * 
	 * @throws ASelectException
	 *             If check fails.
	 */
	@SuppressWarnings("unchecked")
	private void checkSpTimeOut()
		throws ASelectStorageException
	{
		String _sMethod = "checkSpTimeOut";
		long now = new Date().getTime();
		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "IDPTO now="+now);

		Hashtable allTgts = new Hashtable();
		try {
			SSOSessionManager sessionManager = SSOSessionManager.getHandle();
			if (_oTGTManager != null) {
				allTgts = _oTGTManager.getAll();
			}
			if (allTgts == null)
				return;
			_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "IDPTO - TGT Count=" + allTgts.size());

			// For all TGT's
			for (Enumeration<String> e = allTgts.keys(); e.hasMoreElements();) {
				String key = e.nextElement();
				// Get TGT
				Hashtable htTGTContext = (Hashtable) _oTGTManager.get(key);
				String uid = (String) htTGTContext.get("uid");
		        Long lExpInterval = _oTGTManager.getExpirationTime(key) - _oTGTManager.getTimestamp(key);
				// Get the user's session too
				UserSsoSession ssoSession = sessionManager.getSsoSession(uid);
				List<ServiceProvider> spList = ssoSession.getServiceProviders();
				String sKey = (key.length() > 30) ? key.substring(0, 30) + "..." : key;
				String sCreateTime = (String)htTGTContext.get("createtime");
				long lCreateTime = 0;
				try {
					lCreateTime = Long.parseLong(sCreateTime);
				} catch (Exception exc) {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "CreateTime was not set");
				}
				boolean danishLogout = (now >= lCreateTime + timeOutTime);
				_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "ExpInt="+lExpInterval+
						" Timeout="+timeOutTime+" Create="+(lCreateTime-now) + " Danish="+danishLogout);
				for (ServiceProvider sp : spList) {
					_oSystemLogger.log(Level.FINER, MODULE, _sMethod, " IDPTO - Uid=" + uid +
							" key=" + sKey + " SP=" + sp.getServiceProviderUrl() +
							" LastSessionSync=" + (sp.getLastSessionSync()-now));
				}

				// For all SP's attached to this TGT
				for (ServiceProvider sp : spList) {
					long spLastSync = sp.getLastSessionSync();
					
					if (spLastSync == 0) {
						_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "CIO - lastsync was not set!");
						spLastSync = _oTGTManager.getTimestamp(key);
					}
					_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "IDPTO - ListSize="+spList.size()+
								" ExpInt=" + lExpInterval + " LastSync=" + (spLastSync - now) +
								" Left="+(spLastSync+lExpInterval-now)+" SP=" + sp.getServiceProviderUrl());
					if (danishLogout || spLastSync < now - lExpInterval) {  // was: timeLimitSp) {
						if (spList.size() == 1) {
							_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDPTO - Remove TGT Key=" + sKey);
							_oTGTManager.remove(key);
							_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDPTO - Remove Session Key=" + uid);
							sessionManager.remove(uid);
						}
						else {
							_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDPTO - Remove SP="
									+ sp.getServiceProviderUrl() + " from TGT Key=" + sKey);
							ssoSession.removeServiceProvider(sp.getServiceProviderUrl());
							// overwrite the session (needed for database storage)
							sessionManager.putSsoSession(ssoSession);
						}
						_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "IDPTO - Send Logout to SP="
								+ sp.getServiceProviderUrl());
						sendLogOutRequest(uid, sp.getServiceProviderUrl());
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
	 * 
	 * @param uid
	 *            String with the user id
	 * @param urlSp
	 *            String where to send logout request
	 * @throws ASelectException
	 *             If send request fails.
	 */
	private void sendLogOutRequest(String uid, String urlSp)
		throws ASelectException
	{
		String _sMethod = "checkSpTimeOut";
		String user = uid;
		BackChannelLogoutRequestSender requestSender = new BackChannelLogoutRequestSender();
		MetaDataManagerIDP metadataManager = MetaDataManagerIDP.getHandle();
		String url = metadataManager.getLocation(urlSp, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,
				SAMLConstants.SAML2_SOAP11_BINDING_URI);
		try {
			requestSender.sendLogoutRequest(url, _serverUrl, user, "logout:sp-timeout");
		}
		catch (ASelectException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "IDP - exception trying too send logout request", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Get a readable date for logging <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method returns the timestamp in a human readable form for logging
	 * <br>
	 * 
	 * @param timestamp
	 *            Long with timestamp
	 * @return String that is readable for in log.
	 */
	private String getReadableDate(long timestamp)
	{
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(new Date(timestamp));
		StringBuffer temp = new StringBuffer();

		temp.append(calendar.get(Calendar.DAY_OF_MONTH));
		temp.append('.');
		temp.append(calendar.get(Calendar.MONTH) + 1);
		temp.append('.');
		temp.append(calendar.get(Calendar.YEAR));

		temp.append(' ');
		temp.append(calendar.get(Calendar.HOUR_OF_DAY));
		temp.append(':');
		temp.append(calendar.get(Calendar.MINUTE));
		temp.append(':');
		temp.append(calendar.get(Calendar.SECOND));

		return temp.toString();
	}

	@Override
	public void destroy()
	{
		_oTGTManager = null;
		super.destroy();
	}

}
