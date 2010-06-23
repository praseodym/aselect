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
package org.aselect.server.request.handler.xsaml20.sp;

import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * class MetaDataManagerIdp, this class is reading the aselect xml file. The aselect xml file contains the metadata xml
 * file information, this is the the location of the metadata xml file, this can be a pathname or URL
 */
/**
 * @author bauke
 *
 */
public class MetaDataManagerSp extends AbstractMetaDataManager
{
	private static MetaDataManagerSp metaDataManager = null;
	private final String sFederationIdpKeyword = "federation-idp";

	/**
	 * Private constructor --> singleton.
	 */
	private MetaDataManagerSp() {
	}

	/**
	 * Singleton.
	 * 
	 * @return the handle
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static MetaDataManagerSp getHandle()
		throws ASelectException
	{
		if (metaDataManager == null) {
			metaDataManager = new MetaDataManagerSp();
			metaDataManager.init();
		}
		return metaDataManager;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager#getMyRole()
	 */
	public String getMyRole()
	{
		return "SP";
	}
	
	/**
	 * Read Aselect.xml file This file contains the location of the metadata xml file
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	@Override
	protected void init()
		throws ASelectException
	{
		String sMethod = "init()";
		Object sam = null;
		Object agent = null;
		Object idpSection = null;

		super.init();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Role=" + getMyRole() + " id=" + sFederationIdpKeyword);

		sam = _configManager.getSection(null, "sam");
		agent = _configManager.getSection(sam, "agent");
		try {
			Object metaResourcegroup = _configManager.getSection(agent, "resourcegroup", "id=" + sFederationIdpKeyword);
			idpSection = _configManager.getSection(metaResourcegroup, "resource");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No resourcegroup: "+sFederationIdpKeyword+" configured");
		}

		while (idpSection != null) {
			// Look for "id" "url" and "session_sync"
			String sId = _configManager.getParam(idpSection, "id");
			PartnerData idpData = new PartnerData(sId);
			try {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "id="+sId);
				String metadataUrl = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "url", true);
				if (metadataUrl != null)
					idpData.setMetadataUrl(metadataUrl);
				
				String specialSettings = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "special_settings", false);
				if (specialSettings != null)
					idpData.setSpecialSettings(specialSettings);
				String myIssuer = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "local_issuer", false);
				if (myIssuer != null)
					idpData.setLocalIssuer(myIssuer);
				
				String sSessionSync = null;
				if (sId.equals("metadata")) { // 20091030: backward compatibility
					// Get from "saml20_sp_session_sync" handler
					Object oRequestsSection = _configManager.getSection(null, "requests");
					Object oHandlersSection = _configManager.getSection(oRequestsSection, "handlers");
					Object oHandler = _configManager.getSection(oHandlersSection, "handler",
											"id=saml20_sp_session_sync");
					sSessionSync = ASelectConfigManager.getSimpleParam(oHandler, "federation_url", true);
				}
				else {
					sSessionSync = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "session_sync", false);
				}
				if (sSessionSync != null) {
					idpData.setSessionSyncUrl(sSessionSync);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + "<>" + idpData);
				storeAllIdPData.put(sId, idpData);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Metadata retrieval failed", e);
			}
			idpSection = _configManager.getNextSection(idpSection);
		}
		initializeMetaDataHandling();
	}
}
