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
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

// TODO: Auto-generated Javadoc
/**
 * class MetaDataManagerIdp, this class is reading the aselect xml file. The aselect xml file contains the metadata xml
 * file information, this is the the location of the metadata xml file, this can be a pathname or URL
 */
public class MetaDataManagerSp extends AbstractMetaDataManager
{
	private static MetaDataManagerSp metaDataManager = null;
	private final String sFederationIdpKeyword = "federation-idp";

	/**
	 * Constructor.
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
		myRole = "SP";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Role=" + myRole);

		sam = _configManager.getSection(null, "sam");
		agent = _configManager.getSection(sam, "agent");
		Object metaResourcegroup = _configManager.getSection(agent, "resourcegroup", "id=" + sFederationIdpKeyword);

		idpSection = _configManager.getSection(metaResourcegroup, "resource");
		while (idpSection != null) {
			String sId = _configManager.getParam(idpSection, "id");
			try {
				String metadata = _configManager.getParam(idpSection, "url");
				String sSessionSync = null;
				if (metadata != null) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + "<>" + metadata);
					metadataSPs.put(sId, metadata);
				}
				if (sId.equals("metadata")) { // 20091030: backward compatibility
					// Get from "saml20_sp_session_sync" handler
					Object oRequestsSection = _configManager.getSection(null, "requests");
					Object oHandlersSection = _configManager.getSection(oRequestsSection, "handlers");
					Object oHandler = _configManager.getSection(oHandlersSection, "handler",
							"id=saml20_sp_session_sync");
					sSessionSync = ASelectConfigManager.getSimpleParam(oHandler, "federation_url", true);
				}
				else {
					sSessionSync = _configManager.getParam(idpSection, "session_sync");
				}
				if (sSessionSync != null) {
					sessionSyncSPs.put(sId, sSessionSync);
				}
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Metadata retrieval failed", e);
			}
			idpSection = _configManager.getNextSection(idpSection);
		}
		initializeMetaDataHandling();
	}
}
