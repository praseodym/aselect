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

import java.util.logging.Level;

import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.w3c.dom.Element;

// TODO: Auto-generated Javadoc
/**
 * class MetaDataManagerIdp, this class is reading the aselect xml file. The aselect xml file contains the metadata xml
 * file information, this is the the location of the metadata xml file, this can be a pathname or URL
 * 
 * @author Nazif Aksay
 */
public class MetaDataManagerIdp extends AbstractMetaDataManager
{
	private static MetaDataManagerIdp metaDataManager = null;

	/**
	 * Instantiates a new meta data manager idp.
	 */
	private MetaDataManagerIdp() {
	}

	/**
	 * Singleton.
	 * 
	 * @return the handle
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static MetaDataManagerIdp getHandle()
		throws ASelectException
	{
		if (metaDataManager == null) {
			metaDataManager = new MetaDataManagerIdp();
			metaDataManager.init();
		}
		return metaDataManager;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager#getMyRole()
	 */
	public String getMyRole()
	{
		return "IDP";
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
		Object applications = null;
		Object application = null;

		super.init();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Role=" + getMyRole());
		try {
			applications = _configManager.getSection(null, "applications");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config section 'applications' found within aselect.xml", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		try {
			application = _configManager.getSection(applications, "application");
			addMetaDataURLToList(application);
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'application' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		while (application != null) {
			try {
				application = _configManager.getNextSection(application);
				addMetaDataURLToList(application);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config next section 'application' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		initializeMetaDataHandling();
	}

	/**
	 * This method reads the aslect.xml and puts all meta_data xml file pathnames in the metaDataUrls List
	 * 
	 * @param application
	 *            the application
	 */
	protected void addMetaDataURLToList(Object application)
	{
		String sMethod = "addMetaDataURLToList()";
		String sId = null;
		Element metadata = null;

		if (application == null)
			return;

		try {
			sId = _configManager.getParam(application, "id");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Application 'id' is missing", e);
			return;
		}
		try {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "id=" + sId);
			metadata = (Element) _configManager.getSection(application, "meta_data");
		}
		catch (ASelectConfigException e) { // ignore
		}
		if (metadata != null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "metadata=" + sId + "<>"
					+ metadata.getFirstChild().getTextContent());
			PartnerData idpData = new PartnerData(sId);
			idpData.setMetadataUrl(metadata.getFirstChild().getTextContent());
			storeAllIdPData.put(sId, idpData);
			// 20100428: metadataSPs.put(sId, metadata.getFirstChild().getTextContent());
		}
	}
}
