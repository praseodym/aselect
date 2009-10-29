package org.aselect.server.request.handler.xsaml20.sp;

import java.security.PublicKey;
import java.util.logging.Level;
import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

/**
 * class MetaDataManagerIdp, this class is reading the aselect xml file. The
 * aselect xml file contains the metadata xml file information, this is the the
 * location of the metadata xml file, this can be a pathname or URL
 * 
 */
public class MetaDataManagerSp extends AbstractMetaDataManager
{
	private static MetaDataManagerSp metaDataManager = null;

	/**
	 * Constructor
	 */
	private MetaDataManagerSp() {
	}

	/**
	 * Singleton
	 * 
	 * @throws ASelectException
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
	 */
	protected void init()
	throws ASelectException
	{
		String sMethod = "init()";
		Object sam = null;
		Object agent = null;
		Object idp = null;
		
		super.init();
		myRole = "SP";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Role="+myRole);

		sam = _configManager.getSection(null, "sam");
		agent = _configManager.getSection(sam, "agent");
		Object metaResourcegroup = _configManager.getSection(agent, "resourcegroup", "id="+sFederationIdpKeyword);
		
		idp = _configManager.getSection(metaResourcegroup, "resource");
		while (idp != null) {
			String sId = _configManager.getParam(idp, "id");
			//if (sId.equals(sFederationIdpKeyword)) {
			try {
			//	resource = _configManager.getSection(resourcegroup, "resource", "id=metadata");
			//	metadata = (Element) _configManager.getSection(resource, "url");
				String metadata = _configManager.getParam(idp, "url");
				if (metadata != null) {
			//		_systemLogger.log(Level.INFO, MODULE, sMethod, "metadata="+sId+"<>"+metadata.getFirstChild().getTextContent());
			//		metadataSPs.put(sId, metadata.getFirstChild().getTextContent());
					_systemLogger.log(Level.INFO, MODULE, sMethod, "id="+sId+"<>"+metadata);
					metadataSPs.put(sId, metadata);
				}
				String sSessionSync = _configManager.getParam(idp, "session_sync");
				if (sSessionSync != null) {
					sessionSyncSPs.put(sId, sSessionSync);
				}
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Metadata retrieval failed", e);
			}
			//}
			idp = _configManager.getNextSection(idp);
		}
		initializeMetaDataHandling();
	}

	/**
	 * Retrieve the session sync URL for the given entity id.
	 * 
	 * @param entityId
	 * @return The session sync URL, or null on errors.
	 */
	public String getSessionSyncURL(String entityId)
	{
		String sMethod = "getSessionSyncURL";

		String sUrl = sessionSyncSPs.get(entityId);
		if (sUrl == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity id: " + entityId + " is not Configured");
			return null;
		}
		return sUrl;
	}
}
