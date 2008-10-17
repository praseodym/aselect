package org.aselect.server.request.handler.saml20.sp.metadata;

import java.util.logging.Level;

import org.aselect.server.request.handler.saml20.common.MetaDataManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.w3c.dom.Element;

/**
 * class MetaDataManager, this class is reading the aselect xml file. The
 * aselect xml file contains the metadata xml file information, this is the the
 * location of the metadata xml file, this can be a pathname or URL
 * 
 * @author Nazif Aksay
 * 
 */
public class MetaDataManagerSP extends MetaDataManager
{
	private static MetaDataManagerSP metaDataManager = null;

	/**
	 * Constructor
	 */
	private MetaDataManagerSP() {
	}

	/**
	 * Singleton
	 * 
	 * @throws ASelectException
	 */
	public static MetaDataManagerSP getHandle()
		throws ASelectException
	{
		if (metaDataManager == null) {
			metaDataManager = new MetaDataManagerSP();
			metaDataManager.init();
		}
		return metaDataManager;
	}

	/**
	 * Read Aselect.xml file This file contains the location of the metadata xml
	 * file
	 * 
	 * @throws ASelectException
	 */
	protected void init()
	throws ASelectException
	{
		String sMethod = "init()";
		Object sam = null;
		Object agent = null;
		Object resourcegroup = null;
		Object resource = null;
		Element metadata = null;

		super.init();
		myRole = "SP";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Role="+myRole);

		sam = _configManager.getSection(null, "sam");
		agent = _configManager.getSection(sam, "agent");
		resourcegroup = _configManager.getSection(agent, "resourcegroup");

		while (resourcegroup != null) {

			String sId = _configManager.getParam(resourcegroup, "id");
			if (sId.equals(sFederationIdpKeyword)) {
				try {
					resource = _configManager.getSection(resourcegroup, "resource", "id=metadata");
					metadata = (Element) _configManager.getSection(resource, "url");
					if (metadata != null) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "metadata="+sId+"<>"+metadata.getFirstChild().getTextContent());
						metadataSPs.put(sId, metadata.getFirstChild().getTextContent());
					}
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'metadata' found", e);
				}
			}
			resourcegroup = _configManager.getNextSection(resourcegroup);
		}
		getMetaDataProviderfromList();
	}
}
