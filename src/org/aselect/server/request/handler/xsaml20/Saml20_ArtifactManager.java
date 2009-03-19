/*
 * Created on 21-aug-2007
 * 20081109: added RelayState to the Artifact redirection
 */
package org.aselect.server.request.handler.xsaml20;

import java.io.IOException;
import java.io.StringReader;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.storagemanager.StorageManager;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class Saml20_ArtifactManager extends StorageManager
{
	private static final String MODULE = "Saml20_ArtifactManager";
	private ASelectSystemLogger _systemLogger;
	
	// Make me a singleton
	private static Saml20_ArtifactManager artifactManager;

	public static Saml20_ArtifactManager getTheArtifactManager()
		throws ASelectException
	{
		if (artifactManager == null) {
			artifactManager = new Saml20_ArtifactManager();
			artifactManager.init();
		}
		return artifactManager;
	}
	
	// Don't allow others to create me
	private Saml20_ArtifactManager()
	{	
	}

	/**
	 * Send Artifact. <br>
	 * 
	 * @param sArtifact
	 *            String with Artifact.
	 * @param samlObject
	 *            SAMLObject.
	 * @throws IOException
	 *             If sending and storing off Artifact fails.
	 * @throws ASelectStorageException
	 */
	public void sendArtifact(String sArtifact, SAMLObject samlObject, String sAppUrl,
			HttpServletResponse oHttpServletResponse, String sRelayState)
		throws IOException, ASelectStorageException
	{
		String sMethod = "sendArtifact()";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Store");
		putArtifactInStorage(sArtifact, samlObject);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Encode");
		String uencArtifact = URLEncoder.encode(sArtifact, "UTF-8");
		String sRedirectUrl = sAppUrl + "?SAMLart=" + uencArtifact;
		if (sRelayState != null)
			sRedirectUrl += "&RelayState=" + URLEncoder.encode(sRelayState, "UTF-8");

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + sRedirectUrl);
		// RH, 20081113, Set appropriate headers here
		oHttpServletResponse.setHeader("Cache-Control", "no-cache, no-store");
		oHttpServletResponse.setHeader("Pragma", "no-cache");
		oHttpServletResponse.sendRedirect(sRedirectUrl);
		
	}

//	private void putArtifactInStorage(Object key, SAMLObject samlObject) // RH, 20080715, o
	// We want an XMLObject out
	// So we should put an XMLObject in
	private void putArtifactInStorage(Object key, XMLObject samlObject)  // RH, 20080715, n
	throws ASelectStorageException
	{
		String sMethod = "putArtifactInStorage";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "key="+key);

		Element dom = samlObject.getDOM();
//		if (samlObject.getDOM() == null) {
		if (dom == null) {
			// object was not marshalled
			try {
				dom = SamlTools.marshallMessage(samlObject);
			}
			catch (MessageEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error while marshalling message", e);
				throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, e);
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "put key="+key);
		
		// Save as string because these SAML XMLObjects don't want to serialize very well
		super.put(key, XMLHelper.nodeToString(dom));
//		super.put(key, dom);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "put done");
		
		// debug:
		/*HashMap htAll = super.getAll();
        Enumeration eKeys = htAll.keys();
        while (eKeys.hasMoreElements())
        {
            Object oKey = eKeys.nextElement();
    		_systemLogger.log(Level.INFO, MODULE, sMethod, "key="+oKey);            
            HashMap xStorageContainer = (HashMap)htAll.get(oKey);
            Object oValue = xStorageContainer.get("contents");
    		_systemLogger.log(Level.INFO, MODULE, sMethod, "key="+oKey+" contents="+oValue.toString());            
        }*/
	}

	
	// We want an XMLObject removed
	private void removeArtifactFromStorage(Object key)  // RH, 2008113, n
	throws ASelectStorageException
	{
		String sMethod = "removeArtifactFromStorage";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "key="+key);

		// Remove the object from underlying storage
		super.remove(key);
//		super.put(key, dom);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "remove done");
		
		// debug:
		/*HashMap htAll = super.getAll();
        Enumeration eKeys = htAll.keys();
        while (eKeys.hasMoreElements())
        {
            Object oKey = eKeys.nextElement();
    		_systemLogger.log(Level.INFO, MODULE, sMethod, "key="+oKey);            
            HashMap xStorageContainer = (HashMap)htAll.get(oKey);
            Object oValue = xStorageContainer.get("contents");
    		_systemLogger.log(Level.INFO, MODULE, sMethod, "key="+oKey+" contents="+oValue.toString());            
        }*/
	}

	
	
	
	/**
	 * Gets Artifact from Storage. <br>
	 * 
	 * @param key Object.
	 * @return Object
	 * @throws ASelectStorageException
	 * @throws ParserConfigurationException 
	 * @throws IOException 
	 * @throws SAXException 
	 */
	public XMLObject getArtifactFromStorage(Object key)
		throws ASelectStorageException, ParserConfigurationException, SAXException, IOException
	{
		String sMethod = "getArtifactFromStorage";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "get key="+key);
		
		// debug:
		/*HashMap htAll = super.getAll();
        Enumeration eKeys = htAll.keys();
        while (eKeys.hasMoreElements())
        {
            Object oKey = eKeys.nextElement();
            HashMap xStorageContainer = (HashMap)htAll.get(oKey);
            Object oValue = xStorageContainer.get("contents");
    		_systemLogger.log(Level.INFO, MODULE, sMethod, "key="+oKey+" contents="+oValue);            
        }*/

		// Element dom = (Element)super.get(key);
		
		
		String serializedObject = (String)super.get(key);
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
//		dbFactory.setExpandEntityReferences(false);
//		dbFactory.setIgnoringComments(true);
		StringReader stringReader = new StringReader(serializedObject);
		InputSource inputSource = new InputSource(stringReader);

		DocumentBuilder builder = null;
		Document samlResponse = null;
		Element dom = null;
		builder = dbFactory.newDocumentBuilder();
		samlResponse = builder.parse(inputSource);
		dom = samlResponse.getDocumentElement();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "get dom="+dom);
		
		XMLObject xmlObject = null;
		try {
			xmlObject = SamlTools.unmarshallElement(dom);
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error while marshalling message", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		return xmlObject;
	}

	/**
	 * Build Artifact. <br>
	 * 
	 * @param samlObject
	 *            SAMLObject.
	 * @param sIDPServerURL
	 *            String.
	 * @param sRid
	 *            String.
	 * @return String
	 */
	public String buildArtifact(SAMLObject samlObject, String sIDPServerURL, String sRid)
	{
		SAML2ArtifactType0004 artifact = new SAML2ArtifactType0004(new byte[] {
			0, 0
		}, createSHA1HashHandle(sIDPServerURL), createSHA1HashHandle(sRid));
		return artifact.base64Encode();
	}

	private byte[] createSHA1HashHandle(String rid)
	{
		MessageDigest sha1;
		byte[] result = null;

		try {
			sha1 = MessageDigest.getInstance("SHA-1");
			result = sha1.digest(rid.getBytes());
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return result;
	}

	/**
	 * Init for class SAML20ArtifactManager. <br>
	 * 
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	public void init()
	throws ASelectException
	{
		String sMethod = "init()";
		ASelectConfigManager oASelectConfigManager = null;
		Object oArtifactSection = null;

		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			oASelectConfigManager = ASelectConfigManager.getHandle();

			try {
				oArtifactSection = oASelectConfigManager.getSection(null, "storagemanager", "id=artifact");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'storagemanager' config section found with id='artifact'", e);
				throw e;
			}

			super.init(oArtifactSection, oASelectConfigManager, _systemLogger, ASelectSAMAgent.getHandle());

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully initialized Artifact Manager");
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error initializing the Artifact storage", e);
			throw e;
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error while initializing Artifact Manager", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

}
