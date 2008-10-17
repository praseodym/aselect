/*
 * Created on 21-aug-2007
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package org.aselect.server.request.handler.saml20.idp.authentication;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.saml20.common.NodeHelper;
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
import org.w3c.dom.Element;

public class SAML20ArtifactManager extends StorageManager
{
	/** The module name. */
	private static final String MODULE = "SAML20ArtifactManager";

	protected String _sModule = "SAML20ArtifactManager";

	/**
	 * The logger used for system logging
	 */
	private ASelectSystemLogger _systemLogger;

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
			HttpServletResponse oHttpServletResponse)
		throws IOException, ASelectStorageException
	{
		String sMethod = "sendArtifact()";

		putArtifactInStorage(sArtifact, samlObject);
		String uencArtifact = URLEncoder.encode(sArtifact, "UTF-8");
		String sRedirectUrl = sAppUrl + "?SAMLart=" + uencArtifact;

		_systemLogger.log(Level.INFO, _sModule, sMethod, "Redirect to " + sRedirectUrl);
		oHttpServletResponse.sendRedirect(sRedirectUrl);
	}

	private void putArtifactInStorage(Object key, SAMLObject samlObject)
		throws ASelectStorageException
	{
		String sMethod = "putArtifactInStorage";
		Element dom = samlObject.getDOM();
		if (samlObject.getDOM() == null) {
			// object was not marshalled
			NodeHelper nodeHelper = new NodeHelper();
			try {
				dom = nodeHelper.marshallMessage(samlObject);
			}
			catch (MessageEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error while marshalling message", e);
				throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, e);
			}
		}
		super.put(key, dom);
	}

	/**
	 * Gets Artifact from Storage. <br>
	 * 
	 * @param key
	 *            Object.
	 * @return Object
	 * @throws ASelectStorageException
	 */
	public XMLObject getArtifactFromStorage(Object key)
		throws ASelectStorageException
	{
		String sMethod = "getArtifactFromStorage";
		Element dom = (Element) super.get(key);
		NodeHelper nodeHelper = new NodeHelper();
		XMLObject xmlObject = null;
		try {
			xmlObject = nodeHelper.unmarshallElement(dom);
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
