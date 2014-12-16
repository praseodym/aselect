/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 */

/* 
 * $Id: AssertionSessionManager.java,v 1.5 2006/05/03 10:11:08 tom Exp $ 
 */
package org.aselect.server.request.handler.saml11.common;

import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.storagemanager.StorageManager;
import org.opensaml.SAMLAssertion;
import org.opensaml.artifact.Artifact;


/**
 * Session manager for temporary Assertion storage. <br>
 * <br>
 * <b>Description:</b><br>
 * Session manager singleton which is used for temporary Assertion storage for Browser/Artifact.The session manager is
 * used by the <code>SAML11ArtifactRequestHandler</code> and the <code>BrowserArtifact</code> WebSSO profile. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class AssertionSessionManager extends StorageManager
{
	private final static String MODULE = "AssertionSessionManager";
	private static AssertionSessionManager _oAssertionSessionManager;
	private ASelectSystemLogger _systemLogger;

	/**
	 * Initialization of the Assertion session manager. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Calls the super.init() with the given configuration. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * <li>oConfig != null</li> <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oConfig
	 *            Containing the Storage manager configuration
	 * @throws ASelectStorageException
	 *             if initalization fails
	 */
	public void init(Object oConfig)
	throws ASelectStorageException
	{
		String sMethod = "init";
		try {
			_systemLogger = ASelectSystemLogger.getHandle();

			ASelectConfigManager oASelectConfigManager = ASelectConfigManager.getHandle();
			ASelectSAMAgent oASelectSAMAgent = ASelectSAMAgent.getHandle();

			super.init(oConfig, oASelectConfigManager, _systemLogger, oASelectSAMAgent);
		}
		catch (ASelectStorageException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not send initialize", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Returns always the same instance of this object. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new instance of this object if <code>_oAssertionSessionManager</code> is <code>null</code> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return always the same instance of the AssertionSessionManager class
	 */
	public static AssertionSessionManager getHandle()
	{
		if (_oAssertionSessionManager == null)
			_oAssertionSessionManager = new AssertionSessionManager();

		return _oAssertionSessionManager;
	}

	/**
	 * Stores an Assertion indexed by the supplied Artifact. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * <li>Verifies if the SAML Artifact already is stored</li> <li>Stored the SAMLAssertion object with key=Artifact</li>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>oArtifact != null</li> <li>oSAMLAssertion != null</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oArtifact
	 *            SAML Artifact used as key
	 * @param oSAMLAssertion
	 *            SAMLAssertion used as value
	 * @throws ASelectException
	 *             if storing failed
	 */
	public void putAssertion(Artifact oArtifact, SAMLAssertion oSAMLAssertion)
	throws ASelectException
	{
		String sMethod = "putAssertion";
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Store Artifact=" + oArtifact);
			if (containsKey(oArtifact)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Session already exists with id: "
						+ oArtifact.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			try {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Put Artifact=" + oArtifact);
				put(oArtifact, oSAMLAssertion);
			}
			catch (ASelectStorageException e) {
				if (e.getMessage().equals(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Maximum number of request sessions reached", e);
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_BUSY, e);
				}

				throw e;
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create session with session id: "
					+ oArtifact.toString(), e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Returns the specified SAMLAssertion. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the SAMLAssertion from the Session Manager that is indexed by the supplies SAMLArtifact. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <li>oArtifact != null</li> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oArtifact
	 *            SAMLArtifact object
	 * @return SAMLAssertion of the supplied artifact
	 */
	public SAMLAssertion getAssertion(Artifact oArtifact)
	{
		String sMethod = "getAssertion";
		SAMLAssertion oSAMLAssertion = null;
		try {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "oArtifact=" + oArtifact);
			oSAMLAssertion = (SAMLAssertion) get(oArtifact);
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session context with id: " + oArtifact.toString(), e);
		}

		return oSAMLAssertion;
	}

	/**
	 * Private constructor for singleton perposes <br>
	 * <br>
	 * .
	 */
	private AssertionSessionManager() {
		// does nothing
	}

}
