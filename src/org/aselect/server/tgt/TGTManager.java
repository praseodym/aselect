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
 * $Id: TGTManager.java,v 1.16 2006/04/26 12:18:59 tom Exp $ 
 * 
 * Changelog:
 * $Log: TGTManager.java,v $
 * Revision 1.16  2006/04/26 12:18:59  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.15  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.14.4.2  2006/02/02 10:26:14  martijn
 * removed unused code
 *
 * Revision 1.14.4.1  2006/01/25 15:35:19  martijn
 * TGTManager rewritten
 *
 * Revision 1.14  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.13  2005/03/14 16:05:56  martijn
 * fixed typo in javadoc
 *
 * Revision 1.12  2005/03/14 13:03:05  erwin
 * Fixed problems with Admin monitor.
 *
 * Revision 1.11  2005/03/11 21:24:08  martijn
 * config section: storagemanager id='ticket' is renamed to storagemanager id='tgt'
 *
 * Revision 1.10  2005/03/11 21:06:47  martijn
 * now using contains(key) instead of retrieving all objects with getAll() and doing the contains by hand
 *
 * Revision 1.9  2005/03/11 16:49:35  martijn
 * moved verifying if max sessions and tickets are reached to the storagemanager
 *
 * Revision 1.8  2005/03/10 16:21:57  erwin
 * Improved error handling.
 *
 * Revision 1.7  2005/03/09 09:24:50  erwin
 * Renamed and moved errors.
 *
 * Revision 1.6  2005/03/08 14:34:02  martijn
 * Added javadoc and renamed variables to the coding standard
 *
 * Revision 1.5  2005/03/08 12:18:47  martijn
 * Added javadoc and renamed variables to the coding standard
 *
 */

package org.aselect.server.tgt;

import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.storagemanager.StorageManager;
import org.aselect.system.utils.Utils;

/**
 * The A-Select Server TGT manager.
 * <br><br>
 * <b>Description:</b><br>
 * Creates TGT's and storages them in a storage manager.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class TGTManager extends StorageManager
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "TGTManager";
	/**
	 * Size of a TGT
	 */
	private final static int TGT_LENGTH = 128; //256;
	/**
	 * The singleton instance of this object
	 */
	private static TGTManager _oTGTManager;

	/**
	 * The logger used for system logging
	 */
	private ASelectSystemLogger _systemLogger;

	/**
	 * Counts the TGT's
	 */
	private long _lTGTCounter;

	/**
	 * Method to return an instance of the <code>TGTManager</code> instead of 
	 * using the constructor.
	 * <br>
	 * @return always the same <code>TGTManager</code> instance.
	 */
	public static TGTManager getHandle()
	{
		if (_oTGTManager == null)
			_oTGTManager = new TGTManager();

		return _oTGTManager;
	}

	/**
	 * Initializes the A-Select TGT Manager.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * <li>Reads the ticket manager configuration</li>
	 * <li>Initializes the StorageManager object</li>
	 * <li>Resets the <i>_lTGTCounter</i></li>
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * <li>The <code>ASelectSystemLogger</code> must be initialized</li>
	 * <li>The <code>ASelectConfigManager</code> must be initialized</li>
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * All class variables are created and initialized.
	 * <br>
	 * @throws ASelectException if config is missing or the configured information is incorrect
	 */
	public void init()
		throws ASelectException
	{
		String sMethod = "init()";
		ASelectConfigManager oASelectConfigManager = null;
		Object oTicketSection = null;

		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			oASelectConfigManager = ASelectConfigManager.getHandle();

			try {
				oTicketSection = oASelectConfigManager.getSection(null, "storagemanager", "id=tgt");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'storagemanager' config section found with id='tgt'", e);
				throw e;
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "ConfigManager=" + oASelectConfigManager + " ConfigSection="
					+ oTicketSection);
			super.init(oTicketSection, oASelectConfigManager, _systemLogger, ASelectSAMAgent.getHandle());

			//reset the tgt counter
			_lTGTCounter = 0;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully initialized TGT Manager");
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error initializing the TGT storage", e);
			throw e;
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error while initializing TGT Manager", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Creates a new TGT for the supplied data and stores it in the storage manager.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Generates a tgt of TGT_LENGTH random bytes. It is made sure that the tgt
	 * is not present in the current tgt table. The variable
	 * <code>htTGTContext</code> contains information from the caller. The
	 * caller can retrieve this information by calling the
	 * <code>getTGT()</code> method.
	 * <br><br>
	 * <li>checks if the maximum TGT's are reached</li>
	 * <li>generates a unique tgt</li>
	 * <li>stores the ticket to the storage manager</li>
	 * <li>increases the tgt counter for monitoring purposes</li>
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br>
	 * @param htTGTContext The context of the TGT that will be created.
	 * @return the created TGT.
	 * @throws ASelectException If creation fails.
	 */
	synchronized public String createTGT(HashMap htTGTContext)
		throws ASelectException
	{
		String sMethod = "createTGT";
		String sReturn = null;
		String sTGT = null;
		try {
			byte[] baTGT = new byte[TGT_LENGTH];

			//creates a new TGT by resolveing randombytes
			CryptoEngine.nextRandomBytes(baTGT);
			sTGT = Utils.toHexString(baTGT);

			//checks if the generated tgt is unique and create a new one till it is unique
			while (containsKey(sTGT)) {
				CryptoEngine.nextRandomBytes(baTGT);
				sTGT = Utils.toHexString(baTGT);
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "New TGT=" + Utils.firstPartOf(sTGT, 30));
			String sNameID = (String) htTGTContext.get("name_id");
			if (sNameID == null)
				htTGTContext.put("name_id", sTGT);
			put(sTGT, htTGTContext);

			_lTGTCounter++;
			sReturn = sTGT;
		}
		catch (ASelectStorageException e) {
			if (e.getMessage().equals(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Maximum number of TGTs reached", e);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_BUSY, e);
			}

			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not store TGT", e);
			throw e;
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Internal error while creating TGT", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return sReturn;
	}

	/**
	 * Updates a valid tgt context with a new one.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Overwrites the context of the supplied TGT with supplied context with 
	 * the one in the storage manager if the TGT already exists.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br>
	 * @param sTGT The TGT that must be updated
	 * @param htTGTContext The new context of the TGT
	 * @return TRUE if the TGT context is updated.
	 */
	public boolean updateTGT(String sTGT, HashMap htTGTContext)
	{
		String sMethod = "updateTGT";
		boolean bReturn = false;
		if (getTGT(sTGT) != null) {
			try {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "updateTGT("+Utils.firstPartOf(sTGT, 30)+")");
				update(sTGT, htTGTContext);
				bReturn = true;
			}
			catch (Exception e) {
				bReturn = false;
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not update TGT", e);
			}
		}
		return bReturn;
	}

	/**
	 * Returns the tgt context for the tgt specified in <code>sTGT</code>.
	 * <br><br>
	 * @param sTGT The A-Select TGT created with the createTGT method 
	 * @return a <code>HashMap</code> containing the TGT context
	 */
	public HashMap getTGT(String sTGT)
	{
		String sMethod = "getTGT";
		HashMap htContext = null;

		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "getTGT("+Utils.firstPartOf(sTGT, 30)+")");
			htContext = (HashMap)get(sTGT);
		}
		catch (ASelectStorageException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "TGT not found");
		}
		return htContext;
	}

	/**
	 * Returns the number of TGT's that are created by the TGT manager for 
	 * monitoring purposes.
	 * @return the number of TGT's created by this TGT manager 
	 */
	public long getTGTCounter()
	{
		return _lTGTCounter;
	}

	/**
	 * Private constructor.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Creates a new storage manager and retrieves the system logger.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The storage manager is created.
	 */
	private TGTManager() {
	}

}
