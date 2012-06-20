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
 * $Id: StorageManager.java,v 1.15 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: StorageManager.java,v $
 * Revision 1.15  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.14  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.13  2005/03/16 13:38:33  tom
 * Added new log functionality
 *
 * Revision 1.12  2005/03/14 10:04:47  erwin
 * Added timestamp and expire time support.
 *
 * Revision 1.11  2005/03/11 20:57:05  martijn
 * added method containsKey(Object oKey)
 *
 * Revision 1.10  2005/03/11 20:02:28  martijn
 * renamed config item: check to interval
 *
 * Revision 1.9  2005/03/11 16:49:35  martijn
 * moved verifying if max sessions and tickets are reached to the storagemanager
 *
 * Revision 1.8  2005/03/09 16:15:00  martijn
 * Fixed bug in StorageManager: Cleaner.init() logged a strange error message when cleaner was configured as disabled
 *
 * Revision 1.7  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.6  2005/03/01 14:40:22  erwin
 * Cleaner stop log -> FINE
 *
 * Revision 1.5  2005/03/01 14:25:57  martijn
 * added .trim() to retrieval check and expire config params in init()
 *
 * Revision 1.4  2005/03/01 13:01:44  erwin
 * Improved documentation, logging and applied code style.
 *
 * 
 */

package org.aselect.system.storagemanager;

import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;
import org.aselect.system.storagemanager.IStorageHandler.UpdateMode;

/**
 * Store objects to some sort of physical storage. <br>
 * <br>
 * <b>Description: </b> <br>
 * The <code>StorageManager</code> is designed to store objects, like a HashMap, to some sort of physical storage. <br>
 * <br>
 * The StorageManager uses <code>StorageHandler</code> s to actual store the objects. Objects can be stored for a
 * limited amount of time. A Cleaner will remove the objects that have expired. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public class StorageManager
{
	private static final int I_UNLIMITED = -1;
	private static final String STRING_UNLIMITED = "-1";

	/** The module name. */
	public static final String MODULE = "StorageManager";

	/** The configured maximum. */
	private long _iMax;

	/** The storage handler. */
	private IStorageHandler _oStorageHandler;

	private SystemLogger _oSystemLogger;

	/** The storage cleaner. */
	private Cleaner _oCleaner;

	/** The storage expiration time. */
	private long _lExpireTime = 0;

	/**
	 * Default constructor.
	 */
	public StorageManager() {
	}

	/**
	 * (Re)initialize the storage. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This function initializes the StorageManager. The following steps are taken:
	 * <ul>
	 * <li>Get handler from configuration.</li>
	 * <li>Create e new instance of the handler.</li>
	 * <li>Clear old recouerses if this is a reinitialization.</li>
	 * <li>Initialize the handler.</li>
	 * <li>Create a new cleaner and start the cleaning thread.</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oConfigManager != null</code></li>
	 * <li><code>systemLogger != null</code></li>
	 * <li><code>oSAMAgent != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The storage is initialized. <br>
	 * 
	 * @param oConfigSection
	 *            The section within the configuration file in which the parameters for the StorageManager can be found.
	 * @param oConfigManager
	 *            The configuration to be used.
	 * @param systemLogger
	 *            The logger for system entries.
	 * @param oSAMAgent
	 *            The SAM agent to be used.
	 * @throws ASelectStorageException
	 *             If storage initialization fails.
	 */
	public void init(Object oConfigSection, ConfigManager oConfigManager, SystemLogger systemLogger, SAMAgent oSAMAgent)
	throws ASelectStorageException
	{
		String sMethod = "init";
		Object oHandlerSection;
		Class cClass;
		String sStorageHandlerId;
		String sStorageManagerId;
		Object oStorageHandlerSection;

		_oSystemLogger = systemLogger;
		try {
			oHandlerSection = oConfigManager.getSection(oConfigSection, "handler");
		}
		catch (ASelectConfigException x) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "'<handler />' is missing in the configuration file");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INIT, x);
		}

		try {
			sStorageManagerId = oConfigManager.getParam(oConfigSection, "id");
		}
		catch (ASelectConfigException ace) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "storagemanager 'id' is missing", ace);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INIT, ace);
		}

		String sMax = null;
		try {
			sMax = oConfigManager.getParam(oConfigSection, "max");
		}
		catch (ASelectConfigException e) {
			// Allow for "unlimited" storage by setting sMax to -1
			// Also Change "put" method to allow for value -1
			systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No 'max' config item found in storagemanager config section, using unlimited", e);// RH, 20090529
			sMax = STRING_UNLIMITED;
			// throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INIT, e); // RH, 20090529, o
		}

		try {
			_iMax = Integer.parseInt(sMax.trim());
		}
		catch (Exception e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, // formally _iMax this is not a long but an Integer
					"'max' config item in storagemanager config section is not an integer: " + sMax, e);// RH, 20090529,
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INIT, e);
		}

		try {
			cClass = Class.forName(oConfigManager.getParam(oHandlerSection, "class"));
		}
		catch (ASelectConfigException ace) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "'class' is missing in the configuration file", ace);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INIT, ace);

		}
		catch (ClassNotFoundException cnfe) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load the IStorageHandler, class not found",
					cnfe);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INIT, cnfe);
		}

		try {
			sStorageHandlerId = oConfigManager.getParam(oHandlerSection, "id");
		}
		catch (ASelectConfigException ace) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "'id' is missing in the configuration file", ace);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INIT, ace);
		}

		try {
			oStorageHandlerSection = oConfigManager.getSection(oConfigSection, "storagehandler", "id=" + sStorageHandlerId);
		}
		catch (ASelectConfigException ace) {
			systemLogger.log(Level.WARNING, MODULE, sMethod,
					"<storagehandler> </storagehandler> is missing in the configuration file", ace);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INIT, ace);
		}

		try {
			String sConfiguredExpireTime = oConfigManager.getParam(oConfigSection, "expire");
			_lExpireTime = (Long.parseLong(sConfiguredExpireTime.trim()) * 1000);
		}
		catch (ASelectConfigException e) {
			_lExpireTime = I_UNLIMITED;
			systemLogger.log(Level.CONFIG, MODULE, sMethod, "'expire' config item not specified. Cleaning disabled.");
		}

		long lInterval = 0;
		if (_lExpireTime != I_UNLIMITED) {
			try {
				String sConfiguredInterval = oConfigManager.getParam(oConfigSection, "interval");
				lInterval = (Long.parseLong(sConfiguredInterval.trim()) * 1000);
			}
			catch (ASelectConfigException e) {
				lInterval = 60000; // default 1 minute.
				systemLogger.log(Level.CONFIG, MODULE, sMethod, "'interval' config item not specified. Using default (1 minute)");
			}
		}

		try {	// If reinit -> clear old resources
			destroy();

			_oStorageHandler = (IStorageHandler) cClass.newInstance();
			systemLogger.log(Level.INFO, MODULE, sMethod, "ConfigManager=" + oConfigManager + " id="+sStorageHandlerId+
					" ConfigSection="+oStorageHandlerSection + " this=" + this.getClass() + " handler=" + _oStorageHandler.getClass());
			_oStorageHandler.init(oStorageHandlerSection, oConfigManager, systemLogger, oSAMAgent);

			// The cleaner will keep the storage clean.
			_oCleaner = new Cleaner();
			_oCleaner.init(_lExpireTime, lInterval, systemLogger, sStorageManagerId);
			_oCleaner.interrupt();
			_oCleaner.start();
		}
		catch (Exception e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize the StorageManager", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INIT, e);
		}
	}

	/**
	 * Retrieve object from storage. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Returns a particular object from the storage. Calls the handler's <code>get()</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>oKey != null</code><br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oKey
	 *            The identifier of the object that needs to be obtained from the storage.
	 * @return The stored object.
	 * @throws ASelectStorageException
	 *             If retrieving fails.
	 * @see IStorageHandler#get(Object)
	 */
	public Object get(Object oKey)
	throws ASelectStorageException
	{
		String sMethod = "get";

		// _oSystemLogger.log(Level.INFO, MODULE, sMethod,
		// " this="+this.getClass()+" handler="+_oStorageHandler.getClass());
		return _oStorageHandler.get(oKey);
	}

	/**
	 * Retrieve an object its expiration time from storage. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Returns the storage expiration time of a particular object from the storage. Calls the handler its
	 * <code>getTimestamp()</code> and adds the configured expiration time. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>oKey != null</code> <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oKey
	 *            The identifier of the object that needs to be obtained from the storage.
	 * @return The expiration time of the stored object.
	 * @throws ASelectStorageException
	 *             If retrieving fails.
	 * @see IStorageHandler#getTimestamp(Object)
	 */
	public long getExpirationTime(Object oKey)
	throws ASelectStorageException
	{
		long lTimestamp = _oStorageHandler.getTimestamp(oKey);
		return lTimestamp + _lExpireTime;
	}

	/**
	 * Retrieve an object its timestamp from storage. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Returns the storage timestamp of a particular object from the storage. Calls the handler its
	 * <code>getTimestamp()</code>. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>oKey != null</code> <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oKey
	 *            The identifier of the object that needs to be obtained from the storage.
	 * @return The timestamp of the stored object.
	 * @throws ASelectStorageException
	 *             If retrieving fails.
	 * @see IStorageHandler#getTimestamp(Object)
	 */
	public long getTimestamp(Object oKey)
	throws ASelectStorageException
	{
		long lTimestamp = _oStorageHandler.getTimestamp(oKey);
		return lTimestamp;
	}

	/**
	 * Retrieve all stored objects. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Returns all the stored objects. Calls the handler its <code>getAll()</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The storage manager and handler must be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @return A <code>HashMap</code> containing all stored object as key/value.
	 * @throws ASelectStorageException
	 *             if retrieving fails.
	 * @see IStorageHandler#getAll()
	 */
	public HashMap getAll()
	throws ASelectStorageException
	{
		return _oStorageHandler.getAll();
	}

	/**
	 * Retrieve the number of stored objects. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Returns the number of stored objects. Calls the handler its <code>getCount()</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The storage manager and handler must be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @return The number of stored objects
	 * @throws ASelectStorageException
	 *             if retrieving fails.
	 * @see IStorageHandler#getCount()
	 */
	public long getCount()
	throws ASelectStorageException
	{
		return _oStorageHandler.getCount();
	}

	/**
	 * Insert an object in storage. <br>
	 * This method should be used to insert an object, otherwise use update<br>
	 * <b>Description: </b> <br>
	 * Inserts an object into the storage. Along with the storing of the object, a timestamp is created. This timestamp
	 * is used to evaluate whether or not the object should be kept in storage (expiration). <br>
	 * <br>
	 * Calls the handler its <code>put()</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oKey != null</code></li>
	 * <li><code>oValue != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The storage contains the given object. <br>
	 * 
	 * @param oKey
	 *            The identifier of the object that is to be stored.
	 * @param oValue
	 *            The object that is to be stored.
	 * @throws ASelectStorageException
	 *             If storing fails.
	 * @see IStorageHandler#put(Object, Object, Long)
	 */
	public void put(Object oKey, Object oValue)
	throws ASelectStorageException
	{
//		String sMethod = "put";
		// Allow for "unlimited" storage
		// if (_oStorageHandler.isMaximum(_iMax)) // RH, 20090529, o
		if (_iMax != I_UNLIMITED && _oStorageHandler.isMaximum(_iMax)) // RH, 20090529, n
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED);

		// _oSystemLogger.log(Level.INFO, MODULE, sMethod,
		// " this="+this.getClass()+" handler="+_oStorageHandler.getClass());
		Long lTimestamp = new Long(System.currentTimeMillis());
		////////////////////////////////////////////////////////////////
//		_oStorageHandler.put(oKey, oValue, lTimestamp);
		// This method should be used to insert an object, otherwise use update		// RH, 20111117, o
		_oStorageHandler.put(oKey, oValue, lTimestamp, UpdateMode.INSERTFIRST);		// RH, 20111117, n
	}

	/**
	 * Updates an object in storage. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Updates an object into the storage. Along with the storing of the object, a timestamp is created. This timestamp
	 * is used to evaluate whether or not the object should be kept in storage (expiration). <br>
	 * <br>
	 * Calls the handler its <code>put()</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oKey</code> must exist in storage.</li>
	 * <li><code>oKey != null</code></li>
	 * <li><code>oValue != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The storage contains the given object. <br>
	 * 
	 * @param oKey
	 *            The identifier of the object that is to be stored.
	 * @param oValue
	 *            The object that is to be stored.
	 * @throws ASelectStorageException
	 *             If storing fails.
	 * @see IStorageHandler#put(Object, Object, Long)
	 */
	public void update(Object oKey, Object oValue)
	throws ASelectStorageException
	{
		// _oSystemLogger.log(Level.INFO, MODULE, "update",
		// "StorageHandlerClass="+_oStorageHandler.getClass()+" this="+this.getClass());
		// RH, 20111117, sn
		// Sometimes the update is used to insert new values, so check for max
		if (_iMax != I_UNLIMITED && _oStorageHandler.isMaximum(_iMax)) 
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED);
		// RH, 20111117, en
		Long lTimestamp = new Long(System.currentTimeMillis());
		
//		_oStorageHandler.put(oKey, oValue, lTimestamp);		// RH, 20111117, o
		// RH, 20111117, sn
		// Update hopes for an existing key so does an UPDATEFIRST
		_oStorageHandler.put(oKey, oValue, lTimestamp, UpdateMode.UPDATEFIRST);
		// RH, 20111117, en
	}

	
	/**
	 * Creates an object in storage. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates an object into the storage. Along with the storing of the object, a timestamp is created. This timestamp
	 * is used to evaluate whether or not the object should be kept in storage (expiration). <br>
	 * <br>
	 * Calls the handler its <code>put()</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oKey</code> must NOT exist in storage.</li>
	 * <li><code>oKey != null</code></li>
	 * <li><code>oValue != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The storage contains the given object. <br>
	 * 
	 * @param oKey
	 *            The identifier of the object that is to be stored.
	 * @param oValue
	 *            The object that is to be stored.
	 * @return true on successful create, false on duplicate key
	 * @throws ASelectStorageException
	 *             If storing fails or duplicate key, result in ASelectStorageException
	 * @see IStorageHandler#put(Object, Object, Long)
	 */
	public boolean create(Object oKey, Object oValue)
	throws ASelectStorageException
	{
		boolean createOK = false;
		// _oSystemLogger.log(Level.INFO, MODULE, "create",
		// "StorageHandlerClass="+_oStorageHandler.getClass()+" this="+this.getClass());
		if (_iMax != I_UNLIMITED && _oStorageHandler.isMaximum(_iMax)) 
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED);
		
		Long lTimestamp = new Long(System.currentTimeMillis());
		try {
			_oStorageHandler.put(oKey, oValue, lTimestamp, UpdateMode.INSERTONLY);
			createOK = true;
		}
		catch (ASelectStorageException ase) {	// Duplicate key returns false, everything else throws exception
			if ( !Errors.ERROR_ASELECT_STORAGE_DUPLICATE_KEY.equals( ase.getMessage()) ) {
				throw ase;
			}
			_oSystemLogger.log(Level.INFO, MODULE, "create", "Resuming on duplicate key");
		}
		return createOK;
	}

	
	
	/**
	 * Checks if the supplied key already exists in the physical storage.
	 * 
	 * @param oKey
	 *            The unique key that will be checked for existance
	 * @return TRUE if the key exists
	 * @throws ASelectStorageException
	 *             if IO error occurred with physical storage
	 */
	public boolean containsKey(Object oKey)
	throws ASelectStorageException
	{
		return _oStorageHandler.containsKey(oKey);
	}

	/**
	 * Remove a storage object. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Removes a particular object from the storage. Calls the handler its <code>remove()</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>oKey != null</code><br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The object with the given key is removed from the storage. <br>
	 * 
	 * @param oKey
	 *            The identifier of the object that needs to be removed.
	 * @throws ASelectStorageException
	 *             If removal fails.
	 * @see IStorageHandler#remove(Object)
	 */
	public void remove(Object oKey)
	throws ASelectStorageException
	{
		_oStorageHandler.remove(oKey);
	}

	/**
	 * Remove all stored objects. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Removes all the stored objects from the storage. Calls the handler its <code>removeAll()</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All objects in storage are removed. <br>
	 * 
	 * @throws ASelectStorageException
	 *             If removal fails.
	 * @see IStorageHandler#removeAll()
	 */
	public void removeAll()
	throws ASelectStorageException
	{
		_oStorageHandler.removeAll();
	}

	/**
	 * Clean up all used resources. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Performs the following steps:
	 * <ul>
	 * <li>Destroy the storage handler.</li>
	 * <li>Destroy the Cleaner thread.</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The storage manager is cleared.
	 * 
	 * @see IStorageHandler#destroy()
	 * @see Cleaner#destroy()
	 */
	public void destroy()
	{
		_oSystemLogger.log(Level.FINE, MODULE, "destroy", "" + this.getClass());
		if (_oStorageHandler != null) {
			_oStorageHandler.destroy();
			_oStorageHandler = null;
		}

		if (_oCleaner != null) {
			_oCleaner.destroy();
			_oCleaner = null;
		}
	}

	/**
	 * Storage cleaner. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The inner-class Cleaner is a thread that removes objects that have expired from the storage. This is done by
	 * generating a timestamp and calling the cleanup function of the handler. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The called cleanup function should be a thread safe implementation. <br>
	 * 
	 * @author Alfa & Ariss
	 * @see IStorageHandler#cleanup(Long)
	 */
	private class Cleaner extends Thread
	{
		private String _sId = "";
		
		/** Cleaning interval */
		private long _lInterval = 0;

		/** Expiration time. */
		private long _lExpireTime = 0;

		/** True while running. */
		private boolean _bGo = false;

		/** The logger for system entries. */
		private SystemLogger _systemLogger;

		/**
		 * Default constructor.
		 */
		public Cleaner() {
		}

		/**
		 * Initialize the <code>Cleaner</code>. <br>
		 * <br>
		 * <b>Description: </b> <br>
		 * Sets the cleaning interval and the expiration time. <br>
		 * <br>
		 * <b>Concurrency issues: </b> <br>
		 * -<br>
		 * <br>
		 * <b>Preconditions: </b>
		 * <ul>
		 * <li><code>oConfigSection != null</code></li>
		 * <li><code>systemLogger != null</code></li>
		 * </ul>
		 * <br>
		 * <b>Postconditions: </b> <br>
		 * The <code>Cleaner</code> is initialized.
		 * 
		 * @param lExpireTime
		 *            The expire time in seconds
		 * @param lInterval
		 *            The interval time in seconds
		 * @param systemLogger
		 *            The logger to log system entries.
		 */
		public void init(long lExpireTime, long lInterval, SystemLogger systemLogger, String sId)
		{
			_lExpireTime = lExpireTime;
			_lInterval = lInterval;
			_systemLogger = systemLogger;
			_sId = sId;
			
			if (_lExpireTime > 0)
				_bGo = true;
			
			_systemLogger.log(Level.FINEST, MODULE, "init", "Init Cleaner: "+_sId+" expireTime="+_lExpireTime+" go="+_bGo);
		}

		/**
		 * Cleanup the storage. <br>
		 * <br>
		 * <b>Description: </b> <br>
		 * Cleans all expired storage objects at the configured interval. <br>
		 * <br>
		 * <b>Concurrency issues: </b> <br>
		 * -<br>
		 * <br>
		 * <b>Preconditions: </b> <br>
		 * The <code>Cleaner</code> is initialized. <br>
		 * <br>
		 * <b>Postconditions: </b> <br>
		 * -
		 * 
		 * @see java.lang.Runnable#run()
		 */
		@Override
		public void run()
		{
			String sMethod = "run()";
			while (_bGo) {
				try {
					sleep(_lInterval);

					long lCurrentTimestamp = System.currentTimeMillis();
					Long lCleanupTimestamp = new Long(lCurrentTimestamp - _lExpireTime);

					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Go cleanup: "+_sId);
					_oStorageHandler.cleanup(lCleanupTimestamp);
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Cleaned-up: "+_sId);
				}
				catch (ASelectStorageException eAS) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "The storage cleanup failed", eAS);
				}
				catch (InterruptedException eI) {
					// Do nothing if interrupted
				}
				catch (Exception e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "The cleaner could not do her work properly", e);
				}
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "The cleaner has stopped: " + this.getClass()+" id="+_sId);
		}

		/**
		 * Destroys the Cleaner. <br>
		 * <br>
		 * <b>Description: </b> <br>
		 * Stop the thread from running. <br>
		 * <br>
		 * <b>Concurrency issues: </b> <br>
		 * -<br>
		 * <br>
		 * <b>Preconditions: </b> <br>
		 * The <code>Cleaner</code> is initialized. <br>
		 * <br>
		 * <b>Postconditions: </b> <br>
		 * -
		 * 
		 * @see java.lang.Thread#destroy()
		 */
		@Override
		public void destroy()
		{
			String sMethod = "destroy";
			_bGo = false;
			_systemLogger.log(Level.FINE, MODULE, sMethod, "" + this.getClass());
			try
			// interrupt if sleeping
			{
				interrupt();
			}
			catch (Exception e) {
				// no logging
			}

		}
	}
}