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
 * $Id: IStorageHandler.java,v 1.7 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: IStorageHandler.java,v $
 * Revision 1.7  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.6  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.5  2005/03/14 10:04:47  erwin
 * Added timestamp and expire time support.
 *
 * Revision 1.4  2005/03/11 20:57:05  martijn
 * added method containsKey(Object oKey)
 *
 * Revision 1.3  2005/03/11 16:49:35  martijn
 * moved verifying if max sessions and tickets are reached to the storagemanager
 *
 * Revision 1.2  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.1  2005/02/24 14:47:59  erwin
 * Applied code style and improved JavaDoc.
 *
 *
 */

package org.aselect.system.storagemanager;

import java.util.HashMap;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;

// TODO: Auto-generated Javadoc
/**
 * An interface for storage handlers. <br>
 * <br>
 * <b>Description: </b> <br>
 * The <code>IStorageHandler</code> interface defines a generic interface for all StorageHandlers in the StorageManager.
 * A IStorageHandler handles the physical access to the storage. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public interface IStorageHandler
{
	
	/**
	 * Initialize the handler. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This function should perform all one-time initialisation proceedings. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oConfigSection != null</code></li>
	 * <li><code>oConfigManager != null</code></li>
	 * <li><code>systemLogger != null</code></li>
	 * <li><code>oSAMAgent != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The storage handler is initialised. <br>
	 * 
	 * @param oConfigSection
	 *            The section within the configuration file in which the parameters for the IStorageHandler can be
	 *            found.
	 * @param oConfigManager
	 *            The configuration.
	 * @param systemLogger
	 *            The logger for system entries.
	 * @param oSAMAgent
	 *            The SAM agant to use.
	 * @throws ASelectStorageException
	 *             If initialisation fails.
	 */
	public void init(Object oConfigSection, ConfigManager oConfigManager, SystemLogger systemLogger, SAMAgent oSAMAgent)
		throws ASelectStorageException;

	/**
	 * Get a object from storage. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns a particular object from the physical storage. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>oKey != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oKey
	 *            The identifier of the object that needs to be stored.
	 * @return The stored object.
	 * @throws ASelectStorageException
	 *             If retrieving fails.
	 */
	public Object get(Object oKey)
		throws ASelectStorageException;

	/**
	 * Retrieve an object its timestamp from storage. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Returns the storage timestamp of a particular object from the storage. <br>
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
		throws ASelectStorageException;

	/**
	 * Return stored objects. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns all the stored objects. <br>
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
	 * @return A HashMap containing all stored object as key/value.
	 * @throws ASelectStorageException
	 *             If retrieving fails.
	 */
	public HashMap getAll()
		throws ASelectStorageException;

	/**
	 * Return stored object count. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the number of stored objects. <br>
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
	 * @return The number of all stored object.
	 * @throws ASelectStorageException
	 *             If retrieving fails.
	 */
	public long getCount()
		throws ASelectStorageException;

	/**
	 * insert object into storage. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Inserts a particular object into the physical storage. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>oKey != null</code></li>
	 * <li><code>oValue != null</code></li>
	 * <li><code>lTimestamp != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The object is stored. <br>
	 * 
	 * @param oKey
	 *            The identifier of the object that needs to be stored.
	 * @param oValue
	 *            The object that needs to be stored.
	 * @param lTimestamp
	 *            The time at which the object is stored.
	 * @throws ASelectStorageException
	 *             If storing fails.
	 */
	public void put(Object oKey, Object oValue, Long lTimestamp)
		throws ASelectStorageException;

	/**
	 * Removes object from storage. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Removes a particular object from the physical storage. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>oKey != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The object is removed from storage. <br>
	 * 
	 * @param oKey
	 *            The identifier of the object that needs to be removed.
	 * @throws ASelectStorageException
	 *             If removal fails.
	 */
	public void remove(Object oKey)
		throws ASelectStorageException;

	/**
	 * Removes all objects from storage. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Removes all the stored objects from the physical storage. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * All stored objects are removed from the storage. <br>
	 * 
	 * @throws ASelectStorageException
	 *             if removal fails.
	 */
	public void removeAll()
		throws ASelectStorageException;

	/**
	 * Removes expired objects from the storage. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Removes the objects from the physical storage that have expired. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>lTimestamp != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * All object which expire before or at the given time are removed. <br>
	 * 
	 * @param lTimestamp
	 *            The expiration time.
	 * @throws ASelectStorageException
	 *             If cleaning fails.
	 */
	public void cleanup(Long lTimestamp)
		throws ASelectStorageException;

	/**
	 * Clean up all used recourses.
	 */
	public void destroy();

	/**
	 * Checks if the maximum available storage items is reached. <br>
	 * <br>
	 * 
	 * @param lItemCount
	 *            number of items that will be checked if it is the maximum
	 * @return TRUE if storage maximum is reached
	 * @throws ASelectStorageException
	 *             if io error occurred with physical storage
	 */
	public boolean isMaximum(long lItemCount)
		throws ASelectStorageException;

	/**
	 * Checks if the the supplied key object exists in the physical storage. <br>
	 * <br>
	 * 
	 * @param oKey
	 *            The unique key that will be checked for existance
	 * @return TRUE if the key exists
	 * @throws ASelectStorageException
	 *             if IO error occurred with physical storage
	 */
	public boolean containsKey(Object oKey)
		throws ASelectStorageException;
}