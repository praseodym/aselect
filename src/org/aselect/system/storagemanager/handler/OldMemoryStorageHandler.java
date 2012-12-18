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
 * $Id: OldMemoryStorageHandler.java,v 1.13 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: OldMemoryStorageHandler.java,v $
 * Revision 1.13  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.12  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.11  2005/04/08 12:41:30  martijn
 *
 * Revision 1.10  2005/03/16 13:31:51  tom
 * Added new log functionality
 *
 * Revision 1.9  2005/03/14 10:04:47  erwin
 * Added timestamp and expire time support.
 *
 * Revision 1.8  2005/03/11 20:57:05  martijn
 * added method containsKey(Object oKey)
 *
 * Revision 1.7  2005/03/11 16:49:35  martijn
 * moved verifying if max sessions and tickets are reached to the storagemanager
 *
 * Revision 1.6  2005/03/09 12:13:10  erwin
 * Improved error handling. removed '.' in method name.
 *
 * Revision 1.5  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.4  2005/03/01 16:39:04  erwin
 * Fixed some logging issues
 *
 * Revision 1.3  2005/02/24 14:47:24  erwin
 * Applied code style and improved JavaDoc.
 *
 */

package org.aselect.system.storagemanager.handler;

import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;
import org.aselect.system.storagemanager.IStorageHandler;
import org.aselect.system.utils.Utils;

/**
 * memory storage handler. <br>
 * <br>
 * <b>Description: </b> <br>
 * The OldMemoryStorageHandler uses a <code>HashMap</code> for storing objects in memory. <br>
 * <br>
 * In the OldMemoryStorageHandler an additional HashMap is created in which information about the stored record is kept:
 * <code><pre>
 * 
 *  HashMap htStorage { 
 *  	key: Object xKey 
 *  	value: HashMap htStorageContainer {
 *  		key: String &quot;timestamp&quot; value: Long xTimestamp
 *  		key: String &quot;contents&quot; value: Object xValue } 
 *  }
 *  
 * </pre></code><br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public class OldMemoryStorageHandler implements IStorageHandler
{
	/** The module name. */
	public final static String MODULE = "OldMemoryStorageHandler";

	/** The actual storage */
	private HashMap _htStorage;

	/** The logger that is used for system entries */
	private SystemLogger _systemLogger;

	/**
	 * Initialize the <code>OldMemoryStorageHandler</code>. <br>
	 * <br>
	 * <b>Description: </b> Initalises the <code>OldMemoryStorageHandler</code>:
	 * <ul>
	 * <li>Set system logger</li>
	 * <li>create new storage <code>HashMap</code></li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>systemLogger != null</code></li> <br>
	 * <br>
	 * <b>Postconditions: </b>
	 * <ul>
	 * <li>All instance variables are set</li>
	 * <li>A new storage <code>Hashmap</code> is created</li>
	 * </ul>
	 * 
	 * @param oConfigSection
	 *            the o config section
	 * @param oConfigManager
	 *            the o config manager
	 * @param systemLogger
	 *            the system logger
	 * @param oSAMAgent
	 *            the o sam agent
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#init(java.lang.Object,
	 *      org.aselect.system.configmanager.ConfigManager, org.aselect.system.logging.SystemLogger,
	 *      org.aselect.system.sam.agent.SAMAgent)
	 */
	public void init(Object oConfigSection, ConfigManager oConfigManager, SystemLogger systemLogger, SAMAgent oSAMAgent)
	throws ASelectStorageException
	{
		_systemLogger = systemLogger;
		_htStorage = new HashMap(200);
	}

	/**
	 * Get a object from memory.
	 * 
	 * @param oKey
	 *            the o key
	 * @return the object
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#get(java.lang.Object)
	 */
	public Object get(Object oKey)
	throws ASelectStorageException
	{
		String sMethod = "get()";
		Object oValue = null;

		_systemLogger.log(Level.FINEST, MODULE, sMethod, this + " store=" + _htStorage);
		String sTxt = Utils.firstPartOf(oKey.toString(), 30);
		try {
			synchronized (_htStorage) {
				HashMap htStorageContainer = (HashMap) _htStorage.get(oKey);
				oValue = htStorageContainer.get("contents");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "MSH get(" + sTxt + ") -->" + htStorageContainer);
			}
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Not found: " + sTxt);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eNP);
		}

		if (oValue == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied key is not mapped to any value, cause: "
					+ Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
		}
		return oValue;
	}

	/**
	 * Retrieve an object its timestamp from storage. <br>
	 * <br>
	 * 
	 * @param oKey
	 *            the o key
	 * @return the timestamp
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#getTimestamp(java.lang.Object)
	 */
	public long getTimestamp(Object oKey)
	throws ASelectStorageException
	{
		String sMethod = "getTimestamp()";
		long lTimestamp = 0;

		try {
			synchronized (_htStorage) {
				HashMap htStorageContainer = (HashMap) _htStorage.get(oKey);
				Long lValue = (Long) htStorageContainer.get("timestamp");
				lTimestamp = lValue.longValue();
			}
		}
		catch (NullPointerException eNP) {
			StringBuffer sb = new StringBuffer("OldMemoryStorageHandler.getTimestamp() -> ");
			sb.append("Empty (null) key-object was supplied");
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Empty (null) key-object was supplied.");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eNP);
		}

		if (lTimestamp == 0) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied key is not mapped to any value,cause: "
					+ Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
		}
		return lTimestamp;
	}

	// added 1.5.4
	/**
	 * Returns the number of objects stored in memory.
	 * 
	 * @return the count
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#getCount()
	 */
	public long getCount()
	throws ASelectStorageException
	{
		return _htStorage.size();
	}

	/**
	 * Get all objects from memory table.
	 * 
	 * @return the all
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#getAll()
	 */
	public HashMap getAll()
	throws ASelectStorageException
	{
		String sMethod = "getAll()";
		HashMap htReturnTable = new HashMap();
		_systemLogger.log(Level.FINEST, MODULE, sMethod, " this=" + /* this.getClass()+" "+ */this + " store="
				+ _htStorage);

		synchronized (_htStorage) {
			Set keys = _htStorage.keySet();
			for (Object oKey : keys) {
				// Enumeration eKeys = _htStorage.keys();
				// while (eKeys.hasMoreElements()) {
				// Object oKey = eKeys.nextElement();
				HashMap xStorageContainer = (HashMap) _htStorage.get(oKey);
				Object oValue = xStorageContainer.get("contents");
				htReturnTable.put(oKey, oValue);
			}
		}
		return htReturnTable;
	}

	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	public void put(Object oKey, Object oValue, Long lTimestamp, IStorageHandler.UpdateMode eMode)
	throws ASelectStorageException
	{
		// RM_71_01
		// For now we just call the old one
		switch (eMode) {
		case INSERTFIRST: // do insert first
			put(oKey, oValue, lTimestamp);
			break;
		case UPDATEFIRST: // do updatefirst
			put(oKey, oValue, lTimestamp);
			break;
		case INSERTONLY: // do create, throw exception if key exists
			synchronized (_htStorage) {
				if ( containsKey(oKey) ) {
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_DUPLICATE_KEY);
				} else {
					put(oKey, oValue, lTimestamp);
				}
			}
			break;
		default:	// do the old stuff for backward compatibility
			put(oKey, oValue, lTimestamp);
			break;
		}
	
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////	

	/**
	 * Put object in memory.
	 * 
	 * @param oKey
	 *            the o key
	 * @param oValue
	 *            the o value
	 * @param lTimestamp
	 *            the l timestamp
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#put(java.lang.Object, java.lang.Object, java.lang.Long)
	 */
	public void put(Object oKey, Object oValue, Long lTimestamp)
	throws ASelectStorageException
	{
		String sMethod = "put";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, this + " store=" + _htStorage);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "MSH put(" + Utils.firstPartOf(oKey.toString(), 30) + ") ="
				+ oValue.toString() + " timestamp=" + lTimestamp);

		HashMap htStorageContainer = new HashMap();
		try {
			htStorageContainer.put("timestamp", lTimestamp);
			htStorageContainer.put("contents", oValue);
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied value was null", eNP);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, eNP);
		}
		try {
			synchronized (_htStorage) {
				_htStorage.put(oKey, htStorageContainer);
			}
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Empty (null) key-object supplied", eNP);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, eNP);
		}
	}

	/**
	 * Remove an object from memory storage.
	 * 
	 * @param oKey
	 *            the o key
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#remove(java.lang.Object)
	 */
	public void remove(Object oKey)
	throws ASelectStorageException
	{
		String sMethod = "remove()";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, " this=" + /* this.getClass()+" "+ */this + " " + _htStorage);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "MSH remove(" + Utils.firstPartOf(oKey.toString(), 30) + ") ");
		try {
			synchronized (_htStorage) {
				if (_htStorage.remove(oKey) == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not remove object: " + oKey);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
				}
			}
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Empty (null) key-object supplied", eNP);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_REMOVE, eNP);
		}
	}

	/**
	 * Remove all objects from memmory table.
	 * 
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#removeAll()
	 */
	public void removeAll()
	throws ASelectStorageException
	{
		synchronized (_htStorage) {
			_htStorage.clear();
		}
	}

	/**
	 * Removes the objects from memory table that have been expired.
	 * 
	 * @param lTimestamp
	 *            the l timestamp
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#cleanup(java.lang.Long)
	 */
	public void cleanup(Long lTimestamp)
	throws ASelectStorageException
	{
		String sMethod = "cleanup()";
		int countAll = 0, countRemoved = 0;

		_systemLogger.log(Level.FINER, MODULE, sMethod, " CleanupTime=" + lTimestamp);
		synchronized (_htStorage) {
			Set keys = _htStorage.keySet();
			for (Object oKey : keys) {
				// Enumeration eKeys = _htStorage.keys();
				// while (eKeys.hasMoreElements()) {
				// Object oKey = eKeys.nextElement();
				countAll++;
				String sTxt = Utils.firstPartOf(oKey.toString(), 30);
				_systemLogger.log(Level.INFO, MODULE, sMethod, " Get=" + sTxt);
				HashMap xStorageContainer = (HashMap) _htStorage.get(oKey);
				Long lStorageTime = (Long) xStorageContainer.get("timestamp");
				_systemLogger.log(Level.INFO, MODULE, sMethod, " timestamp=" + lStorageTime);

				if (lTimestamp.longValue() >= lStorageTime.longValue()) {
					_htStorage.remove(oKey);
					countRemoved++;
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "MSH Key=" + sTxt + " TimeStamp=" + lStorageTime
							+ " Left=" + (lStorageTime - lTimestamp) + " removed");
				}
				else {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "MSH Key=" + sTxt + " TimeStamp=" + lStorageTime
							+ " Left=" + (lStorageTime - lTimestamp));
				}
			}
		}
		int countLeft = countAll - countRemoved;
		_systemLogger.log(Level.FINER, MODULE, sMethod, " CleanupTime=" + lTimestamp + " total was " + countAll
				+ " removed " + countRemoved + " left " + countLeft);
	}

	/**
	 * Clear the storage <code>HashMap</code>.
	 * 
	 * @see org.aselect.system.storagemanager.IStorageHandler#destroy()
	 */
	public void destroy()
	{
		if (_htStorage != null) {
			_htStorage.clear();
			_htStorage = null;
		}
	}

	/**
	 * Checks if the configured maximum items is reached. <br>
	 * <br>
	 * 
	 * @param lItemCount
	 *            the l item count
	 * @return true, if checks if is maximum
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#isMaximum(long)
	 */
	public boolean isMaximum(long lItemCount)
	throws ASelectStorageException
	{
		return (_htStorage.size() >= lItemCount);
	}

	/**
	 * Checks if the supplied key already exists in the <code>HashMap</code> <br>
	 * <br>
	 * .
	 * 
	 * @param oKey
	 *            the o key
	 * @return true, if contains key
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#containsKey(java.lang.Object)
	 */
	public boolean containsKey(Object oKey)
	throws ASelectStorageException
	{
		// _systemLogger.log(Level.INFO, MODULE, "containsKey", "Key="+oKey+", Storage="+_htStorage);
		return _htStorage.containsKey(oKey);
	}
}