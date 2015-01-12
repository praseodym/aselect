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
 * $Id: JDBCStorageHandler.java,v 1.21 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: JDBCStorageHandler.java,v $
 * Revision 1.21  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.20  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.19  2005/04/08 12:41:30  martijn
 *
 * Revision 1.18  2005/03/16 09:26:17  martijn
 * fixed typo in logging of method get()
 *
 * Revision 1.17  2005/03/14 16:05:13  martijn
 * more clear error message in getTimestamp()
 *
 * Revision 1.16  2005/03/14 15:39:14  martijn
 * fixed typo's in logging of getTimestamp()
 *
 * Revision 1.15  2005/03/14 10:35:21  martijn
 * made a working getTimeStamp()
 *
 * Revision 1.14  2005/03/14 10:04:47  erwin
 * Added timestamp and expire time support.
 *
 * Revision 1.13  2005/03/11 20:57:05  martijn
 * added method containsKey(Object oKey)
 *
 * Revision 1.12  2005/03/11 16:49:35  martijn
 * moved verifying if max sessions and tickets are reached to the storagemanager
 *
 * Revision 1.11  2005/03/09 12:13:10  erwin
 * Improved error handling. removed '.' in method name.
 *
 * Revision 1.10  2005/03/09 11:06:12  erwin
 * Improved error handling
 *
 * Revision 1.9  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.8  2005/03/08 08:20:50  martijn
 * changed the config structure for JDBC storagehandlers (no double configs needed anymore)
 *
 * Revision 1.7  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.6  2005/03/02 08:43:58  erwin
 * Fixed problem with closing of the statements and resultsets.
 *
 * Revision 1.5  2005/03/01 16:39:04  erwin
 * Fixed some logging issues
 *
 * Revision 1.4  2005/02/24 14:47:11  erwin
 * Applied code style and improved JavaDoc.
 *
 */

package org.aselect.system.storagemanager.handler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.db.connection.IConnectionHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.storagemanager.IStorageHandler;

/**
 * DBMS storage handler. <br>
 * <br>
 * <b>Description: </b> <br>
 * The JDBCStorageHandler uses a DBMS for physical storage. <br>
 * <br>
 * The DBMS is accessed through JDBC. Objects that are written to the DBMS are encoded to bytes, using the
 * <code>ObjectOutputStream</code> mechanism of Java. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public class JDBCStorageHandler implements IStorageHandler
{
	private static final String DEFAULT_CONNECTION_HANDLER = "org.aselect.system.db.connection.impl.NonClosingConnectionHandler";
	// private static final String DEFAULT_CONNECTION_HANDLER =
	// "org.aselect.system.db.connection.impl.ClosingConnectionHandler";
	protected static final String DEFAULTIDENTIFIERQUOTE = "\""; // use double-quote as default
	protected String identifierQuote = DEFAULTIDENTIFIERQUOTE;

	/** name of this module, used for logging */
	protected static final String MODULE = "JDBCStorageHandler";

	/** The database connection. */
	// protected Connection _oActiveConnection;

	/** The active SAM resource. */
	protected SAMResource _oActiveResource;

	/** The database table name. */
	protected String _sTableName;

	/** The resource group containing database connection information */
	protected String _sResourceGroup;

	/** The context key hash */
	protected String _sContextKeyHash;

	/** The context timestamp */
	protected String _sContextTimestamp;

	/** The context key */
	protected String _sContextKey;

	/** The context value */
	protected String _sContextValue;

	/** The logger that is used for system entries */
	protected SystemLogger _systemLogger;

	/** The configuration. */
	protected ConfigManager _oConfigManager;

	/** The SAM agent. */
	protected SAMAgent _oSAMAgent;

	protected IConnectionHandler _oConnectionHandler;
	protected Class cClass;

	/**
	 * Initialize the <code>JDBCStorageHandler</code>. <br>
	 * <br>
	 * <b>Description: </b> Initalises the <code>JDBCStorageHandler</code>:
	 * <ul>
	 * <li>Set system logger and managers</li>
	 * <li>Reads the necessary configuration</li>
	 * <li>Initialise the database connection</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oConfigSection != null</code></li>
	 * <li><code>oConfigManager != null</code></li>
	 * <li><code>systemLogger != null</code></li>
	 * <li><code>oSAMAgent != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b>
	 * <ul>
	 * <li>All instance variables are set</li>
	 * <li>The database is connected</li>
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
		String sMethod = "init";
		Object oTableSection = null;

		try {
			_systemLogger = systemLogger;
			_oConfigManager = oConfigManager;
			_oSAMAgent = oSAMAgent;

			try {
				_sResourceGroup = oConfigManager.getParam(oConfigSection, "resourcegroup");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found resourcegroup: " + _sResourceGroup);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'resourcegroup' section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
//			if (_oActiveResource == null || !_oActiveResource.live())	// RH, 20131125, o
			// Get 'most recent'  active resource		// RH, 20131125, n
			if (_oActiveResource == null || !_oActiveResource.live()	 ||	!_oActiveResource.getId().equals(  _oSAMAgent.getActiveResource(_sResourceGroup).getId() ) 	)	// RH, 20131125, n
				_oActiveResource = _oSAMAgent.getActiveResource(_sResourceGroup);
			Object oResourceConfigSection = _oActiveResource.getAttributes();
			try {
				String _connHandler = _oConfigManager.getParam(oResourceConfigSection, "connectionhandler");
				systemLogger.log(Level.INFO, MODULE, sMethod, "Found connectionhandler: " + _connHandler);
				// cClass = Class.forName(_oConfigManager.getParam(oResourceConfigSection, "connectionhandler"));
				cClass = Class.forName(_connHandler);
			}
			catch (ASelectConfigException ace) {
				systemLogger.log(Level.INFO, MODULE, sMethod,
						"No connectionhandler given in the configuration file, using '"+DEFAULT_CONNECTION_HANDLER+"'");
				cClass = Class.forName(DEFAULT_CONNECTION_HANDLER);
			}

			_oConnectionHandler = (IConnectionHandler) cClass.newInstance();
			systemLogger.log(Level.INFO, MODULE, sMethod, "Using connectionhandler: " + _oConnectionHandler.getClass().getCanonicalName());
			_oConnectionHandler.Init(_oConfigManager, _systemLogger, _oSAMAgent, _sResourceGroup);

			// RH, 20090604, sn
			// This also prepares the connection
			String intentifierQuoteString = getConnection().getMetaData().getIdentifierQuoteString(); // RH, 20090604, n
			// getIdentifierQuoteString() returns " " (space) if quoting is unsupported
			if (intentifierQuoteString != null)
				identifierQuote = intentifierQuoteString.trim();
			// RM_69_01
			// RH, 20090604, sn

			try {
				oTableSection = oConfigManager.getSection(oConfigSection, "table");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'table' config section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sTableName = identifierQuote + oConfigManager.getParam(oTableSection, "name") + identifierQuote;
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'name' config item in 'table' section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sContextKeyHash = identifierQuote + oConfigManager.getParam(oTableSection, "hash") + identifierQuote;
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'hash' config item in 'table' section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sContextTimestamp = identifierQuote + oConfigManager.getParam(oTableSection, "timestamp")
						+ identifierQuote;
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'timestamp' config item in 'table' section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sContextKey = identifierQuote + oConfigManager.getParam(oTableSection, "key") + identifierQuote;
			}
			catch (ASelectConfigException e) {
				_systemLogger
						.log(Level.WARNING, MODULE, sMethod, "No valid 'key' config item in 'table' section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sContextValue = identifierQuote + oConfigManager.getParam(oTableSection, "value") + identifierQuote;
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'value' config item in 'table' section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			// getConnection(); // RH, 20090604, o
		}
		catch (ASelectStorageException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "The JDBC IStorageHandler could not be initialized");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Returns a particular object from the database.
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
		String sMethod = "get";
		Object oRet = null;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {
			// int iKey = 0; // oKey.hashCode();

			StringBuffer sbBuffer = new StringBuffer();
			sbBuffer.append("SELECT ").append(_sContextValue).append(" ");
			sbBuffer.append("FROM ").append(_sTableName).append(" ");
			// sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
			sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer);  // 20120405: + " -> " + oKey);

			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.prepareStatement(sbBuffer.toString());

			// 20090212, Bauke: use oKey as key to the table instead of the hashvalue
			// oStatement.setInt(1, iKey); // old
			byte[] baKey = encode(oKey); // new
			oStatement.setBytes(1, baKey); // new
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) { // record exists.

				// oRet = decode(oResultSet.getBytes(_sContextValue.replace(identifierQuote, " ").trim())); // o
				oRet = decode(oResultSet.getBytes(_sContextValue.substring(identifierQuote.length(),
						_sContextValue.length()	- identifierQuote.length())));
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "result=" + oRet);
			}
			else {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "The supplied key is not mapped to any value.");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			}
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not decode the object from the database");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eIO);
		}
		catch (ClassNotFoundException eCNF) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not decode the object from the database");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eCNF);
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Empty (null) key-object was supplied");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eNP);
		}
		catch (Exception e) {
			//_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve the object from the database");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		finally {
			try {
				if (oResultSet != null) {
					oResultSet.close();
				}
				if (oStatement != null) {
					oStatement.close();
				}
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.");
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en
		}
		if (oRet == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied key is not mapped to any value");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE);
		}
		return oRet;
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
		String sMethod = "getTimestamp";
		long lRet = 0;
		PreparedStatement oStatement = null;
		Connection oConnection = null; // RH, 20090604, n
		ResultSet oResultSet = null;
		StringBuffer sbQuery = new StringBuffer();

		try {
			int iKey = 0; // oKey.hashCode();

			sbQuery.append("SELECT ").append(_sContextTimestamp).append(" ");
			sbQuery.append("FROM ").append(_sTableName).append(" ");
			// sbQuery.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
			sbQuery.append("WHERE ").append(_sContextKey).append(" = ?"); // new
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbQuery + " -> " + iKey + " key=" + oKey);

			// Connection oConnection = getConnection(); // RH, 20090604, o
			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.prepareStatement(sbQuery.toString());
			// oStatement.setInt(1, iKey); // old
			byte[] baKey = encode(oKey); // new
			oStatement.setBytes(1, baKey); // new
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) // record exists.
			{
				Timestamp oTimestamp = oResultSet.getTimestamp(1);
				lRet = oTimestamp.getTime();
			}
			else {
				StringBuffer sbError = new StringBuffer("The supplied key is not mapped to any value - key: ");
				sbError.append(oKey);
				_systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
				throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			}
		}
		catch (ASelectStorageException e) {
			throw e;
		}
		catch (SQLException e) {
			StringBuffer sbError = new StringBuffer(
					"Could not resolve the timestamp from the JDBC database by executing the query: ");
			sbError.append(sbQuery.toString());
			_systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Empty (null) key-object was supplied");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eNP);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve the object from the database");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		finally {
			try {
				if (oResultSet != null) {
					oResultSet.close();
				}
				if (oStatement != null) {
					oStatement.close();
				}
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.");
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en

		}
		if (lRet == 0) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied key is not mapped to any value",
					new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE));
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE);
		}
		return lRet;
	}

	/**
	 * Returns the number of objects stored in the table.
	 * 
	 * @return the count
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#getCount()
	 */
	public long getCount()
	throws ASelectStorageException
	{
		String sMethod = "getCount";
		long lCount = -1;
		StringBuffer sbBuffer = null;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {
			sbBuffer = new StringBuffer();
			sbBuffer.append("SELECT COUNT(*) ");
			sbBuffer.append("FROM ").append(_sTableName);

			// Connection oConnection = getConnection(); // RH, 20090604, o
			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			oResultSet = oStatement.executeQuery();

			while (oResultSet.next()) {
				lCount = oResultSet.getLong(1);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"An error occured while retrieving objects from the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en

		}
		return lCount;
	}

	/**
	 * Returns all the objects stored in the table.
	 * 
	 * @return the all
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#getAll()
	 */
	public HashMap getAll()
	throws ASelectStorageException
	{
		HashMap htResponse = new HashMap();
		StringBuffer sbBuffer = null;
		String sMethod = "getAll";
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {
			sbBuffer = new StringBuffer();
			sbBuffer.append("SELECT * ");
			sbBuffer.append("FROM ").append(_sTableName);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer);

			// Connection oConnection = getConnection(); // RH, 20090604, o
			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			oResultSet = oStatement.executeQuery();

			while (oResultSet.next()) {

				// Object oKey = decode(oResultSet.getBytes(_sContextKey.replace(identifierQuote, ' ').trim())); // o
				// Object oValue = decode(oResultSet.getBytes(_sContextValue.replace(identifierQuote, ' ').trim())); //
				// o
				Object oKey = decode(oResultSet.getBytes(_sContextKey.substring(identifierQuote.length(), _sContextKey
						.length()
						- identifierQuote.length())));
				Object oValue = decode(oResultSet.getBytes(_sContextValue.substring(identifierQuote.length(),
						_sContextValue.length() - identifierQuote.length())));

				htResponse.put(oKey, oValue);
			}
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not decode one or more objects", eIO);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eIO);
		}
		catch (ClassNotFoundException eCNF) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not decode one or more objects", eCNF);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eCNF);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"An error occured while retrieving objects from the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en
		}
		return htResponse;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	public void put(Object oKey, Object oValue, Long lTimestamp, IStorageHandler.UpdateMode eMode)
	throws ASelectStorageException
	{
		String sMethod = "put(), with MODE flag";
		// RM_69_02
		switch (eMode) {
		case INSERTFIRST: // do insert first
			_systemLogger.log(Level.FINER, MODULE, sMethod,
					"Doing put with eMode INSERTFIRST" );
			try {
				create(oKey, oValue, lTimestamp);
			}
			catch (SQLException e) {
				// If create fails we try update
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
				"INSERTFIRST fails where it should succeed, trying update" );
				try {
					update(oKey, oValue, lTimestamp);
				}
				catch (SQLException e1) {
					// If update also fails we throw an ASelectStorageException
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Could not insert or update",  e1);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT,  e1);
				}
			}
			break;
		case UPDATEFIRST: // do updatefirst
			_systemLogger.log(Level.FINER, MODULE, sMethod,
			"Doing put with eMode UPDATEFIRST" );
			try {
				update(oKey, oValue, lTimestamp);
			}
			catch (SQLException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
				"UPDATEFIRST fails where it should succeed, trying create" );
				try {
					create(oKey, oValue, lTimestamp);
				}
				catch (SQLException e1) {
					// If create also fails we throw an ASelectStorageException
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Could not update or insert",  e1);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT,  e1);
				}
			}
			break;
		case INSERTONLY: // do only insert, throw exception on duplicate key
			_systemLogger.log(Level.FINER, MODULE, sMethod,
			"Doing put with eMode INSERTONLY" );
			try {
				create(oKey, oValue, lTimestamp);
			}
			catch (SQLException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
				"INSERTONLY fails where it should succeed, might be duplicate key" );
				// Is this a duplicate key?
				if (containsKey(oKey)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Insert on duplicate key attempt, resuming" );
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_DUPLICATE_KEY);
				} else {
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT);
				}
			}
			break;
		default:	// do the old stuff for backward compatibility
			_systemLogger.log(Level.FINER, MODULE, sMethod,
			"Doing put with eMode default" );
			put(oKey, oValue, lTimestamp);
			break;
		}
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////	

	/**
	 * Inserts a particular object into the database.
	 * 
	 * @param oKey
	 *            the o key
	 * @param oValue
	 *            the o value
	 * @param lTimestamp
	 *            the l timestamp
	 * @throws ASelectStorageException 
	 *             the a select storage exception
	 * @throws SQLException
	 * 				if not exactly one row was affected, e.g. if duplicate key was encountered
	 * @see org.aselect.system.storagemanager.IStorageHandler#put(java.lang.Object, java.lang.Object, java.lang.Long)
	 */
	private void create(Object oKey, Object oValue, Long lTimestamp)
	throws SQLException, ASelectStorageException
	{
		String sMethod = "create";
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {
			int iKey = 0; // old: oKey.hashCode();
			Timestamp oTimestamp = new Timestamp(lTimestamp.longValue());
			byte[] baKey = encode(oKey);
			byte[] baValue = encode(oValue);

			StringBuffer sbBuffer = new StringBuffer();
//			sbBuffer.append("SELECT ").append(_sContextTimestamp).append(" ");
//			sbBuffer.append("FROM ").append(_sTableName).append(" ");
//			// sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
//			sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
//			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oKey);
//
//			// Connection oConnection = getConnection(); // RH, 20090604, o
			oConnection = getConnection(); // RH, 20090604, n
//			oStatement = oConnection.prepareStatement(sbBuffer.toString());
//			// oStatement.setInt(1, iKey); // old
//			oStatement.setBytes(1, baKey); // new
//			oResultSet = oStatement.executeQuery();

//			if (oResultSet.next()) { // record exists.
//				sbBuffer = new StringBuffer();
//				sbBuffer.append("UPDATE ").append(_sTableName).append(" ");
//				sbBuffer.append("SET ").append(_sContextValue).append(" = ? , ").append(_sContextTimestamp).append(
//						" = ? ");
//				// sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
//				sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
//				_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oKey);
//
//				try { // added 1.5.4
//					oStatement.close();
//				}
//				catch (SQLException e) {
//					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
//				}
//				oStatement = oConnection.prepareStatement(sbBuffer.toString());
//				oStatement.setBytes(1, baValue);
//				oStatement.setTimestamp(2, oTimestamp);
//				// oStatement.setInt(3, iKey); // old
//				oStatement.setBytes(3, baKey); // new
//			}
//			else { // new record.
				sbBuffer = new StringBuffer();
				sbBuffer.append("INSERT INTO ").append(_sTableName).append(" ");
				// RH, 20080714, sn
				// It's quite bad practice not to include column names
				sbBuffer.append("( ");
				sbBuffer.append(_sContextKeyHash).append(", ");
				sbBuffer.append(_sContextTimestamp).append(", ");
				sbBuffer.append(_sContextKey).append(", ");
				sbBuffer.append(_sContextValue).append(" ");
				sbBuffer.append(") ");
				// RH, 20080714, en
				sbBuffer.append("VALUES (?,?,?,?)");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oValue);

//				try { // added 1.5.4
//					oStatement.close();
//				}
//				catch (SQLException e) {
//					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
//				}
				oStatement = oConnection.prepareStatement(sbBuffer.toString());
				oStatement.setInt(1, iKey);
				oStatement.setTimestamp(2, oTimestamp);
				oStatement.setBytes(3, baKey);
				oStatement.setBytes(4, baValue);
//			}
			// oStatement.executeUpdate();
			int rowsAffected = oStatement.executeUpdate();
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Rows affected -> " + rowsAffected);
			if (rowsAffected != 1) {
				throw new SQLException("Invalid number of rows affected");
			}
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not decode one or more objects that were retrieved from the database", eIO);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, eIO);
		}

//		catch (Exception e) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod,
//					"An error occured while inserting objects into the database", e);
//			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, e);
//		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en
		}
	}

	
	/**
	 * Updates a particular object in the database.
	 * 
	 * @param oKey
	 *            the o key
	 * @param oValue
	 *            the o value
	 * @param lTimestamp
	 *            the l timestamp
	 * @throws ASelectStorageException 
	 *             the a select storage exception
	 * @throws SQLException
	 * 				if not exactly one row was affected
	 * @see org.aselect.system.storagemanager.IStorageHandler#put(java.lang.Object, java.lang.Object, java.lang.Long)
	 */
	private void update(Object oKey, Object oValue, Long lTimestamp)
	throws SQLException, ASelectStorageException
	{
		String sMethod = "update";
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {
			int iKey = 0; // old: oKey.hashCode();
			Timestamp oTimestamp = new Timestamp(lTimestamp.longValue());
			byte[] baKey = encode(oKey);
			byte[] baValue = encode(oValue);

			StringBuffer sbBuffer = new StringBuffer();
//			sbBuffer.append("SELECT ").append(_sContextTimestamp).append(" ");
//			sbBuffer.append("FROM ").append(_sTableName).append(" ");
//			// sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
//			sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
//			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oKey);
//
//			// Connection oConnection = getConnection(); // RH, 20090604, o
			oConnection = getConnection(); // RH, 20090604, n
//			oStatement = oConnection.prepareStatement(sbBuffer.toString());
//			// oStatement.setInt(1, iKey); // old
//			oStatement.setBytes(1, baKey); // new
//			oResultSet = oStatement.executeQuery();

//			if (oResultSet.next()) { // record exists.
				sbBuffer = new StringBuffer();
				sbBuffer.append("UPDATE ").append(_sTableName).append(" ");
				sbBuffer.append("SET ").append(_sContextValue).append(" = ? , ").append(_sContextTimestamp).append(
						" = ? ");
				// sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
				sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oValue);

//				try { // added 1.5.4
//					oStatement.close();
//				}
//				catch (SQLException e) {
//					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
//				}
				oStatement = oConnection.prepareStatement(sbBuffer.toString());
				oStatement.setBytes(1, baValue);
				oStatement.setTimestamp(2, oTimestamp);
				// oStatement.setInt(3, iKey); // old
				oStatement.setBytes(3, baKey); // new
//			}
//			else { // new record.
//				sbBuffer = new StringBuffer();
//				sbBuffer.append("INSERT INTO ").append(_sTableName).append(" ");
//				// RH, 20080714, sn
//				// It's quite bad practice not to include column names
//				sbBuffer.append("( ");
//				sbBuffer.append(_sContextKeyHash).append(", ");
//				sbBuffer.append(_sContextTimestamp).append(", ");
//				sbBuffer.append(_sContextKey).append(", ");
//				sbBuffer.append(_sContextValue).append(" ");
//				sbBuffer.append(") ");
//				// RH, 20080714, en
//				sbBuffer.append("VALUES (?,?,?,?)");
//				_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oKey);

//				try { // added 1.5.4
//					oStatement.close();
//				}
//				catch (SQLException e) {
//					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
//				}
//				oStatement = oConnection.prepareStatement(sbBuffer.toString());
//				oStatement.setInt(1, iKey);
//				oStatement.setTimestamp(2, oTimestamp);
//				oStatement.setBytes(3, baKey);
//				oStatement.setBytes(4, baValue);
//			}
			// oStatement.executeUpdate();
			int rowsAffected = oStatement.executeUpdate();
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Rows affected -> " + rowsAffected);
			if (rowsAffected != 1) {
				throw new SQLException("Invalid number of rows affected");
			}
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not decode one or more objects that were retrieved from the database", eIO);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, eIO);
		}

//		catch (Exception e) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod,
//					"An error occured while inserting objects into the database", e);
//			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, e);
//		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en
		}
	}

	
	
	
	
	/**
	 * Inserts a particular object into the database.
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
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {
			int iKey = 0; // old: oKey.hashCode();
			Timestamp oTimestamp = new Timestamp(lTimestamp.longValue());
			byte[] baKey = encode(oKey);
			byte[] baValue = encode(oValue);

			StringBuffer sbBuffer = new StringBuffer();
			sbBuffer.append("SELECT ").append(_sContextTimestamp).append(" ");
			sbBuffer.append("FROM ").append(_sTableName).append(" ");
			// sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
			sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oValue);

			// Connection oConnection = getConnection(); // RH, 20090604, o
			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			// oStatement.setInt(1, iKey); // old
			oStatement.setBytes(1, baKey); // new
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) { // record exists.
				sbBuffer = new StringBuffer();
				sbBuffer.append("UPDATE ").append(_sTableName).append(" ");
				sbBuffer.append("SET ").append(_sContextValue).append(" = ? , ").append(_sContextTimestamp).append(
						" = ? ");
				// sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
				sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
				_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oKey);

				try { // added 1.5.4
					oStatement.close();
				}
				catch (SQLException e) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
				}
				oStatement = oConnection.prepareStatement(sbBuffer.toString());
				oStatement.setBytes(1, baValue);
				oStatement.setTimestamp(2, oTimestamp);
				// oStatement.setInt(3, iKey); // old
				oStatement.setBytes(3, baKey); // new
			}
			else { // new record.
				sbBuffer = new StringBuffer();
				sbBuffer.append("INSERT INTO ").append(_sTableName).append(" ");
				// RH, 20080714, sn
				// It's quite bad practice not to include column names
				sbBuffer.append("( ");
				sbBuffer.append(_sContextKeyHash).append(", ");
				sbBuffer.append(_sContextTimestamp).append(", ");
				sbBuffer.append(_sContextKey).append(", ");
				sbBuffer.append(_sContextValue).append(" ");
				sbBuffer.append(") ");
				// RH, 20080714, en
				sbBuffer.append("VALUES (?,?,?,?)");
				_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oKey);

				try { // added 1.5.4
					oStatement.close();
				}
				catch (SQLException e) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
				}
				oStatement = oConnection.prepareStatement(sbBuffer.toString());
				oStatement.setInt(1, iKey);
				oStatement.setTimestamp(2, oTimestamp);
				oStatement.setBytes(3, baKey);
				oStatement.setBytes(4, baValue);
			}
			// oStatement.executeUpdate();
			int rowsAffected = oStatement.executeUpdate();
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Rows affected -> " + rowsAffected);
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not decode one or more objects that were retrieved from the database", eIO);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, eIO);
		}

		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"An error occured while inserting objects into the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en
		}
	}

	/**
	 * Removes a particular object from the database.
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
		String sMethod = "remove";
		StringBuffer sbBuffer = null;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		int iKey = 0; // oKey.hashCode();
		_systemLogger.log(Level.FINER, MODULE, sMethod, " -> " + iKey + " key=" + oKey);

		try {
			sbBuffer = new StringBuffer();
			sbBuffer.append("DELETE FROM ").append(_sTableName).append(" ");
			// sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
			sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer + " -> " + iKey + " key=" + oKey);

			// // RH, 20090604, so
			// Connection oConnection = null;
			// try {
			// oConnection = getConnection();
			// }
			// catch (ASelectStorageException e) {
			// _systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not connect", e);
			// throw e;
			// }
			// RH, 20090604, eo
			oConnection = getConnection(); // RH, 20090604, n

			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			// oStatement.setInt(1, iKey); // old
			byte[] baKey = encode(oKey); // new
			oStatement.setBytes(1, baKey); // new

			if (oStatement.executeUpdate() == 0) {
				StringBuffer sbError = new StringBuffer("Could not remove object: ");
				sbError.append(oKey);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			}
		}
		catch (ASelectStorageException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"An error occured while removing an object from the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_REMOVE, e);
		}
		finally {
			try {
				if (oStatement != null) {
					oStatement.close();
				}
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en
		}
	}

	/**
	 * Removes all the stored objects from the database.
	 * 
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#removeAll()
	 */
	public void removeAll()
	throws ASelectStorageException
	{
		String sMethod = "removeAll";
		StringBuffer sbBuffer = null;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		try {
			sbBuffer = new StringBuffer();
			sbBuffer.append("DELETE FROM ").append(_sTableName);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer);

			// Connection oConnection = getConnection(); // RH, 20090604, o
			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			oStatement.executeUpdate();
		}
		catch (ASelectStorageException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not decode one or more objects that were retrieved from the database.", eAS);
			throw eAS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"An error occured while removing objects from the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_REMOVE, e);
		}
		finally {
			try {
				if (oStatement != null) {
					oStatement.close();
				}
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en
		}
	}

	/**
	 * Removes the objects from the database that have expired.
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
		String sMethod = "cleanup";
		StringBuffer sbBuffer = null;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		try {
			Timestamp oTimestamp = new Timestamp(lTimestamp.longValue());

			sbBuffer = new StringBuffer();
			sbBuffer.append("DELETE FROM ").append(_sTableName).append(" ");
			sbBuffer.append("WHERE ").append(_sContextTimestamp).append(" <= ?");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sql=" + sbBuffer + " -> " + lTimestamp); // RH, 20090127,
			// n

			// Connection oConnection = getConnection(); // RH, 20090604, o
			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			oStatement.setTimestamp(1, oTimestamp);
			oStatement.executeUpdate();
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "An error occured while cleaning up the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_CLEAN_UP, e);
		}
		finally {
			try {
				if (oStatement != null) {
					oStatement.close();
					oStatement = null;
				}
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en
		}
	}

	/**
	 * Clean up all used recourses.
	 * 
	 * @see org.aselect.system.storagemanager.IStorageHandler#destroy()
	 */
	public void destroy()
	{
		// try {
		// if (_oActiveConnection != null) {
		// _oActiveConnection.close();
		// _oActiveConnection = null;
		// }
		// }
		// catch (Exception e) { // Only log to system logger.
		// _systemLogger.log(Level.FINE, MODULE, "destroy", "An error occured while trying to destroy the module", e);
		// }
	}

	/**
	 * Checks if the maximum items is reached. <br>
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
		String sMethod = "isMaximum";
		boolean bReturn = false;
		StringBuffer sbQuery = new StringBuffer("SELECT count(*) FROM ");
		sbQuery.append(_sTableName);
		long lMaximum = -1;
		Connection oConnection = null; // RH, 20090604, n
		Statement oStatement = null;
		ResultSet oResultSet = null;

		try {
			// Connection oConnection = getConnection(); // RH, 20090604, o
			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.createStatement();
			oResultSet = oStatement.executeQuery(sbQuery.toString());

			if (oResultSet.next()) { // record exists.
				lMaximum = oResultSet.getLong(1);
			}
			if (lMaximum >= lItemCount)
				bReturn = true;
		}
		catch (SQLException e) {
			StringBuffer sbError = new StringBuffer(
					"Could not resolve the maximum number of items by executing the query: ");
			sbError.append(sbQuery.toString());
			_systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Error during resolve of the maximum number of items", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en
		}
		return bReturn;
	}

	/**
	 * Checks if the supplied key already exists in the database <br>
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
		String sMethod = "containsKey";
		boolean bReturn = false;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;
		int iKey = 0; // oKey.hashCode();

		
//		StringBuffer sbQuery = new StringBuffer("SELECT * FROM ");	// RH, 20111115, o
		// RH, 20111115, sn
		StringBuffer sbQuery = new StringBuffer("SELECT ");
		sbQuery.append(_sContextKey);
		sbQuery.append(" FROM ");
		// RH, 20111115, en
		sbQuery.append(_sTableName);
		sbQuery.append(" WHERE ");
		// sbQuery.append(_sContextKeyHash); // old // was _sContextKey in the sfs
		sbQuery.append(_sContextKey); // was _sContextKey in the sfs
		// release, saml20 update
		sbQuery.append(" = ?");
		_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbQuery + " -> " + iKey + " key=" + oKey);

		try {
			// Connection oConnection = getConnection(); // RH, 20090604, o
			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.prepareStatement(sbQuery.toString());
			// oStatement.setInt(1, iKey); // old
			byte[] baKey = encode(oKey); // new
			oStatement.setBytes(1, baKey); // new
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) // record exists.
				bReturn = true;
			else
				bReturn = false;
		}
		catch (ASelectStorageException e) {
			throw e;
		}
		catch (SQLException e) {
			StringBuffer sbError = new StringBuffer("Could not execute query: ");
			sbError.append(sbQuery.toString());
			_systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Error during resolve of the maximum number of items", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en
		}
		return bReturn;
	}

	/**
	 * Create a database connection. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * First checks whether or not the database is still up. If not, an alternative resource will be obtained from de
	 * SAMAgent. Second, a check is done on the status of the database connection. If closed, a new connection will be
	 * opened. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b>
	 * <ul>
	 * <li>The database driver is initialised.</li>
	 * <li>The active database connection is established</li>
	 * </ul>
	 * 
	 * @return A <code>Connection</code> with the database.
	 * @throws ASelectStorageException
	 *             If connecting fails.
	 */
	// private Connection getConnection() throws ASelectStorageException
	// Keep this method for backward compatibility with other/extending classes
	protected Connection getConnection()
	throws ASelectStorageException
	{

		return _oConnectionHandler.getConnection();
		/*
		 * String sMethod = "getConnection"; String sPassword = null; String sJDBCDriver = null; String sUsername =
		 * null; String sURL = null; Connection _oActiveConnection = null; int i=1; try { if (_oActiveResource == null
		 * || !_oActiveResource.live()) { _oActiveResource = _oSAMAgent.getActiveResource(_sResourceGroup); Object
		 * oConfigSection = _oActiveResource.getAttributes(); try { sJDBCDriver =
		 * _oConfigManager.getParam(oConfigSection, "driver"); } catch (ASelectConfigException eAC) {
		 * _systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'driver' config item found", eAC); throw new
		 * ASelectStorageException(Errors.ERROR_ASELECT_NOT_FOUND, eAC); } try { sUsername =
		 * _oConfigManager.getParam(oConfigSection, "username"); } catch (ASelectConfigException eAC) {
		 * _systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'username' config item found", eAC); throw new
		 * ASelectStorageException(Errors.ERROR_ASELECT_NOT_FOUND, eAC); } try { sPassword =
		 * _oConfigManager.getParam(oConfigSection, "password"); } catch (ASelectConfigException e) { sPassword = "";
		 * _systemLogger.log(Level.CONFIG, MODULE, sMethod,
		 * "Invalid or empty password found in config, using empty password", e); } try { sURL =
		 * _oConfigManager.getParam(oConfigSection, "url"); } catch (ASelectConfigException e) {
		 * _systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'url' config item found", e); throw new
		 * ASelectStorageException(Errors.ERROR_ASELECT_NOT_FOUND, e); } try { Class.forName(sJDBCDriver); } catch
		 * (Exception e) { StringBuffer sbFailed = new StringBuffer("Could not initialze the JDBC Driver: ");
		 * sbFailed.append(sJDBCDriver); _systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
		 * throw new ASelectStorageException(Errors.ERROR_ASELECT_DATABASE_INIT, e); } try { _oActiveConnection =
		 * DriverManager.getConnection(sURL, sUsername, sPassword); } catch (Exception e) { StringBuffer sbFailed = new
		 * StringBuffer("Could not create a connection with: "); sbFailed.append(sURL); sbFailed.append(", driver: ");
		 * sbFailed.append(sJDBCDriver); _systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
		 * throw new ASelectStorageException(Errors.ERROR_ASELECT_DATABASE_INIT, e); } } // if
		 * (_oActiveConnection.isClosed()) { if (_oActiveConnection == null) { Object oConfigSection =
		 * _oActiveResource.getAttributes(); try { sUsername = _oConfigManager.getParam(oConfigSection, "username"); }
		 * catch (ASelectConfigException eAC) { _systemLogger.log(Level.WARNING, MODULE, sMethod,
		 * "No valid 'username' config item found", eAC); throw new
		 * ASelectStorageException(Errors.ERROR_ASELECT_NOT_FOUND, eAC); } try { sPassword =
		 * _oConfigManager.getParam(oConfigSection, "password"); } catch (ASelectConfigException e) { sPassword = "";
		 * _systemLogger.log(Level.CONFIG, MODULE, sMethod,
		 * "Invalid or empty password found in config, using empty password", e); } try { sURL =
		 * _oConfigManager.getParam(oConfigSection, "url"); } catch (ASelectConfigException e) {
		 * _systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'url' config item found", e); throw new
		 * ASelectStorageException(Errors.ERROR_ASELECT_NOT_FOUND, e); } try { _oActiveConnection =
		 * DriverManager.getConnection(sURL, sUsername, sPassword); } catch (Exception e) { StringBuffer sbFailed = new
		 * StringBuffer("Could not create a connection with: "); sbFailed.append(sURL); _systemLogger.log(Level.WARNING,
		 * MODULE, sMethod, sbFailed.toString(), e); throw new
		 * ASelectStorageException(Errors.ERROR_ASELECT_DATABASE_INIT, e); } } } catch (ASelectStorageException eAS) {
		 * throw eAS; } catch (ASelectSAMException e) { _oActiveResource = null; StringBuffer sbError = new
		 * StringBuffer("No resource was available, original cause: "); sbError.append(e.getMessage());
		 * _systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e); throw new
		 * ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_CONNECTION_FAILURE, e); } catch (Exception e) {
		 * _systemLogger.log(Level.WARNING, MODULE, sMethod, "An error occured while trying to connect to the database",
		 * e); throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_CONNECTION_FAILURE, e); } return
		 * _oActiveConnection;
		 */
	}

	/**
	 * Encode a object for storage. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Encodes an object so that is can be stored in the database. <br>
	 * <br>
	 * <i>Note: This method does not log itself.</i> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>o != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param o
	 *            The object that needs to be encoded.
	 * @return The encoded object.
	 * @throws IOException
	 *             If encoding fails.
	 */
	// private static byte[] encode(Object o) throws IOException
	protected byte[] encode(Object o)
	throws IOException
	{
		byte[] baResponse = null;
		ByteArrayOutputStream osBytes = new ByteArrayOutputStream();
		ObjectOutputStream osObject = new ObjectOutputStream(osBytes);
		osObject.writeObject(o);
		osObject.close();
		baResponse = osBytes.toByteArray();
		osBytes.close();

		if (baResponse == null) {
			throw new IOException("No bytes have been encoded.");
		}
		return baResponse;
	}

	/**
	 * Decodes an object. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Decodes an object that is returned from the database. <br>
	 * <br>
	 * <i>Note: This method does not log itself.</i> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>baBytes != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param baBytes
	 *            the bytes to be decoded.
	 * @return The decoded <code>Object</code>.
	 * @throws IOException
	 *             if decoding fails.
	 * @throws ClassNotFoundException
	 *             if decoding fails.
	 */
	// private static Object decode(byte[] baBytes) throws IOException, ClassNotFoundException
	protected Object decode(byte[] baBytes)
	throws IOException, ClassNotFoundException
	{
		Object oResponse = null;

		ByteArrayInputStream isBytes = new ByteArrayInputStream(baBytes);
		ObjectInputStream isObject = new ObjectInputStream(isBytes);
		oResponse = isObject.readObject();
		isObject.close();
		isBytes.close();

		if (oResponse == null) {
			throw new IOException("No bytes have been decoded.");
		}
		return oResponse;
	}
}