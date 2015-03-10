/**
 * 
 */
package org.aselect.system.db.connection.impl;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.db.connection.AbstractConnectionHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;


/**
 * @author root
 */
public class NonClosingConnectionHandler extends AbstractConnectionHandler
{
	/** name of this module, used for logging */
	private static final String MODULE = "NonClosingConnectionHandler";

	/** The database connection. */
	protected Connection _oActiveConnection;

	/*
	 * (non-Javadoc)
	 * @see org.aselect.system.db.jdbc.AbstractConnectionHandler#Init(org.aselect.system.sam.agent.SAMAgent,
	 * java.lang.String)
	 */
	@Override
	public void Init(ConfigManager configMan, SystemLogger systemLogger, SAMAgent sam, String resourcegroup)
	{
		super.Init(configMan, systemLogger, sam, resourcegroup);
	}

	/*
	 * (non-Javadoc)
	 * @see org.aselect.system.db.jdbc.AbstractConnectionHandler#getConnection()
	 */
	@Override
	public Connection getConnection()
	throws ASelectStorageException
	{
		super.getConnection();
		String sMethod = "getConnection";
		String sPassword = null;
		String sJDBCDriver = null;
		String sUsername = null;
		String sURL = null;
		try {
//			if (_oActiveResource == null || !_oActiveResource.live()) {
				// Get 'most recent'  active resource		// RH, 20131125, n
				if (_oActiveResource == null || !_oActiveResource.live()	 ||	!_oActiveResource.getId().equals(  _oSAMAgent.getActiveResource(_sResourceGroup).getId() ) 	)	{	// RH, 20131125, n

				_oActiveResource = _oSAMAgent.getActiveResource(_sResourceGroup);
				Object oConfigSection = _oActiveResource.getAttributes();

				try {
					sJDBCDriver = _oConfigManager.getParam(oConfigSection, "driver");
				}
				catch (ASelectConfigException eAC) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'driver' config item found", eAC);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_NOT_FOUND, eAC);
				}

				try {
					sUsername = _oConfigManager.getParam(oConfigSection, "username");
				}
				catch (ASelectConfigException eAC) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'username' config item found", eAC);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_NOT_FOUND, eAC);
				}

				try {
					sPassword = _oConfigManager.getParam(oConfigSection, "password");
				}
				catch (ASelectConfigException e) {
					sPassword = "";
					_systemLogger.log(Level.CONFIG, MODULE, sMethod,
							"Invalid or empty password found in config, using empty password", e);
				}
				try {
					sURL = _oConfigManager.getParam(oConfigSection, "url");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'url' config item found", e);

					throw new ASelectStorageException(Errors.ERROR_ASELECT_NOT_FOUND, e);
				}

				try {
					Class.forName(sJDBCDriver);
				}
				catch (Exception e) {
					StringBuffer sbFailed = new StringBuffer("Could not initialze the JDBC Driver: ");
					sbFailed.append(sJDBCDriver);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_DATABASE_INIT, e);
				}

				try {
					_oActiveConnection = DriverManager.getConnection(sURL, sUsername, sPassword);
				}
				catch (Exception e) {
					StringBuffer sbFailed = new StringBuffer("Could not create a connection with: ");
					sbFailed.append(sURL);
					sbFailed.append(", driver: ");
					sbFailed.append(sJDBCDriver);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_DATABASE_INIT, e);
				}
			}

			if (_oActiveConnection.isClosed()) {
				Object oConfigSection = _oActiveResource.getAttributes();

				try {
					sUsername = _oConfigManager.getParam(oConfigSection, "username");
				}
				catch (ASelectConfigException eAC) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'username' config item found", eAC);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_NOT_FOUND, eAC);
				}

				try {
					sPassword = _oConfigManager.getParam(oConfigSection, "password");
				}
				catch (ASelectConfigException e) {
					sPassword = "";
					_systemLogger.log(Level.CONFIG, MODULE, sMethod,
							"Invalid or empty password found in config, using empty password", e);
				}
				try {
					sURL = _oConfigManager.getParam(oConfigSection, "url");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'url' config item found", e);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_NOT_FOUND, e);
				}
				try {
					_oActiveConnection = DriverManager.getConnection(sURL, sUsername, sPassword);
				}
				catch (Exception e) {
					StringBuffer sbFailed = new StringBuffer("Could not create a connection with: ");
					sbFailed.append(sURL);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_DATABASE_INIT, e);
				}
			}
		}
		catch (ASelectStorageException eAS) {
			throw eAS;
		}
		catch (ASelectSAMException e) {
			_oActiveResource = null;
			StringBuffer sbError = new StringBuffer("No resource was available, original cause: ");
			sbError.append(e.getMessage());

			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_CONNECTION_FAILURE, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"An error occured while trying to connect to the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_CONNECTION_FAILURE, e);
		}
		return _oActiveConnection;

	}

	/*
	 * (non-Javadoc)
	 * @see org.aselect.system.db.jdbc.AbstractConnectionHandler#releaseConnection(java.sql.Connection)
	 */
	@Override
	public void releaseConnection(Connection c)
	{
		String sMethod = "releaseConnection";

		// We only close the connection on destroy
		// Connection will be reused, depends on thread-safety of JDBC Driver (which should be thread-safe)
		super.releaseConnection(c);
		_systemLogger.log(Level.FINEST, MODULE, sMethod,
				"Database connection kept open for next request (connection not returned to pool)");
	}

	/**
	 * Clean up all used recourses.
	 */
	public void destroy()
	{
		try {
			if (_oActiveConnection != null) {
				_oActiveConnection.close();
				_oActiveConnection = null;
				_systemLogger.log(Level.FINE, MODULE, "destroy", "Active connection closed");
			}
		}
		catch (Exception e) { // Only log to system logger.
			_systemLogger
					.log(Level.FINE, MODULE, "destroy", "An error occured while trying to destroy the module", e);
		}
	}

}
