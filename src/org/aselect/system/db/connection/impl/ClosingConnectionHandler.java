/**
 * 
 */
package org.aselect.system.db.connection.impl;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
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
 *
 */
public class ClosingConnectionHandler extends AbstractConnectionHandler
{
	/** name of this module, used for logging */
	private static final String MODULE = "ClosingConnectionHandler";

	
	/* (non-Javadoc)
	 * @see org.aselect.system.db.jdbc.AbstractConnectionHandler#Init(org.aselect.system.sam.agent.SAMAgent, java.lang.String)
	 */
	@Override
	public void Init(ConfigManager configMan, SystemLogger systemLogger, SAMAgent sam, String resourcegroup)
	{
		// TODO Auto-generated method stub
		super.Init(configMan, systemLogger, sam, resourcegroup);
	}

	
	/* (non-Javadoc)
	 * @see org.aselect.system.db.jdbc.AbstractConnectionHandler#getConnection()
	 */
	@Override
	public Connection getConnection() throws ASelectStorageException
	{
		// TODO Auto-generated method stub
		super.getConnection();
		String sMethod = "getConnection()";
		String sPassword = null;
		String sJDBCDriver = null;
		String sUsername = null;
		String sURL = null;
		
		Connection _oActiveConnection = null;
		int i=1;
		try {
			if (_oActiveResource == null || !_oActiveResource.live()) {
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

			// if (_oActiveConnection.isClosed()) {
			if (_oActiveConnection == null) {
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


	/* (non-Javadoc)
	 * @see org.aselect.system.db.jdbc.AbstractConnectionHandler#releaseConnection(java.sql.Connection)
	 */
	@Override
	public void releaseConnection(Connection oConnection)
	{
		String sMethod = "releaseConnection()";
		super.releaseConnection(oConnection);
		try { // Always try to return connection to the pool (if defined)
			if (oConnection != null) {
				oConnection.close();
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Database connection closed (connection returned to pool)");
			}
			} catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database connection (connection not returned to pool)", e);
			}

	}


}
