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
 * $Id: JDBCConnector.java,v 1.17 2006/05/03 10:11:56 tom Exp $ 
 * 
 * Changelog:
 * $Log: JDBCConnector.java,v $
 * Revision 1.17  2006/05/03 10:11:56  tom
 * Removed Javadoc version
 *
 * Revision 1.16  2005/11/22 07:53:59  erwin
 * SQL Injection patch
 *
 * Revision 1.15  2005/09/08 13:08:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.14  2005/04/29 11:37:53  erwin
 * Added isUserEnabled() and getUserAttributes() functionality
 *
 * Revision 1.13  2005/03/15 16:22:46  tom
 * Fixed Javadoc
 *
 * Revision 1.12  2005/03/14 14:25:24  martijn
 * The UDBConnector init method expects the connector config section instead of a resource config section. The resource config will now be resolved when the connection with the resource must be opened.
 *
 * Revision 1.11  2005/03/10 16:19:33  tom
 * Updated Javadoc
 *
 * Revision 1.10  2005/03/10 16:18:11  tom
 * Added new Authentication Logger
 *
 * Revision 1.9  2005/03/09 21:11:16  martijn
 * bug fixed in getUserProfile(): if the column aselectAccountEnabled can't be found, the account is will now be disabled.
 *
 * Revision 1.8  2005/03/09 09:24:28  erwin
 * Renamed and moved errors.
 *
 * Revision 1.7  2005/03/08 08:35:36  martijn
 * changed config item security_principal_name to username and security_principal_password to password
 *
 * Revision 1.6  2005/03/07 14:22:13  martijn
 * changed authentication log information
 *
 * Revision 1.5  2005/03/02 14:27:57  martijn
 * Fixed a few bugs
 *
 * Revision 1.4  2005/02/28 15:46:38  martijn
 * changed all variable names to naming convention and added java documentation
 *
 * Revision 1.3  2005/02/28 09:49:38  martijn
 * changed all variable names to naming convention and added java documentation
 *
 */

package org.aselect.server.udb.jdbc;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.exception.ASelectUDBException;
import org.aselect.system.sam.agent.SAMResource;

// TODO: Auto-generated Javadoc
/**
 * JDBC database connector. <br>
 * <br>
 * <b>Description:</b><br>
 * Database connector that uses an JDBC database as physical storage. <br>
 * <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class JDBCConnector implements IUDBConnector
{
	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "JDBCConnector";

	/**
	 * Logger used for system logging
	 */
	private ASelectSystemLogger _oASelectSystemLogger;
	/**
	 * Logger used for authentication logging
	 */
	private ASelectAuthenticationLogger _oASelectAuthenticationLogger;

	/**
	 * The table name containing the user information
	 */
	private String _sUsersTableName;
	/**
	 * the column name containing the user id
	 */
	private String _sUserIdColumn;
	/**
	 * Contains all AuthSPs configured in the A-Select Server configuration
	 */
	private HashMap _htConfiguredAuthSPs;
	/**
	 * The configured resourcegroup
	 */
	private String _sUDBResourceGroup;

	/**
	 * The ASelect Config Manager
	 */
	private ASelectConfigManager _oASelectConfigManager;

	/**
	 * The ASelect SAMAgent for retrieving an available resource
	 */
	private ASelectSAMAgent _oASelectSAMAgent;

	/**
	 * Initializes managers and opens a JDBC connection to the A-Select user db. <br>
	 * <br>
	 * 
	 * @param oConfigSection
	 *            the o config section
	 * @throws ASelectUDBException
	 *             the a select udb exception
	 * @see org.aselect.server.udb.IUDBConnector#init(java.lang.Object)
	 */
	public void init(Object oConfigSection)
		throws ASelectUDBException
	{
		String sMethod = "init()";
		_oASelectConfigManager = ASelectConfigManager.getHandle();
		_oASelectSystemLogger = ASelectSystemLogger.getHandle();
		_oASelectAuthenticationLogger = ASelectAuthenticationLogger.getHandle();
		_oASelectSAMAgent = ASelectSAMAgent.getHandle();

		_htConfiguredAuthSPs = new HashMap();
		Object oAuthSPs = null;
		Object oAuthSP = null;
		String sAuthSPID = null;

		try {
			try {
				_sUsersTableName = _oASelectConfigManager.getParam(oConfigSection, "users_table");
			}
			catch (Exception e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'users_table' found", e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sUserIdColumn = _oASelectConfigManager.getParam(oConfigSection, "users_table_id_column");
			}
			catch (Exception e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config item 'users_table_id_column' found", e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sUDBResourceGroup = _oASelectConfigManager.getParam(oConfigSection, "resourcegroup");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No 'resourcegroup' config item found in udb 'connector' config section.", e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			// check if there is at least one active resource available
			getConnection();

			// Get all enabled AuthSPs from config
			try {
				oAuthSPs = _oASelectConfigManager.getSection(null, "authsps");
			}
			catch (Exception e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config section 'authsps' found in main A-Select config", e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				oAuthSP = _oASelectConfigManager.getSection(oAuthSPs, "authsp");
			}
			catch (Exception e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config section 'authsps' found in main A-Select config", e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			while (oAuthSP != null) {
				try {
					sAuthSPID = _oASelectConfigManager.getParam(oAuthSP, "id");
				}
				catch (Exception e) {
					_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
							"No config item 'id' found in 'authsp' section", e);

					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				_htConfiguredAuthSPs.put(sAuthSPID.toUpperCase(), sAuthSPID);
				oAuthSP = _oASelectConfigManager.getNextSection(oAuthSP);
			}

		}
		catch (ASelectUDBException e) {
			throw e;
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize JDBC UDB Connector", e);

			throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Returns a hashtable with the user's record. <br>
	 * <br>
	 * <b>Description</b>: <br>
	 * The returned hashtable contains a <code>result_code</code> and <code>user_authsps</code> which is a hashtable
	 * containing the AuthSP's that the user is registered for. Within this hashtable each AuthSP has an entry with the
	 * value of the user attributes that specific AuthSP. <br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the s user id
	 * @return the user profile
	 * @see org.aselect.server.udb.IUDBConnector#getUserProfile(java.lang.String)
	 */
	public HashMap getUserProfile(String sUserId)
	{
		String sMethod = "getUserProfile()";

		HashMap htResponse = new HashMap();
		HashMap htUserAttributes = new HashMap();
		HashMap htUserRecord = new HashMap();

		Connection oConnection = null;
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;
		ResultSetMetaData oResultSetMetaData = null;

		htResponse.put("result_code", Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);

		try {
			oConnection = getConnection();

			StringBuffer sbQuery = new StringBuffer();
			sbQuery.append("SELECT * FROM ");
			sbQuery.append(_sUsersTableName);
			sbQuery.append(" WHERE ");
			sbQuery.append(_sUserIdColumn);
			sbQuery.append("=?");

			try {
				oStatement = oConnection.prepareStatement(sbQuery.toString());
				oStatement.setString(1, sUserId);
				oResultSet = oStatement.executeQuery();
			}
			catch (Exception e) {
				_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not execute query: "
						+ sbQuery.toString(), e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_INTERNAL, e);
			}

			if (!oResultSet.next()) {
				logAuthentication(sUserId, Errors.ERROR_ASELECT_UDB_UNKNOWN_USER, "denied");

				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_UNKNOWN_USER);
			}

			oResultSetMetaData = oResultSet.getMetaData();
			int iNumCols = oResultSetMetaData.getColumnCount();

			// put resultset in a hashtable
			for (int i = 1; i <= iNumCols; i++) {
				String sAttributeName = oResultSetMetaData.getColumnName(i);
				String sAttributeValue = oResultSet.getString(i);
				if (sAttributeValue == null)
					sAttributeValue = "";

				// attribute must be stored in the HashMap with an uppercase
				// key to match the key of the _htConfiguredAuthSPs
				htUserRecord.put(sAttributeName.toUpperCase(), sAttributeValue);
			}

			String sAccountEnabled = (String) htUserRecord.get("ASELECTACCOUNTENABLED");
			if (sAccountEnabled == null) {
				logAuthentication(sUserId, Errors.ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED, "denied");

				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED);
			}

			if (sAccountEnabled.equalsIgnoreCase("false")) {
				logAuthentication(sUserId, Errors.ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED, "denied");

				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED);
			}

			// resolve all user attributes
			String sAttributeValue = null;
			Set keys = htUserRecord.keySet();
			for (Object s : keys) {
				String sAttributeName = (String) s;
				// Enumeration enumAttributeKeys = htUserRecord.keys();
				// while (enumAttributeKeys.hasMoreElements())
				// {
				// sAttributeName = (String)enumAttributeKeys.nextElement();
				sAttributeValue = (String) htUserRecord.get(sAttributeName);

				if (sAttributeName.startsWith("ASELECT") && sAttributeName.endsWith("REGISTERED")) {// only store user
					// attributes of
					// authsps that are
					// registered for
					// the user
					if (sAttributeValue.equalsIgnoreCase("TRUE")) {
						// The authsp id is the substring between ASELECT(7 chars) and REGISTERED(10 chars)
						String sAuthSPID = sAttributeName.substring(7, sAttributeName.length() - 10);

						StringBuffer sbUserAttributes = new StringBuffer("ASELECT");
						sbUserAttributes.append(sAuthSPID);
						sbUserAttributes.append("USERATTRIBUTES");

						sAttributeValue = (String) htUserRecord.get(sbUserAttributes.toString());
						// a user attbiute can be empty
						if (sAttributeValue == null)
							sAttributeValue = "";

						String sCFGAuthSPID = (String) _htConfiguredAuthSPs.get(sAuthSPID);
						if (sCFGAuthSPID != null)
							htUserAttributes.put(sCFGAuthSPID, sAttributeValue);
					}
				}
			}

			if (htUserAttributes.size() == 0) {
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, "No user attributes found for user: " + sUserId);
				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
			}

			htResponse.put("user_authsps", htUserAttributes);
			htResponse.put("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectUDBException e) {
			htResponse.put("result_code", e.getMessage());
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to fetch profile of user: " + sUserId, e);
			htResponse.put("result_code", Errors.ERROR_ASELECT_UDB_INTERNAL);
		}
		finally {
			// try { // RH, 20090605, sn
			if (oResultSet != null) {
				try {
					oResultSet.close();
				}
				catch (SQLException e) {
					_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, "Could not close resultset");
				}
				oResultSet = null;
			}
			if (oStatement != null) {
				try {
					oStatement.close();
				}
				catch (SQLException e) {
					_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, "Could not close statement");
				}
				oStatement = null;
			}
			if (oConnection != null) {
				try {
					oConnection.close();
				}
				catch (SQLException e) {
					_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, "Could not close connection");
				}
				oConnection = null;
			}
			// }
			// catch (Exception e) {
			// } // RH, 20090605, en

		}
		return htResponse;
	}

	/**
	 * Retrieve the A-Select user attributes. <br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the s user id
	 * @param sAuthSPId
	 *            the s auth sp id
	 * @return the user attributes
	 * @throws ASelectUDBException
	 *             If database fails.
	 * @see org.aselect.server.udb.IUDBConnector#getUserAttributes(java.lang.String, java.lang.String)
	 */
	public String getUserAttributes(String sUserId, String sAuthSPId)
		throws ASelectUDBException
	{
		String sMethod = "getUserAttributes()";

		String sAttributes = null;
		Connection oConnection = null;
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;
		ResultSetMetaData oResultSetMetaData = null;

		try {
			oConnection = getConnection();

			StringBuffer sbQuery = new StringBuffer();
			sbQuery.append("SELECT * FROM ");
			sbQuery.append(_sUsersTableName);
			sbQuery.append(" WHERE ");
			sbQuery.append(_sUserIdColumn);
			sbQuery.append("=?");

			oStatement = oConnection.prepareStatement(sbQuery.toString());
			oStatement.setString(1, sUserId);
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) {
				oResultSetMetaData = oResultSet.getMetaData();
				int iNumCols = oResultSetMetaData.getColumnCount();

				for (int i = 1; i <= iNumCols; i++) {
					// get database coulumn name
					String sColumnName = oResultSetMetaData.getColumnName(i);
					// create attribute column name
					StringBuffer sbUserAttributes = new StringBuffer("ASELECT");
					sbUserAttributes.append(sAuthSPId);
					sbUserAttributes.append("USERATTRIBUTES");

					if (sColumnName.equalsIgnoreCase(sbUserAttributes.toString())) {
						String sAttributeValue = oResultSet.getString(i);
						sAttributes = sAttributeValue;
						i = iNumCols;
					}
				}

				if (sAttributes == null) // user attributes not found for AuthSP
				{
					StringBuffer sb = new StringBuffer("User attributes for AuthSP: '");
					sb.append(sAuthSPId).append("' not found for user: '");
					sb.append(sUserId).append("'");
					_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sb.toString());
				}
			}
			else {
				StringBuffer sb = new StringBuffer("User not found: '");
				sb.append(sUserId).append("'");
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sb.toString(), new ASelectUDBException(
						Errors.ERROR_ASELECT_UDB_UNKNOWN_USER));
			}

		}
		catch (SQLException eSQL) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "Could not execute database query", eSQL);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_INTERNAL, eSQL);
		}
		catch (ASelectUDBException e) {
			throw e;
		}
		catch (ASelectSAMException e) {
			throw new ASelectUDBException(e.getMessage(), e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
			}
			catch (Exception e) {
			}
			try {
				if (oStatement != null)
					oStatement.close();
			}
			catch (Exception e) {
			}
			try {
				if (oConnection != null)
					oConnection.close();
			}
			catch (Exception e) {
			}
		}
		return sAttributes;
	}

	/**
	 * Check if user is A-Select enabled. <br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the s user id
	 * @return true, if checks if is user enabled
	 * @throws ASelectUDBException
	 *             If database fails.
	 * @see org.aselect.server.udb.IUDBConnector#isUserEnabled(java.lang.String)
	 */
	public boolean isUserEnabled(String sUserId)
		throws ASelectUDBException
	{
		String sMethod = "isUserEnabled()";
		boolean bEnabled = false;

		Connection oConnection = null;
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;
		ResultSetMetaData oResultSetMetaData = null;

		try {
			oConnection = getConnection();

			StringBuffer sbQuery = new StringBuffer();
			sbQuery.append("SELECT * FROM ");
			sbQuery.append(_sUsersTableName);
			sbQuery.append(" WHERE ");
			sbQuery.append(_sUserIdColumn);
			sbQuery.append("=?");

			oStatement = oConnection.prepareStatement(sbQuery.toString());
			oStatement.setString(1, sUserId);
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) {
				oResultSetMetaData = oResultSet.getMetaData();
				int iNumCols = oResultSetMetaData.getColumnCount();
				// put resultset in a hashtable
				for (int i = 1; i <= iNumCols; i++) {
					String sAttributeName = oResultSetMetaData.getColumnName(i);
					if (sAttributeName.equalsIgnoreCase("ASELECTACCOUNTENABLED")) {
						String sAttributeValue = oResultSet.getString(i);
						if (sAttributeValue != null && sAttributeValue.equalsIgnoreCase("true")) {
							// account enabled
							bEnabled = true;
							i = iNumCols; // stop searching
						}
						else // user not enabled
						{
							i = iNumCols; // stop searching
						}
					}
				}

				if (!bEnabled) {
					StringBuffer sb = new StringBuffer("User not A-Select enabled: '");
					sb.append(sUserId).append("'");
					_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sb.toString(), new ASelectUDBException(
							Errors.ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED));
				}
			}
			else {
				StringBuffer sb = new StringBuffer("User not found: '");
				sb.append(sUserId).append("'");
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sb.toString(), new ASelectUDBException(
						Errors.ERROR_ASELECT_UDB_UNKNOWN_USER));
			}

		}
		catch (SQLException eSQL) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "Could not execute database query", eSQL);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_INTERNAL, eSQL);
		}
		catch (ASelectUDBException e) {
			throw e;
		}
		catch (ASelectSAMException e) {
			throw new ASelectUDBException(e.getMessage(), e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
			}
			catch (Exception e) {
			}
			try {
				if (oStatement != null)
					oStatement.close();
			}
			catch (Exception e) {
			}
			try {
				if (oConnection != null)
					oConnection.close();
			}
			catch (Exception e) {
			}
		}
		return bEnabled;
	}

	/**
	 * Opens a new JDBC connection to the resource that is retrieved from the SAMAgent. <br>
	 * <br>
	 * 
	 * @return <code>Connection</code> that contains the JDBC connection
	 * @throws ASelectUDBException
	 *             if the connection could not be opened
	 * @throws ASelectSAMException
	 *             if no valid resource could be found
	 */
	private Connection getConnection()
		throws ASelectUDBException, ASelectSAMException
	{
		String sMethod = "getConnection()";

		Connection oConnection = null;
		SAMResource oSAMResource = null;
		String sDriver = null;
		String sUsername = null;
		String sPassword = null;
		String sUrl = null;
		Object oResourceConfig = null;

		try {
			oSAMResource = _oASelectSAMAgent.getActiveResource(_sUDBResourceGroup);
		}
		catch (ASelectSAMException e) {
			StringBuffer sbFailed = new StringBuffer("No active resource found in udb resourcegroup: ");
			sbFailed.append(_sUDBResourceGroup);
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);

			throw e;
		}

		oResourceConfig = oSAMResource.getAttributes();

		try {
			sDriver = _oASelectConfigManager.getParam(oResourceConfig, "driver");
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'driver' found", e);

			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			// initialize driver
			Class.forName(sDriver);
		}
		catch (Exception e) {
			StringBuffer sbFailed = new StringBuffer("Can't initialize driver: ");
			sbFailed.append(sDriver);
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);

			throw new ASelectUDBException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		try {
			sPassword = _oASelectConfigManager.getParam(oResourceConfig, "password");
		}
		catch (Exception e) {
			sPassword = "";
			_oASelectSystemLogger
					.log(
							Level.CONFIG,
							MODULE,
							sMethod,
							"No or empty config item 'security_principal_password' found, using empty password. Don't use this in a live production environment.",
							e);
		}

		try {
			sUrl = _oASelectConfigManager.getParam(oResourceConfig, "url");
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'url' found", e);

			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			sUsername = _oASelectConfigManager.getParam(oResourceConfig, "username");
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'security_principal_name' found",
					e);

			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			oConnection = DriverManager.getConnection(sUrl, sUsername, sPassword);
		}
		catch (SQLException e) {
			StringBuffer sbFailed = new StringBuffer("Could not open connection to: ");
			sbFailed.append(sUrl);
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);

			throw new ASelectUDBException(Errors.ERROR_ASELECT_IO, e);
		}

		return oConnection;
	}

	/**
	 * Sorts authentication logging parameters and logs them. <br>
	 * <br>
	 * 
	 * @param sUserID
	 *            The A-Select user id
	 * @param sErrorCode
	 *            The error code of the error that occured
	 * @param sMessage
	 *            The authentication log message
	 */
	private void logAuthentication(String sUserID, String sErrorCode, String sMessage)
	{
		_oASelectAuthenticationLogger.log(new Object[] {
			MODULE, sUserID, null, null, null, sMessage, sErrorCode
		});
	}

}
