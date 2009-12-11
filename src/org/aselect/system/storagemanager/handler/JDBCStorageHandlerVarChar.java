/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.system.storagemanager.handler;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.logging.Level;

import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.BASE64Encoder;

// TODO: Auto-generated Javadoc
/**
 * @deprecated class hasn't been updated and therefore may be buggy, use {@link #JDBCStorageHandler()}
 */
@Deprecated
public class JDBCStorageHandlerVarChar extends JDBCStorageHandler
{
	
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
	@Override
	public Object get(Object oKey)
		throws ASelectStorageException
	{
		String sMethod = "get()";
		Object oRet = null;
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;
		// int iKey = oKey.hashCode();

		try {
			StringBuffer sbBuffer = new StringBuffer();
			sbBuffer.append("SELECT ").append(_sContextValue).append(" ");
			sbBuffer.append("FROM ").append(_sTableName).append(" ");
			// sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
			sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oKey);

			Connection oConnection = getConnection();
			oStatement = oConnection.prepareStatement(sbBuffer.toString());

			// 20090212, Bauke: use oKey as key to the table instead of the hashvalue
			// oStatement.setInt(1, iKey); // old
			byte[] baKey = encode(oKey); // new
			oStatement.setBytes(1, baKey); // new
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) { // record exists.
				// oRet = decode(oResultSet.getBytes(_sContextValue.replace(BACKTICK, ' ').trim()));
				BASE64Decoder b64e = new BASE64Decoder();
				// oRet = decode(b64e.decodeBuffer(oResultSet.getString(_sContextValue.replace(BACKTICK, ' ').trim())));
				// oRet = decode(b64e.decodeBuffer(oResultSet.getString(_sContextValue.replace(identifierQuote,
				// ' ').trim())));
				oRet = decode(b64e.decodeBuffer(_sContextValue.substring(identifierQuote.length(), _sContextValue
						.length()
						- identifierQuote.length())));
				_systemLogger.log(Level.FINER, MODULE, sMethod, "result=" + oRet);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied key is not mapped to any value.");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			}
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not decode the object from the database", eIO);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eIO);
		}
		catch (ClassNotFoundException eCNF) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not decode the object from the database", eCNF);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eCNF);
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Empty (null) key-object was supplied", eNP);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eNP);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve the object from the database", e);
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
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
		}
		if (oRet == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied key is not mapped to any value",
					new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE));
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE);
		}
		return oRet;
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
	@Override
	public void put(Object oKey, Object oValue, Long lTimestamp)
		throws ASelectStorageException
	{
		String sMethod = "put()";
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;
		Connection oConnection = null; // RH, 20090605, n
		try {
			int iKey = 0; // oKey.hashCode();
			Timestamp oTimestamp = new Timestamp(lTimestamp.longValue());
			byte[] baKey = encode(oKey);
			byte[] baValue = encode(oValue);

			StringBuffer sbBuffer = new StringBuffer();
			sbBuffer.append("SELECT ").append(_sContextTimestamp).append(" ");
			sbBuffer.append("FROM ").append(_sTableName).append(" ");
			// sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?"); // old
			sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer + " -> " + oKey);

			// Connection oConnection = getConnection(); // RH, 20090605, o
			oConnection = getConnection(); // RH, 20090605, n
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

				// oStatement.setBytes(1, baValue);
				BASE64Encoder b64e = new BASE64Encoder();
				oStatement.setString(1, b64e.encode(baValue));

				oStatement.setTimestamp(2, oTimestamp);
				oStatement.setInt(3, iKey);
			}
			else { // new record.
				sbBuffer = new StringBuffer();
				sbBuffer.append("INSERT INTO ").append(_sTableName).append(" ");
				// sbBuffer.append("VALUES (?,?,?,?)");
				sbBuffer.append("VALUES (?,?,?,?,?)");
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
				// oStatement.setBytes(4, baValue);
				oStatement.setBytes(4, null);
				BASE64Encoder b64e = new BASE64Encoder();
				oStatement.setString(5, b64e.encode(baValue));
			}
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
}
