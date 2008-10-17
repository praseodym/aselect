package org.aselect.system.storagemanager.handler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
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
import org.aselect.system.utils.Base64;

public class JDBCStorageHandlerVarChar extends JDBCStorageHandler {

	
    /**
     * Returns a particular object from the database.
     * @see org.aselect.system.storagemanager.IStorageHandler#get(java.lang.Object)
     */
    public Object get(Object oKey) throws ASelectStorageException
    {
        String sMethod = "get()";
        Object oRet = null;
        PreparedStatement oStatement = null;
        ResultSet oResultSet = null;

        try
        {
            int iKey = oKey.hashCode();

            StringBuffer sbBuffer = new StringBuffer();
            sbBuffer.append("SELECT ").append(_sContextValue).append(" ");
            sbBuffer.append("FROM ").append(_sTableName).append(" ");
            sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?");
            _systemLogger.log(Level.INFO, MODULE, sMethod, "sql="+sbBuffer+" -> "+oKey);
            _systemLogger.log(Level.INFO, MODULE, sMethod, "Looking for hashkey -> "+iKey);

            Connection oConnection = getConnection();
            oStatement = oConnection.prepareStatement(
                sbBuffer.toString());
            oStatement.setInt(1, iKey);
            oResultSet = oStatement.executeQuery();

            if (oResultSet.next()) // record exists.
            { 
            	
//                oRet = decode(oResultSet.getBytes(_sContextValue.replace(BACKTICK, ' ').trim()));
            	BASE64Decoder b64e = new BASE64Decoder();
                oRet = decode(b64e.decodeBuffer(oResultSet.getString(_sContextValue.replace(BACKTICK, ' ').trim())));
                _systemLogger.log(Level.INFO, MODULE, sMethod, "result="+oRet);
            }
            else
            {
                _systemLogger.log(Level.FINE, MODULE, sMethod, "The supplied key is not mapped to any value.");
                throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
            }
        }
        catch (IOException eIO)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod, 
                "Could not decode the object from the database", eIO);
            throw new ASelectStorageException(
                Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eIO);
        }
        catch (ClassNotFoundException eCNF)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "Could not decode the object from the database", eCNF);
            throw new ASelectStorageException(
                Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eCNF);
        }
        catch (NullPointerException eNP)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "Empty (null) key-object was supplied", eNP);
            throw new ASelectStorageException(
                Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eNP);
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "Could not retrieve the object from the database", e);
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

        if (oRet == null)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "The supplied key is not mapped to any value",
                new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE));
            throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE);
        }

        return oRet;
    }

    /**
	 * Inserts a particular object into the database.
	 * 
	 * @see org.aselect.system.storagemanager.IStorageHandler#put(java.lang.Object,
	 *      java.lang.Object, java.lang.Long)
	 */
    public void put(Object oKey, Object oValue, Long lTimestamp)
        throws ASelectStorageException
    {
        String sMethod = "put()";
        PreparedStatement oStatement = null;
        ResultSet oResultSet = null;
        try
        {
            int iKey = oKey.hashCode();
            Timestamp oTimestamp = new Timestamp(lTimestamp.longValue());
            byte[] baKey = encode(oKey);
            byte[] baValue = encode(oValue);

            StringBuffer sbBuffer = new StringBuffer();
            sbBuffer.append("SELECT ").append(_sContextTimestamp).append(" ");
            sbBuffer.append("FROM ").append(_sTableName).append(" ");
            sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?");
            _systemLogger.log(Level.INFO, MODULE, sMethod, "sql="+sbBuffer+" -> "+oKey);
            
            Connection oConnection = getConnection();
            oStatement = oConnection.prepareStatement(sbBuffer.toString());
            oStatement.setInt(1, iKey);
            _systemLogger.log(Level.INFO, MODULE, sMethod, "Looking for hashkey -> "+iKey);
            oResultSet = oStatement.executeQuery();

            if (oResultSet.next()) // record exists.
            { 
                sbBuffer = new StringBuffer();
                sbBuffer.append("UPDATE ").append(_sTableName).append(" ");
//                sbBuffer.append("SET ").append(_sContextValue).append(" = ?, ")
                sbBuffer.append("SET ").append(_sContextValue).append(" = ? , ")
                    					.append(_sContextTimestamp).append(" = ? ");
                sbBuffer.append("WHERE ").append(_sContextKeyHash).append(" = ?");
                _systemLogger.log(Level.INFO, MODULE, sMethod, "sql="+sbBuffer+" -> "+oKey);
                _systemLogger.log(Level.INFO, MODULE, sMethod, "Updating for hashkey -> "+iKey);

                try {  // added 1.5.4
					oStatement.close();
				}
				catch (SQLException e) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
				}
                oStatement = oConnection.prepareStatement(sbBuffer.toString());
                
//                oStatement.setBytes(1, baValue);
                BASE64Encoder b64e = new BASE64Encoder();
                oStatement.setString(1, b64e.encode(baValue));
                
                oStatement.setTimestamp(2, oTimestamp);
                oStatement.setInt(3, iKey);
            }
            else // new record.
            { 
                sbBuffer = new StringBuffer();
                sbBuffer.append("INSERT INTO ").append(_sTableName).append(" ");
//                sbBuffer.append("VALUES (?,?,?,?)");
                sbBuffer.append("VALUES (?,?,?,?,?)");
                _systemLogger.log(Level.INFO, MODULE, sMethod, "sql="+sbBuffer+" -> "+oKey);
                _systemLogger.log(Level.INFO, MODULE, sMethod, "Inserting hashkey -> "+iKey);

                try {  // added 1.5.4
					oStatement.close();
				}
				catch (SQLException e) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
				}
                oStatement = oConnection.prepareStatement(sbBuffer.toString());
                oStatement.setInt(1, iKey);
                oStatement.setTimestamp(2, oTimestamp);
                oStatement.setBytes(3, baKey);
//                oStatement.setBytes(4, baValue);
                oStatement.setBytes(4, null);
                BASE64Encoder b64e = new BASE64Encoder();
                oStatement.setString(5, b64e.encode(baValue));
            }
            // oStatement.executeUpdate();
            int rowsAffected = oStatement.executeUpdate();
            _systemLogger.log(Level.INFO, MODULE, sMethod, "Rows affected -> "+rowsAffected);
        }
        catch (IOException eIO)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "Could not decode one or more objects that were retrieved from the database",
                eIO);
            throw new ASelectStorageException(
                Errors.ERROR_ASELECT_STORAGE_INSERT,eIO);
        }

        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "An error occured while inserting objects into the database", e);
            throw new ASelectStorageException(
                Errors.ERROR_ASELECT_STORAGE_INSERT, e);
        }
        finally {
			try {
				if (oResultSet != null) oResultSet.close();
				if (oStatement != null) oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
			}
		}
    }

    

}
