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
 * $Id: SQLDatabaseConnector.java,v 1.11 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: SQLDatabaseConnector.java,v $
 * Revision 1.11  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.10  2005/09/08 12:47:12  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.9  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.8  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.7  2005/03/01 13:32:57  erwin
 * Improved logging message style.
 *
 * Revision 1.6  2005/02/23 10:40:29  erwin
 * Applied code style.
 *
 * Revision 1.5  2005/02/23 10:04:14  erwin
 * Improved Exception handling.
 *
 * Revision 1.4  2005/02/22 16:20:08  erwin
 * Improved error handling.
 *
 * Revision 1.3  2005/02/21 12:59:34  erwin
 * Applied code style and added Javadoc.
 *
 * Revision 1.2  2005/02/15 16:22:04  erwin
 * Applied code style and added Javadoc to some methods.
 * 
 */

package org.aselect.system.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;

import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectDatabaseException;
import org.aselect.system.logging.SystemLogger;

/**
 * SQL database connection functionality. 
 * <br><br>
 * <b>Description: </b> br> Database connection and query functionality for an
 * SQL database (e.g. MySQL). <br>
 * <br>
 * If you are using transactions safe tables (like InnoDB, BDB) you can use the
 * {@link #startTransaction(Statement)},{@link #commitTransaction(Statement)},
 * and {@link #rollbackTransaction(Statement)}methods to start, commit and
 * rollback transactions. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * The functionality of this class is threadsafe. All critical methods are
 * synchronized. <br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class SQLDatabaseConnector
{
    /** Database connection. */
    private Connection _oConn = null;
    /** Database URL */
    private String _sSQLURL;
    /** Database uer */
    private String _sSQLUser;
    /** Database password */
    private String _sSQLPassword;
    /** The current number of open database connections. */
    private int _iConnCount = 0;

    /** The logger for system log entries. */
    private SystemLogger _systemLogger = null;

    /** The module name */
    private static final String MODULE = "SQLDatabaseConnector";

    /**
     * Create a new instance. 
     * <br><br>
     * <b>Description: </b> <br>
     * Create a new <code>SQLDatabaseConnector</code>:
     * <ul>
     * <li>Set system logger</li>
     * <li>Set database properties</li>
     * <li>Initialize database driver</li>
     * </ul>
     * <br>
     * <b>Concurrency issues: </b> <br>-<br>
     * <br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>systemLogger</code> is an initialized
     * <code>SystemLogger</code>.
     * <li><code>sDriverName != null</code></li>
     * <li><code>sUser != null</code></li>
     * <li><code>sPassword != null</code></li>
     * <li><code>sURL != null</code></li>
     * </ul>
     * <br>
     * <b>Postconditions: </b> <br>
     * The systemlogger and database variables have been set. <br>
     * 
     * @param sDriverName
     *            The database driver name.
     * @param sUser
     *            The database user.
     * @param sPassword
     *            The database password.
     * @param sURL
     *            The database URL.
     * @param systemLogger
     *            The system logger.
     * @throws ASelectDatabaseException
     *             If database driver initialization fails.
     */
    public SQLDatabaseConnector (String sDriverName, String sUser,
        String sPassword, String sURL, SystemLogger systemLogger)
        throws ASelectDatabaseException
    {
        String sMethod = "SQLDatabaseConnector()";
        _systemLogger = systemLogger;
        _sSQLUser = sUser;
        _sSQLPassword = sPassword;
        _sSQLURL = sURL;

        try
        {
            //initialise database driver
            Class.forName(sDriverName);
        }
        catch (ClassNotFoundException eCNF)
        {
            StringBuffer sbError = new StringBuffer("Database initialisation failed, driver unknown: ");
            sbError.append(eCNF);
            sbError.append(" errorcode: ");
            sbError.append(Errors.ERROR_ASELECT_DATABASE_INIT);
            _systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), eCNF);
            throw new ASelectDatabaseException(Errors.ERROR_ASELECT_DATABASE_INIT, eCNF);
        }
    }

    /**
     * Update connection counter. 
     * <br><br>
     * <b>Description: </b> <br>
     * Updates the number of currently open connections. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * This method is synchronized. <br>
     * <br>
     * <b>Preconditions: </b> <br>-<br>
     * <br>
     * <b>Postconditions: </b> <br>
     * The number of connections is updated. <br>
     * 
     * @param bConnect
     *            If true the number of open connections is increased, otherwise
     *            it is decreased.
     */
    public synchronized void updateCount(boolean bConnect)
    {
        if (bConnect)
            _iConnCount++;
        else
            _iConnCount--;
    }

    /**
     * Connect to the database. 
     * <br><br>
     * <b>Description: </b> <br>
     * This methods performs the following steps:
     * <ul>
     * <li>Create a new <code>Connection</code> if connection with database
     * does not exist yet</li>
     * <li>Create e new <code>Statement</code></li>
     * <li>Increase connection counter</li>
     * </ul>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * This method is synchronized. <br>
     * <br>
     * <b>Preconditions: </b> <br>-<br>
     * <br>
     * <b>Postconditions: </b> <br>
     * There is a connection with the database. <br>
     * 
     * @return A new created <code>Statement</code>.
     */
    public synchronized Statement connect()
    {
        String sMethod = "connect()";
        Statement oStmt = null;

        try
        {
            if (_oConn == null || _oConn.isClosed())
                _oConn = DriverManager.getConnection(_sSQLURL, _sSQLUser,
                    _sSQLPassword);

            oStmt = _oConn.createStatement();

            this.updateCount(true);

        }
        catch (SQLException eS)
        {
            oStmt = null;
            _systemLogger.log(Level.WARNING, 
                				MODULE, 
                				sMethod, 
                				"Database connection failed", 
                				eS);
        }
        catch (Exception e)
        {
            oStmt = null;
            _systemLogger.log(Level.SEVERE, 
                MODULE, sMethod, "Database connection failed", e);
        }
        return oStmt;
    }

    /**
     * Close the database connection. 
     * <br><br>
     * <b>Description: </b> <br>
     * Close the given database statement and if applicable the database
     * connection. <br>
     * <br>
     * This methods performs the following steps:
     * <ul>
     * <li>Close the statement</li>
     * <li>Decrease the connection count</li>
     * <li>If connection count is zero or less disconnect the database</li>
     * </ul>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * This method is synchronized. <br>
     * <br>
     * <b>Preconditions: </b> <br>
     * <code>oStmt</code> should be retrieved by calling {@link #connect()}
     * <br>
     * <br>
     * <b>Postconditions: </b> <br>
     * The connection counter is lowered. If the connection counter is 0, the
     * database connection is closed. <br>
     * 
     * @param oStmt
     *            The statement that is to be closed.
     * @return True if closing succeeded, otherwise false.
     */
    public synchronized boolean disconnect(Statement oStmt)
    {

        String sMethod = "disconnect()";
        boolean bRet = false;

        try
        {
            if (oStmt != null)
                oStmt.close();
            oStmt = null;

            this.updateCount(false);

            if (_iConnCount < 1)
            {
                if (_oConn != null)
                    _oConn.close();
                _oConn = null;
            }

            bRet = true;
        }
        catch (SQLException eS)
        {
            _systemLogger.log(Level.WARNING, 
                MODULE, sMethod, "Disconnect failed", eS);
        }
        catch (Exception e)
        {

            _systemLogger.log(Level.WARNING, 
                MODULE, sMethod, "Disconnect failed", e);
        }
        return bRet;
    }

    /**
     * Execute a SQL query. 
     * <br><br>
     * <b>Description: </b> <br>
     * Uses the given <code>Statement</code> to execute the given query. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * Every thread should use its own statement. This method should be called
     * sequentially when using the same <code>Statement</code>.<br>
     * <br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>oStmt</code> should be retrieved by calling
     * {@link #connect()}</li>
     * <li><code>sQuery</code> should be a correct SQL query</li>
     * </ul>
     * <br>
     * <b>Postconditions: </b> <br>-<br>
     * 
     * @param oStmt
     *            The statement that is used for rhe execution of the query.
     * @param sQuery
     *            The query that is to be executed.
     * @return The result of the query.
     * @throws ASelectDatabaseException
     *             If execution fails.
     */
    public ResultSet executeQuery(Statement oStmt, String sQuery)
        throws ASelectDatabaseException
    {
        String sMethod = "executeQuery()";
        ResultSet rs = null;

        try
        {
            if (oStmt == null)
            {
                StringBuffer sbError = new StringBuffer("No database connection available, ");
                sbError.append(Errors.ERROR_ASELECT_DATABASE_QUERY_FAILED);
                _systemLogger.log(Level.SEVERE, 
                    MODULE, sMethod, sbError.toString());
                throw new ASelectDatabaseException(
                    Errors.ERROR_ASELECT_DATABASE_QUERY_FAILED);
            }
            rs = oStmt.executeQuery(sQuery);

        }
        catch (SQLException eSQL)
        {
            _systemLogger.log(Level.WARNING, 
                MODULE, sMethod, "Error executing query",eSQL);
            throw new ASelectDatabaseException(
                Errors.ERROR_ASELECT_DATABASE_QUERY_FAILED, eSQL);
        }
        return rs;
    }

    /**
     * Execute a SQL update query. 
     * <br><br>
     * <b>Description: </b> <br>
     * Uses the given <code>Statement</code> to execute the given query. The
     * query updates data in the database. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * Every thread should use its own statement. This method should be called
     * sequentially when using the same <code>Statement</code>.<br>
     * <br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>oStmt</code> should be retrieved by calling
     * {@link #connect()}</li>
     * <li><code>sQuery</code> should be a correct SQL query</li>
     * </ul>
     * <br>
     * <b>Postconditions: </b> <br>-<br>
     * 
     * @param oStmt
     *            The statement that is used for the execution of the query.
     * @param sQuery
     *            The query that is to be executed.
     * @return The number of updated rows.
     * @throws ASelectDatabaseException
     *             If update fails.
     * @see java.sql.Statement#executeUpdate(java.lang.String)
     */
    public int executeUpdate(Statement oStmt, String sQuery)
        throws ASelectDatabaseException
    {
        String sMethod = "executeUpdate()";
        int iRowsChanged = -1;

        try
        {
            if (oStmt == null)
            {
                StringBuffer sbError = new StringBuffer("No database connection available, ");
                sbError.append("cause: ");
                sbError.append(Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED);
                _systemLogger.log(Level.SEVERE, 
                    MODULE, sMethod, sbError.toString());
                throw new ASelectDatabaseException(Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED);
            }

            iRowsChanged = oStmt.executeUpdate(sQuery);
        }
        catch (SQLException eSQL)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod, "Error executing update query", eSQL);
            throw new ASelectDatabaseException(Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED, eSQL);
        }

        return iRowsChanged;
    }

    /**
     * Execute the "BEGIN" command. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * Excute the SQL "BEGIN" command as a query. This command marks the
     * beginning of a transaction. This is the recommended way to start an
     * ad-hoc transaction as this is SQL-99 syntax. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * Every thread should use its own statement. <br>
     * <br>
     * <b>Preconditions: </b> <br>
     * <code>oStmt</code> should be retrieved by calling {@link #connect()}
     * <br>
     * <br>
     * <b>Postconditions: </b> <br>
     * The database has started a new transaction. <br>
     * 
     * @param oStmt
     *            The statement that is used for the execution.
     * @throws ASelectDatabaseException
     *             If transaction could not be started.
     */
    public void startTransaction(Statement oStmt)
        throws ASelectDatabaseException
    {
        String sMethod = "startTransaction()";
        try
        {
            if (oStmt == null)
            {
                StringBuffer sbError = new StringBuffer("No database connection available, ");
                sbError.append("cause: ");
                sbError.append(Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED);
                _systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
                throw new ASelectDatabaseException(
                    Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED);
            }
            oStmt.execute("BEGIN");
        }
        catch (SQLException eSQL)
        {
            _systemLogger.log(Level.WARNING, 
                MODULE, sMethod, "Error executing 'BEGIN'", eSQL);
            throw new ASelectDatabaseException(
                Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED, eSQL);
        }
    }

    /**
     * Excute the "ROLLBACK" command. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * Excute the SQL "ROLLBACK" command as a query. Use this command if you
     * want to ignore the changes you have made since the beginning of your
     * transaction. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * Every thread should use its own statement. <br>
     * <br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>oStmt</code> should be retrieved by calling
     * {@link #connect()}</li>
     * <li>{@link #startTransaction(Statement)}should be executed before
     * calling this method</li>
     * </ul>
     * <br>
     * <b>Postconditions: </b> <br>
     * All queries during transaction are rolled back. <br>
     * 
     * @param oStmt
     *            The statement that is used for the execution.
     * @throws ASelectDatabaseException
     *             If transaction could not be rolled back.
     */
    public void rollbackTransaction(Statement oStmt)
        throws ASelectDatabaseException
    {
        String sMethod = "rollbackTransaction()";
        try
        {
            if (oStmt == null)
            {
                StringBuffer sbError = new StringBuffer("No database connection available, ");
                sbError.append("cause: ");
                sbError.append(Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED);
                _systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
                throw new ASelectDatabaseException(
                    Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED);
            }
            oStmt.execute("ROLLBACK");
        }
        catch (SQLException eSQL)
        {
            _systemLogger.log(Level.WARNING, 
                MODULE, sMethod, "Error executing 'ROLLBACK'",eSQL);
            throw new ASelectDatabaseException(
                Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED, eSQL);
        }
    }

    /**
     * Excute the "COMMIT" command. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * Excute the SQL "COMMIT" command as a query. After the "COMMIT" query the
     * recent changes are stored. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * Every thread should use its own statement. <br>
     * <br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>oStmt</code> should be retrieved by calling
     * {@link #connect()}</li>
     * <li>{@link #startTransaction(Statement)}should be executed</li>
     * </ul>
     * <br>
     * <b>Postconditions: </b> <br>
     * All queries during transaction are committed. <br>
     * 
     * @param oStmt
     *            The statement that is used for the execution.
     * @throws ASelectDatabaseException
     *             If transaction could not be committed.
     */
    public void commitTransaction(Statement oStmt)
        throws ASelectDatabaseException
    {
        String sMethod = "commitTransaction()";
        try
        {
            if (oStmt == null)
            {
                StringBuffer sbError = new StringBuffer("No database connection available, ");
                sbError.append("cause: ");
                sbError.append(Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED);
                _systemLogger.log(Level.SEVERE, 
                    MODULE, sMethod, sbError.toString());
                throw new ASelectDatabaseException(
                    Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED);
            }

            oStmt.execute("COMMIT");

        }
        catch (SQLException eSQL)
        {
            _systemLogger.log(Level.WARNING,
                MODULE, sMethod, "Error executing 'COMMIT'",eSQL);
            throw new ASelectDatabaseException(
                Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED, eSQL);
        }
    }

    /**
     * Returns the database URL.
     * 
     * @return The URL of the database.
     */
    public String getDatabaseUrl()
    {
        return _sSQLURL;
    }
}