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
 * $Id: AuthenticationLogger.java,v 1.18 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthenticationLogger.java,v $
 * Revision 1.18  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.17  2006/04/12 13:20:41  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.16.4.1  2006/04/05 13:34:55  martijn
 * fixed memory leakage bug by closing statements in a finally{} block
 *
 * Revision 1.16  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.15  2005/04/27 09:43:24  erwin
 * Fixed bug with "i+1", improved system logging.
 *
 * Revision 1.14  2005/04/15 10:15:22  martijn
 * fixed bug in closeHandlers() that threw a NullPointerException if the SystemLogger init() method was is been called
 *
 * Revision 1.13  2005/03/16 13:42:39  tom
 * Added new log functionality
 *
 * Revision 1.12  2005/03/10 17:02:43  martijn
 * moved reading of the system logger configuration to the right classes, so changed init() methods
 *
 * Revision 1.11  2005/03/10 15:15:53  tom
 * Fixed double component id logging
 *
 * Revision 1.10  2005/03/10 12:45:03  martijn
 * removed deprecated init() method
 *
 * Revision 1.9  2005/03/10 11:14:14  martijn
 * moved the config retrieving from the ASelect component to the AuthenticationLogger: resulted in a new init() method
 *
 * Revision 1.8  2005/03/09 13:56:25  remco
 * fixed bug
 *
 * Revision 1.7  2005/03/09 13:53:45  martijn
 * The log(String sMessage) gave a nullpointer exception when using file as a target, this bug is fixed
 *
 * Revision 1.6  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.5  2005/03/07 14:17:33  martijn
 * Added javadoc and some minor bugfixes in logging to database
 *
 * Revision 1.4  2005/03/04 16:26:14  martijn
 * Added a new init() / added db table configuration / added log(Object[]) / restructured sb log handling
 *
 * Revision 1.3  2005/03/01 10:50:21  erwin
 * Fixed the 2nd init method (systemlogger)
 * converted destroy() to closeHandlers()
 *
 * Revision 1.2  2005/02/21 16:25:58  erwin
 * Applied code style and improved JavaDoc.
 *
 * Revision 1.1  2005/01/28 15:36:19  remco
 * Removed obsolete class VerboseLogger
 * Introduced AuthenticationLogger
 *
 */

package org.aselect.system.logging;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Calendar;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;

/**
 * Authentication logger. 
 * <br>
 * <br>
 * <b>Description: </b> <br>
 * This class implements a logger with the purpose of logging authentication
 * message to a system logger or a database. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * This class is thread-safe. <br>
 * <br>
 * This class only writes log items and can therefore use one resource (e.g.
 * database connection). <br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class AuthenticationLogger
{
    /** The module name. */
    private final String MODULE = "AuthenticationLogger";

    /**
     * The default delimiter for file logging
     */
    private final String DELIMITER = ",";
    
    /**
     * The component name that uses the logger
     */
    private String _sLogComponent;
        
    /**
     * The delimiter used if the target is a file
     */
    private String _sDelimiter;
    
    /** Specify if database logging is enabled */
    private boolean _bLogToDatabase = false;
    
    /**
     * The database connect url
     */
    private String _sUrl;
    /**
     * The database driver
     */
	private String _sDriver;
	/**
     * The database username
     */
	private String _sUser;
	/**
     * The database password
     */
	private String _sPassword;
	/**
     * The database table name
     */
	private String _sTableName;
	/**
     * The database PreparedStatement query
     */
	private StringBuffer _sbPreparedQuery;
	/**
     * The names of the configured database columns
     */
	private Vector _vColumnNames = null;
	/**
     * The types of the configured database columns
     */
	private Vector _vColumnTypes = null;

    /**
     * The database connecton. This connection is shared among all
     * <code>AuthenticationLoggers</code>.
     */
    private static Connection _conn = null;

    /**
     * The backup logger. This logger is used in case of exception while logging
     */
    private SystemLogger _systemLogger = null;


    /**
     * Create a new default instance. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * Creates a new <code>AuthenticationLogger</code>. If you use this
     * constructor you'll need to call one of the init() methods.
     */
    public AuthenticationLogger ()
    {}

    /**
     * Initializes the Authentication logger with a file back-end.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * <li>Reads configuration</li>
     * <li>Sets the <i>_bLogToDatabase</i> to FALSE</li>
     * <li>Creates a new <code>SystemLogger</code> object and initializes it 
     * with the configuration.</li>
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <li><i>oConfigManager</i> must be initialized</li>
     * <li><i>oSystemLogger</i> must be initialized</li>
     * <li><i>oConfigManager</i> may not be <code>null</code></li>
     * <li><i>oLogTargetConfig</i> may not be <code>null</code></li>
     * <li><i>oSystemLogger</i> may not be <code>null</code></li>
     * <li><i>sComponent</i> may not be <code>null</code></li>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * Sets <i>_systemLogger</i> class vairable and initializes it.
     * <br>
     * @param sComponent The name of the A-Select component for which the 
     * authentication logger is used
     * @param sLogFileNamePrefix The log file name prefix (".log" is appended).
     * @param sLoggerNamespace The namespace of this system logger.
     * @param oConfigManager The config manager used to retrieve the 
     * configuration from
     * @param oLogTargetConfig The 'target' config section containing the file 
     * configuration 
     * @param oSystemLogger The back-up logger that must be used to log any 
     * errors if database logging failed
     * @param sWorkingDir The workingdir that must be used when no directory is 
     * configured
     * @throws ASelectException if initializing failed (missing config items)
     */
    public void init(String sComponent, String sLogFileNamePrefix,
        String sLoggerNamespace, ConfigManager oConfigManager, 
        Object oLogTargetConfig, SystemLogger oSystemLogger, String sWorkingDir) 
    	throws ASelectException
    {
        String sMethod = "init()";
        
        try
        {
            _bLogToDatabase = false;
            
            _sLogComponent = sComponent;
            if (_sLogComponent == null) _sLogComponent = "";
            
	        try
	        {
	            _sDelimiter = oConfigManager.getParam(oLogTargetConfig, "delimiter");
	        }
	        catch (Exception e)
	        {
	            _sDelimiter = DELIMITER;
	            
	            StringBuffer sbInfo = new StringBuffer("No valid config item: 'delimiter' in config section 'target' found, using default value: ");
	            sbInfo.append(_sDelimiter);
	            oSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString(), e);
	        }
	        
	        _systemLogger = new SystemLogger();
	        _systemLogger.init(sLogFileNamePrefix, sLoggerNamespace, oConfigManager, oLogTargetConfig, sWorkingDir);
        }
        catch (Exception e)
        {
            oSystemLogger.log(Level.CONFIG, MODULE, sMethod, "Could not initialize Authentication Logger", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }
    
    /**
     * Initializes the Authentication logger with a database back-end.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * <li>Reads configuration</li>
     * <li>Tries to connect to the database</li>
     * <li>Retrieves the column types of the database columns that are configured</li>
     * <li>Creates the query for the PreparedStatement that is used by logging</li>
     * <li>Sets the <i>_bLogToDatabase</i> to TRUE</li>
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <li><i>oConfigManager</i> must be initialized</li>
     * <li><i>oSystemLogger</i> must be initialized</li>
     * <li><i>oConfigManager</i> may not be <code>null</code></li>
     * <li><i>oLogTargetConfig</i> may not be <code>null</code></li>
     * <li><i>oSystemLogger</i> may not be <code>null</code></li>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sComponent The name of the A-Select component for which the 
     * authentication logger is used
     * @param oConfigManager The config manager used to retrieve the 
     * configuration from
     * @param oLogTargetConfig The 'target' config section containing the 
     * configuration 
     * @param oSystemLogger The back-up logger that must be used to log any 
     * errors if database logging failed
     * @throws ASelectException if initializing failed (missing config items)
     */
    public void init(String sComponent, ConfigManager oConfigManager, 
        Object oLogTargetConfig, SystemLogger oSystemLogger)
		throws ASelectException
	{
        String sMethod = "init()";
        
        try
        {
            //set default delimiter for back-up logging
            _sDelimiter = DELIMITER;
            
            _sLogComponent = sComponent;
            if (_sLogComponent == null) _sLogComponent = "";
            
			_systemLogger = oSystemLogger;
			
			readConfig(oConfigManager, oLogTargetConfig);
	        
			//test connection
			try
			{
				connect();
			}
		    catch (Exception e)
			{
		     	StringBuffer sbTemp = new StringBuffer("Could not connect with logger back-end: ");
		     	sbTemp.append(_sUrl);
		     	throw new ASelectException (sbTemp.toString(), e);
			}
		    
		    //read column types
		    _vColumnTypes = retrieveColumnTypes();
		    
		    //create query string
			_sbPreparedQuery = createStatementQuery();
			
		    //setting log to database to true
		    _bLogToDatabase = true;
        }
        catch (ASelectException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error during initialize", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
	}

    /**
     * Write a log item. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * Write a log item with detailed information. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>-<br>
     * <br>
     * <b>Preconditions: </b> <br>
     * The <code>AuthenticationLogger</code> is initialized. <br>
     * <br>
     * <b>Postconditions: </b> <br>-<br>
     * 
     * @param sAction
     *            The action that should be logged.
     * @param sUser
     *            The user that should be logged.
     * @param sIP
     *            The remote IP address.
     * @param sAppID
     *            The application id.
     * @param sMessage
     *            The log message.
     */
    public void log(String sAction, String sUser, String sIP, String sAppID,
        String sMessage)
    {
        Object[] oaFields = 
        {
            sAction,
            sUser,
            sIP,
            sAppID,
            sMessage
        };
        
        log(oaFields);
    }

    /**
     * Log a message. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * Logs a simple log message. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>-<br>
     * <br>
     * <b>Preconditions: </b> <br>
     * The <code>AuthenticationLogger</code> is initialized. <br>
     * <br>
     * <b>Postconditions: </b> <br>-<br>
     * 
     * @param sMessage
     *            The message to be logged.
     */
    public void log(String sMessage)
    {
        Object[] oaLogFields = null;
        if (_bLogToDatabase)
        {
	        int iFields = _vColumnNames.size();
	        oaLogFields = new Object[iFields];
	        oaLogFields[iFields] = sMessage;
	        log(oaLogFields);
        }
        else
        {
            oaLogFields = new Object[1];
            oaLogFields[0] = sMessage;
            log(oaLogFields);
        }
    }
    
    /**
     * Logs all objects in the supplied object array to the logging target.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * <li>If the target is a file, all objects in the supplied array will be concat 
     * with '::' to one <code>String</code> and the string will be logged to a 
     * file.</li>
     * <li>If the target is a database, every object in the supplied array will 
     * be stored in a column of the configured database table.</li>
     * <br>
     * <b>
     * Within A-Select components (UDB Connectors and AuthSP Handlers) 
     * the following components sequence will be used.<br>
     * <li>A-Select component. (e.g. A-Select Server)</li> 
     * <li>Action (MODULE.method())</li>
     * <li>IP (Users IP address)</li>
     * <li>User (A-Select user id)</li>
     * <li>Organization (The A-Select organization)</li>
     * <li>APP ID (A-Select app_id for which the user will be authenticated)</li>
     * <li>Message (The log message)</li>
     * </b> 
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param oLogFields All objects that should be logged
     */
    public void log(Object[] oLogFields)
	{
        if (oLogFields != null)
        {
	        if (_bLogToDatabase)
	            try
	            {
	                logToDB(oLogFields);
	            }
	        	catch (Exception e)
	        	{
				    try
				    {
				        _systemLogger.log(Level.WARNING, MODULE, "log()", 
				            "Logging to database failed (first try), retrying.");
				        
				        connect();
				        logToDB(oLogFields);
				    }
				    catch (Exception eE) 
				    {
				        _systemLogger.log(Level.WARNING, MODULE, "log()", 
			            "Logging to database failed (second try) using back-up logger.");
				        logToFile(oLogFields);    
				    }	
	        	}
	        else
	            logToFile(oLogFields);
        }
	}
    
    /**
     * Cleanup logger resources. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * Closes all openend log handlers. Disconnects the database connection if
     * applicable. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>-<br>
     * <br>
     * <b>Preconditions: </b> <br>-<br>
     * <br>
     * <b>Postconditions: </b>
     * <ul>
     * <li>All used log handlers are closed.</li>
     * <li>The database connection is closed.</li>
     * </ul>
     * <br>
     * 
     * @see SystemLogger#closeHandlers()
     */
    public void closeHandlers()
    {
        if (!_bLogToDatabase && _systemLogger != null)
        {
            _systemLogger.closeHandlers();
        }
        disconnect();
    }
    
    /**
     * Logs the given object array to the file.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Will concat all objects to one <code>String</code> and logs the resulting 
     * string to the log file
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param oLogFields An array of objects that must be logged
     */
    private void logToFile(Object[] oLogFields)
    {
        StringBuffer sbMessage = new StringBuffer(_sLogComponent);
        sbMessage.append(_sDelimiter);
        for (int i = 0; i < oLogFields.length; i++)
        {
            Object oField = oLogFields[i];
            String sField = "";
            if (oField instanceof String)
                sField = (String)oField;
            
            sbMessage.append(sField);
            
            if (i < (oLogFields.length - 1))
                sbMessage.append(_sDelimiter);
                
        }
        _systemLogger.log(Level.INFO, sbMessage.toString());
    }
    
    /**
     * Logs the given object array to the database.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * The first field will always be filled with the <i>sLogComponent</i> that 
     * is supplied at initialization.<br>
     * If there are more objects supplied then all ending <code>String</code> 
     * objects will be concat (with ',') to one <code>String</code> and will be 
     * written to the last database table column.<br>
     * If <code>NULL</code> is supplied then an SQL NULL object will be written 
     * to the column.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param oLogFields An array of objects that must be logged
     * @throws ASelectException If the the supplied object array could not be 
     * logged to the database. (connection lost)
     */
    private void logToDB(Object[] oLogFields) throws ASelectException
	{
        String sMethod = "logToDB";
        PreparedStatement oStatement = null;
		try
		{
		    int iFields = oLogFields.length;
		    //add one, because the first column will be filled with _sLogComponent
			int iWriteFields = iFields + 1;
			int iColumns = _vColumnTypes.size();
			StringBuffer sbLastField = new StringBuffer();
			
			//if more log fields are supplied, then the last log fields will be 
			//merged in the last column
			if (iWriteFields > iColumns)
			{
			    for (int i = (iColumns - 1); i < iWriteFields; i++)
			    {
			        Object oField = oLogFields[i - 1];
			        String sField = "";
			        if (oField instanceof String)
			            sField = (String)oField;
			            
			        sbLastField.append(sField);
			        
			        if ((i + 1) < iWriteFields)
			            sbLastField.append(",");
			    }
			}
			
			oStatement = _conn.prepareStatement(_sbPreparedQuery.toString());
			
			for (int i = 1; i <= iColumns; i++)
			{
			    int iColumnType = ((Integer)_vColumnTypes.get(i - 1)).intValue();
			    
			    if (i <= iWriteFields)
			    {
			        Object oValue = null;
			        
				    if (i == 1)
				        oValue = _sLogComponent;
				    else if (iColumns == i && iWriteFields > iColumns)
			            oValue = sbLastField.toString();
			        else
			            oValue = oLogFields[i - 2];
			        
			        try
					{
					    oStatement.setObject(i, oValue, iColumnType);
					}
					catch(Exception e)
					{
					    oStatement.setNull(i, iColumnType);
					    
					    StringBuffer sbInfo = new StringBuffer("Could not write object: '");
					    sbInfo.append(oValue);
					    sbInfo.append("' to column '");
					    sbInfo.append(i);
					    sbInfo.append("' of database table: ");
					    sbInfo.append(_sTableName);
					    _systemLogger.log(Level.FINE, MODULE, sMethod, sbInfo.toString());
					}
					
				}
			    else
			    {
			        //if there are more fields in the statement then supplied to 
			        //the log method, then add NULL fields
			        oStatement.setNull(i, iColumnType);
			    }
			}

			oStatement.executeUpdate();
		}
		catch(ArrayIndexOutOfBoundsException eAIOOB)
		{
		    _systemLogger.log(Level.WARNING, MODULE, sMethod, 
		        "Internal error: Array index out of bounds", eAIOOB);		    
		    throw new ASelectException(
		        Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED, eAIOOB); 
		}
		catch (Exception e)
		{
		    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Internal error", e);
		    
		    throw new ASelectException(Errors.ERROR_ASELECT_DATABASE_UPDATE_FAILED, e);
		}
        finally
        {
            if (oStatement != null)
            {
                try
                {
                    oStatement.close();
                }
                catch (SQLException e) {}
            }
        }
	}


    /**
     * Connects to the database if applicable.
     * 
     * @throws Exception
     *             If connection fails.
     */
    private synchronized void connect() throws Exception
    {
        try
	    {
	        _conn.close();      
	    }
	    catch (Exception eE) {}
	    
	    _conn = null;
	    
        _conn = DriverManager.getConnection(_sUrl, _sUser, _sPassword);
    }

    /**
     * Closes the database connection. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * Closes the connection to the database if database logging is enabled.
     * <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * This method is synchronized. <br>
     * <br>
     * <b>Preconditions: </b> <br>-<br>
     * <br>
     * <b>Postconditions: </b> <br>
     * The database connection is closed. <br>
     */
    private synchronized void disconnect()
    {
        String sMethod = new String("disconnect()");

        try
        {
            if (_bLogToDatabase)
            {
                if (_conn != null)
                    _conn.close();
            }
        }
        catch (SQLException eS)
        {
            altLog(sMethod, "Database Error" + eS.getMessage() );
        }
        catch (Exception eX)
        {
            altLog(sMethod, "Internal Error" + eX.getMessage() );
        }
        _conn = null;
    }
    
    /**
     * Write an alternative log message. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * Use the alternative logger if primairy logging fails. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>-<br>
     * <br>
     * <b>Preconditions: </b> <br>-<br>
     * <br>
     * <b>Postconditions: </b> <br>-<br>
     * 
     * @param sMethod
     * 			  the method to be logged
     * @param sMessage
     *            the message to be logged.
     */
    private void altLog(String sMethod, String sMessage)
    {
        if (_systemLogger == null)
            System.err.println("[" + getTimestamp() + "] " + MODULE + "." + sMethod + " -> " +sMessage);
        else
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, sMessage);
    }

    /**
     * get the current timestamp. 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * get the current system timestamp in a logable format. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>-<br>
     * <br>
     * <b>Preconditions: </b> <br>-<br>
     * <br>
     * <b>Postconditions: </b> <br>-<br>
     * 
     * @return The current date/time in a logable format.
     */
    private String getTimestamp()
    {
        int i;
        Calendar cNow = Calendar.getInstance();
        StringBuffer sb = new StringBuffer();
        sb.append(cNow.get(Calendar.YEAR)).append("-");
        if ((i = cNow.get(Calendar.MONTH) + 1) < 10)
            sb.append("0");
        sb.append(i).append("-");
        if ((i = cNow.get(Calendar.DAY_OF_MONTH)) < 10)
            sb.append("0");
        sb.append(i).append(" ");
        if ((i = cNow.get(Calendar.HOUR_OF_DAY)) < 10)
            sb.append("0");
        sb.append(i).append(":");
        if ((i = cNow.get(Calendar.MINUTE)) < 10)
            sb.append("0");
        sb.append(i).append(":");
        if ((i = cNow.get(Calendar.SECOND)) < 10)
            sb.append("0");
        sb.append(i);
        return sb.toString();
    }
    
    
	/**
	 * Reads the configuration of a database target database.
	 * <br><br>
	 * @param oConfigManager The config manager that is used to retrieve the 
	 * configuration
	 * @param oLogTargetConfig The configuration database target section 
	 * @throws ASelectException if incorrect configuration is found
	 */
	private void readConfig(ConfigManager oConfigManager, Object oLogTargetConfig) 
		throws ASelectException
	{
	    String sMethod = "readConfig()";

		Object oTable = null;
		Object oColumn = null;
	
		try
		{
			try
			{
				_sUrl =  oConfigManager.getParam(oLogTargetConfig, "url");
			}
			catch (Exception e)
			{
				throw new ASelectException("No valid 'url' config item found in logging 'target' section");
			}
			
			try
			{
				_sDriver =  oConfigManager.getParam(oLogTargetConfig, "driver");
			}
			catch (Exception e)
			{
				throw new ASelectException("No valid 'driver' config item found in logging 'target' section");
			}
			
			try
			{
				//initialize driver
				Class.forName(_sDriver);
			}
			catch (Exception e)
			{
				throw new ASelectException("Could not initialize driver that is configured int the 'back-end' in logger section", e);
			}
			
			try
			{
				_sUser =  oConfigManager.getParam(oLogTargetConfig, "user");
			}
			catch (Exception e)
			{
				throw new ASelectException("No valid 'user' config item found in logging 'target' section");
			}
			
			try
			{
				_sPassword =  oConfigManager.getParam(oLogTargetConfig, "password");
			}
			catch (Exception e)
			{
				_sPassword = "";
				_systemLogger.log(Level.CONFIG, 
				    	MODULE, 
				    	sMethod, 
				    	"Invalid or empty 'password' config item found, using empty password", 
				    	e);
			}	
			
			try
			{
				oTable =  oConfigManager.getSection(oLogTargetConfig, "table");
			}
			catch (Exception e)
			{
				throw new Exception("Could not find the 'table' config section in logger 'target' section");
			}
			
			try
			{
				_sTableName =  oConfigManager.getParam(oTable, "name");
			}
			catch (Exception e)
			{
				throw new ASelectException("No valid 'name' config item found in 'table' section", e);
			}
			
			//read all column names and create first part of the query
			_vColumnNames = new Vector();
			try
			{
			    oColumn = oConfigManager.getSection(oTable, "column");
			}
			catch (Exception e)
			{
			    throw new ASelectException("Not one valid 'column' config item found in 'table' section", e);
			}
			while (oColumn != null)
		    {
			    String sName = null;
			    try
				{
			        sName = oConfigManager.getParam(oColumn, "name");
				}
			    catch (Exception e)
			    {
			        throw new ASelectException("Not one valid 'name' config item found in 'column' section", e);
			    }
		    	_vColumnNames.add(sName);
			    
		    	oColumn = oConfigManager.getNextSection(oColumn);
		    }
		}
		catch (ASelectException e)
		{
		    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Error reading config", e);
		    
		    throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (Exception e)
		{
		    _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
		    
		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}
	
	/**
	 * Retrieves the column types of the configured database.
	 * <br>
	 * The columns in the configured database must match the configured column 
	 * names.
	 * <br><br>
	 * @return a <code>Vector</code> containing all column types that will be 
	 * needed for database logging
	 * @throws ASelectException if a column type or name could not be resolved
	 */
	private Vector retrieveColumnTypes() throws ASelectException
	{
	    String sMethod = "retrieveColumnTypes()";
        Statement oStatement = null;
	    ResultSet rsSelect = null;
	    ResultSetMetaData rsmdTypes = null;
	    Vector vReturn = new Vector();
	    
		try
		{
		    oStatement = _conn.createStatement();
			
			StringBuffer sbQuery = new StringBuffer("SELECT * FROM ");
			sbQuery.append(_sTableName);
						
			try
			{
			    rsSelect = oStatement.executeQuery(sbQuery.toString());
			}
			catch(Exception e)
			{
			    StringBuffer sbFailed = new StringBuffer("Could not execute query:");
			    sbFailed.append(sbQuery.toString());
			    throw new ASelectException(sbFailed.toString(), e);
			}
			
			try
			{
			    rsmdTypes = rsSelect.getMetaData();
			}
			catch (Exception e)
			{
			    throw new ASelectException("Could not resolve meta data", e);
			}
			for (int i = 1; i <= rsmdTypes.getColumnCount(); i++)
			{
				if (_vColumnNames.contains(rsmdTypes.getColumnName(i)))
				{
					vReturn.add(new Integer(rsmdTypes.getColumnType(i)));
				}
			}
		}
		catch (ASelectException e)
		{
		    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Error retreiving ColumnTypes", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (Exception e)
		{
		    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
        finally
        {
            if (rsSelect != null) 
            {
                try
                {
                    rsSelect.close();
                }
                catch (SQLException e) {}
                
                rsSelect = null;
            }
            
            if (oStatement != null) 
            {
                try
                {
                    oStatement.close();
                }
                catch (SQLException e) {}
                
                oStatement = null;
            }   
        }
        
		return vReturn;
	}
	
	/**
	 * Creates the PrepareStatement query used for logging.
	 * <br><br>
	 * @return a <code>StringBuffer</code> containing the UPDATE query
	 * @throws ASelectException if the query could not be created
	 */
	private StringBuffer createStatementQuery() throws ASelectException
	{
	    String sMethod = "createStatementQuery()";
	    
	    StringBuffer sbPreparedQuery = null;
	    try
		{
		    //read all column names and create first part of the query
		    sbPreparedQuery = new StringBuffer("INSERT INTO ");
			sbPreparedQuery.append(_sTableName);
			sbPreparedQuery.append(" (");
			
			for (int i = 0; i < _vColumnTypes.size(); i++)
		    {
				sbPreparedQuery.append(_vColumnNames.get(i)).append(",");
		    }
			String sColumnQuery = sbPreparedQuery.toString();
		    if (sColumnQuery.endsWith(","))
		    {
		    	sColumnQuery = sColumnQuery.substring(0, sColumnQuery.length() -1);
		    }
		    sColumnQuery = sColumnQuery + ") ";
		    		    
		    sbPreparedQuery = new StringBuffer(sColumnQuery);
		    sbPreparedQuery.append(" VALUES (");
		    for (int i = 0; i < _vColumnTypes.size() - 1; i++)
			{
		    	sbPreparedQuery.append("?,");
			}
		    sbPreparedQuery.append("?)");
		}
		catch (Exception e)
		{
		    _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
		    throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		
		return sbPreparedQuery;
	}
}
