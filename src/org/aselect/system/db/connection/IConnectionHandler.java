/**
 * 
 */
package org.aselect.system.db.connection;

import java.sql.Connection;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;

// TODO: Auto-generated Javadoc
/**
 * @author RH
 */
public interface IConnectionHandler
{
	
	/**
	 * Inits the.
	 * 
	 * @param configMan
	 *            the config man
	 * @param systemLogger
	 *            the system logger
	 * @param sam
	 *            the sam
	 * @param resourcegroup
	 *            the resourcegroup
	 */
	void Init(ConfigManager configMan, SystemLogger systemLogger, SAMAgent sam, String resourcegroup);

	/**
	 * Gets the connection.
	 * 
	 * @return the connection
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 */
	Connection getConnection()
		throws ASelectStorageException;

	/**
	 * Release connection.
	 * 
	 * @param c
	 *            the c
	 */
	void releaseConnection(Connection c);
}
