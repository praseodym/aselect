/**
 * 
 */
package org.aselect.system.db.connection;

import java.sql.Connection;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;

/**
 * @author RH
 *
 */
public interface IConnectionHandler
{
	void Init(ConfigManager configMan, SystemLogger systemLogger, SAMAgent sam, String resourcegroup);
	Connection getConnection() throws ASelectStorageException;
	void releaseConnection(Connection c);
}
