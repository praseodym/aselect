/**
 * 
 */
package org.aselect.system.db.connection;

import java.sql.Connection;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;
import org.aselect.system.sam.agent.SAMResource;

/**
 * @author root
 *
 */
public abstract class AbstractConnectionHandler implements IConnectionHandler
{
	protected ConfigManager _oConfigManager = null;
	protected SAMAgent _oSAMAgent = null;
	protected SAMResource _oActiveResource = null;
	protected String _sResourceGroup = null;
	protected SystemLogger _systemLogger;
	
	/* (non-Javadoc)
	 * @see org.aselect.system.db.jdbc.IConnectionHandler#Init(org.aselect.system.sam.agent.SAMAgent, java.lang.String)
	 */
	public void Init(ConfigManager configMan, SystemLogger systemLogger, SAMAgent sam, String resourcegroup)
	{
		this._systemLogger = systemLogger;
		this._oSAMAgent = sam;
		this._sResourceGroup = resourcegroup;
		this._oConfigManager = configMan;

	}

	/* (non-Javadoc)
	 * @see org.aselect.system.db.jdbc.IConnectionHandler#getConnection()
	 */
	public Connection getConnection() throws ASelectStorageException
	{
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.db.jdbc.IConnectionHandler#releaseConnection(java.sql.Connection)
	 */
	public void releaseConnection(Connection c)
	{
		// TODO Auto-generated method stub

	}

}
