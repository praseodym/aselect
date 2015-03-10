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
 * $Id: SessionMonitorModel.java,v 1.9 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: SessionMonitorModel.java,v $
 * Revision 1.9  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.8  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/04/14 16:22:01  tom
 * Removed old logging statements
 *
 * Revision 1.6  2005/03/14 10:09:07  erwin
 * The ticket and session expiration and start
 * time are now read from the ticket and session
 * manager.
 *
 * Revision 1.5  2005/03/11 21:03:53  martijn
 * config item max_sessions ihas been renamed to 'max' in storagemanager section with id='session'
 *
 * Revision 1.4  2005/03/03 17:24:19  erwin
 * Applied code style, added javadoc comment.
 *
 * Revision 1.3  2005/02/25 15:51:33  erwin
 * Improved logging.
 *
 * Revision 1.2  2005/02/24 15:09:09  ali
 * Added IAgentEventListener class and updates internal Javadoc.
 *
 */

package org.aselect.agent.admin;

import java.util.Date;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.swing.table.AbstractTableModel;

import org.aselect.agent.config.ASelectAgentConfigManager;
import org.aselect.agent.log.ASelectAgentSystemLogger;
import org.aselect.agent.session.SessionManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectStorageException;

/**
 * Monitors the pending authentication sessions of the A-Select Agent. <br>
 * <br>
 * <b>Description: </b> <br>
 * This method monitors the pending authentication sessions of the A-Select Agent. This class implements Runnable in
 * which it periodically checks the SessionManager for pending sessions. The data is used by the AdminMonitor for
 * display in the GUI. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * None. <br>
 * 
 * @author Alfa & Ariss
 */
public class SessionMonitorModel extends AbstractTableModel implements Runnable
{
	private Thread _runner;
	private String[] _sessionsStrings;
	private String[] _headersStrings = {
		"Rid", "On A-Select Server", "Expires at", "For Application", "Type"
	};

	private int _iCheckInterval;
	private HashMap _sessionContexts;
	private SessionManager _sessionManager;
	private ASelectAgentConfigManager _configManager;
	private boolean _active;

	/** The MODULE name. */
	public static final String MODULE = "SessionMonitorModel";

	/**
	 * Initializes the class. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method initalizes the class by initializing variables and starting the runner thread for monitoring. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param iCheckInterval
	 *            the monitoring interval (in seconds) to wait for updating the sessions information.
	 * @throws ASelectConfigException
	 *             on error.
	 */
	public SessionMonitorModel(int iCheckInterval)
	throws ASelectConfigException {
		_sessionManager = SessionManager.getHandle();
		_configManager = ASelectAgentConfigManager.getHandle();
		_active = false;

		_iCheckInterval = iCheckInterval;

		Object oStorageMngrSection = _configManager.getSection(null, "storagemanager", "id=session");
		String sMaxSession = _configManager.getParam(oStorageMngrSection, "max");
		Integer intMaxSessions = Integer.valueOf(sMaxSession);

		_sessionsStrings = new String[intMaxSessions.intValue()];

		getAgentStatus();

		_active = true;
		_runner = new Thread(this);
		_runner.start();

		fireTableDataChanged();
	}

	/**
	 * Stops monitoring.
	 */
	public void stop()
	{
		_active = false;
		_runner.interrupt();
	}

	/**
	 * Gets the sessions counter.
	 * 
	 * @return the number of pending sessions.
	 */
	public long getSessionsCounter()
	{
		return _sessionManager.getSessionsCounter();
	}

	/**
	 * Returns the number of rows.
	 * 
	 * @return the row count
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	public int getRowCount()
	{
		return _sessionContexts.size();
	}

	/**
	 * Returns the number of columns.
	 * 
	 * @return the column count
	 * @see javax.swing.table.TableModel#getColumnCount()
	 */
	public int getColumnCount()
	{
		return _headersStrings.length;
	}

	/**
	 * Returns the value of an information items in this model.
	 * 
	 * @param iRow
	 *            the i row
	 * @param iColumn
	 *            the i column
	 * @return the String representation of the item.
	 * @see javax.swing.table.TableModel#getValueAt(int, int)
	 */
	public Object getValueAt(int iRow, int iColumn)
	{
		String sSession = _sessionsStrings[iRow];
		HashMap xSessionContext = (HashMap) _sessionContexts.get(sSession);

		if (iColumn == 0)
			return xSessionContext.get("rid");
		if (iColumn == 1)
			return xSessionContext.get("a-select-server");
		if (iColumn == 2) {
			long lTimestamp = 0;
			try {
				lTimestamp = _sessionManager.getSessionTimeout(sSession);
				return new Date(lTimestamp).toString();
			}
			catch (ASelectStorageException e) {
				return "unknown";
			}
		}
		if (iColumn == 3)
			return xSessionContext.get("app_id");
		if (iColumn == 4)
			return xSessionContext.get("user_type");

		return null;
	}

	/**
	 * Returns the column name.
	 * 
	 * @param iIndex
	 *            the i index
	 * @return the column name
	 * @see javax.swing.table.TableModel#getColumnName(int)
	 */
	@Override
	public String getColumnName(int iIndex)
	{
		return _headersStrings[iIndex];
	}

	/**
	 * Perfoms the Gui update. <br>
	 * <br>
	 * Loops and upon wakeup (monitoring interval), fetches the pending sessions information from the SessionManger.
	 * 
	 * @see java.lang.Runnable#run()
	 */
	public void run()
	{
		String sMethod = "run";

		while (_active) {
			try {
				Thread.sleep(_iCheckInterval * 1000);
				getAgentStatus();
				fireTableDataChanged();
			}
			catch (Exception x) {
			}
		}
		ASelectAgentSystemLogger.getHandle().log(Level.INFO, MODULE, sMethod, "SessionMonitorModel stopped.");
	}

	/**
	 * Fetches the SessionContexts from the SessionManager.
	 */
	private void getAgentStatus()
	{
		_sessionContexts = _sessionManager.getSessionContexts();

		int i = 0;
		Set keys = _sessionContexts.keySet();
		for (Object s : keys) {
			_sessionsStrings[i++] = (String) s;
		}
		/*
		 * Enumeration xSessionContextsEnum = _sessionContexts.keys(); while (xSessionContextsEnum.hasMoreElements()) {
		 * _sessionsStrings[i++] = (String)xSessionContextsEnum.nextElement(); }
		 */
	}
}
