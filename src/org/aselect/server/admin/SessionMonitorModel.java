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
 * $$Id: SessionMonitorModel.java,v 1.13 2006/04/26 12:14:34 tom Exp $$ 
 * 
 * Changelog:
 * $$Log: SessionMonitorModel.java,v $
 * $Revision 1.13  2006/04/26 12:14:34  tom
 * $QA: removed javadoc version tag, minor javadoc fixes
 * $
 * $Revision 1.12  2006/04/12 13:18:38  martijn
 * $merged A-SELECT-1_5_0-SAML
 * $
 * $Revision 1.11.10.2  2006/01/25 15:35:19  martijn
 * $TGTManager rewritten
 * $
 * $Revision 1.11.10.1  2006/01/13 08:36:49  martijn
 * $requesthandlers seperated from core
 * $
 * $Revision 1.11  2005/04/01 14:23:43  peter
 * $cross aselect redesign
 * $
 * $Revision 1.10  2005/03/30 12:39:19  erwin
 * $Fixed logging (MODULE added)
 * $
 * $Revision 1.9  2005/03/22 14:56:57  peter
 * $Fixed bug in shutting down admin monitor.
 * $
 * $Revision 1.8  2005/03/14 13:03:05  erwin
 * $Fixed problems with Admin monitor.
 * $
 * $Revision 1.7  2005/03/14 07:59:43  martijn
 * $removed unused code in retrieving configuration items
 * $
 * $Revision 1.6  2005/03/11 21:07:15  martijn
 * $config item max_sessions has been renamed to 'max' in storagemanager section with id='session'
 * $
 * $Revision 1.5  2005/03/10 10:08:01  erwin
 * $Removed some compiler warnings.
 * $
 * $Revision 1.4  2005/03/10 10:05:29  erwin
 * $Improved error handling. Made instance variables private.
 * $
 * $Revision 1.3  2005/03/04 11:29:33  tom
 * $Code has been styled and reformated accoring to templates.
 * $Javadoc has been added.
 * $$
 */

package org.aselect.server.admin;

import java.util.Date;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.swing.table.AbstractTableModel;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectStorageException;

/**
 * SessionMonitorModel class used by the AdminMonitor.
 * 
 * <br>
 * <br>
 * <b>Description: </b> <br>
 * This monitor contains all the information concerning the A-Select Sessions.
 * <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class SessionMonitorModel extends AbstractTableModel implements Runnable
{
	/**
	 * The module name.
	 */
	public static final String MODULE = "SessionMonitorModel";

	/**
	 * Main thread.
	 */
	private Thread _oRunnerThread;

	/**
	 * String array containing sessions.
	 */
	private String[] _saSessions;

	/**
	 * String array containing all the headers used in the Monitor.
	 */
	private String[] _saHeaders = {
		"User", "For Application", "Expires at", "AuthSP", "Type"
	};

	/**
	 * Interval for checking for new information.
	 */
	private int _iCheckInterval;

	/**
	 * HashMap containing all session contexts.
	 */
	private HashMap _htSessionContexts;

	/**
	 * A-Select Session Manager.
	 */
	private SessionManager _oSessionManager = SessionManager.getHandle();

	/**
	 * Main A-Select Config Manager.
	 */
	private ASelectConfigManager _oConfigManager = ASelectConfigManager.getHandle();

	/**
	 * Used to check if the SessionModel is active or not.
	 */
	private boolean _bActive = false;

	/**
	 * SessionMonitorModel constructor.
	 * 
	 * <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Initializes the SessionMonitorModel. 
	 * <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * iCheckInterval > 0 <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The Main RunnerThread is running. <br>
	 * 
	 * @param iCheckInterval
	 *            Interval used to check for new information.
	 */
	public SessionMonitorModel(int iCheckInterval) {
		this._iCheckInterval = iCheckInterval;

		Integer intMaxSessions = null;
		try {
			Object oStorageMngrSection = _oConfigManager.getSection(null, "storagemanager", "id=session");
			String sMaxSessions = _oConfigManager.getParam(oStorageMngrSection, "max");
			intMaxSessions = Integer.valueOf(sMaxSessions);
		}
		catch (ASelectConfigException e) {
			ASelectSystemLogger.getHandle().log(Level.SEVERE, MODULE, "SessionMonitorModel()",
					"No valid 'max' config item in storage handler with id='session'", e);
			intMaxSessions = Integer.valueOf("100");
		}
		_saSessions = new String[intMaxSessions.intValue()];

		getServerStatus();

		_bActive = true;
		_oRunnerThread = new Thread(this);
		_oRunnerThread.start();
		fireTableDataChanged();
	}

	/**
	 * This functions stops the SessionMonitor.
	 * 
	 * <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * _bActive is set to false and the current thread is interupted. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * none <br>
	 *  
	 */
	public void stop()
	{
		_bActive = false;
		_oRunnerThread.interrupt();
	}

	/**
	 * Returns the session count.
	 * 
	 * <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This function calls _oSessionManager.getSessionsCounter() to retrieve the
	 * session count. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * none <br>
	 * 
	 * @return <code>long</code> containing session count.
	 */
	public long getSessionsCounter()
	{
		return _oSessionManager.getCounter();
	}

	/**
	 * Returns the current row count. <br>
	 * <br>
	 * 
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	public int getRowCount()
	{
		return _htSessionContexts.size();
	}

	/**
	 * Returns the current column count. <br>
	 * <br>
	 * 
	 * @see javax.swing.table.TableModel#getColumnCount()
	 */
	public int getColumnCount()
	{
		return _saHeaders.length;
	}

	/**
	 * Returns the current value at a specific row and column. <br>
	 * <br>
	 * 
	 * @see javax.swing.table.TableModel#getValueAt(int, int)
	 */
	public Object getValueAt(int iRow, int iColumn)
	{
		String sSession = _saSessions[iRow];
		HashMap htSessionContext = (HashMap) _htSessionContexts.get(sSession);
		String sItem, sItem1, sItem2;
		StringBuffer sbBuffer;

		if (iColumn == 0) {
			sItem = (String) htSessionContext.get("user_id");
			if (sItem == null)
				return "[unknown]";

			return sItem;
		}
		if (iColumn == 1) {
			sItem1 = (String) htSessionContext.get("remote_session");
			sItem2 = (String) htSessionContext.get("local_organization");
			if (sItem1 != null && sItem2 != null) {
				sbBuffer = new StringBuffer();
				sbBuffer.append("[unknown] at ");
				sbBuffer.append(sItem2);
				sItem = sbBuffer.toString();
				return sItem;
			}
			sItem1 = (String) htSessionContext.get("app_id");
			sItem2 = (String) htSessionContext.get("app_url");

			if (sItem1 == null) {
				sItem = "[unknown] at ";
			}
			else {
				sItem = sItem1;
			}

			if (sItem2 == null) {
				sbBuffer = new StringBuffer(sItem);
				sbBuffer.append("[unknown]");
				sItem = sbBuffer.toString();
			}
			else {
				sbBuffer = new StringBuffer(sItem);
				sbBuffer.append(" (at ");
				sbBuffer.append(sItem2);
				sbBuffer.append(")");
				sItem = sbBuffer.toString();

			}
			return sItem;
		}
		if (iColumn == 2) {
			long lTimestamp = 0;
			try {
				lTimestamp = _oSessionManager.getExpirationTime(sSession);
				return new Date(lTimestamp).toString();
			}
			catch (ASelectStorageException e) {
				return "unknown";
			}
		}
		if (iColumn == 3) {
			sItem = (String) htSessionContext.get("authsp");
			if (sItem == null) {
				return "Not chosen yet";
			}

			return sItem;
		}
		if (iColumn == 4) {
			sItem = (String) htSessionContext.get("remote_organization");
			if (sItem == null) {
				return "Local";
			}
			return "Cross (at " + sItem + ")";
		}
		if (iColumn == 5) {
			return sSession;
		}

		return null;
	}

	/**
	 * Returns the name of the column based on iIndex. <br>
	 * <br>
	 * 
	 * @see javax.swing.table.TableModel#getColumnName(int)
	 */
	public String getColumnName(int iIndex)
	{
		return _saHeaders[iIndex];
	}

	/**
	 * Main run function for the Runner Thread. <br>
	 * <br>
	 * 
	 * @see java.lang.Runnable#run()
	 */
	public void run()
	{
		while (_bActive) {
			try {
				Thread.sleep(_iCheckInterval * 1000);
				getServerStatus();
				fireTableDataChanged();
			}
			catch (Exception e) {
			}
		}
		ASelectSystemLogger.getHandle().log(Level.INFO, MODULE, "run()", "SessionMonitorModel stopped");
	}

	/**
	 * Retrieve the current A-Select Session information.
	 * 
	 * <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This function retrieves the session context using
	 * _oSessionManager.getSessionContexts() and copies the session information
	 * into the local session array _saSessions. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * _oSessionManager must be intialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * _saSessions now contains the latest session information. <br>
	 *  
	 */
	private void getServerStatus()
	{
		try {
			_htSessionContexts = _oSessionManager.getAll();

			int i = 0;
			Set keys = _htSessionContexts.keySet();
			for (Object s : keys) {
				//Enumeration enumSessionContexts = _htSessionContexts.keys();
				//while (enumSessionContexts.hasMoreElements())
				//{
				_saSessions[i++] = (String) s;
			}
		}
		catch (Exception e) {
			ASelectSystemLogger.getHandle().log(Level.WARNING, MODULE, "getServerStatus()",
					"No session contexts available");
		}
	}
}
