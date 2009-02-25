/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license. See the included
 * LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE please contact SURFnet bv.
 * (http://www.surfnet.nl)
 */

/*
 * $$Id: TGTMonitorModel.java,v 1.12 2006/04/26 12:14:34 tom Exp $$
 * 
 * Changelog: $$Log: TGTMonitorModel.java,v $
 * Changelog: $Revision 1.12  2006/04/26 12:14:34  tom
 * Changelog: $QA: removed javadoc version tag, minor javadoc fixes
 * Changelog: $
 * Changelog: $Revision 1.11  2006/04/12 13:18:38  martijn
 * Changelog: $merged A-SELECT-1_5_0-SAML
 * Changelog: $
 * Changelog: $Revision 1.10.10.1  2006/01/25 15:35:19  martijn
 * Changelog: $TGTManager rewritten
 * Changelog: $
 * Changelog: $Revision 1.10  2005/04/05 09:05:02  peter
 * Changelog: $added cross proxy monitoring
 * Changelog: $
 * Changelog: $Revision 1.9  2005/03/22 14:56:56  peter
 * Changelog: $Fixed bug in shutting down admin monitor.
 * Changelog: $
 * Changelog: $Revision 1.8  2005/03/14 13:03:05  erwin
 * Changelog: $Fixed problems with Admin monitor.
 * Changelog: $
 * Changelog: $Revision 1.7  2005/03/11 21:24:08  martijn
 * Changelog: $config section: storagemanager id='ticket' is renamed to storagemanager id='tgt'
 * Changelog: $
 * Changelog: $Revision 1.6  2005/03/11 21:08:11  martijn
 * Changelog: $config item max_tgt has been renamed to 'max' in storagemanager section with id='ticket'
 * Changelog: $
 * Changelog: $Revision 1.5  2005/03/10 10:08:01  erwin
 * Changelog: $Removed some compiler warnings.
 * Changelog: $
 * Changelog: $Revision 1.4  2005/03/10 10:05:29  erwin
 * Changelog: $Improved error handling. Made instance variables private.
 * Changelog: $
 * Changelog: $Revision 1.3  2005/03/04 11:29:33  tom
 * Changelog: $Code has been styled and reformated accoring to templates.
 * Changelog: $Javadoc has been added.
 * Changelog: $$
 */

package org.aselect.server.admin;

import java.util.Date;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.swing.table.AbstractTableModel;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectStorageException;

/**
 * Main TGTMonitorModel Class.
 * 
 * <br><br>
 * <b>Description:</b><br>
 * This monitor contains all the information concerning the A-Select TGTs.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * none
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class TGTMonitorModel extends AbstractTableModel implements Runnable
{
	/**
	 * The module name.
	 */
	public static final String MODULE = "TGTMonitorModel";

	/**
	 *  Main thread.
	 */
	private Thread _oRunnerThread;

	/**
	 * String array containing TGTs.
	 */
	private String[] _saTGTs;

	/**
	 * String array containing all the headers used in the Monitor.
	 */
	private String[] _saHeaders = {
		"Issued to", "From Organization", "TGT Expires at", "AuthSP Used", "TGT Level", "For Application"
	};

	/**
	 * Interval for checking for new information.
	 */
	private int _iCheckInterval;

	/**
	 * HashMap containing all session contexts.
	 */
	private HashMap _htTGTContexts;

	/**
	 * A-Select TGT Manager.
	 */
	private TGTManager _oTGTManager = TGTManager.getHandle();

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
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * Initializes the SessionMonitorModel.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * none
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * iCheckInterval > 0.
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * The Main RunnerThread is running. <br>
	 * @param iCheckInterval
	 * 					Interval used to check for new information.
	 */
	public TGTMonitorModel(int iCheckInterval) {
		this._iCheckInterval = iCheckInterval;
		String sMaxTgt = null;
		Integer intMaxTGT = null;
		try {
			Object oStorageMngrSection = _oConfigManager.getSection(null, "storagemanager", "id=tgt");
			sMaxTgt = _oConfigManager.getParam(oStorageMngrSection, "max");
			intMaxTGT = Integer.valueOf(sMaxTgt);
		}
		catch (ASelectConfigException e) {
			ASelectSystemLogger.getHandle().log(Level.SEVERE, MODULE, "TGTMonitorModel()",
					"No valid 'max' config item found in 'storagemanager' config section with id='tgt'", e);

			intMaxTGT = Integer.valueOf("100");
		}

		_saTGTs = new String[intMaxTGT.intValue()];

		getServerStatus();

		_bActive = true;
		_oRunnerThread = new Thread(this);
		_oRunnerThread.start();
		fireTableDataChanged();
	}

	/**
	 * This functions stops the TGTMonitor.
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
	 * Returns the TGT count.
	 * 
	 * <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This function calls _oTGTManager.getTGTCounter() to retrieve the
	 * TGT count. 
	 * <br><br>
	 * <b>Concurrency issues: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * none <br>
	 * 
	 * @return <code>long</code> containing TGT count.
	 */
	public long getTGTCounter()
	{
		return _oTGTManager.getTGTCounter();
	}

	/**
	 * Returns the current row count. <br>
	 * <br>
	 * 
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	public int getRowCount()
	{
		return _htTGTContexts.size();
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
		String sTGT = _saTGTs[iRow];
		HashMap htTGTContext = (HashMap) _htTGTContexts.get(sTGT);

		if (iColumn == 0)
			return (String) htTGTContext.get("uid");
		if (iColumn == 1) {
			String sProxy = (String) htTGTContext.get("proxy_organization");
			if (sProxy == null)
				return (String) htTGTContext.get("organization");
			return (String) htTGTContext.get("organization") + "@" + sProxy;
		}
		if (iColumn == 2) {
			try {
				long lTimeout = _oTGTManager.getExpirationTime(sTGT);
				return (new Date(lTimeout)).toString();
			}
			catch (ASelectStorageException e) {
				return "unknown";
			}
		}
		if (iColumn == 3)
			return (String) htTGTContext.get("authsp");
		if (iColumn == 4)
			return (String) htTGTContext.get("authsp_level");
		if (iColumn == 5)
			return (String) htTGTContext.get("app_id");
		if (iColumn == 6)
			return sTGT;

		return null;
	}

	/**
	 * Returns the name of the column based on iIndex. <br>
	 * <br>
	 * 
	 * @see javax.swing.table.TableModel#getColumnName(int)
	 */
	public String getColumnName(int xIndex)
	{
		return _saHeaders[xIndex];
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
			catch (Exception x) {
			}
		}
		ASelectSystemLogger.getHandle().log(Level.INFO, MODULE, "run()", "TGT Monitor model stopped");
	}

	/**
	 * Retrieve the current A-Select TGT information.
	 * 
	 * <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This function retrieves the TGT context using
	 * _oTGTManager.getTGTContexts() and copies the TGT information
	 * into the local TGT array _saTGTs. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * none <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * _oTGTManager must be intialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * _saTGTs now contains the latest TGT information. <br>
	 *  
	 */
	private void getServerStatus()
	{
		try {
			_htTGTContexts = _oTGTManager.getAll();

			int i = 0;
			Set keys = _htTGTContexts.keySet();
			for (Object s : keys) {
				//Enumeration _enumTGTContexts = _htTGTContexts.keys();
				//while (_enumTGTContexts.hasMoreElements())
				//{
				_saTGTs[i++] = (String) s;
			}
		}
		catch (Exception e) {
			ASelectSystemLogger.getHandle().log(Level.WARNING, MODULE, "getServerStatus()",
					"No session contexts available");
		}
	}
}