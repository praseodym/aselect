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
 * $Id: TicketMonitorModel.java,v 1.10 2006/04/14 13:42:48 tom Exp $
 * 
 * Changelog: 
 * $Log: TicketMonitorModel.java,v $
 * Revision 1.10  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.9  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.8  2005/04/14 16:22:01  tom
 * Removed old logging statements
 *
 * Revision 1.7  2005/03/14 10:09:07  erwin
 * The ticket and session expiration and start
 * time are now read from the ticket and session
 * manager.
 *
 * Revision 1.6  2005/03/11 21:05:08  martijn
 * config item max_tickets has been renamed to 'max' in storagemanager section with id='ticket'
 *
 * Revision 1.5  2005/03/07 14:43:24  erwin
 * asp -> authsp in requests and admin monitor.
 *
 * Revision 1.4  2005/03/03 17:24:19  erwin
 * Applied code style, added javadoc comment.
 *
 * Revision 1.3  2005/02/25 15:51:33  erwin
 * Improved logging.
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
import org.aselect.agent.ticket.TicketManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectStorageException;

/**
 * Monitors the tickets that are issued by the A-Select Agent. 
 * <br><br>
 * <b>Description: </b> 
 * <br>
 * This method monitors the issued tickets of the A-Select Agent. This class
 * implements Runnable in which it periodically checks the TicketManager for
 * issued ticket. The data is used by the AdminMonitor for display in the GUI.
 * <br>
 * <br>
 * <b>Concurrency issues: </b> 
 * <br>
 * None. <br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class TicketMonitorModel extends AbstractTableModel implements Runnable
{
	private Thread _runner;
	private String[] _ticketsStrings;
	private String[] _headersStrings = {
		"Issued to", "From Organization", "By A-Select Server", "Issued at", "Expires at", "AuthSP Used", "Level"
	};

	private int _iCheckInterval;
	private HashMap _ticketContexts;
	private TicketManager _ticketManager;
	private ASelectAgentConfigManager _configManager;
	private boolean _active;

	/** The MODULE name. */
	public static final String MODULE = "TicketMonitorModel";

	/**
	 * Initializes the class. 
	 * <br><br>
	 * <b>Description: </b> <br>
	 * This method initalizes the class by initializing variables and starting
	 * the runner thread for monitoring. <br>
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
	 *            the monitoring interval (in seconds) to wait for updating the
	 *            ticket information.
	 * 
	 * @throws ASelectConfigException
	 * on configuration error. @ throws NumberFormatException on non-parseable
	 *             <code>max_tickets</code> config item.
	 * @throws NumberFormatException If 'max_tickets' parameter is incorrect.
	 */
	public TicketMonitorModel(int iCheckInterval)
		throws NumberFormatException, ASelectConfigException {
		_ticketManager = TicketManager.getHandle();
		_configManager = ASelectAgentConfigManager.getHandle();

		_iCheckInterval = iCheckInterval;

		Object oStorageMngrSection = _configManager.getSection(null, "storagemanager", "id=ticket");
		String sMaxTickets = _configManager.getParam(oStorageMngrSection, "max");
		Integer intMaxTickets = Integer.valueOf(sMaxTickets);

		_ticketsStrings = new String[intMaxTickets.intValue()];

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
	 * @return the number of issued tickets.
	 */
	public long getTicketsCounter()
	{
		return _ticketManager.getTicketsCounter();
	}

	/**
	 * Returns the number of rows.
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	public int getRowCount()
	{
		return _ticketContexts.size();
	}

	/**
	 * Returns the number of columns. 
	 * @see javax.swing.table.TableModel#getColumnCount()
	 */
	public int getColumnCount()
	{
		return _headersStrings.length;
	}

	/**
	 * Returns the value of an information items in this model. 
	 * 
	 * @see javax.swing.table.TableModel#getValueAt(int, int)
	 * @return the String representation of the item.
	 */
	public Object getValueAt(int iRow, int iColumn)
	{
		String sTicket = _ticketsStrings[iRow];
		HashMap htTicketContext = (HashMap) _ticketContexts.get(sTicket);

		if (iColumn == 0)
			return (String) htTicketContext.get("uid");
		if (iColumn == 1)
			return (String) htTicketContext.get("organization");
		if (iColumn == 2)
			return (String) htTicketContext.get("a-select-server");
		if (iColumn == 3) {
			try {
				long lTimestamp = _ticketManager.getTicketStartTime(sTicket);
				return new Date(lTimestamp).toString();
			}
			catch (ASelectStorageException e) {
				return "unknown";
			}
		}
		if (iColumn == 4) {
			try {
				long lTimestamp = _ticketManager.getTicketTimeout(sTicket);
				return new Date(lTimestamp).toString();
			}
			catch (ASelectStorageException e) {
				return "unknown";
			}

		}
		if (iColumn == 5)
			return (String) htTicketContext.get("authsp");
		if (iColumn == 6)
			return (String) htTicketContext.get("authsp_level");
		if (iColumn == 7)
			return sTicket;

		return null;
	}

	/**
	 * Returns the colum nname. 
	 * @see javax.swing.table.TableModel#getColumnName(int)
	 */
	public String getColumnName(int xIndex)
	{
		return _headersStrings[xIndex];
	}

	/**
	 * Loops and upon wakeup (monitoring interval), fetches the ticket
	 * information from the TicketManager. 
	 * 
	 * @see java.lang.Runnable#run()
	 */
	public void run()
	{
		String sMethod = "run()";

		while (_active) {
			try {
				Thread.sleep(_iCheckInterval * 1000);
				getAgentStatus();
				fireTableDataChanged();
			}
			catch (Exception x) {
			}
		}
		ASelectAgentSystemLogger.getHandle().log(Level.INFO, MODULE, sMethod, "TicketMonitorModel stopped.");
	}

	/**
	 * Fetches the TicketContexts from the SessionManager.
	 */
	private void getAgentStatus()
	{
		_ticketContexts = _ticketManager.getTicketContexts();

		int i = 0;
		Set keys = _ticketContexts.keySet();
		for (Object s : keys) {
			_ticketsStrings[i++] = (String) s;
		}
		/*        Set xTicketContextsEnum = _ticketContexts.keySet();
		 while (xTicketContextsEnum.hasMoreElements())
		 {
		 _ticketsStrings[i++] = (String)xTicketContextsEnum.nextElement();
		 }*/
	}
}