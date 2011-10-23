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
 * $Id: AdminMonitor.java,v 1.9 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: AdminMonitor.java,v $
 * Revision 1.9  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.8  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/04/14 16:22:01  tom
 * Removed old logging statements
 *
 * Revision 1.6  2005/04/08 12:40:34  martijn
 * fixed todo's
 *
 * Revision 1.5  2005/03/14 13:01:28  erwin
 * Added TOdo in gui Window closing.
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

import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;
import java.util.Date;
import java.util.logging.Level;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;

import org.aselect.agent.ASelectAgent;
import org.aselect.agent.config.ASelectAgentConfigManager;
import org.aselect.agent.log.ASelectAgentSystemLogger;
import org.aselect.agent.ticket.TicketManager;

/**
 * Implements a GUI for monitoring tickets that are issued by the A-Select Agent. <br>
 * <br>
 * <b>Description: </b> <br>
 * This class implements a convenient GUI implemented as a JFrame for monitoring sessions and tickets that are issued by
 * the A-Select Agent. This tool can also be used to shutdown the A-Select Agent service. <br>
 * <br>
 * This class uses Models for implementing the data providers for the current sessions and tickets. <br>
 * <br>
 * <i> Note: This class works only when there is a graphics display found. This means that if the A-Select Agent runs as
 * a service in Windows, this tool won't run. Same applies to console mode terminals for other platforms. </i> <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None. <br>
 */
public class AdminMonitor extends JFrame implements TableModelListener
{
	private JTable _ticketsTable;
	private JLabel _ticketsLabel = null;
	private TicketMonitorModel _ticketsMonitorModel = null;
	private JScrollPane xTicketsScrollPane = null;

	private JTable _sessionsTable;
	private JLabel _sessionsLabel = null;
	private JScrollPane xSessionsScrollPane = null;
	private SessionMonitorModel _sessionsMonitorModel = null;

	private JButton _killTicketButton = null;
	private JButton _killAllTicketsButton = null;
	private JButton _stopAgentButton = null;

	private int _buttonWidth = 130;
	private int _buttonHeight = 24;
	private JButton _line1, _line2, _line3;
	private JLabel _numberOfTicketsLabel, _numberOfSessionsLabel;
	private JLabel _totalSessionsLabel, _totalTicketsLabel, _timeLabel;

	private TicketManager xTicketManager = TicketManager.getHandle();

	/**
	 * The module name.
	 */
	public static final String MODULE = "AdminMonitor";

	/**
	 * Starts the GUI of the monitor. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method starts up the GUI by initializing the complete JFrame and all fields and initializing the models. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * A-Select Agent must have been started in console mode and a graphics display adapter is available. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param iCheckInterval
	 *            the interval in seconds to update the GUI.
	 * @throws Exception
	 *             when something goes wrong.
	 */
	public void start(int iCheckInterval)
		throws Exception
	{
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		StringBuffer sbVersion = new StringBuffer(ASelectAgent.MODULE);
		sbVersion.append(" ").append(ASelectAgent.VERSION);
		sbVersion.append(" Admin Monitor");
		setTitle(sbVersion.toString());

		setSize(800, 600);

		setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
		addWindowListener(new BasicWindowAdapter());

		getContentPane().setLayout(null);
		_ticketsMonitorModel = new TicketMonitorModel(iCheckInterval);
		_ticketsMonitorModel.addTableModelListener(this);
		_ticketsTable = new JTable(_ticketsMonitorModel);
		xTicketsScrollPane = new JScrollPane(_ticketsTable);
		getContentPane().add(xTicketsScrollPane);
		_ticketsLabel = new JLabel("Issued tickets");
		getContentPane().add(_ticketsLabel);

		_sessionsMonitorModel = new SessionMonitorModel(iCheckInterval);
		_sessionsMonitorModel.addTableModelListener(this);
		_sessionsTable = new JTable(_sessionsMonitorModel);
		xSessionsScrollPane = new JScrollPane(_sessionsTable);
		getContentPane().add(xSessionsScrollPane);
		_sessionsLabel = new JLabel("Pending sessions");
		getContentPane().add(_sessionsLabel);

		_killAllTicketsButton = new JButton("Kill All Tickets");
		getContentPane().add(_killAllTicketsButton);
		_killAllTicketsButton.addActionListener(new KillAllButtonListener());

		_stopAgentButton = new JButton("Stop Agent");
		getContentPane().add(_stopAgentButton);
		_stopAgentButton.addActionListener(new StopAgentButtonListener());

		_line1 = new JButton();
		_line1.setEnabled(false);
		getContentPane().add(_line1);

		_line2 = new JButton();
		_line2.setEnabled(false);
		getContentPane().add(_line2);

		_line3 = new JButton();
		_line3.setEnabled(false);
		getContentPane().add(_line3);

		_numberOfSessionsLabel = new JLabel("");
		getContentPane().add(_numberOfSessionsLabel);
		_numberOfTicketsLabel = new JLabel("");
		getContentPane().add(_numberOfTicketsLabel);

		_totalSessionsLabel = new JLabel("");
		getContentPane().add(_totalSessionsLabel);
		_totalTicketsLabel = new JLabel("");
		getContentPane().add(_totalTicketsLabel);

		_timeLabel = new JLabel("Started at " + new Date().toString());
		getContentPane().add(_timeLabel);

		_killTicketButton = new JButton("Kill Ticket");
		getContentPane().add(_killTicketButton);
		_killTicketButton.addActionListener(new KillButtonListener());
		getRootPane().setDefaultButton(_killTicketButton);

		setLocation(1, 1);
		setVisible(true);
		toFront();
	}

	/**
	 * Callback method to update the GUI. <br>
	 * This method is called by Swing when the GUI needs to be updated. <br>
	 * <br>
	 * 
	 * @param xEvent
	 *            the x event
	 * @see javax.swing.event.TableModelListener#tableChanged(javax.swing.event.TableModelEvent)
	 */
	public void tableChanged(TableModelEvent xEvent)
	{
		// refresh al the labels
		StringBuffer xBuffer = new StringBuffer("Number of pending sessions: ");
		xBuffer.append(_sessionsMonitorModel.getRowCount());
		_numberOfSessionsLabel.setText(xBuffer.toString());

		xBuffer = new StringBuffer("Number of issued tickets: ");
		xBuffer.append(_ticketsMonitorModel.getRowCount());
		_numberOfTicketsLabel.setText(xBuffer.toString());

		xBuffer = new StringBuffer("Total sessions handled since startup: ");
		xBuffer.append(_sessionsMonitorModel.getSessionsCounter());
		_totalSessionsLabel.setText(xBuffer.toString());

		xBuffer = new StringBuffer("Total tickets issued since startup: ");
		xBuffer.append(_ticketsMonitorModel.getTicketsCounter());
		_totalTicketsLabel.setText(xBuffer.toString());
	}

	/**
	 * Stops the GUI monitor. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method stops the GUI monitor by disposing the GUI and shutting down the monitor models. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None.
	 */
	public void stop()
	{
		String sMethod = "stop()";

		if (_ticketsMonitorModel != null)
			_ticketsMonitorModel.stop();

		if (_sessionsMonitorModel != null)
			_sessionsMonitorModel.stop();

		ASelectAgentSystemLogger.getHandle().log(Level.INFO, MODULE, sMethod, "AdminMonitor stopped.");
	}

	/**
	 * Implements the paint message for the GUI monitor.
	 * 
	 * @param xGraphics
	 *            the x graphics
	 * @see java.awt.Component#paint(java.awt.Graphics)
	 */
	@Override
	public void paint(Graphics xGraphics)
	{
		int x, y, xWidth;
		Dimension xDim = getContentPane().getSize();

		x = 4;
		y = 16;
		xWidth = xDim.width - 8;

		_sessionsLabel.setBounds(x + 10, y, xWidth, 20);
		xSessionsScrollPane.setBounds(x, y + 24, xWidth, 120);

		y = xSessionsScrollPane.getY() + xSessionsScrollPane.getHeight() + 20;
		_line1.setBounds(x, y, xWidth, 2);
		y += 12;

		_ticketsLabel.setBounds(x + 10, y, xWidth, 20);
		xTicketsScrollPane.setBounds(x, y + 24, xWidth, xDim.height - 400);

		y = xTicketsScrollPane.getY() + xTicketsScrollPane.getHeight() + 4;
		_killTicketButton.setBounds((xWidth - _buttonWidth) / 2, y, _buttonWidth, _buttonHeight);

		x = 4;
		y = _killTicketButton.getY() + _killTicketButton.getHeight() + 20;
		_line2.setBounds(x, y, xWidth, 2);
		_line3.setBounds(xWidth - _buttonWidth - 20, y, 2, xDim.height - y);
		y += 30;

		_killAllTicketsButton.setBounds(xWidth - _buttonWidth - 8, y, _buttonWidth, _buttonHeight);

		_stopAgentButton.setBounds(xWidth - _buttonWidth - 8, y + _buttonHeight + 20, _buttonWidth, _buttonHeight);

		x = 8;
		y -= 20;
		_numberOfSessionsLabel.setBounds(x, y, _stopAgentButton.getX() - 10, 20);

		y += 24;
		_totalSessionsLabel.setBounds(x, y, _stopAgentButton.getX() - 10, 20);

		y += 24;
		_numberOfTicketsLabel.setBounds(x, y, _stopAgentButton.getX() - 10, 20);

		y += 24;
		_totalTicketsLabel.setBounds(x, y, _stopAgentButton.getX() - 10, 20);

		y += 24;
		_timeLabel.setBounds(x, y, _stopAgentButton.getX() - 10, 20);

		super.paint(xGraphics);
	}

	/**
	 * ActionListener for the Kill Ticket Button implemented as an inner class. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Trivial. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * 
	 * @author Alfa & Ariss
	 */
	class KillButtonListener implements ActionListener
	{
		
		/**
		 * Kills the selected ticket(s) from the GUI at the TicketManager. <br>
		 * <br>
		 * 
		 * @param e
		 *            the e
		 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
		 */
		public void actionPerformed(ActionEvent e)
		{
			try {
				// get the selected row(s)
				int[] xRows = _ticketsTable.getSelectedRows();
				if (xRows == null)
					return;

				// fetch the ticket value and kill it at the TicketManager
				for (int i = 0; i < xRows.length; i++) {
					xTicketManager.killTicket((String) _ticketsMonitorModel.getValueAt(xRows[i], _ticketsMonitorModel
							.getColumnCount()));
				}
			}
			catch (Exception x) {
			}
		}
	}

	/**
	 * ActionListener for the Kill All Tickets Button implemented as an inner class. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Trivial. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * 
	 * @author Alfa & Ariss
	 */
	private class KillAllButtonListener implements ActionListener
	{
		
		/**
		 * Simply tells the TicketManager to kill all issued tickets. <br>
		 * <br>
		 * 
		 * @param e
		 *            the e
		 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
		 */
		public void actionPerformed(ActionEvent e)
		{
			try {
				xTicketManager.killAllTickets();
			}
			catch (Exception x) {
			}
		}
	}

	/**
	 * ActionListener for the Stop Agent Button implemented as an inner class. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Trivial. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * 
	 * @author Alfa & Ariss
	 */
	private class StopAgentButtonListener implements ActionListener
	{
		
		/**
		 * Stops the A-Select Agent by sending a <code>request=stop</code> command to the A-Select Agent. <br>
		 * <br>
		 * 
		 * @param e
		 *            the e
		 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
		 */
		public void actionPerformed(ActionEvent e)
		{
			try {
				ASelectAgentConfigManager xASelectAgentConfigManager = ASelectAgentConfigManager.getHandle();
				Object objAgentSection = xASelectAgentConfigManager.getSection(null, "agent");
				String xPort = xASelectAgentConfigManager.getParam(objAgentSection, "adminport");

				Socket xSocket = new Socket("localhost", Integer.parseInt(xPort));
				PrintStream xOutput = new PrintStream(xSocket.getOutputStream());
				BufferedReader xInput = new BufferedReader(new InputStreamReader(xSocket.getInputStream()));
				xOutput.println("request=stop");
				String xResponse = xInput.readLine();
				System.out.println(xResponse);
				xSocket.close();
			}
			catch (Exception x) {
				System.out.println(x.getMessage());
			}
		}
	}

	/**
	 * BasicWindowAdapter that couples to the GUI. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This inner class doesn't implement any logic. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * 
	 * @author Alfa & Ariss
	 */
	private class BasicWindowAdapter extends WindowAdapter
	{
		
		/**
		 * Handles the windowClosing event.
		 * 
		 * @param xEvent
		 *            the x event
		 * @see java.awt.event.WindowListener#windowClosing(java.awt.event.WindowEvent)
		 */
		@Override
		public void windowClosing(WindowEvent xEvent)
		{
			Object oObject = xEvent.getSource();
			if (oObject == AdminMonitor.this) {
				// TODO stop GUI (Stop()) and/or agent? (Erwin)
			}
		}
	}
}
