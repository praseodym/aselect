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
 * $Id: AdminMonitor.java,v 1.12 2006/04/26 12:14:34 tom Exp $ 
 * 
 * Changelog:
 * $Log: AdminMonitor.java,v $
 * Revision 1.12  2006/04/26 12:14:34  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.11  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.10.10.1  2006/01/25 15:35:19  martijn
 * TGTManager rewritten
 *
 * Revision 1.10  2005/04/26 15:12:09  erwin
 * Fixed problem with session/TGT counter mix up.
 *
 * Revision 1.9  2005/03/30 12:54:10  erwin
 * Fixed problem with restarting A-Select and the Admin Monitor.
 *
 * Revision 1.8  2005/03/14 13:03:05  erwin
 * Fixed problems with Admin monitor.
 * 
 * Revision 1.7  2005/03/10 14:17:45  erwin
 * Improved Javadoc.
 * 
 * Revision 1.6  2005/03/10 10:42:56  erwin
 * Added dynamic window name.
 * 
 * Revision 1.5  2005/03/10 10:08:01  erwin
 * Removed some compiler warnings.
 * 
 * Revision 1.4  2005/03/10 10:05:29  erwin
 * Improved error handling. Made instance variables private.
 * 
 * Revision 1.3  2005/03/04 11:29:33  tom
 * Code has been styled and reformated accoring to templates.
 * Javadoc has been added.
 */

package org.aselect.server.admin;

import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Date;
import java.util.logging.Level;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.UIManager;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;

import org.aselect.server.config.Version;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.tgt.TGTManager;

/**
 * The AdminMonitor main Class.
 * <br>
 * <br>
 * <b>Description: </b> <br>
 * Provides a GUI for A-Select session and ticket management. 
 * <br><br>
 * <b>Concurrency issues: </b> 
 * <br>none <br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class AdminMonitor extends JFrame implements TableModelListener
{
    /**
     * The module name.
     */
    public static final String MODULE = "AdminMonitor";

    /**
     * JTable for TGTs.
     */
    private JTable _oTGTsTable;

    /**
     * JLabel for TGTs.
     */
    private JLabel _oTGTsLabel = null;

    /**
     * TGTMonitorModel for TGTs.
     */
    private TGTMonitorModel _oTGTsModel = null;

    /**
     * JScrollPane for TGTs.
     */
    private JScrollPane _oTGTsScrollPane = null;

    /**
     * JTable for Sessions.
     */
    private JTable _oSessionsTable;

    /**
     * JLabel for Sessions.
     */
    private JLabel _oSessionsLabel = null;

    /**
     * JScrollPane for Sessions.
     */
    private JScrollPane _oSessionsScrollPane = null;

    /**
     * SessionMonitorModel for Sessions.
     */
    private SessionMonitorModel _oSessionsModel = null;

    /**
     * JButton to revoke TGT.
     */
    private JButton _oRevokeTGTButton = null;

    /**
     * JButton to revoke all TGT.
     */
    private JButton _oRevokeAllTGTsButton = null;

    /**
     * Default button width.
     */
    private int _iButtonWidth = 130;

    /**
     * Default button height.
     */
    private int _iButtonHeight = 24;

    /**
     * JButtons for Lines.
     */
    private JButton _oLineButton1, _oLineButton2, _oLineButton3;

    /**
     * JLabel for number of TGTs and number of Sessions.
     */
    private JLabel _oNumberOfTGTsLabel, _oNumberOfSessionsLabel;

    /**
     * JLabels for Total Sessions, Total TGTs and Time.
     */
    private JLabel _oTotalSessionsLabel, _oTotalTGTsLabel,
        _oTimeLabel;

    /**
     * Main TGTManager.
     */
    private TGTManager _oTGTManager = TGTManager.getHandle();

    /**
     * Create a new instance. <br>
     * <br>
     * <b>Description: </b> <br>
     * Performs all default construction work:
     * <ul>
     * <li>Initialize the GUI</li>
     * <li>Add tables for session and ticket monitoring</li>
     * <li>Add all labels and buttons</li>
     * </ul>
     * <br>
     * <b>Concurrency issues: </b> <br>-<br>
     * <br>
     * <b>Preconditions: </b> <br>-<br>
     * <br>
     * <b>Postconditions: </b> <br>
     * The <code>AdminMonitor</code> is ready to be started. <br>
     * 
     * @throws Exception
     *             If <code>setLookAndFeel()</code> fails.
     *  
     */
    public AdminMonitor() throws Exception
    {
        //Initialize GUI
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        StringBuffer sbInfo = new StringBuffer(Version.getVersion());
        sbInfo.append(" Admin Monitor ");
        setTitle(sbInfo.toString());
        setSize(800, 600);
        setLocation(1, 1);
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new BasicWindowAdapter());
        getContentPane().setLayout(null);
        
        //TGT monitor
        _oTGTsTable = new JTable();
        _oTGTsScrollPane = new JScrollPane(_oTGTsTable);
        getContentPane().add(_oTGTsScrollPane);
        _oTGTsLabel = new JLabel("Issued TGT's");
        getContentPane().add(_oTGTsLabel);
        
        //Session monitor
        _oSessionsTable = new JTable();
        _oSessionsScrollPane = new JScrollPane(_oSessionsTable);
        getContentPane().add(_oSessionsScrollPane);
        _oSessionsLabel = new JLabel("Pending sessions");
        getContentPane().add(_oSessionsLabel);
        
        //Buttons and labels
        _oLineButton1 = new JButton();
        _oLineButton1.setEnabled(false);
        getContentPane().add(_oLineButton1);

        _oLineButton2 = new JButton();
        _oLineButton2.setEnabled(false);
        getContentPane().add(_oLineButton2);

        _oLineButton3 = new JButton();
        _oLineButton3.setEnabled(false);
        getContentPane().add(_oLineButton3);

        _oNumberOfSessionsLabel = new JLabel("");
        getContentPane().add(_oNumberOfSessionsLabel);
        _oNumberOfTGTsLabel = new JLabel("");
        getContentPane().add(_oNumberOfTGTsLabel);

        _oTotalSessionsLabel = new JLabel("");
        getContentPane().add(_oTotalSessionsLabel);

        _oTotalTGTsLabel = new JLabel("");
        getContentPane().add(_oTotalTGTsLabel);
        
        _oTimeLabel = new JLabel("");
        getContentPane().add(_oTimeLabel);

        //kill all TGTs button
        _oRevokeAllTGTsButton = new JButton("Kill All TGTs");
        getContentPane().add(_oRevokeAllTGTsButton);
        _oRevokeAllTGTsButton
            .addActionListener(new RevokeAllTGTsButtonListener());
        
        //kill TGT button
        _oRevokeTGTButton = new JButton("Kill TGT");
        getContentPane().add(_oRevokeTGTButton);
        _oRevokeTGTButton.addActionListener(new RevokeTGTButtonListener());
        getRootPane().setDefaultButton(_oRevokeTGTButton);
    }
    
    /**
     * Function to start the AdminMonitor.
     * <br><br>
     * <b>Description: </b> <br>
     * This function initializes the session and TGT monitor model, starts the 
     * AdminMonitor and makes it visible.
     * <br><br>
     * <b>Concurrency issues: </b> <br>
     * none <br>
     * <br>
     * <b>Preconditions: </b> <br>
     * <code>iCheckInterval > 0</code><br>
     * <br>
     * <b>Postconditions: </b> 
     * <br>
     * GUI is visible and models are running. 
     * <br>
     * 
     * @param iCheckInterval
     *            Interval in seconds that defines when AdminMonitor checks for
     *            new information.
     * @throws Exception
     */
    public void start(int iCheckInterval) throws Exception
    {
        
        _oTGTsModel = new TGTMonitorModel(iCheckInterval);
        _oTGTsModel.addTableModelListener(this);
        _oTGTsTable.setModel(_oTGTsModel);         

        _oSessionsModel = new SessionMonitorModel(iCheckInterval);
        _oSessionsModel.addTableModelListener(this);
        _oSessionsTable.setModel(_oSessionsModel);

        _oTimeLabel.setText("Started at " + new Date().toString());
       
        //make visible
        repaint();
        setVisible(true);
        toFront();
        
        //log success
        ASelectSystemLogger.getHandle().log(Level.INFO, MODULE, "start()", 
        "Successfully initialized Admin monitor.");
    }

    /**
     * Function to stop the AdminMonitor.
     * 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * This function stops the TGT and session model. 
     * The AdminMonitor GUI is made invisible.
     * <br><br>
     * <b>Concurrency issues: </b> <br>
     * none <br>
     * <br>
     * <b>Preconditions: </b> 
     * <br>none <br>
     * <br>
     * <b>Postconditions: </b> 
     * <br>
     * The GUI is invisible and models are stopped.
     * <br>
     *  
     */
    public void stop()
    {
      
        if (_oTGTsModel != null)
            _oTGTsModel.stop();

        if (_oSessionsModel != null)
            _oSessionsModel.stop();
        
        setVisible(false);       

        ASelectSystemLogger.getHandle().log(Level.INFO, MODULE, "stop()", 
            "Admin monitor stopped");
    }

    /**
     * Updates the session and TGT information in the GUI. 
     * <br><br>
     * @see javax.swing.event.TableModelListener#tableChanged(javax.swing.event.TableModelEvent)
     */
    public void tableChanged(TableModelEvent oTableModelEvent)
    {
        StringBuffer sbBuffer = new StringBuffer();
        sbBuffer.append("Number of pending sessions: ");
        sbBuffer.append(Integer.toString(_oSessionsModel.getRowCount()));
        _oNumberOfSessionsLabel.setText(sbBuffer.toString());

        sbBuffer = new StringBuffer();
        sbBuffer.append("Number of issued TGT's: ");
        sbBuffer.append(Integer.toString(_oTGTsModel.getRowCount()));
        _oNumberOfTGTsLabel.setText(sbBuffer.toString());

        sbBuffer = new StringBuffer();
        sbBuffer.append("Total sessions handled since startup: ");
        sbBuffer.append(_oSessionsModel.getSessionsCounter());
        _oTotalSessionsLabel.setText(sbBuffer.toString());

        sbBuffer = new StringBuffer();
        sbBuffer.append("Total TGT's issued since startup: ");
        sbBuffer.append(_oTGTsModel.getTGTCounter());
        _oTotalTGTsLabel.setText(sbBuffer.toString());
    }

    /**
     * (re)paints all the specific AdminMonitor graphics. 
     * @see java.awt.Component#paint(java.awt.Graphics)
     */
    public void paint(Graphics oGraphics)
    {
        int x, y, iWidth;
        Dimension oDim = getContentPane().getSize();

        x = 4;
        y = 16;
        iWidth = oDim.width - 8;

        _oSessionsLabel.setBounds(x + 10, y, iWidth, 20);
        _oSessionsScrollPane.setBounds(x, y + 24, iWidth, 120);

        y = _oSessionsScrollPane.getY() + _oSessionsScrollPane.getHeight() + 20;
        _oLineButton1.setBounds(x, y, iWidth, 2);
        y += 12;

        _oTGTsLabel.setBounds(x + 10, y, iWidth, 20);
        _oTGTsScrollPane.setBounds(x, y + 24, iWidth, oDim.height - 400);

        y = _oTGTsScrollPane.getY() + _oTGTsScrollPane.getHeight() + 4;
        _oRevokeTGTButton.setBounds((iWidth - _iButtonWidth) / 2, y,
            _iButtonWidth, _iButtonHeight);

        x = 4;
        y = _oRevokeTGTButton.getY() + _oRevokeTGTButton.getHeight() + 20;
        _oLineButton2.setBounds(x, y, iWidth, 2);
        _oLineButton3.setBounds(iWidth - _iButtonWidth - 20, y, 2, oDim.height
            - y);
        y += 30;

        _oRevokeAllTGTsButton.setBounds(iWidth - _iButtonWidth - 8, y,
            _iButtonWidth, _iButtonHeight);

        x = 8;
        y -= 20;
        _oNumberOfSessionsLabel.setBounds(x, y,
            _oRevokeAllTGTsButton.getX() - 10, 20);

        y += 24;
        _oTotalSessionsLabel.setBounds(x, y, _oRevokeAllTGTsButton.getX() - 10,
            20);

        y += 24;
        _oNumberOfTGTsLabel.setBounds(x, y, _oRevokeAllTGTsButton.getX() - 10,
            20);

        y += 24;
        _oTotalTGTsLabel.setBounds(x, y, _oRevokeAllTGTsButton.getX() - 10, 20);

        y += 24;
        _oTimeLabel.setBounds(x, y, _oRevokeAllTGTsButton.getX() - 10, 20);

        super.paint(oGraphics);
    }

    /**
     * This ActionListener is called when a user clicks on RevokeTGT.
     * 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * This function finds the selected TGT and calls _oTGTManager.killTGT. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * none <br>
     * 
     * @author Alfa & Ariss
     * 
     */
    class RevokeTGTButtonListener implements ActionListener
    {
        /**
         * Find selected TGT and call _oTGTManager.killTGT. <br>
         * <br>
         * 
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        public void actionPerformed(ActionEvent ae)
        {
            try
            {
                int[] iRows = _oTGTsTable.getSelectedRows();
                if (iRows == null)
                    return;
                for (int i = 0; i < iRows.length; i++)
                {
                    _oTGTManager.remove(_oTGTsModel.getValueAt(
                        iRows[i], _oTGTsModel.getColumnCount()));
                }
            }
            catch (Exception e)
            {}
            repaint();
        }
    }

    /**
     * This ActionListener is called when a user click on RevokeAllTGTs.
     * 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * This function revokes all TGTs by calling _oTGTManager.killAllTGTs().
     * <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * none <br>
     * 
     * @author Alfa & Ariss
     * 
     */
    class RevokeAllTGTsButtonListener implements ActionListener
    {
        /**
         * revoke all TGTs by calling _oTGTManager.killAllTGTs(). <br>
         * <br>
         * 
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        public void actionPerformed(ActionEvent e)
        {
            try
            {
                _oTGTManager.removeAll();
            }
            catch (Exception x)
            {}
            repaint();
        }
    }

    /**
     * BasicWindowAdapter for the AdminMonitor.
     * 
     * <br>
     * <br>
     * <b>Description: </b> <br>
     * This class does nothing. <br>
     * <br>
     * <b>Concurrency issues: </b> <br>
     * none <br>
     * 
     * @author Alfa & Ariss
     * 
     */
    class BasicWindowAdapter extends WindowAdapter
    {
        /**
         * @see java.awt.event.WindowListener#windowClosing(java.awt.event.WindowEvent)
         */
        public void windowClosing(WindowEvent xEvent)
        {
            Object o = xEvent.getSource();
            if (o == AdminMonitor.this){ 
                //TODO stop() can be called here to stop Gui (Erwin)          
            }
        }
    }
}

