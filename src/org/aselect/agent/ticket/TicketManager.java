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
 * $Id: TicketManager.java,v 1.16 2006/04/14 13:42:48 tom Exp $
 * 
 * Changelog: 
 * $Log: TicketManager.java,v $
 * Revision 1.16  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.15  2005/09/08 12:46:02  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.14  2005/04/15 11:51:42  tom
 * Removed old logging statements
 *
 * Revision 1.13  2005/04/08 12:40:51  martijn
 * fixed todo's
 *
 * Revision 1.12  2005/04/04 14:46:35  erwin
 * Added todo for kill_ticket ticket validation.
 *
 * Revision 1.11  2005/03/14 10:09:07  erwin
 * The ticket and session expiration and start
 * time are now read from the ticket and session
 * manager.
 *
 * Revision 1.10  2005/03/11 21:06:28  martijn
 * now using contains(key) instead of retrieving all objects with getAll() and doing the contains by hand
 *
 * Revision 1.9  2005/03/11 16:49:35  martijn
 * moved verifying if max sessions and tickets are reached to the storagemanager
 *
 * Revision 1.8  2005/03/08 09:30:20  erwin
 * Fixed double initialisation of static instance
 *
 * Revision 1.7  2005/03/08 08:44:46  erwin
 * Improved Ticket managent
 *
 * Revision 1.6  2005/03/03 17:24:19  erwin
 * Applied code style, added javadoc comment.
 *
 * Revision 1.5  2005/03/01 14:08:34  martijn
 * fixed stop() method
 *
 * Revision 1.4  2005/02/28 14:04:47  erwin
 * Fixed level of succes message.
 *
 * Revision 1.3  2005/02/25 15:51:33  erwin
 * Improved logging.
 *
 * Revision 1.2  2005/02/24 15:09:09  ali
 * Added IAgentEventListener class and updates internal Javadoc.
 * 
 */

package org.aselect.agent.ticket;

import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.logging.Level;

import org.aselect.agent.config.ASelectAgentConfigManager;
import org.aselect.agent.log.ASelectAgentSystemLogger;
import org.aselect.agent.sam.ASelectAgentSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.storagemanager.StorageManager;
import org.aselect.system.utils.Utils;

/**
 * Manages A-Select Agent tickets.
 * <br><br>
 * <b>Description:</b><br>
 * Provides methods for managing ticket:
 * <ul>
 *  <li>Create a ticket</li>
 *  <li>Update a ticket</li>
 *  <li>Remove a ticket</li>
 * </ul>
 * The ticket contexts are stored using a <code>StorageManager</code>.
 * <br><br>
 * <i>Note: This manager is implemented as a Singleton.</i> 
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 */
public class TicketManager
{
    /** The module name */
    public static final String MODULE = "TicketManager";

    /** The static instance. */
    private static TicketManager _instance;
        
    /** The configuration. */
    private ASelectAgentConfigManager _oConfigManager;
    
    /** The actual storage. */
    private StorageManager _oTicketTable;
    
    /** The random generator. */
    private SecureRandom _oRandomGenerator;
    
    /** The logger for system log entries. */
    private SystemLogger _systemLogger;
    
    /** number of Agent tickets issued since startup. */
    private long _lTicketsCounter;

    /** The length of the Agent ticket. */
    private static final int TICKET_LENGTH = 128;  // 256;

    /**
     * Get a static handle to the <code>TicketManager</code> instance.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Checks if a static instance exists, otherwise it is created. This 
     * instance is returned.
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
     * A static instance of the <code>TicketManager</code> exists.
     * 
     * @return A static handle to the <code>TicketManager</code>
     */
    public static TicketManager getHandle()
    {
        if(_instance == null)
            _instance = new TicketManager();     
        return _instance;
    }

    /**
     * Initializes the <code>TicketManager</code>.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Read configuration settings and initializes the components.
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
     * The instance variables and components are initialized.
     * <br>
     * @return true if initialization succeeds, otherwise false.
     */
    public boolean init()
    {
        String sMethod = "init()";
        try
        {
            _oConfigManager = ASelectAgentConfigManager.getHandle();
    
            Object objTicketMngrConfig = null;
            try
            {
                objTicketMngrConfig = _oConfigManager.getSection(null,
                    "storagemanager", "id=ticket");
            }
            catch (ASelectConfigException eAC)
            {
                _systemLogger.log(Level.SEVERE, 
                    MODULE, sMethod, "no storagemanager section with 'id=ticket' declared in config file", eAC);
                return false;
            }
    
            _oTicketTable = new StorageManager();
            _oTicketTable.init(objTicketMngrConfig, _oConfigManager,
                ASelectAgentSystemLogger.getHandle(), ASelectAgentSAMAgent
                    .getHandle());
    
            //initialize Randomgenerator
            _oRandomGenerator = SecureRandom.getInstance("SHA1PRNG");
            _oRandomGenerator.setSeed(_oRandomGenerator.generateSeed(20));
    
            _lTicketsCounter = 0;
    
            _systemLogger.log(Level.INFO, 
                MODULE, sMethod, "Ticket manager Successfully started.");
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, 
                MODULE, sMethod, "Exception occured.", e);
            return false;
        }
        return true;
    }

    /**
     * Stop the <code>TicketManager</code>.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Destroys all current tickets.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * After this method is finished, no methods may be called 
     * in other threads.
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * The <code>TicketManager</code> has stopped.
     * 
     */
    public void stop()
    {
        String sMethod = "stop()";

        if (_oTicketTable != null)
            _oTicketTable.destroy();

        _systemLogger.log(Level.INFO, 
            MODULE, sMethod, "Ticket manager stopped.");
    }

    /**
     * Create a Agent ticket.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Create a new Agent ticket which is used as a ID for the given 
     * ticket context. Adds the given ticket context to the storage.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <code>htTicketContext != null</code>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * The ticket context is added to the storage.
     * <br>
     * @param htTicketContext The ccontext to be add.
     * @return The created ticket.
     */
    public String createTicket(Hashtable htTicketContext)
    {
        String sMethod = "createTicket()";
        String sTicket = null;
        byte[] baTicketBytes = new byte[TICKET_LENGTH];
    
        try
        {
            synchronized (_oTicketTable)
            {
                _oRandomGenerator.nextBytes(baTicketBytes);
                sTicket = Utils.toHexString(baTicketBytes);
    
                while (_oTicketTable.containsKey(sTicket))
                {
                    _oRandomGenerator.nextBytes(baTicketBytes);
                    sTicket = Utils.toHexString(baTicketBytes);
                }               
                               
                try
                {
                    _systemLogger.log(Level.INFO, MODULE, sMethod, "New Ticket="+sTicket+", Context="+htTicketContext);
                    _oTicketTable.put(sTicket, htTicketContext);
                }
                catch (ASelectStorageException e)
                {
                    if (e.getMessage().equals(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED))
                    {
                        _systemLogger.log(Level.WARNING, MODULE, sMethod, "Maximum number of tickets reached", e);
                        return null;
                    }
                    
                    throw e;
                }
    
                _lTicketsCounter++;
            }
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, 
                MODULE, sMethod, "Exception occured.", e);
        }
    
        return sTicket;
    }

    /**
     * Update a ticket.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Overwrites the new ticket context in the storage.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <ul>
     * 	<li><code>sTicket != null</code></li>
     * 	<li><code>htTicketContext != null</code></li>
     * </ul>
     * <br>
     * <b>Postconditions:</b>
     * <br>
     * The given ticket is updated with the new context.
     * <br>
     * @param sTicket The ticket to be updated.
     * @param htTicketContext The new ticket context.
     */
    public void updateTicketContext(String sTicket, Hashtable htTicketContext)
    {
        String sMethod = "updateTicketContext()";
    
        try
        {
            synchronized (_oTicketTable)
            {
                _oTicketTable.update(sTicket, htTicketContext);
            }
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, 
                MODULE, sMethod, "Exception occured.", e);
        }
    }

    /**
     * Kill Agent ticket.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Remove the context of a given ticket from the storage.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <code>sTicket != null</code>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * The ticket context is removed from storage.
     * <br>
     * @param sTicket The ticket to be removed.
     * @return True if removal succeeds, otherwise false.
     */
    public boolean killTicket(String sTicket)
    {
        String sMethod = "killTicket()";
    
        try
        {
            synchronized (_oTicketTable)
            {
                _oTicketTable.remove(sTicket);
            }
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, 
                MODULE, sMethod, "Exception occured.", e);
            return false;
        }
    
        return true;
    }    

    /**
     * Kill all Agent tickets.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Remove all ticket contexts from the storage.
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
     * The ticket storage is empty.
     * <br>
     * 
     */
    public void killAllTickets()
    {
        String sMethod = "killAllTickets()";
    
        try
        {
            synchronized (_oTicketTable)
            {
                _oTicketTable.removeAll();
            }
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, 
                MODULE, sMethod, "Exception occured.", e);
        }
    }

    /**
     * Get Agent ticket context.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Retrieve Agent ticket context from the storage.
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
     * @param sTicket The ticket to retrieve.
     * @return The ticket context.
     */
    public Hashtable getTicketContext(String sTicket)
    {
        String sMethod = "getTicketContext()";
        Hashtable htResponse = null;
    
        if (sTicket == null || sTicket.equals(""))
            return null;
    
        try
        {
        	int len = sTicket.length();
            _systemLogger.log(Level.INFO, MODULE, sMethod, "Get Ticket("+sTicket.substring(0, (len<30)?len:30));
            htResponse = (Hashtable)_oTicketTable.get(sTicket);
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer("Ticket doesn't exist: ");
            sbError.append(sTicket);
            _systemLogger.log(Level.FINE, 
                MODULE, sMethod, sbError.toString(), e);
        }
        return htResponse;
    }
    
    /**
     * Returns the ticket timeout.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Return the ticket timeout from the given ticket.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <code>sTicket != null</code>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sTicket the ticket.
     * @return The expiration time of the ticket.
     * @throws ASelectStorageException If retrieving ticket timeout fails.
     */
    public long getTicketTimeout(String sTicket) throws ASelectStorageException
    {
        return _oTicketTable.getExpirationTime(sTicket);
    }
    
    /**
     * Returns the ticket start time.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Return the ticket timestamp form the given ticket.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <code>sTicket != null</code>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sTicket the ticket.
     * @return The start time of the ticket.
     * @throws ASelectStorageException If retrieving ticket start time fails.
     */
    public long getTicketStartTime(String sTicket) throws ASelectStorageException
    {
        return _oTicketTable.getTimestamp(sTicket);
    }

    /**
     * Get all ticket context.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Retrieve all Agent ticket contexts from the storage.
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
     * @return all Agent ticket contexts in a <code>Hashtable</code>.
     */
    public Hashtable getTicketContexts()
    {
        String sMethod = "getTicketContexts()";
        Hashtable xResponse = null;

        try
        {
            xResponse = _oTicketTable.getAll();
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, 
                MODULE, sMethod, "Exception occured.", e);
        }

        return xResponse;
    }

    /** 
     * Get the number of issued tickets since startup.    
     * @return The number of issued Agent tickets.
     */
    public long getTicketsCounter()
    {
        return _lTicketsCounter;
    }
    
    

    /**
     * Private constructor.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * retrieves a handle to the system logger.  
     * 
     */
    private TicketManager()
    {
        _systemLogger = ASelectAgentSystemLogger.getHandle();
    }
}