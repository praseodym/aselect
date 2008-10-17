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
 * $Id: AbstractRADIUSProtocolHandler.java,v 1.7 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $Log: AbstractRADIUSProtocolHandler.java,v $
 * Revision 1.7  2006/05/03 10:07:31  tom
 * Removed Javadoc version
 *
 * Revision 1.6  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.5  2005/03/23 11:24:18  erwin
 * Fixed javadoc.
 *
 * Revision 1.4  2005/03/14 07:30:54  tom
 * Minor code style changes
 *
 * Revision 1.3  2005/03/07 15:57:40  leon
 * - New Failure Handling
 * - Extra Javadoc
 *
 * Revision 1.2  2005/02/09 09:17:04  leon
 * added License
 * code restyle
 * 
 *
 */
package org.aselect.authspserver.authsp.radius;

import org.aselect.system.logging.SystemLogger;

/**
 * Abstract Radius Protocol Handler.
 * <br><br>
 * <b>Description:</b><br>
 * Abstract implementation of the Radius AuthSP Handler, which can be used as
 * base for other implementations of the Radius Protocol Handler (CHAP/PAP)
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * None
 * <br>
 * @author Alfa & Ariss
 * 
 */
public abstract class AbstractRADIUSProtocolHandler
    implements IRADIUSProtocolHandler
{
    /** The radius server. */
    protected String _sRadiusServer;
    /** The radius server port. */
    protected int _iPort;
    /** The shared secret. */
    protected String _sSharedSecret;
    /** The complete user ID. */
    protected boolean _bFullUid;
    /** The user ID. */
    protected String _sUid;
    /** The logger for system entries. */
    protected SystemLogger _systemLogger;

    /**
     * Initializes the Radius Protocol Handler.
     * <br><br>
     * @see org.aselect.authspserver.authsp.radius.IRADIUSProtocolHandler#init(java.lang.String, int, java.lang.String, boolean, java.lang.String, org.aselect.system.logging.SystemLogger)
     */
    public boolean init(String sRadiusServer, int iPort,
                        String sSharedSecret, boolean bFullUid,
                        String sUid, SystemLogger systemLogger)
    {
        _sRadiusServer = sRadiusServer;
        _iPort = iPort;
        _sSharedSecret = sSharedSecret;
        _bFullUid = bFullUid;
        _sUid = sUid;
        _systemLogger = systemLogger;

        return true;

    }

    /**
     * Autehnticate a user with Radius.
     * <br><br>
     * @see org.aselect.authspserver.authsp.radius.IRADIUSProtocolHandler#authenticate(java.lang.String)
     */
    public abstract String authenticate(String sPassword);
}
