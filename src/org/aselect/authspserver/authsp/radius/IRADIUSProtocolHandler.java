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
 * $Id: IRADIUSProtocolHandler.java,v 1.5 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $Log: IRADIUSProtocolHandler.java,v $
 * Revision 1.5  2006/05/03 10:07:31  tom
 * Removed Javadoc version
 *
 * Revision 1.4  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/03/29 12:39:26  erwin
 * Improved logging.
 *
 * Revision 1.2  2005/03/14 07:30:54  tom
 * Minor code style changes
 *
 * Revision 1.1  2005/03/07 15:58:39  leon
 * Interface RadiusProtocolHandler -> IRadiusProtocolHandler
 *
 * Revision 1.2  2005/02/09 09:17:04  leon
 * added License
 * code restyle
 *
 */
package org.aselect.authspserver.authsp.radius;

import org.aselect.system.logging.SystemLogger;

/**
 * Interface Class for a Radius Protocol Handler.
 * <br><br>
 * <b>Description:</b><br>
 * This interface class describes the functions which have to be implemented
 * by a Radius Prototcol Handler 
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * None
 * <br>
 * @author Alfa & Ariss
 * 
 */
public interface IRADIUSProtocolHandler
{

    /**
     * ACCESS_REQUEST 
     */
    public static final byte ACCESS_REQUEST = 1;
    
    /**
     * ACCESS_ACCEPT 
     */
    public static final byte ACCESS_ACCEPT = 2;
    
    /**
     * ACCESS_REJECT
     */
    public static final byte ACCESS_REJECT = 3;
    
    /**
     * RADIUS_ATTRIBUTE_TYPE_USER_NAME
     */
    public static final byte RADIUS_ATTRIBUTE_TYPE_USER_NAME = 1;
    
    /**
     * RADIUS_ATTRIBUTE_TYPE_USER_PASSWORD
     */
    public static final byte RADIUS_ATTRIBUTE_TYPE_USER_PASSWORD = 2;
    
    /**
     * RADIUS_ATTRIBUTE_TYPE_CHAP_PASSWORD
     */
    public static final byte RADIUS_ATTRIBUTE_TYPE_CHAP_PASSWORD = 3;
    
    /**
     * RADIUS_ATTRIBUTE_TYPE_CHAP_CHALLENGE
     */
    public static final byte RADIUS_ATTRIBUTE_TYPE_CHAP_CHALLENGE = 60;

    /**
     * MAX_RADIUS_PACKET_SIZE
     */
    public static final int MAX_RADIUS_PACKET_SIZE = 512;

    /**
     * RADIUS_PORT
     */
    public static final int RADIUS_PORT = 1812;


    /**
     * Initializes the Radius Protocol Handler.
     * <br>
     * @param sRadiusServer
     * @param iPort
     * @param sSharedSecret
     * @param bFullUid
     * @param sUid
     * @param systemLogger
     * @return true
     */
    public boolean init(String sRadiusServer,
                        int iPort,
                        String sSharedSecret,
                        boolean bFullUid,
                        String sUid,
                        SystemLogger systemLogger);


    /**
     * The authenticate function which must be implemented for all 
     * Radius Protocol handlers.
     * <br><br>
     * @param sPassword
     * @return Result Code
     */
    public String authenticate(String sPassword);
}
