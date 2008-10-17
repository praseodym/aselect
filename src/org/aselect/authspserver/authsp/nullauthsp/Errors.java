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
 * $Id: Errors.java,v 1.5 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $Log: Errors.java,v $
 * Revision 1.5  2006/05/03 10:07:31  tom
 * Removed Javadoc version
 *
 * Revision 1.4  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/03/03 12:50:09  martijn
 * added javadoc / made compatible with A-Select 1.4.1
 *
 * Revision 1.2  2005/02/09 09:17:44  leon
 * added License
 * code restyle
 *
 */
package org.aselect.authspserver.authsp.nullauthsp;

/**
 * Null AuthSP error codes. <br>
 * <br>
 * <b>Description: </b> <br>
 * Error codes that are used by the Null AuthSP.
 * <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -
 * <br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class Errors
{
    /**
     * No error
     */
    public final static String ERROR_NULL_SUCCESS = "000";

    /**
     * Internal error has occurred
     */
    public final static String ERROR_NULL_INTERNAL = "100";

    /**
     * An invalid request has been sent
     */
    public final static String ERROR_NULL_INVALID_REQUEST = "200";
    
    /**
     * Access is denied
     */
    public final static String ERROR_NULL_ACCESS_DENIED = "800";

    /**
     * User could not be authenticated
     */
    public final static String ERROR_NULL_COULD_NOT_AUTHENTICATE_USER = "900";
}
