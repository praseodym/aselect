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
 * $Id: ASelectException.java,v 1.7 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectException.java,v $
 * Revision 1.7  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.6  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.5  2005/02/23 10:40:43  erwin
 * Applied code style and added JavaDoc.
 *
 * Revision 1.4  2005/02/23 10:04:14  erwin
 * Improved Exception handling.
 *
 * Revision 1.3  2005/02/22 12:59:50  erwin
 * *** empty log message ***
 *
 * Revision 1.2  2005/02/22 12:44:03  erwin
 * Change Exception handling removed "error class" variable.
 *
 */

package org.aselect.system.exception;

/**
 * Standard A-Select exception. 
 * <br><br>
 * <b>Description: </b> <br>
 * This exception is thrown if an A-Select (sub)system fails. <br>
 * <br>
 * <i>Note: The message will be an error code. <br>
 * see <code>org.aselect.system.error.Errors</code> for more information. </i>
 * <br>
 * <br>
 * <b>Concurrency issues: </b> 
 * <br>-<br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class ASelectException extends Exception
{
    /**
     * Creates a new instance. 
     * <br><br>
     * <b>Description: </b> <br>
     * Creates and initializes a new <code>ASelectException<code> 
     * with the given code.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <code>sCode != null</code>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * 
     * @param sErrorCode The error code.
     */
    public ASelectException (String sErrorCode)
    {
        super(sErrorCode);
    }

    /**
     * Create new instance with a cause. 
     * <br><br>
     * <b>Description: </b> <br>
     * Creates a new <code>ASelectException</code> with the given code and
     * cause. <br>
     * <br>
     * <b>Concurrency issues: </b> 
     * <br>-<br>
     * <br>
     * <b>Preconditions: </b>
     * <ul>
     * <li><code>sCode != null</code></li>
     * <li><code>tCause != null</code></li>
     * </ul>
     * <br>
     * <b>Postconditions: </b> 
     * <br>-<br>
     * 
     * @param sCode
     *            The error code.
     * @param tCause
     *            the error cause.
     */
    public ASelectException (String sCode, Throwable tCause)
    {
        super(sCode, tCause);
    }
}