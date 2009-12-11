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
 * $Id: ASelectAuthorizationException.java,v 1.3 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectAuthorizationException.java,v $
 * Revision 1.3  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.2  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.1  2005/08/23 13:37:57  erwin
 * Added error code and exception for authorization.
 *
 *
 */

package org.aselect.system.exception;

// TODO: Auto-generated Javadoc
/**
 * Aurhorization exception. <br>
 * <br>
 * <b>Description: </b> <br>
 * This exception is thrown if an error occurs during the authorization of a user. <br>
 * <br>
 * <i>Note: The message will be an error code. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 * @see org.aselect.system.error.Errors
 */
public class ASelectAuthorizationException extends ASelectException
{
	
	/**
	 * Creates a new instance. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates and initializes a new <code>ASelectAuthorizationException<code>
	 * with the given code.
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * <code>sCode != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sCode
	 *            The error code.
	 */
	public ASelectAuthorizationException(String sCode) {
		super(sCode);
	}

	/**
	 * Create new instance with a cause. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a new <code>ASelectAuthorizationException</code> with the given code and cause. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>sCode != null</code></li>
	 * <li><code>tCause != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param sCode
	 *            The error code.
	 * @param tCause
	 *            The error cause.
	 */
	public ASelectAuthorizationException(String sCode, Throwable tCause) {
		super(sCode, tCause);
	}
}