/**
  * * Copyright (c) Anoigo. All rights reserved.
 *
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 * 
 */

/** 
 * DelegateException.java 
 *
 * Changelog:
 *
 *
 */
package org.aselect.authspserver.authsp.delegator;

import org.aselect.system.exception.ASelectException;


/**
 * @author RH
 */
public class DelegateException extends ASelectException
{

	/**
	 * Comment for <code>serialVersionUID</code>
	 */
	private static final long serialVersionUID = 2488443686997370192L;


	/**
	 * The Constructor.
	 * 
	 * @param message
	 *            the message
	 */
	public DelegateException(String message) {
		super(message);
	}

	/**
	 * The Constructor.
	 * 
	 * @param message
	 *            the message
	 * @param cause
	 *            the cause
	 */
	public DelegateException(String message, Throwable cause) {
		super(message, cause);
	}


}
