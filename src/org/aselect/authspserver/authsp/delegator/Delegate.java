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
 * Delegate.java 
 *
 * Changelog:
 *
 *
 */
package org.aselect.authspserver.authsp.delegator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author RH
 */
public interface Delegate
{
	
	/**
	 * Result Code for: Delegate result Success
	 */
	public static final int DELEGATE_SUCCESS = 200;

	/**
	 * Result Code for: Delegate result Success but no content returned
	 */
	public static final int DELEGATE_SUCCESS_NO_CONTENT = 204;

	/**
	 * Result Code for: Delegate unsure, requires more info
	 */
	public static final int DELEGATE_INQUIRE = 300;

	/**
	 * Result Code for: Delegate failed/refused
	 */
	public static final int DELEGATE_FAIL = 400;

	/**
	 * Result Code for: Delegate failed/refused for invalid mime type
	 */
	public static final int DELEGATE_FAIL_INCORRECT_MIME = 406;

	
	/**
	 * authenticate.
	 * 
	 * @param Map<String, Object> requestparameters
	 *            parameters to pass to delegate
	 * @param Map<String,  List<String>> responseparameters 
	 *           result parameters from delegate
	 * @return the result, depending on mplementation
	 * 
	 * @throws DelegateException
	 *             other error conditions
	 */
	public int authenticate( Map<String, String> requestparameters, Map<String,  List<String>> responseparameters )
	throws DelegateException;
}
