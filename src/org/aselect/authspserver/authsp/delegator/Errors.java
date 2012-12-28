/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */

package org.aselect.authspserver.authsp.delegator;

/**
 * Contains specific Delegate AuthSP errors. <br>
 * <br>
 * <b>Description:</b><br>
 * The PKI result codes. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 */
public class Errors
{
	/**
	 * Error Code for: Delegate result Success
	 */
	public static final String DELEGATOR_DELEGATE_SUCCESS = "200";

	/**
	 * Error Code for: Delegate result Success with no content
	 */
	public static final String DELEGATOR_DELEGATE_SUCCESS_NO_CONTENT = "204";

	/**
	 * Error Code for: Delegate unsure, requires more info
	 */
	public static final String DELEGATOR_DELEGATE_INQUIRE = "300";

	/**
	 * Error Code for: Delegate failed/refused
	 */
	public static final String DELEGATOR_DELEGATE_FAIL = "400";

	/**
	 * Error Code for: Delegate failed/refused invalid MIME type
	 */
	public static final String DELEGATOR_DELEGATE_FAIL_INCORRECT_MIMETYPE = "406";


	/**
	 * Error Code for: Client Certificate Ok
	 */
	public static final String DELEGATOR_SUCCESS = "000";

	/**
	 * Error Code for: Invalid Request
	 */
	public static final String DELEGATOR_INVALID_REQUEST = "009";

	/**
	 * Error Code for: Internal Error
	 */
	public static final String DELEGATOR_INTERNAL_SERVER_ERROR = "010";

	/**
	 * Error Code for: Invalid password format
	 */
	public static final String DELEGATOR_INVALID_USER_PASSWORD_FORMAT = "010";

	/**
	 * Error Code for: Config Error occured
	 */
	public static final String DELEGATOR_CONFIG_ERROR = "101";
}
