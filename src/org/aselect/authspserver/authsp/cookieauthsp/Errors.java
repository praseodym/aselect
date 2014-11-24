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
package org.aselect.authspserver.authsp.cookieauthsp;

/**
 * CookieAuthSP error codes. <br>
 * <br>
 * <b>Description: </b> <br>
 * Error codes that are used by the CookieAuthSP. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * - <br>
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
