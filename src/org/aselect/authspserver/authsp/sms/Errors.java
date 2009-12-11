/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.authspserver.authsp.sms;

/**
 * Contains specific DB AuthSP errors. <br>
 * <br>
 * <b>Description:</b><br>
 * The DB result codes. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Cristina Gavrila, BTTSD
 */
public class Errors
{

	/** Success. */
	public final static String ERROR_SMS_SUCCESS = "000";

	/** Internal error. */
	public final static String ERROR_SMS_INTERNAL_ERROR = "100";

	/** Invalid request. */
	public final static String ERROR_SMS_INVALID_REQUEST = "200";

	/** SMS server unreachable. */
	public final static String ERROR_SMS_COULD_NOT_REACH_SMS_SERVER = "300";

	/** Invalid password. */
	public final static String ERROR_SMS_INVALID_PASSWORD = "400";

	/** Access denied. */
	public final static String ERROR_SMS_ACCESS_DENIED = "800";

	/** Could not authneticate user. */
	public final static String ERROR_SMS_COULD_NOT_AUTHENTICATE_USER = "900";
}
