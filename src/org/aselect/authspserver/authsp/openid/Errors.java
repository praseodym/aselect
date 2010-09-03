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
package org.aselect.authspserver.authsp.openid;

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
	public final static String ERROR_DB_SUCCESS = "000";

	/** Internal error. */
	public final static String ERROR_DB_INTERNAL_ERROR = "100";

	/** Invalid request. */
	public final static String ERROR_DB_INVALID_REQUEST = "200";

	/** DB server unreachable. */
	public final static String ERROR_DB_COULD_NOT_REACH_DB_SERVER = "300";

	/** Invalid password. */
	public final static String ERROR_DB_INVALID_PASSWORD = "400";

	/** Access denied. */
	public final static String ERROR_DB_ACCESS_DENIED = "800";

	/** Could not authneticate user. */
	public final static String ERROR_DB_COULD_NOT_AUTHENTICATE_USER = "900";
}
