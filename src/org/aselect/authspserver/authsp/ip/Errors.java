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
 * $Id: Errors.java,v 1.6 2006/05/03 10:06:47 tom Exp $ 
 *
 * Changelog:
 * $Log: Errors.java,v $
 * Revision 1.6  2006/05/03 10:06:47  tom
 * Removed Javadoc version
 *
 * Revision 1.5  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.4  2005/03/24 14:47:32  martijn
 * added more javadoc
 *
 * Revision 1.3  2005/03/24 14:43:15  martijn
 * code restyle, javadoc and error handling
 *
 * Revision 1.2  2005/01/31 14:21:34  leon
 * License toevoegen
 *
 */
package org.aselect.authspserver.authsp.ip;

/**
 * Contains specific IP AuthSP errors. <br>
 * <br>
 * <b>Description:</b><br>
 * The IP result codes. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class Errors
{
	/** Success. */
	public final static String ERROR_IP_SUCCESS = "000";

	/** Internal error. */
	public final static String ERROR_IP_INTERNAL_ERROR = "100";

	/** Invalid request. */
	public final static String ERROR_IP_INVALID_REQUEST = "200";

	/** Access denied. */
	public final static String ERROR_IP_ACCESS_DENIED = "800";

	/** Could not authenticate. */
	public final static String ERROR_IP_COULD_NOT_AUTHENTICATE_USER = "900";
}
