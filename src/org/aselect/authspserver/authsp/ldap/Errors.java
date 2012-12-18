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
 * $Id: Errors.java,v 1.5 2006/05/03 10:06:47 tom Exp $ 
 *
 * Changelog:
 * $Log: Errors.java,v $
 * Revision 1.5  2006/05/03 10:06:47  tom
 * Removed Javadoc version
 *
 * Revision 1.4  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/03/23 09:48:38  erwin
 * - Applied code style
 * - Added javadoc
 * - Improved error handling
 *
 * Revision 1.2  2005/02/04 10:12:40  leon
 * code restyle and license added
 */

package org.aselect.authspserver.authsp.ldap;

/**
 * Contains specific LDAP AuthSP errors. <br>
 * <br>
 * <b>Description:</b><br>
 * The LDAP result codes. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class Errors
{

	/** Success. */
	public final static String ERROR_LDAP_SUCCESS = "000";

	/** Internal error. */
	public final static String ERROR_LDAP_INTERNAL_ERROR = "100";

	/** Invalid request. */
	public final static String ERROR_LDAP_INVALID_REQUEST = "200";

	/** LDAP server unreachable. */
	public final static String ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER = "300";

	/** Invalid password. */
	public final static String ERROR_LDAP_INVALID_PASSWORD = "400";

	/** Access denied. */
	public final static String ERROR_LDAP_ACCESS_DENIED = "800";

	/** Could not authneticate user. */
	public final static String ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER = "900";
}
