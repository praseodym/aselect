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
 * $Id: Errors.java,v 1.6 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $Log: Errors.java,v $
 * Revision 1.6  2006/05/03 10:07:31  tom
 * Removed Javadoc version
 *
 * Revision 1.5  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.4  2005/03/10 07:48:20  tom
 * Added new Logger functionality
 * Added new Configuration functionality
 * Fixed small bug in Authenticator verification
 *
 * Revision 1.3  2005/03/07 15:57:40  leon
 * - New Failure Handling
 * - Extra Javadoc
 *
 * Revision 1.2  2005/02/09 09:17:04  leon
 * added License
 * code restyle
 *
 */

package org.aselect.authspserver.authsp.radius;

/**
 * Error Class for Radius AuthSP. <br>
 * <br>
 * <b>Description:</b><br>
 * Class with Error codes, which can occur in the Radius AuthSP <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss
 */
public class Errors
{
	/**
	 * Error Code for Successfull handled Request
	 */
	public final static String ERROR_RADIUS_SUCCESS = "000";

	/**
	 * Error Code for Internal Error
	 */
	public final static String ERROR_RADIUS_INTERNAL_ERROR = "100";

	/**
	 * Error Code for Invalid Request
	 */
	public final static String ERROR_RADIUS_INVALID_REQUEST = "200";

	/**
	 * Error Code for Could Not Reach Radius Server.
	 */
	public final static String ERROR_RADIUS_COULD_NOT_REACH_RADIUS_SERVER = "300";

	/**
	 * Error Code for Access Denied
	 */
	public final static String ERROR_RADIUS_ACCESS_DENIED = "800";

	/**
	 * Error Code for Could Not Authenticate User
	 */
	public final static String ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER = "900";
}
