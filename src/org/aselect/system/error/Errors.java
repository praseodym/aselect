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
 * $Id: Errors.java,v 1.24 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: Errors.java,v $
 * Revision 1.24  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.23  2006/04/12 13:20:41  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.22.4.1  2006/03/16 08:41:05  leon
 * Error added
 *
 * Revision 1.22  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.21  2005/08/30 08:01:08  erwin
 * Added an Authorization error
 *
 * Revision 1.20  2005/08/23 13:37:57  erwin
 * Added error code and exception for authorization.
 *
 * Revision 1.19  2005/05/11 07:46:19  erwin
 * removed double error codes (4008 & 4009)
 *
 * Revision 1.18  2005/04/26 15:13:43  erwin
 * IF -> ID in error
 *
 * Revision 1.17  2005/04/07 08:17:04  remco
 * Added CORRUPT_ATTRIBUTES error
 *
 * Revision 1.16  2005/03/17 12:47:54  martijn
 * added ERROR_ASELECT_UNKNOWN_USER
 *
 * Revision 1.15  2005/03/16 13:48:35  tom
 * Added todo
 *
 * Revision 1.14  2005/03/16 13:11:27  martijn
 * changed todo
 *
 * Revision 1.13  2005/03/14 14:03:10  martijn
 * added ERROR_ASELECT_CONFIG_ERROR
 *
 * Revision 1.12  2005/03/11 16:49:35  martijn
 * moved verifying if max sessions and tickets are reached to the storagemanager
 *
 * Revision 1.11  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.10  2005/03/08 12:56:45  erwin
 * Added cancel.
 *
 * Revision 1.9  2005/03/04 08:19:47  martijn
 * added AUTHSP Handler errors
 *
 * Revision 1.8  2005/02/25 10:34:07  martijn
 * added/changed UDB error codes
 *
 * Revision 1.7  2005/02/23 09:53:53  erwin
 * Applied code style and improved JavaDoc.
 *
 * Revision 1.6  2005/02/23 09:48:00  erwin
 * Added additional errors.
 *
 * Revision 1.5  2005/02/23 08:41:31  erwin
 * Added additional errors.
 *
 * Revision 1.4  2005/02/22 16:20:17  erwin
 * Added additional errors.
 *
 * Revision 1.3  2005/02/22 13:05:46  erwin
 * Added additional errors.
 *
 * Revision 1.2  2005/02/21 12:59:46  erwin
 * Added A-Select errors
 *
 * Revision 1.1  2005/02/07 15:14:15  martijn
 * changed all variable names to naming convention
 *
 */

package org.aselect.system.error;

/**
 * A-Select error codes. <br>
 * <br>
 * <b>Description: </b> <br>
 * Error codes that are used within A-Select.
 * 
 * @author Alfa & Ariss Note: Some fault codes are used more than once, this should be checked (Erwin)
 */
public class Errors
{
	/**
	 * Success.
	 */
	public static final String ERROR_ASELECT_SUCCESS = "0000";

	/**
	 * A-Select error: The A-Select Server could not handle the request due to an internal error.
	 */
	public final static String ERROR_ASELECT_INTERNAL_ERROR = "0001";

	/**
	 * A-Select error: the user does not exist in the udb
	 */
	public final static String ERROR_ASELECT_UDB_UNKNOWN_USER = "0002";

	/**
	 * A-Select error: The A-Select Server could not authenticate the user.
	 */
	public final static String ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER = "0003";
	public final static String ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER = "0003";

	/**
	 * A-Select error: The TGT of the user was invalid.
	 */
	public final static String ERROR_ASELECT_SERVER_TGT_NOT_VALID = "0004";

	/**
	 * A-Select error: The TGT of the user has expired.
	 */
	public final static String ERROR_ASELECT_SERVER_TGT_EXPIRED = "0005";

	/**
	 * A-Select error: TGT credentials are too low.
	 */
	// public final static String ERROR_ASELECT_SERVER_TGT_TOO_LOW = "0006";

	/**
	 * A-Select error: Unknown TGT.
	 */
	public final static String ERROR_ASELECT_SERVER_UNKNOWN_TGT = "0007";

	/**
	 * A-Select error: User account is disabled with the A-Select Server.
	 */
	public final static String ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED = "0008";

	/**
	 * A-Select error: User is not allowed to get A-Select credentials due to restrictions on his/her account.
	 */
	public final static String ERROR_ASELECT_SERVER_USER_NOT_ALLOWED = "0009";

	/**
	 * A-Select error: Invalid response from an AuthSP is received.
	 */
	public final static String ERROR_ASELECT_AUTHSP_INVALID_RESPONSE = "000a";

	/**
	 * A-Select error: Access denied.
	 */
	public final static String ERROR_ASELECT_AUTHSP_ACCESS_DENIED = "000b";

	/**
	 * A-Select error: The A-Select Server received an invalid request from the A-Select Agent.
	 */
	public final static String ERROR_ASELECT_SERVER_INVALID_REQUEST = "0030";

	/**
	 * A-Select error: Unknown application id was provided.
	 */
	public final static String ERROR_ASELECT_SERVER_UNKNOWN_APP = "0031";

	/**
	 * A-Select error: Invalid application URL was sent to the A-Select Server.
	 */
	// public final static String ERROR_ASELECT_SERVER_INVALID_APP_URL = "0032";

	/**
	 * A-Select error: A-Select Server id mismatch.
	 */
	public final static String ERROR_ASELECT_SERVER_ID_MISMATCH = "0033";

	/**
	 * A-Select error: Unknown <code>remote_organization</code>.
	 */
	public final static String ERROR_ASELECT_SERVER_UNKNOWN_ORG = "0034";

	/**
	 * A-Select error: Invalid <code>app level</code>.
	 */
	public static final String ERROR_ASELECT_SERVER_INVALID_APP_LEVEL = "0035";

	/**
	 * A-Select error: The user has canceled authentication.
	 */
	public final static String ERROR_ASELECT_SERVER_CANCEL = "0040";

	/**
	 * A-Select error: The A-Select Server is busy and cannot handle the request.
	 */
	public final static String ERROR_ASELECT_SERVER_BUSY = "0050";

	/**
	 * A-Select error: Internal error for UDB connectors
	 */
	public final static String ERROR_ASELECT_UDB_INTERNAL = "0060";

	/**
	 * A-Select error: Session invalid.
	 */
	public final static String ERROR_ASELECT_SERVER_INVALID_SESSION = "0070";

	/**
	 * A-Select error: Session expired.
	 */
	public final static String ERROR_ASELECT_SERVER_SESSION_EXPIRED = "0102";

	// User already logged in (second browser instance)
	public final static String ERROR_ASELECT_SERVER_USER_ALREADY_LOGGED_IN = "0104";

	/**
	 * Agent internal error.
	 */
	public final static String ERROR_ASELECT_AGENT_INTERNAL_ERROR = "0101";

	/**
	 * Agent error: Session expired.
	 */
	public final static String ERROR_ASELECT_AGENT_SESSION_EXPIRED = "0102";

	/**
	 * Agent error: Could not authenticate user.
	 */
	// public final static String ERROR_ASELECT_AGENT_COULD_NOT_AUTHENTICATE_USER = "0103";

	/**
	 * Agent error: User's TGT is not valid.
	 */
	// public final static String ERROR_ASELECT_AGENT_TGT_NOT_VALID = "0105";

	/**
	 * Agent error: User's TGT has expired.
	 */
	// public final static String ERROR_ASELECT_AGENT_TGT_EXPIRED = "0106";

	/**
	 * Agent error: User's TGT does not meet the level of required authentication.
	 */
	// public final static String ERROR_ASELECT_AGENT_TGT_TOO_LOW = "0107";

	/**
	 * Agent error: Unknown TGT.
	 */
	// public final static String ERROR_ASELECT_AGENT_UNKNOWN_TGT = "0108";

	/**
	 * Agent error: User's ticket is not valid.
	 */
	public final static String ERROR_ASELECT_AGENT_TICKET_NOT_VALID = "0109";

	/**
	 * Agent error: User's ticket has expired.
	 */
	// public final static String ERROR_ASELECT_AGENT_TICKET_EXPIRED = "010a";

	/**
	 * Agent error: Unknown ticket.
	 */
	public final static String ERROR_ASELECT_AGENT_UNKNOWN_TICKET = "010b";

	/**
	 * Agent error: A-Select Agent could not reach A-Select Server.
	 */
	public final static String ERROR_ASELECT_AGENT_COULD_NOT_REACH_ASELECT_SERVER = "010c";

	/**
	 * Agent error: Maximum number of issued tickets has been reached.
	 */
	public final static String ERROR_ASELECT_AGENT_TOO_MUCH_USERS = "010d";

	/**
	 * Agent error: Attributes mismatch (during verify_ticket)
	 */
	public final static String ERROR_ASELECT_AGENT_CORRUPT_ATTRIBUTES = "010e";

	/**
	 * Agent error: Invalid API request.
	 */
	public final static String ERROR_ASELECT_AGENT_INVALID_REQUEST = "0130";

	/**
	 * Agent error: Authorization failed.
	 */
	public final static String ERROR_ASELECT_AGENT_AUTHORIZATION_FAILED = "0140";

	/**
	 * Agent error: Authorization not enabled.
	 */
	public final static String ERROR_ASELECT_AGENT_AUTHORIZATION_NOT_ENABLED = "0141";

	/**
	 * Error: Can't open datasource
	 */
	public static final String ERROR_ASELECT_CANT_OPEN = "4002";
	/**
	 * Error: Can't close datasource
	 */
	public static final String ERROR_ASELECT_CANT_CLOSE = "4003";
	/**
	 * Error: Can't read from datasource
	 */
	public static final String ERROR_ASELECT_READ = "4004";
	/**
	 * Error: Does not exist
	 */
	public static final String ERROR_ASELECT_NOT_FOUND = "4005";
	/**
	 * Error: IO
	 */
	public static final String ERROR_ASELECT_IO = "4006";

	/**
	 * Usage error.
	 */
	public static final String ERROR_ASELECT_USE_ERROR = "4007";

	/**
	 * Parsing failed.
	 */
	public static final String ERROR_ASELECT_PARSE_ERROR = "4008";

	/**
	 * Initialisation failed.
	 */
	public static final String ERROR_ASELECT_INIT_ERROR = "4009";

	/**
	 * Username unknown.
	 */
	public static final String ERROR_ASELECT_UNKNOWN_USER = "4010";

	/**
	 * Could not find the right config item failed.
	 */
	public static final String ERROR_ASELECT_CONFIG_ERROR = "4011";

	/**
	 * Database initialisation failed
	 */
	public static final String ERROR_ASELECT_DATABASE_INIT = "5001";

	/**
	 * Database connection failed
	 */
	public static final String ERROR_ASELECT_DATABASE_CONNECT = "5002";

	/**
	 * Database query failed
	 */
	public static final String ERROR_ASELECT_DATABASE_QUERY_FAILED = "5003";

	/**
	 * Database update query failed
	 */
	public static final String ERROR_ASELECT_DATABASE_UPDATE_FAILED = "5004";

	/**
	 * Storage initialisation failed
	 */
	public final static String ERROR_ASELECT_STORAGE_INIT = "6001";

	/**
	 * Storage retrieval failed
	 */
	public final static String ERROR_ASELECT_STORAGE_RETRIEVE = "6002";

	/**
	 * Storage key not found
	 */
	public final static String ERROR_ASELECT_STORAGE_NO_SUCH_KEY = "6003";

	/**
	 * Storage insertion failed
	 */
	public final static String ERROR_ASELECT_STORAGE_INSERT = "6004";

	/**
	 * Storage removal failed
	 */
	public final static String ERROR_ASELECT_STORAGE_REMOVE = "6005";

	/**
	 * Storage cleanup failed
	 */
	public final static String ERROR_ASELECT_STORAGE_CLEAN_UP = "6006";

	/**
	 * Storage encoding failed
	 */
	// public final static String ERROR_ASELECT_STORAGE_ENCODING_FAILURE = "6007";

	/**
	 * Storage decoding failed
	 */
	// public final static String ERROR_ASELECT_STORAGE_DECODING_FAILURE = "6008";

	/**
	 * Storage connection failed
	 */
	public final static String ERROR_ASELECT_STORAGE_CONNECTION_FAILURE = "6009";

	/**
	 * Maximum storage items reached
	 */
	public final static String ERROR_ASELECT_STORAGE_MAXIMUM_REACHED = "6010";

	/**
	 * SAM recourse not available.
	 */
	public final static String ERROR_ASELECT_SAM_UNAVALABLE = "7001";

	/**
	 * No active SAM resource.
	 */
	public final static String ERROR_ASELECT_SAM_NO_RESOURCE_ACTIVE = "7002";

}