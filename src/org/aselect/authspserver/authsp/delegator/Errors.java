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
 * $Id: Errors.java,v 1.2 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $log$
 *
 */
package org.aselect.authspserver.authsp.delegator;

/**
 * Contains specific PKI AuthSP errors. <br>
 * <br>
 * <b>Description:</b><br>
 * The PKI result codes. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
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
	 * Error Code for: Client Certificate is not yet valid
	 */
	public static final String PKI_CLIENT_CERT_NOT_YET_VALID = "003";

	/**
	 * Error Code for: Client Certificate is expired
	 */
	public static final String PKI_CLIENT_CERT_EXPIRED = "004";

	/**
	 * Error Code for: Client Certificate is Revoked
	 */
	public static final String PKI_CLIENT_CERT_REVOKED = "005";

	/**
	 * Error Code for: No matching binary blob
	 */
	public static final String PKI_CLIENT_CERT_BLOB_NOT_VALID = "006";

	/**
	 * Error Code for: DN in certificate did not match the one in the ASelect UDB
	 */
	public static final String PKI_SUBJECT_DN_NOT_VALID = "007";

	/**
	 * Error Code for: Out of retries for 2 Factor Authentication
	 */
	public static final String PKI_2FACTOR_NO_RETRIES_LEFT = "008";

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
	/**
	 * Error Code for: No Client certificate
	 */
	public static final String PKI_NO_CLIENT_CERT = "102";
	/**
	 * Error Code for: No Common Authority found
	 */
	public static final String PKI_NO_CA_FOUND = "103";

	/**
	 * Error Code for: CRL is not signed by CA
	 */
	public static final String PKI_CRL_IS_NOT_SIGNED_BY_CA = "104";

	/**
	 * Error Code for: Invalid Request
	 */
	// public static final String PKI_INVALID_REQUEST = "105";

	/**
	 * Error Code for: Internal Error
	 */
	// public static final String PKI_INTERNAL_SERVER_ERROR = "106";

	/**
	 * Error Code for: No CRL Distribution Point(s) in CA Certificate
	 */
	public static final String PKI_NO_CRL_DISTR_POINT_IN_CA_CERT = "107";

	/**
	 * Error Code for: No CRL Found For CA
	 */
	public static final String PKI_NO_CRL_FOUND_FOR_CA = "108";

	/**
	 * Error Code for: No CA Certificate in keystore is expired
	 */
	public static final String PKI_CA_CERT_IS_EXPIRED = "109";
}
