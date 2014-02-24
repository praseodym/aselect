package org.aselect.authspserver.authsp.social;

/**
 * Social AuthSP error codes. <br>
 */
public class Errors
{
	/**
	 * No error
	 */
	public final static String ERROR_SOCIAL_SUCCESS = "000";

	/** Internal error. */
	public final static String ERROR_SOCIAL_INTERNAL_ERROR = "100";

	/**
	 * An invalid request has been sent
	 */
	public final static String ERROR_SOCIAL_INVALID_REQUEST = "200";

	/**
	 * Access is denied
	 */
	public final static String ERROR_SOCIAL_ACCESS_DENIED = "800";

	/**
	 * User could not be authenticated
	 */
	public final static String ERROR_SOCIAL_COULD_NOT_AUTHENTICATE_USER = "900";
}
