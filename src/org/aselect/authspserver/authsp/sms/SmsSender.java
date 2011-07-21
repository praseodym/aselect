/*
 * Created on Nov 26, 2004
 */
package org.aselect.authspserver.authsp.sms;

/**
 * @author ernst-jan
 */
public interface SmsSender
{
	/**
	 * Send sms.
	 * 
	 * @param message
	 *            the message
	 * @param from
	 *            the message sender id
	 * @param recipients
	 *            the recipients (phone numbers)
	 * @return the result, 0 = OK, 1 = bad phonenumber
	 * 
	 * @throws SmsException
	 *             other error conditions
	 */
	public int sendSms(String message, String from, String recipients)
	throws SmsException;
}
