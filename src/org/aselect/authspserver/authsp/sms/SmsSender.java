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
	 *            the from
	 * @param recipients
	 *            the recipients
	 * @return the int
	 * @throws SmsException
	 *             the sms exception
	 */
	public int sendSms(String message, String from, String recipients)
		throws SmsException;

}
