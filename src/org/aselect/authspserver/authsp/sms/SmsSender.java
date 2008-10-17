/*
 * Created on Nov 26, 2004
 */
package org.aselect.authspserver.authsp.sms;

/**
 * @author ernst-jan
 *
 */
public interface SmsSender {
   
   public int sendSms(String message, String from, String recipients) throws SmsException;

}
