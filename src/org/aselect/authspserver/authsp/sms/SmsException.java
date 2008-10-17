/*
 * Created on Nov 26, 2004
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package org.aselect.authspserver.authsp.sms;

/**
 * @author ernst-jan
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class SmsException extends Exception {

   /**
    * Comment for <code>serialVersionUID</code>
    */
   private static final long serialVersionUID = 8682017536264393258L;

   /**
    * 
    */
   public SmsException() {
      super();
   }

   /**
    * @param message
    */
   public SmsException(String message) {
      super(message);
   }

   /**
    * @param message
    * @param cause
    */
   public SmsException(String message, Throwable cause) {
      super(message, cause);
   }

   /**
    * @param cause
    */
   public SmsException(Throwable cause) {
      super(cause);
   }

}
