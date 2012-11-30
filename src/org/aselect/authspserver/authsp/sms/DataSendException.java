/*
 * Copyright (c) Anoigo. All rights reserved.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl)
 *
 * Author: Bauke Hiemstra
 */
package org.aselect.authspserver.authsp.sms;

/**
 * The Class DataSendException.
 * 
 *	Simple communication exception utility
 */
public class DataSendException extends Exception
{
	private static final long serialVersionUID = 1L;
	
	/**
	 * Instantiates a new data send exception.
	 */
	public DataSendException() {
      super();
   }
   
   /**
	 * Instantiates a new data send exception.
	 * 
	 * @param message
	 *            the message
	 */
   public DataSendException(String message) {
      super(message);
   }
   
   /**
	 * Instantiates a new data send exception.
	 * 
	 * @param message
	 *            the message
	 * @param cause
	 *            the cause
	 */
   public DataSendException(String message, Throwable cause) {
      super(message, cause);
   }
   
   /**
	 * Instantiates a new data send exception.
	 * 
	 * @param cause
	 *            the cause
	 */
   public DataSendException(Throwable cause) {
      super(cause);
   }
}