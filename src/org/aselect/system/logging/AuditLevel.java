package org.aselect.system.logging;

import org.apache.log4j.Level;

public class AuditLevel extends Level {
	
	 /**
	 * 
	 */
	private static final long serialVersionUID = -3286629221695935369L;

	/** 
	  * Value of my audit level. This value is higher than 
	  * {@link org.apache.log4j.Priority#INFO_INT} 
	  * and lesser than {@link org.apache.log4j.Level#WARN_INT} 
	  */ 
	 public static final int AUDIT_INT = INFO_INT + 10; 
	 
	 /** 
	  * {@link Level} representing my log level 
	  */ 
	 public static final Level AUDIT = new AuditLevel(AUDIT_INT,"AUDIT",6);// 6 Informational: informational messages 

	     /**
	       * Constructor
	        *
	       * @param arg0
	       * @param arg1
	       * @param arg2
	        */
	     protected AuditLevel(int arg0, String arg1, int arg2) {
	         super(arg0, arg1, arg2);

	     }

	     /**
	       *
	       * @see Level#toLevel(java.lang.String)
	       * @see Level#toLevel(java.lang.String, org.apache.log4j.Level)
	       *
	       */
	     public static Level toLevel(String sArg) {
	         if (sArg != null && sArg.toUpperCase().equals("AUDIT")) {
	             return AUDIT;
	         }
	         return (Level) toLevel(sArg, Level.INFO);
	     }

	     /**
	       * @see Level#toLevel(int)
	       * @see Level#toLevel(int, org.apache.log4j.Level)
	       *
	       */
	     public static Level toLevel(int val) {
	         if (val == AUDIT_INT) {
	             return AUDIT;
	         }
	         return (Level) toLevel(val, Level.DEBUG);
	     }

	     /**
	      * @see Level#toLevel(int, org.apache.log4j.Level)
	      */
	     public static Level toLevel(int val, Level defaultLevel) {
	         if (val == AUDIT_INT) {
	             return AUDIT;
	         }
	         return Level.toLevel(val,defaultLevel);
	     }

	     /**
	  * @see Level#toLevel(java.lang.String, org.apache.log4j.Level)
	  */
	 public static Level toLevel(String sArg, Level defaultLevel) {     
	        if(sArg != null && sArg.toUpperCase().equals("AUDIT")) {
	            return AUDIT;
	        }
	        return Level.toLevel(sArg,defaultLevel);
	 }
	 
	 public static Level parse(String name)
     throws IllegalArgumentException{
		 return toLevel("AUDIT"); 
	 }
     
     
     
	}
