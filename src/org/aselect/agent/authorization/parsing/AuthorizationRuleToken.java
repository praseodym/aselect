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
 * $Id: AuthorizationRuleToken.java,v 1.7 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthorizationRuleToken.java,v $
 * Revision 1.7  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.6  2005/08/25 15:22:40  erwin
 * Added support for multiple time and dat formats
 *
 * Revision 1.5  2005/08/24 14:27:13  erwin
 * Implemented evaluator
 *
 * Revision 1.4  2005/08/24 08:55:48  erwin
 * Improved error handling and Javadoc.
 *
 * Revision 1.3  2005/08/23 15:31:19  erwin
 * Implemented the parser
 *
 * Revision 1.2  2005/08/19 12:57:09  erwin
 * added SINGLE_QUOTED_STRING
 *
 * Revision 1.1  2005/08/19 08:34:57  erwin
 * Initial version
 *
 * 
 */
package org.aselect.agent.authorization.parsing;

import java.text.DateFormat;
import java.text.ParseException;
import java.util.Locale;

import org.aselect.agent.authorization.parsing.types.IPv4Address;
import org.aselect.agent.authorization.parsing.types.IPv6Address;

/**
 * A token that is used when scanning, parsing and evaluating authorization rules.
 * <br><br>
 * <b>Description:</b><br>
 * This token can represent different types of tokens from an authorization rule.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class AuthorizationRuleToken
{   
    //The groups.
    /** Value or key group. */
    public static final int DATA_GROUP = 0;
    /** Operator group. */
    public static final int OPERATOR_GROUP = 1;
    /** Logic operator group. */
    public static final int LOGIC_OPERATOR_GROUP = 2;
    
    //The types.
    /** String type. */
    public static final int STRING = 0;
    /** Quoted string type.*/
    public static final int QUOTED_STRING = 1;
    /** Single quoted string type.*/
    public static final int SINGLE_QUOTED_STRING = 2;
    /** Unquoted string type.*/
    public static final int UNQUOTED_STRING = 3;
    /** List type.*/
    public static final int LIST = 4;
    /** Greater then operator. */
    public static final int GREATER_THEN = 5;
    /** Less then operator. */
    public static final int LESS_THEN = 6;
    /** Greater then or equal to operator. */
    public static final int GREATER_THEN_OR_EQUAL_TO = 7;
    /** less then or equal to operator. */
    public static final int LESS_THEN_OR_EQUAL_TO = 8;
    /** Equal to operator. */
    public static final int EQUAL_TO = 9;
    /** Not equal to operator. */
    public static final int NOT_EQUAL_TO = 10;
    /** &quot;in&quot; operator. */
    public static final int IN = 11;
    /** Regular expression operator. */
    public static final int MATCH_REGULAR_EXPRESSION = 12;
    /** Wildcar expression operator. */
    public static final int MATCH_WILDCARD_EXPRESSION = 13;
    /** Logic and operator. */
    public static final int AND = 14;
    /** Logic or operator. */
    public static final int OR = 15;
    /** Logic not operator. */
    public static final int NOT = 16;
    /** Logic group operator start. */
    public static final int GROUP_START = 17;
    /** Logic group operator end. */
    public static final int GROUP_END = 18;
    
    /** The token group */
    public int _iGroup;
    /** The kind of token. */
    public int _iKind;
    /** The actual data of the token */
    private Object _oValue;
    
    /**
     * Create a new <code>AuthorizationRuleToken</code>.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Create a new <code>AuthorizationRuleToken</code> with the given properties.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param iGroup The token group.
     * @param iKind The token kind.
     * @param oValue The value of the token.
     */
    public AuthorizationRuleToken(int iGroup, int iKind, Object oValue)
    {
        _iGroup = iGroup;
        _iKind =  iKind;
        _oValue = oValue;
        
    }
    
    /**
     * Retrieve the token group.
     * @return The token group.
     */
    public int getGroup()
    {
        return _iGroup;
    }

    /**
     * retrieve the token kind.
     * @return The kind of token.
     */
    public int getKind()
    {
        return _iKind;
    }

    /**
     * Set a new value.
     * @param value The value to be set.
     */
    public void setValue(Object value)
    {
        _oValue = value;
    }

    /**
     * Retrieve the token value.
     * @return The value of the token.
     */
    public Object getValue()
    {
        return _oValue;
    }

    /**
     * Returns the kind of token.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
       return _iKind;
    }

    /**
     * Returns true if the given <code>Object</code> is equal to this token.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object o)
    {
        if(o instanceof AuthorizationRuleToken)
        {
            AuthorizationRuleToken t = (AuthorizationRuleToken)o;
            return t._iKind == this._iKind && t._iGroup == this._iGroup;
        }
        return false;
    }   

    /**
     * Retrieve a <code>String</code> representation of this token.
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sb = new StringBuffer("{token(");
        sb.append(_iGroup).append(", ");
        sb.append(_iKind).append(") '");
        sb.append(_oValue).append("'}");
        return sb.toString();
    }
    
    /**
	 * Convert a <code>String</code> to known Java types.
	 * <br>
	 * Tries to create the following objects if <code>oIn</code> is a 
	 * <code>String</code>:
	 * <ul>
	 * 	<li>{@link IPv4Address}</code></li>
	 * 	<li>{@link IPv6Address}</code></li>
	 * 	<li>{@link java.util.Date}</li>
	 * 	<li>{@link java.lang.Integer}</li>
	 * </ul>
	 * If no other object can be created <code>oIn</code> is returned.
	 * <br>
	 * <b>Preconditions:</b>
	 * <br>
	 * <code>oIn != null</code>
	 * <br>
	 * <b>Postconditions:</b>
	 * <br>
	 * -
	 * <br><br>
	 * @param oIn the <code>Object</code> to be converted.
	 * @return The converted object.
	 */
	public static Object convertToKnownType(Object oIn)
	{
	    Object oRet = oIn;
	    if(oIn instanceof String) //Object is String 
	    {
	        //try object parsing
	        String sIn = (String)oIn;

	        
	        //IP v4 address
	        if(sIn.matches(IPv4Address.IPV4_REGEX))
	        {
		        try 
		        {
		                    
		            return new IPv4Address(sIn);
		        }
		        catch(Exception e)
		        {
		            //Not a valid Inet4Address adress
		        }
	        }
	        
	        //IP v6 address
	        if( sIn.matches(IPv6Address.IPV6_REGEX))
	        {
		        try 
		        {
		            return new IPv6Address(sIn);
		        }
		        catch(Exception e)
		        {
		            //Not a valid Inet6Address adress
		        }
	        }
	        
	        //	      DateTime	
	        Locale[] lc = DateFormat.getAvailableLocales();     
	        for(int i = 0;i<lc.length;i++)
	        {
	          DateFormat oDateTimeFormat = DateFormat.getDateTimeInstance(
	              DateFormat.SHORT,DateFormat.SHORT,lc[i]); 	          
	          try
		      {
	              return oDateTimeFormat.parse(sIn);
		      }
		      catch (ParseException e)
		      {
		          //try next format
		      }
	        }
	        
	        //Date
	        for(int i = 0;i<lc.length;i++)
	        {
	          DateFormat oDateFormat = DateFormat.getDateInstance(
	              DateFormat.SHORT,lc[i]); 	          
	          try
		      {
	              return oDateFormat.parse(sIn);
		      }
		      catch (ParseException e)
		      {
		          //try next format
		      }
	        }
	        
	        //Time	
	        for(int i = 0;i<lc.length;i++)
	        {
	          DateFormat oTimeFormat = DateFormat.getTimeInstance(
	              DateFormat.SHORT,lc[i]); 	          
	          try
		      {
	              return oTimeFormat.parse(sIn);
		      }
		      catch (ParseException e)
		      {
		          //try next format
		      }
	        }        
	                	        
	        //Number
	        if(sIn.matches("[0-9]+"))
	        {
		        try 
		        {
		            return new Integer(sIn);
		        }
		        catch(NumberFormatException e)
		        {
		            //Not a valid Integer adress
		        }	
	        }
	    }	    
	    return oRet;	        
	}
}
