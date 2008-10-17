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
 * $Id: AbstractAPIRequestHandler.java,v 1.4 2006/05/03 10:10:18 tom Exp $ 
 * 
 * Changelog:
 * $Log: AbstractAPIRequestHandler.java,v $
 * Revision 1.4  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2006/03/10 15:14:39  martijn
 * added support for multivalue attributes in serializeattributes()
 *
 * Revision 1.2  2006/03/09 12:32:52  jeroen
 * Adaptation to support multi-valued attributes
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.1  2006/01/13 08:40:00  martijn
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.13  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.12  2005/05/20 13:08:32  erwin
 * Fixed some minor bugs in Javadoc
 *
 * Revision 1.11  2005/05/02 14:14:51  peter
 * Fixed logging and code-style
 *
 * Revision 1.10  2005/04/27 12:58:41  erwin
 * Fixed error codes and logging.
 *
 * Revision 1.9  2005/04/26 15:13:18  erwin
 * IF -> ID in error
 *
 * Revision 1.8  2005/04/15 11:51:23  tom
 * Removed old logging statements
 *
 * Revision 1.7  2005/04/07 13:44:59  tom
 * Fixed UTF-8 encoding in serializeAttributes
 *
 * Revision 1.6  2005/04/07 09:05:17  remco
 * Attributes (keys and values) are now URL encoded
 *
 * Revision 1.5  2005/04/07 07:38:09  erwin
 * Moved serializeAttributes() to abstract class
 *
 * Revision 1.4  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.3  2005/03/16 12:52:10  tom
 * - Fixed javadoc
 *
 * Revision 1.2  2005/03/15 15:18:51  erwin
 * Moved redundant code to seperate methods and AbstractAPIRequestHandler.
 *
 * Revision 1.1  2005/03/15 10:15:29  erwin
 * Moved redundant code to seperate class (AbstractAPIRequestHandler)
 *
 */
 
package org.aselect.server.request.handler.aselect.authentication;

import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.communication.server.Communicator;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.communication.server.IMessageCreatorInterface;
import org.aselect.system.communication.server.IOutputMessage;
import org.aselect.system.communication.server.IProtocolRequest;
import org.aselect.system.communication.server.IProtocolResponse;
import org.aselect.system.communication.server.ServletRequestWrapper;
import org.aselect.system.communication.server.ServletResponseWrapper;
import org.aselect.system.communication.server.raw.RawMessageCreator;
import org.aselect.system.communication.server.soap11.SOAP11MessageCreator;
import org.aselect.system.communication.server.soap12.SOAP12MessageCreator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Encoder;

/**
 * Abstract API request handler.
 * <br><br>
 * <b>Description:</b><br>
 * This class can be used as a base class for request handlers which handle API 
 * requests. The <code>AbstractAPIRequestHandler</code> creates an appropriate 
 * message creator.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * Use one <code>AbstractAPIRequestHandler</code> implementation 
 * for a single request.
 * <br>
 * @author Alfa & Ariss
 * 
 */
public abstract class AbstractAPIRequestHandler implements IRequestHandler
{
    /** The module name. Can be overwritten in sub classes */
    protected String _sModule = "AbstractAPIRequestHandler";  
    
    /** The message creator. */
    private IMessageCreatorInterface _messageCreator = null;
    
    /** The system logger. */
    protected ASelectSystemLogger _systemLogger; 
    
    private HttpServletRequest _servletRequest;    
    private HttpServletResponse _servletResponse;
    
    /** The server ID */
    protected String _sMyServerId;
    
    /** The origanisation */
    protected String _sMyOrg;
        
    /**
     * Construct a instance.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Handles are obtained to relevant managers and determines the protocol.
     * <br>
     * @param reqParser The request parser to be used.
     * @param servletRequest The request.
     * @param servletResponse The response.
     * @param sMyServerId The A-Select Server ID.
     * @param sMyOrg The A-Select Server organisation.
     * @throws ASelectCommunicationException If communication fails.
     */
    public AbstractAPIRequestHandler (RequestParser reqParser, 
        								HttpServletRequest servletRequest, 
        								HttpServletResponse servletResponse,
        								String sMyServerId, String sMyOrg)
    throws ASelectCommunicationException
    {       
        String sMethod = "AbstractAPIRequestHandler()";
        
        _systemLogger = ASelectSystemLogger.getHandle();
		_servletRequest = servletRequest;
		_servletResponse = servletResponse;
		_sMyServerId = sMyServerId;
		_sMyOrg = sMyOrg;
		
		switch(reqParser.getRequestProtocol())
		{
		    case RequestParser.PROTOCOL_SOAP11:
		        _messageCreator = new SOAP11MessageCreator(
		            _servletRequest.getRequestURL().toString(), "ASelect",
		            _systemLogger);
		    	break;
		    case RequestParser.PROTOCOL_SOAP12:
		        _messageCreator = new SOAP12MessageCreator(
		            _servletRequest.getRequestURL().toString(), "ASelect",
		            _systemLogger);
		    	break;
		    case RequestParser.PROTOCOL_CGI:
		        _messageCreator = new RawMessageCreator(
		            _systemLogger);
		    	break;
		    default:
		        _systemLogger.log(Level.WARNING,_sModule,sMethod,
		            "Invalid request protocol received.");
		        throw new ASelectCommunicationException(
		            Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
    }
      
    /**
     * Main process function.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Creates a <code>Communicator</code> and calls  
     * {@link #processAPIRequest(IProtocolRequest, IInputMessage, IOutputMessage)}
     * @throws ASelectException if communication fails and no response 
     * is send to the client.
     */
    public void processRequest() throws ASelectException
    {
        String sMethod = "processRequest()";

        //create protocol wrappers
        IProtocolRequest protocolRequest = new ServletRequestWrapper(
            _servletRequest);
        IProtocolResponse protocolResponse = new ServletResponseWrapper(
            _servletResponse);

        //create the communicator with the messagecreator
        Communicator communicator = new Communicator(_messageCreator);
        try
        {
            if (communicator.init(protocolRequest, protocolResponse))
            {
                IInputMessage inputMessage = communicator.getInputMessage();
                IOutputMessage outputMessage = communicator
                    .getOutputMessage();
               
                try
                {
                    String sServerId = null;
                    
                    try
                    {
                        sServerId = inputMessage.getParam("a-select-server");
                    }
                    catch(ASelectException ase)
                    {
     	 			   _systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameter \"a-select-server\"");
                        throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);                
            		}
                    
            		if (!sServerId.equals(_sMyServerId))
            		{
     	  			   _systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid \"a-select-server\" parameter: " +sServerId);
            		    throw new ASelectCommunicationException(
            		        Errors.ERROR_ASELECT_SERVER_ID_MISMATCH);
            		}

    	            _systemLogger.log(Level.INFO, _sModule, sMethod, "AbstApiREQ processAPIRequest"); 
            		processAPIRequest(protocolRequest, 
                        	inputMessage, outputMessage);
            	}
	            catch (ASelectException ace)
	    	    {     
	    	        try
	    	        {
	    	            outputMessage.setParam("result_code",ace.getMessage());
	    	        }
	    	        catch(ASelectCommunicationException ace2)
	    	        {
	    	            _systemLogger.log(Level.WARNING, _sModule, sMethod, 
	    	                "Error setting 'result_code' in outputmessage", ace2);
	    	            throw ace2;	            
	    	        }                        
	    	    }  
	            finally
	            {
		            try
			        {
		                outputMessage.setParam("a-select-server", _sMyServerId);
			        }
			        catch(ASelectCommunicationException ace2)
			        {
			            _systemLogger.log(Level.WARNING, _sModule, sMethod, 
			                "Error setting 'a-select-server' in outputmessage", ace2);
			            throw ace2;
			        }
	            }
                
	            communicator.send();
            }
            else
            //could not init
            {
                _systemLogger.log(Level.WARNING, _sModule, sMethod,
                    "Can't initialize Message Creator object: "
                    + _messageCreator.getClass().getName());
                //error is sent in communicator.
            }
        }
        catch(ASelectException eAS)
        {
            _systemLogger.log(Level.WARNING, _sModule, sMethod, 
                "Error while processing API request",eAS);
            throw eAS;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, _sModule, sMethod, 
                "Internal error while processing API request", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR,e);
        }
    }
    
    /**
     * Prosesses the API request.
     * <br><br>
     * @param oProtocolRequest The request protocol properties.
     * @param oInputMessage The input message.
     * @param oOutputMessage The output message.
     * @throws ASelectException If processing fails and no response 
     * is send to the client.
     */
    abstract protected void processAPIRequest(
        IProtocolRequest oProtocolRequest, 
        IInputMessage oInputMessage, 
        IOutputMessage oOutputMessage) throws ASelectException;
    
    /**
     * Serialize attributes contained in a hashtable.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * This method serializes attributes contained in a hashtable:
     * <ul>
     * <li>They are formatted as attr1=value1&attr2=value2;...
     * <li>If a "&amp;" or a "=" appears in either the attribute name
     * or value, they are transformed to %26 or %3d respectively.
     * <li>The end result is base64 encoded.
     * </ul>
     * <br>
     * @param htAttributes Hashtable containing all attributes
     * @return Serialized representation of the attributes
     * @throws ASelectException If serialization fails.
     */
    protected String serializeAttributes(Hashtable htAttributes)
    throws ASelectException
    {
        final String sMethod = "serializeAttributes()";
        try
        {
            if (htAttributes == null || htAttributes.isEmpty())
                return null;
            StringBuffer sb = new StringBuffer();
            for (Enumeration e = htAttributes.keys();
                e.hasMoreElements(); )
            {
                String sKey = (String)e.nextElement();
                Object oValue = htAttributes.get(sKey);
                
                if (oValue instanceof Vector)
                {//it's a multivalue attribute
                    Vector vValue = (Vector)oValue;
                    
                    sKey = URLEncoder.encode(sKey + "[]", "UTF-8");
                    Enumeration eEnum = vValue.elements();
                    while (eEnum.hasMoreElements())
                    {
                        String sValue = (String)eEnum.nextElement();

                        //add: key[]=value 
                        sb.append(sKey);
                        sb.append("=");
                        sb.append(URLEncoder.encode(sValue, "UTF-8")); 
                        
                        if (eEnum.hasMoreElements())
                            sb.append("&");
                    }
                }
                else if(oValue instanceof String)
                {//it's a single value attribute
                    String sValue = (String)oValue;

                    sb.append(URLEncoder.encode(sKey, "UTF-8"));
                    sb.append("=");
                    sb.append(URLEncoder.encode(sValue, "UTF-8"));
                }
                
                if (e.hasMoreElements())
                    sb.append("&");
            }
            BASE64Encoder b64enc = new BASE64Encoder();
            return b64enc.encode(sb.toString().getBytes("UTF-8"));
        }
        catch(Exception e)
        {
            _systemLogger.log(Level.WARNING, _sModule, sMethod,
                "Could not serialize attributes", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }


	public synchronized HttpServletRequest get_servletRequest() {
		return _servletRequest;
	}


}
