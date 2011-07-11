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
 * $Id: ServletRequestWrapper.java,v 1.4 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: ServletRequestWrapper.java,v $
 * Revision 1.4  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/02/10 16:09:39  erwin
 * Applied code style and Javadoc comment.
 *
 *
 */
package org.aselect.system.communication.server;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import javax.servlet.http.HttpServletRequest;

/**
 * Wrapper to communicate in a transparant manner to a <CODE>HttpServletRequest</CODE>. <br>
 * <br>
 * <b>Description:</b><br>
 * This class is a Wrapper for the <code>HttpServletRequest</code> which implements <code>IProtocolRequest</code>. <br>
 * <br>
 * <i>Note: Wrapper is commonly used Design pattern also known as adapter.</i> <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class ServletRequestWrapper implements IProtocolRequest
{
	/** The actual request. */
	private HttpServletRequest _oRequest;

	/** The request data */
	private String _sMessage;

	/**
	 * Create a new instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new instance wrapping <code>oRequest</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>oRequest</code> should be created by a servlet container. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * This instance wraps <code>oRequest</code>. <br>
	 * 
	 * @param oRequest
	 *            The <CODE>HttpServletRequest</CODE> that this wrapper wraps.
	 */
	public ServletRequestWrapper(HttpServletRequest oRequest) {
		_oRequest = oRequest;
	}

	/**
	 * Get the input stream of the request protocol. The input stream is buffered in a <code>String</code>. <br>
	 * <br>
	 * 
	 * @return the input stream
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see org.aselect.system.communication.server.IProtocolRequest#getInputStream()
	 */
	public InputStream getInputStream()
		throws IOException
	{
		// read the original data and put it in a buffer (String)
		BufferedReader br = new BufferedReader(new InputStreamReader(_oRequest.getInputStream()));
		StringBuffer sb = new StringBuffer();
		String s;

		while ((s = br.readLine()) != null) {
			sb.append(s);
			sb.append("\r\n");
		}
		_sMessage = sb.toString();

		// return a new InputSTream which reads from the buffer
		return new ByteArrayInputStream(sb.toString().getBytes());
	}

	/**
	 * Retrieve a property of the request protocol.
	 * 
	 * @param name
	 *            the name
	 * @return the property
	 * @see org.aselect.system.communication.server.IProtocolRequest#getProperty(java.lang.String)
	 */
	public String getProperty(String name)
	{
		String xRetVal = null;
		if (name.equalsIgnoreCase("QueryString")) {
			xRetVal = _oRequest.getQueryString();
		}
		else {
			xRetVal = _oRequest.getHeader(name);
		}
		return xRetVal;
	}

	/**
	 * Retrieve the name of the protocol that is wrapped by this wrapper.
	 * 
	 * @return the protocol name
	 * @see org.aselect.system.communication.server.IProtocolRequest#getProtocolName()
	 */
	public String getProtocolName()
	{
		return _oRequest.getProtocol();
	}

	/**
	 * Retrieve the full servlet address.
	 * 
	 * @return the target
	 * @see org.aselect.system.communication.server.IProtocolRequest#getTarget()
	 */
	public String getTarget()
	{
		return _oRequest.getRequestURL().toString();
	}

	/**
	 * Gets the message.
	 * 
	 * @return the message
	 * @see org.aselect.system.communication.server.IProtocolRequest#getMessage()
	 */
	public String getMessage()
	{
		return _sMessage;
	}
}