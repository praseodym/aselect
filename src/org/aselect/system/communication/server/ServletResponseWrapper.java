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
 * $Id: ServletResponseWrapper.java,v 1.4 2006/05/03 09:29:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: ServletResponseWrapper.java,v $
 * Revision 1.4  2006/05/03 09:29:48  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/02/10 16:09:47  erwin
 * Applied code style and Javadoc comment.
 *
 *
 */
package org.aselect.system.communication.server;

import java.io.IOException;
import java.io.OutputStream;

import javax.servlet.http.HttpServletResponse;

/**
 * Wrapper to communicate in a transparant manner to a <CODE>HttpServletResponse</CODE>. <br>
 * <br>
 * <b>Description:</b><br>
 * This class is a Wrapper for the <code>HttpServletResponse</code> which implements <code>IProtocolResponse</code>. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class ServletResponseWrapper implements IProtocolResponse
{

	/** The actual response. */
	private HttpServletResponse _oResponse;

	/**
	 * Create a new instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new instance wrapping <code>oResponse</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>oResponse</code> should be created by a servlet container. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * This instance wraps <code>oResponse</code>. <br>
	 * 
	 * @param oResponse
	 *            The <CODE>HttpServletResponse</CODE> that this wrapper wraps.
	 */
	public ServletResponseWrapper(HttpServletResponse oResponse) {
		_oResponse = oResponse;
	}

	/**
	 * Get the ouput stream of the response message.
	 * 
	 * @return the output stream
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see org.aselect.system.communication.server.IProtocolResponse#getOutputStream()
	 */
	public OutputStream getOutputStream()
		throws IOException
	{
		return _oResponse.getOutputStream();
	}

	/**
	 * Set a property of the response protocol. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Set the HTTP status code ("Status") or a HTTP header value (e.g. "Content-Type").
	 * 
	 * @param name
	 *            the name
	 * @param value
	 *            the value
	 * @see org.aselect.system.communication.server.IProtocolResponse#setProperty(java.lang.String, java.lang.String)
	 */
	public void setProperty(String name, String value)
	{
		if (name.equalsIgnoreCase("Status"))// HTTP status code is not a mime
		// header
		{
			_oResponse.setStatus(Integer.parseInt(value));
		}
		else if (name.equalsIgnoreCase("Content-Type"))// Set contentType
		// seperately
		{
			_oResponse.setContentType(value);
		}
		else
		// it must be a mime header and it can be set
		{
			_oResponse.setHeader(name, value);
		}
	}

}