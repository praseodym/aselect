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
 * $Id: RequestState.java,v 1.3 2006/04/26 12:18:08 tom Exp $ 
 */

package org.aselect.server.request;

/**
 * RequestHandler state object. <br>
 * <br>
 * <b>Description:</b><br>
 * Contains the next request handler, used by request handler chaining <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class RequestState
{
	private String _sNextHandler;

	/**
	 * The constructor used for creating an object of this class. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates the RequestState object with the supplied id of the next handler <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sNextHandler
	 *            ID of the next requesthandler in the chaining process
	 */
	public RequestState(String sNextHandler) {
		_sNextHandler = sNextHandler;
	}

	/**
	 * Returns TRUE if a next handler is available. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return FALSE if a next handler is not available
	 */
	public boolean hasNextHandler()
	{
		return _sNextHandler != null;
	}

	/**
	 * Returns the ID of the next handler for chaining. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The ID of the next handler were the request must be processed <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return String containing the ID of the next handler
	 */
	public String getNextHandler()
	{
		return _sNextHandler;
	}
}
