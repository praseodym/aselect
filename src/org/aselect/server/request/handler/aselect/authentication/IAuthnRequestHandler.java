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
 * $Id: IAuthnRequestHandler.java,v 1.2 2006/05/03 10:10:18 tom Exp $ 
 * 
 * Changelog:
 * $Log: IAuthnRequestHandler.java,v $
 * Revision 1.2  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.1  2006/01/13 08:40:26  martijn
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.5  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.4  2005/03/15 11:50:18  tom
 * Added Javadoc
 *
 * Revision 1.3  2005/03/15 09:12:27  tom
 * Changed ASelectCommunicationException to ASelectException
 *
 * Revision 1.2  2005/03/15 09:00:30  tom
 * Added ASelectCommunicationException
 *
 * Revision 1.1  2005/03/15 08:22:02  tom
 * - Redesign of request handling
 *
 */

package org.aselect.server.request.handler.aselect.authentication;

import org.aselect.system.exception.ASelectException;

/**
 * RequestHandler Interface. <br>
 * <br>
 * <b>Description:</b><br>
 * This Class is implemented by the AbstractAPIRequestHandler and AbstractBrowserRequestHandler. <br>
 * 
 * @author Alfa & Ariss
 */
// 20090606, Bauke changed name from IRequestHandler to avoid confusion
public interface IAuthnRequestHandler
{
	
	/**
	 * Main processRequest function called when a handler is to process a request. <br>
	 * <br>
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	public void processRequest()
	throws ASelectException;
}
