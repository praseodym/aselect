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
 * $Id: SOAP11ErrorHandler.java,v 1.5 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: SOAP11ErrorHandler.java,v $
 * Revision 1.5  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.4  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/02/15 10:53:09  erwin
 * Applied code format.
 *
 * Revision 1.2  2005/02/14 13:54:30  erwin
 * Applied code style and added Javadoc.
 *
 */
package org.aselect.system.communication.server.soap11;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * SOAP 1.1 parse error handler.
 * <br><br>
 * <b>Description:</b><br>
 * An error handler that handles SOAP11 message parse and validation errors.
 * This implementation just throws the received warning and errors.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class SOAP11ErrorHandler implements ErrorHandler
{

    /**
     * Handle a parser warning.
     * 
     * @see org.xml.sax.ErrorHandler#warning(org.xml.sax.SAXParseException)
     */
    public void warning(SAXParseException eSP) throws SAXException
    {
        throw eSP;
    }

    /**
     * Handle a parser error.
     * 
     * @see org.xml.sax.ErrorHandler#error(org.xml.sax.SAXParseException)
     */
    public void error(SAXParseException eSP) throws SAXException
    {
        throw eSP;
    }

    /**
     * Handle a parser fatal error.
     * 
     * @see org.xml.sax.ErrorHandler#fatalError(org.xml.sax.SAXParseException)
     */
    public void fatalError(SAXParseException eSP) throws SAXException
    {
        throw eSP;
    }

}