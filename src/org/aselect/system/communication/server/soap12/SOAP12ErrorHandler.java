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
 * $Id: SOAP12ErrorHandler.java,v 1.4 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: SOAP12ErrorHandler.java,v $
 * Revision 1.4  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/02/15 10:57:37  erwin
 * Applied code style and added Javadoc.
 *
 *
 */

package org.aselect.system.communication.server.soap12;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;


/**
 * SOAP 1.2 error handler. <br>
 * <br>
 * <b>Description: </b> <br>
 * An error handler that handles SOAP 1.2 parse and message validation errors. <br>
 * <br>
 * <i>Note: The current SOAP schema specification uses the statement: <br>
 * <br>
 * <code>&lt;xs:import namespace="http://www.w3.org/XML/1998/namespace"&gt;</code> <br>
 * <br>
 * rather than the form: <br>
 * <br>
 * <code>&lt;xs:import namespace="http://www.w3.org/XML/1998/namespace"
 * schemaLocation="http://www.w3.org/2001/xml.xsd"&gt;</code> <br>
 * <br>
 * This means that parsers which do not have built-in knowledge of the xml namespace schema location, like Xerces, will
 * fail to parse a SOAP 1.2 schema and errors in this schema have to be ignored. (see <a
 * href="http://www.w3.org/2000/xp/Group/xmlp-rec-issues.html" target="_blank">Feedback on SOAP 1.2 Recommendation </a>)
 * </i> <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public class SOAP12ErrorHandler implements ErrorHandler
{
	
	/**
	 * Handle a parser warning.
	 * 
	 * @param xSE
	 *            the x se
	 * @throws SAXException
	 *             the SAX exception
	 * @see org.xml.sax.ErrorHandler#warning(org.xml.sax.SAXParseException)
	 */
	public void warning(SAXParseException xSE)
	throws SAXException
	{
		throw xSE;
	}

	/**
	 * Handle a parser error.
	 * 
	 * @param xSE
	 *            the x se
	 * @throws SAXException
	 *             the SAX exception
	 * @see org.xml.sax.ErrorHandler#error(org.xml.sax.SAXParseException)
	 */
	public void error(SAXParseException xSE)
	throws SAXException
	{
		throw xSE;
	}

	/**
	 * Handle a parser fatal error.
	 * 
	 * @param xSE
	 *            the x se
	 * @throws SAXException
	 *             the SAX exception
	 * @see org.xml.sax.ErrorHandler#fatalError(org.xml.sax.SAXParseException)
	 */
	public void fatalError(SAXParseException xSE)
	throws SAXException
	{
		throw xSE;
	}

}