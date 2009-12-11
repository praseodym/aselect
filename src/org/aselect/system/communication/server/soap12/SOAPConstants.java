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
 * $Id: SOAPConstants.java,v 1.4 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: SOAPConstants.java,v $
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

/**
 * SOAP 1.2 constants. <br>
 * <br>
 * <b>Description:</b><br>
 * This class contains constants for creating SOAP messages. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class SOAPConstants
{
	/** The MIME content type for SOAP 1.2 */
	public static final String CONTENT_TYPE = "application/soap+xml; charset=utf-8";

	/** The MIME content type for SOAP 1.1 */
	public static final String CONTENT_TYPE_11 = "text/xml; charset=utf-8";

	/** The language setting */
	public static final String XML_LANG = "en-us";

	/** SOAP environment prefix. */
	public static final String NS_PREFIX_SOAP_ENV = "env";

	/** SOAP encryption prefix. */
	public static final String NS_PREFIX_SOAP_ENC = "enc";

	/** XML namespace prefix constant. */
	public static final String NS_PREFIX_XMLNS = "xmlns";

	/** XML prefix constant. */
	public static final String NS_PREFIX_XML = "xml";

	/** A-Select method prefix constant. */
	public static final String NS_PREFIX_RPC = "m";

	/** XML Schema instance prefix constant. */
	public static final String NS_PREFIX_XSI = "xsi";

	/** XML Schema prefix constant. */
	public static final String NS_PREFIX_XSD = "xsd";

	/** SOAP 1.2 URI. */
	public static final String URI_SOAP12_ENV = "http://www.w3.org/2003/05/soap-envelope";

	/** SOAP 1.1 URI. */
	public static final String URI_SOAP11_ENV = "http://www.w3.org/2001/12/soap-envelope";

	/** SOAP 1.2 Encoding URI. */
	public static final String URI_SOAP12_ENC = "http://www.w3.org/2003/05/soap-encoding";

	/** SOAP 1.2 RPC URI. */
	public static final String URI_SOAP12_RPC = "http://www.w3.org/2003/05/soap-rpc";

	/** XML Schema instance URI. */
	public static final String URI_XML_XSI = "http://www.w3.org/2001/XMLSchema-instance";

	/** XML Schema URI. */
	public static final String URI_XML_XSD = "http://www.w3.org/2001/XMLSchema";

	/** SOAP envelope. */
	public static final String ELEM_ENVELOPE = "Envelope";

	/** SOAP header. */
	public static final String ELEM_HEADER = "Header";

	/** SOAP body. */
	public static final String ELEM_BODY = "Body";

	/** SOAP Fault. */
	public static final String ELEM_FAULT = "Fault";

	/** Not understood fault. */
	public static final String ELEM_NOTUNDERSTOOD = "NotUnderstood";

	/** Upgrade fault. */
	public static final String ELEM_UPGRADE = "Upgrade";

	/** Supported envelope for upgrade Fault. */
	public static final String ELEM_SUPPORTEDENVELOPE = "SupportedEnvelope";

	/** version mismatch error */
	public static final String ERR_VERSION_MISMATCH = "VersionMismatch";

	/** Must understand error */
	public static final String ERR_MUST_UNDERSTAND = "MustUnderstand";

	/** Data encoding unkonown */
	public static final String ERR_DATA_ENCODING_UNKNOWN = "DataEncodingUnknown";

	/** Client error */
	public static final String ERR_CLIENT = "Sender";

	/** Server error */
	public static final String ERR_SERVER = "Receiver";

	/** HTTP status code version mismatch */
	public static final int STATUS_VERSION_MISMATCH = 500;

	/** HTTP status code must understand */
	public static final int STATUS_MUST_UNDERSTAND = 500;

	/** HTTP status code client/sender */
	public static final int STATUS_CLIENT = 400;

	/** HTTP status code server/receiver */
	public static final int STATUS_SERVER = 500;

	/** HTTP status code DataEncodingUnknown */
	public static final int STATUS_DATA_ENCODING_UNKNOWN = 500;

	/** SOAP Fault code. */
	public static final String ELEM_FAULT_CODE = "Code";

	/** SOAP Fault code value. */
	public static final String ELEM_FAULT_CODE_VALUE = "Value";

	/** SOAP Fault reason. */
	public static final String ELEM_FAULT_REASON = "Reason";

	/** Fault String. */
	public static final String ELEM_FAULT_STRING = "faultstring";

	/** Fault detail. */
	public static final String ELEM_FAULT_DETAIL = "Detail";

	/** Encoding style attribute. */
	public static final String ATTR_ENCODING_STYLE = "encodingStyle";

}