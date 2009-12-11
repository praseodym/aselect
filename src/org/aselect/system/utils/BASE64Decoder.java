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
 * $Id: BASE64Decoder.java,v 1.4 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: BASE64Decoder.java,v $
 * Revision 1.4  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.1  2005/02/22 12:03:29  martijn
 * moved org.aselect.utils to org.aselect.system.utils
 *
 * Revision 1.2  2005/01/28 10:09:44  ali
 * Javadoc toegevoegd en kleine code cleanup acties.
 *
 */
package org.aselect.system.utils;

// TODO: Consider using: import org.apache.commons.codec.binary.Base64;

/**
 * RFC 2045 compliant Base64 decoder. <br>
 * <br>
 * <b>Description:</b><br>
 * Decodes a Base64 String. Callers should instantiate this class to decode a Base64 encoded String. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None. <br>
 * 
 * @author Alfa & Ariss
 */
public class BASE64Decoder
{
	
	/**
	 * Decodes a Base64 input String. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method uses the Base64 Codec to decode the input String. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None. <br>
	 * 
	 * @param xEncodedString
	 *            Base64 encoded String.
	 * @return byte array containing the decoded input string.
	 */
	public byte[] decodeBuffer(String xEncodedString)
	{
		return Base64.decode(xEncodedString);
	}
}
