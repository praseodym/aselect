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
 * $Id: BASE64Encoder.java,v 1.4 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: BASE64Encoder.java,v $
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

/**
 * RFC 2045 compliant Base64 encoder. <br>
 * <br>
 * <b>Description:</b><br>
 * Base64 encodes a byte array. Callers should instantiate this class to encode a byte array into Base64. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None. <br>
 * 
 * @author Alfa & Ariss
 */
public class BASE64Encoder
{
	
	/**
	 * Encodes a byte array into a Base64 String . <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method uses the Base64 Codec to encode the input bytes. <br>
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
	 * @param xData
	 *            input byte array.
	 * @return the Base64 encoded representation of <code>xData</code>.
	 */
	public String encode(byte[] xData)
	{
		return Base64.encode(xData);
	}
}
