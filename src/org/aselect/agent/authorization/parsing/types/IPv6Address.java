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
 * $Id: IPv6Address.java,v 1.4 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: IPv6Address.java,v $
 * Revision 1.4  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.3  2005/08/25 14:28:41  erwin
 * Implemented compareTo()
 *
 * Revision 1.2  2005/08/24 14:27:13  erwin
 * Implemented evaluator
 *
 * Revision 1.1  2005/08/23 15:31:19  erwin
 * Implemented the parser
 *
 */

package org.aselect.agent.authorization.parsing.types;

import java.util.StringTokenizer;


/**
 * IP Version 6 Address. <br>
 * <br>
 * <b>Description:</b><br>
 * A simple Java object to compare IPv6 adresses. <br>
 * <br>
 * Only default IPv6 adresses with subnet mask are supported: <code>x:x:x:x:x:x:x:x(/x:x:x:x:x:x:x:x or /x)</code>,
 * where the 'x's are the hexadecimal values of the eight 16-bit pieces of the address. <br>
 * <br>
 * Examples:
 * <ul>
 * <li><code>FEDC:BA98:7654:3210:FEDC:BA98:7654:3210</code></li>
 * <li><code>1080:0:0:0:8:800:200C:417A/FFFF:0:0:0:0:0:0:0</code></li>
 * <li><code>1080:0:0:0:8:800:200C:417A/32</code></li>
 * </ul>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * <br>
 * 
 * @author Alfa & Ariss
 * @see <a href="http://www.ietf.org/rfc/rfc2373.txt"> IP Version 6 Addressing Architecture </a>
 */
public class IPv6Address implements Comparable
{
	/**
	 * Regex for IP v6 address.
	 */
	public static final String IPV6_REGEX = "(([0-9a-fA-F]{1,4}\\:){7}[0-9a-fA-F]{1,4})(\\/[0-9a-fA-F]{1,4}(\\:[0-9a-fA-F]{1,4}){0,7})?";

	/**
	 * Default Subnet Mask.
	 */
	private final int[] DEFAULT_MASK = {
		0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF
	};

	/**
	 * Emty Subnet Mask.
	 */
	private final int[] EMPTY_MASK = {
		0, 0, 0, 0, 0, 0, 0, 0
	};

	/**
	 * Address
	 */
	private int[] _iaAddress;

	/**
	 * Subnet Mask.
	 */
	private int[] _iaMask;

	/**
	 * Create new <code>IPv6Address</code>.
	 * 
	 * @param s
	 *            The String respresentation of the address.
	 * @throws Exception
	 *             If parsing fails.
	 */
	public IPv6Address(String s)
	throws Exception {
		String sAdress = null;

		if (!s.matches(IPV6_REGEX)) {
			throw new Exception("Not a valid IP v6 address");
		}

		int index = s.indexOf('/');
		if (index > 0) // mask available
		{
			sAdress = s.substring(0, index);
			String sMask = s.substring(index + 1, s.length());
			_iaMask = convertAddress(sMask, true);
		}
		else {
			sAdress = s;
			_iaMask = DEFAULT_MASK;
		}
		_iaAddress = convertAddress(sAdress, false);

	}

	/**
	 * Compare two ip adresses (Only equals is supported).
	 * 
	 * @param oOther
	 *            The object to compare with.
	 * @return <code>0</code> if the ip adresses are equal with network mask taken in account, otherwise -1.
	 * @throws ClassCastException
	 *             If the provided <code>Object</code> is not an <code>IPv6Address</code>.
	 */
	public int compareTo(Object oOther)
	throws ClassCastException
	{
		int iRet = 0;
		if (oOther instanceof IPv6Address) {
			IPv6Address aOther = (IPv6Address) oOther;
			boolean bOk = true;
			for (int i = 0; i < 8 && bOk; i++) {
				bOk = (aOther._iaAddress[i] & this._iaMask[i]) == this._iaAddress[i];
			}

			if (bOk)
				iRet = 0;
			else {
				iRet = -1;
			}
		}
		else {
			throw new ClassCastException("IPv6Address objects are only comparable to other IPv6Address objects");
		}
		return iRet;
	}

	/**
	 * Retrieve a <code>String</code> representation.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString()
	{
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < _iaAddress.length; i++) {
			sb.append(Integer.toHexString(_iaAddress[i]));
			if (i < _iaAddress.length - 1)
				sb.append(":");
		}
		if (_iaMask.length > 0) {
			sb.append("/");
			for (int i = 0; i < _iaMask.length; i++) {
				sb.append(Integer.toHexString(_iaMask[i]));
				if (i < _iaMask.length - 1)
					sb.append(":");
			}
		}
		return sb.toString();
	}

	/**
	 * Convert an address to a int array.
	 * 
	 * @param s
	 *            The address as string.
	 * @param bIsMask
	 *            <code>true</code> if this address is a subnet mask.
	 * @return The address as a <code>int[]</code>.
	 * @throws NumberFormatException
	 *             If parsing fails.
	 */
	private int[] convertAddress(String s, boolean bIsMask)
	throws NumberFormatException
	{
		int[] ia = null;
		StringTokenizer st = new StringTokenizer(s, ":");
		int iSize = st.countTokens();
		if (iSize == 1 && bIsMask) {
			int iValue = Integer.parseInt(st.nextToken());
			if (iValue >= 0 && iValue <= 128) {
				ia = EMPTY_MASK;
				int i = 0;
				while (iValue >= 16) // for every full 16-bits block
				{
					ia[i] = 0xFFFF;
					iValue = iValue - 16;
					i++;
				}
				if (iValue > 0) // shift remaining bits
				{
					ia[i] = 0xFFFF << (16 - iValue);
				}
			}
			else {
				throw new NumberFormatException("Invalid IP v6 address");
			}
		}
		else {
			ia = new int[iSize];
			for (int i = 0; i < iSize; i++) {
				String sToken = st.nextToken();
				ia[i] = Integer.parseInt(sToken, 16);
			}
		}
		return ia;
	}
}
