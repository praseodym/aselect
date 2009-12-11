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
 * $Id: IPv4Address.java,v 1.5 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: IPv4Address.java,v $
 * Revision 1.5  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.4  2005/08/25 14:28:41  erwin
 * Implemented compareTo()
 *
 * Revision 1.3  2005/08/24 14:27:13  erwin
 * Implemented evaluator
 *
 * Revision 1.2  2005/08/24 08:55:48  erwin
 * Improved error handling and Javadoc.
 *
 * Revision 1.1  2005/08/23 15:31:19  erwin
 * Implemented the parser
 *
 */

package org.aselect.agent.authorization.parsing.types;

import java.util.StringTokenizer;

// TODO: Auto-generated Javadoc
/**
 * IP Version 4 Address. <br>
 * <br>
 * <b>Description:</b><br>
 * A simple Java object to compare IPv4 adresses. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * <br>
 * 
 * @author Alfa & Ariss
 */
public class IPv4Address implements Comparable
{
	/**
	 * Regex for IP v4 address.
	 */
	public static final String IPV4_REGEX = "([0-9]+\\.){3}([0-9]+)(\\/([0-9]+)(\\.[0-9]+){0,3})?";

	/**
	 * Convert table for short notation of subnet mask
	 */
	private final byte[][] MASK_CONVERT_TABLE = {
		{
			(byte) 0, (byte) 0, (byte) 0, (byte) 0
		}, {
			(byte) 128, (byte) 0, (byte) 0, (byte) 0
		}, {
			(byte) 192, (byte) 0, (byte) 0, (byte) 0
		}, {
			(byte) 224, (byte) 0, (byte) 0, (byte) 0
		}, {
			(byte) 240, (byte) 0, (byte) 0, (byte) 0
		}, {
			(byte) 248, (byte) 0, (byte) 0, (byte) 0
		}, {
			(byte) 252, (byte) 0, (byte) 0, (byte) 0
		}, {
			(byte) 254, (byte) 0, (byte) 0, (byte) 0
		}, {
			(byte) 255, (byte) 0, (byte) 0, (byte) 0
		}, {
			(byte) 255, (byte) 128, (byte) 0, (byte) 0
		}, {
			(byte) 255, (byte) 192, (byte) 0, (byte) 0
		}, {
			(byte) 255, (byte) 224, (byte) 0, (byte) 0
		}, {
			(byte) 255, (byte) 240, (byte) 0, (byte) 0
		}, {
			(byte) 255, (byte) 248, (byte) 0, (byte) 0
		}, {
			(byte) 255, (byte) 252, (byte) 0, (byte) 0
		}, {
			(byte) 255, (byte) 254, (byte) 0, (byte) 0
		}, {
			(byte) 255, (byte) 255, (byte) 0, (byte) 0
		}, {
			(byte) 255, (byte) 255, (byte) 128, (byte) 0
		}, {
			(byte) 255, (byte) 255, (byte) 192, (byte) 0
		}, {
			(byte) 255, (byte) 255, (byte) 224, (byte) 0
		}, {
			(byte) 255, (byte) 255, (byte) 240, (byte) 0
		}, {
			(byte) 255, (byte) 255, (byte) 252, (byte) 0
		}, {
			(byte) 255, (byte) 255, (byte) 254, (byte) 0
		}, {
			(byte) 255, (byte) 255, (byte) 255, (byte) 0
		}, {
			(byte) 255, (byte) 255, (byte) 255, (byte) 128
		}, {
			(byte) 255, (byte) 255, (byte) 255, (byte) 192
		}, {
			(byte) 255, (byte) 255, (byte) 255, (byte) 224
		}, {
			(byte) 255, (byte) 255, (byte) 255, (byte) 240
		}, {
			(byte) 255, (byte) 255, (byte) 255, (byte) 248
		}, {
			(byte) 255, (byte) 255, (byte) 255, (byte) 252
		}, {
			(byte) 255, (byte) 255, (byte) 255, (byte) 254
		}, {
			(byte) 255, (byte) 255, (byte) 255, (byte) 255
		},
	};

	/**
	 * Default Subnet Mask.
	 */
	private final byte[] DEFAULT_MASK = {
		(byte) 255, (byte) 255, (byte) 255, (byte) 255
	};

	/**
	 * Adress.
	 */
	private byte[] _baAddress;

	/**
	 * Subnet Mask.
	 */
	private byte[] _baMask;

	/**
	 * Create new <code>IPv4Address</code>.
	 * 
	 * @param s
	 *            The String respresentation of the address.
	 * @throws Exception
	 *             If parsing fails.
	 */
	public IPv4Address(String s)
		throws Exception {
		String sAdress = null;

		if (!s.matches(IPV4_REGEX)) {
			throw new Exception("Not a valid IP v4 address");
		}

		int index = s.indexOf('/');
		if (index > 0) // mask available
		{
			sAdress = s.substring(0, index);
			String sMask = s.substring(index + 1, s.length());
			_baMask = convertAddress(sMask, true);
		}
		else {
			sAdress = s;
			_baMask = DEFAULT_MASK;
		}
		_baAddress = convertAddress(sAdress, false);
	}

	/**
	 * Compare two ip adresses (Only equals is supported).
	 * 
	 * @param oOther
	 *            The object to compare with.
	 * @return <code>0</code> if the ip adresses are equal with network mask taken in account, otherwise -1.
	 * @throws ClassCastException
	 *             If the provided <code>Object</code> is not an <code>IPv4Address</code>.
	 */
	public int compareTo(Object oOther)
		throws ClassCastException
	{
		int iRet = 0;
		if (oOther instanceof IPv4Address) {
			IPv4Address aOther = (IPv4Address) oOther;

			boolean bOk = true;
			for (int i = 0; i < 4 && bOk; i++) {

				bOk = (aOther._baAddress[i] & this._baMask[i]) == this._baAddress[i];
			}

			if (bOk)
				iRet = 0;
			else {
				iRet = -1;
			}
		}
		else {
			throw new ClassCastException("IPv4Address objects are only comparable to other IPv4Address objects");
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
		for (int i = 0; i < _baAddress.length; i++) {
			sb.append(_baAddress[i]);
			if (i < _baAddress.length - 1)
				sb.append(".");
		}
		if (_baMask.length > 0) {
			sb.append("/");
			for (int i = 0; i < _baMask.length; i++) {
				sb.append(_baMask[i]);
				if (i < _baMask.length - 1)
					sb.append(".");
			}
		}
		return sb.toString();
	}

	/**
	 * Convert an address to a byte array.
	 * 
	 * @param s
	 *            The address as string.
	 * @param bIsMask
	 *            <code>true</code> if address is a subnet mask.
	 * @return The address as a <code>byte[]</code>.
	 * @throws NumberFormatException
	 *             If parsing fails.
	 */
	private byte[] convertAddress(String s, boolean bIsMask)
		throws NumberFormatException
	{
		StringTokenizer st = new StringTokenizer(s, ".");
		byte[] ba = null;
		int iSize = st.countTokens();
		if (iSize == 1 && bIsMask) {
			int iValue = Integer.parseInt(st.nextToken());
			if (iValue >= 0 && iValue <= 32) {
				ba = MASK_CONVERT_TABLE[iValue - 1];
			}
			else {
				throw new NumberFormatException("Invalid IP v4 address");
			}
		}
		else {
			ba = new byte[iSize];
			for (int i = 0; i < iSize; i++) {
				String sToken = st.nextToken();
				int iValue = Integer.parseInt(sToken);
				if (iValue >= 0 && iValue <= 255) {
					ba[i] = (byte) iValue;
				}
				else {
					throw new NumberFormatException("Invalid IP v4 address");
				}
			}
		}
		return ba;
	}

}
