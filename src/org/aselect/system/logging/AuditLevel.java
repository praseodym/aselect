/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.system.logging;

import org.apache.log4j.Level;

public class AuditLevel extends Level
{
	private static final long serialVersionUID = -3286629221695935369L;

	/**
	 * Value of my audit level. This value is higher than {@link org.apache.log4j.Priority#INFO_INT} and lesser than
	 * {@link org.apache.log4j.Level#WARN_INT}
	 */
	public static final int AUDIT_INT = INFO_INT + 10;

	/**
	 * {@link Level} representing my log level
	 */
	public static final Level AUDIT = new AuditLevel(AUDIT_INT, "AUDIT", 6);// 6 Informational: informational messages

	/**
	 * Constructor.
	 * 
	 * @param arg0
	 *            the arg0
	 * @param arg1
	 *            the arg1
	 * @param arg2
	 *            the arg2
	 */
	protected AuditLevel(int arg0, String arg1, int arg2) {
		super(arg0, arg1, arg2);

	}

	/**
	 * To level.
	 * 
	 * @param sArg
	 *            the s arg
	 * @return the level
	 * @see Level#toLevel(java.lang.String)
	 * @see Level#toLevel(java.lang.String, org.apache.log4j.Level)
	 */
	public static Level toLevel(String sArg)
	{
		if (sArg != null && sArg.toUpperCase().equals("AUDIT")) {
			return AUDIT;
		}
		return toLevel(sArg, Level.INFO);
	}

	/**
	 * To level.
	 * 
	 * @param val
	 *            the val
	 * @return the level
	 * @see Level#toLevel(int)
	 * @see Level#toLevel(int, org.apache.log4j.Level)
	 */
	public static Level toLevel(int val)
	{
		if (val == AUDIT_INT) {
			return AUDIT;
		}
		return toLevel(val, Level.DEBUG);
	}

	/**
	 * To level.
	 * 
	 * @param val
	 *            the val
	 * @param defaultLevel
	 *            the default level
	 * @return the level
	 * @see Level#toLevel(int, org.apache.log4j.Level)
	 */
	public static Level toLevel(int val, Level defaultLevel)
	{
		if (val == AUDIT_INT) {
			return AUDIT;
		}
		return Level.toLevel(val, defaultLevel);
	}

	/**
	 * To level.
	 * 
	 * @param sArg
	 *            the s arg
	 * @param defaultLevel
	 *            the default level
	 * @return the level
	 * @see Level#toLevel(java.lang.String, org.apache.log4j.Level)
	 */
	public static Level toLevel(String sArg, Level defaultLevel)
	{
		if (sArg != null && sArg.toUpperCase().equals("AUDIT")) {
			return AUDIT;
		}
		return Level.toLevel(sArg, defaultLevel);
	}

	/**
	 * Parses the.
	 * 
	 * @param name
	 *            the name
	 * @return the level
	 * @throws IllegalArgumentException
	 *             the illegal argument exception
	 */
	public static Level parse(String name)
	throws IllegalArgumentException
	{
		return toLevel("AUDIT");
	}

}
