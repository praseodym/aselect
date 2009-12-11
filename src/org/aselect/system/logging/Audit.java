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

import java.util.logging.Level;

// TODO: Auto-generated Javadoc
public class Audit extends Level
{
	// Create the new level
	public static final Level AUDIT = new Audit("AUDIT", Level.INFO.intValue() + 10);

	/**
	 * Instantiates a new audit.
	 * 
	 * @param name
	 *            the name
	 * @param value
	 *            the value
	 */
	public Audit(String name, int value) {
		super(name, value);
	}

	// TODO parse int (Level.INFO.intValue()+10) value supplied as string
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
		if ("AUDIT".equalsIgnoreCase(name)) {
			return AUDIT;
		}
		else
			return Level.parse(name);
	}

}
