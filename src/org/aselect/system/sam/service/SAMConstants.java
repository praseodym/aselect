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
 * $Id: SAMConstants.java,v 1.5 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: SAMConstants.java,v $
 * Revision 1.5  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.4  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/02/10 14:11:25  martijn
 * Removed HTMLHandler class and replaced it's functionality by html form support.
 *
 * Revision 1.2  2005/02/09 16:07:01  martijn
 * added javadoc
 *
 * Revision 1.1  2005/02/09 15:31:10  martijn
 * added SAMConstants, containing static vars with OID's
 *
 */

package org.aselect.system.sam.service;

/**
 * Class that contains static variables containing all OID's used by the A-Select SAM Service. <br>
 * <br>
 * <b>Description:</b><br>
 * Contains all IOD's and Names of these OID's that are supported by the A-Select SAM Service. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class SAMConstants
{
	/**
	 * OID for a-select.statistics
	 */
	public final static String OID_BASE = "1.3.6.1.4.1.15396.10.10.2";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2
	 */
	public final static String NAME_BASE = "a-select.statistics";

	/**
	 * OID for a-select.statistics.sysDescr
	 */
	public final static String OID_SYSDESCR = "1.3.6.1.4.1.15396.10.10.2.1.1";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2.1.1
	 */
	public final static String NAME_SYSDESCR = "a-select.statistics.sysDescr";

	/**
	 * OID for a-select.statistics.version
	 */
	public final static String OID_VERSION = "1.3.6.1.4.1.15396.10.10.2.1.2";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2.1.2
	 */
	public final static String NAME_VERSION = "a-select.statistics.version";

	/**
	 * OID for a-select.statistics.operational
	 */
	public final static String OID_OPERATIONAL = "1.3.6.1.4.1.15396.10.10.2.1.3";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2.1.3
	 */
	public final static String NAME_OPERATIONAL = "a-select.statistics.operational";

	/**
	 * OID for a-select.statistics.uptime
	 */
	public final static String OID_UPTIME = "1.3.6.1.4.1.15396.10.10.2.1.4";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2.1.4
	 */
	public final static String NAME_UPTIME = "a-select.statistics.uptime";

	/**
	 * OID for a-select.statistics.load
	 */
	public final static String OID_LOAD = "1.3.6.1.4.1.15396.10.10.2.1.5";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2.1.5
	 */
	public final static String NAME_LOAD = "a-select.statistics.load";

	/**
	 * OID for a-select.statistics.wwwDescr
	 */
	public final static String OID_WWWDESCR = "1.3.6.1.4.1.15396.10.10.2.1.6";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2.1.6
	 */
	public final static String NAME_WWWDESCR = "a-select.statistics.wwwDescr";

	/**
	 * OID for a-select.statistics.cpus
	 */
	public final static String OID_CPUS = "1.3.6.1.4.1.15396.10.10.2.1.7";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2.1.7
	 */
	public final static String NAME_CPUS = "a-select.statistics.cpus";

	/**
	 * OID for a-select.statistics.freeMem
	 */
	public final static String OID_FREEMEM = "1.3.6.1.4.1.15396.10.10.2.1.8";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2.1.8
	 */
	public final static String NAME_FREEMEM = "a-select.statistics.freeMem";

	/**
	 * OID for a-select.statistics.maxMem
	 */
	public final static String OID_MAXMEM = "1.3.6.1.4.1.15396.10.10.2.1.9";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2.1.9
	 */
	public final static String NAME_MAXMEM = "a-select.statistics.maxMem";

	/**
	 * OID for a-select.statistics.totalMem
	 */
	public final static String OID_TOTALMEM = "1.3.6.1.4.1.15396.10.10.2.1.10";
	/**
	 * Name for 1.3.6.1.4.1.15396.10.10.2.1.10
	 */
	public final static String NAME_TOTALMEM = "a-select.statistics.totalMem";

}
