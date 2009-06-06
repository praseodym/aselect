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
 * $Id: Version.java,v 1.9 2006/05/03 10:09:18 tom Exp $ 
 * 
 * Changelog:
 * $Log: Version.java,v $
 * Revision 1.9  2006/05/03 10:09:18  tom
 * Removed Javadoc version
 *
 * Revision 1.8  2006/05/03 09:33:23  martijn
 * changes for version 1.5
 *
 * Revision 1.7  2006/03/22 09:04:29  martijn
 * changed version to 1.5 RC2
 *
 * Revision 1.6  2006/03/14 15:10:02  martijn
 * changed release to 1.5 RC1a
 *
 * Revision 1.5  2005/09/08 12:47:54  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.4  2005/03/21 15:26:14  tom
 * Changed version, removed service pack
 *
 * Revision 1.3  2005/03/11 13:27:07  erwin
 * Improved error handling.
 *
 * Revision 1.2  2005/02/09 12:42:49  martijn
 * changed all variable names to naming convention and added javadoc
 *
 */

package org.aselect.authspserver.config;

/**
 * Class containing the version of the A-Select AuthSP Server.
 * <br><br>
 * <b>Description:</b><br>
 * Methods that supply this version of the A-Select AuthSP Server
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class Version
{
    /**
     * The main release version of this A-Select AuthSP Server
     */
    private final static String VERSION = "1.9";

    /**
     * The service pack version of this A-Select AuthSP Server
     */
    private final static String SP      = "0";

    /**
     * The patch version of this A-Select AuthSP Server
     */
    private final static String PATCH   = "0";

    /**
     * Returns the main version of this A-Select AuthSP Server.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Static method that returns the main version as <code>String</code>.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @return the full version of this A-Select AuthSP Server
     */
    public static String getVersion()
    {
        StringBuffer sbVersion = new StringBuffer(VERSION);
        sbVersion.append(getSP());
        sbVersion.append(getPatch());
        return  sbVersion.toString();
    }

    /**
     * Returns the service pack version of this A-Select AuthSP Server.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Static method that returns the service pack version as <code>String</code>.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @return the service pack version of this A-Select AuthSP Server
     */
    public static String getSP()
    {
        if (!SP.equals("0"))
            return "." + SP;

        return "";
    }

    /**
     * Returns the patch version of this A-Select AuthSP Server.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Static method that returns the patch version as <code>String</code>.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @return the pacth version of this A-Select AuthSP Server
     */
    public static String getPatch()
    {
        if (!PATCH.equals("0"))
            return " (p. " + PATCH + ")";
        
        return "";
    }
}