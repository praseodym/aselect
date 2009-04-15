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
 * $Id: Version.java,v 1.11 2006/05/03 09:29:46 martijn Exp $ 
 * 
 * Changelog:
 * $Log: Version.java,v $
 * Revision 1.11  2006/05/03 09:29:46  martijn
 * changes for version 1.5
 *
 * Revision 1.10  2006/04/26 12:17:06  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.9  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.8.4.2  2006/03/22 09:04:17  martijn
 * changed version to 1.5 RC2
 *
 * Revision 1.8.4.1  2006/03/14 15:10:16  martijn
 * changed release to 1.5 RC1a
 *
 * Revision 1.8  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/03/21 11:34:45  tom
 * Changed version, removed service pack
 *
 * Revision 1.6  2005/03/10 10:41:56  erwin
 * Renamed constant variables.
 *
 * Revision 1.5  2005/02/10 14:15:21  martijn
 * added new method that only returns the main release version: getRelease()
 *
 * Revision 1.4  2005/02/08 15:33:37  martijn
 * added the component name to the getVersion() method
 *
 * Revision 1.3  2005/02/08 10:38:09  martijn
 * changed all variable names to naming convention and added javadoc
 *
 */

package org.aselect.server.config;


/**
 * Class containing the version of the A-Select Server.
 * <br><br>
 * <b>Description:</b><br>
 * Methods that supply this version of the A-Select Server
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
     * The component name
     */
    private final static String COMPONENT = "A-Select Server ";
    
    /**
     * The main release version of this A-Select Server
     */
    private final static String RELEASE = "1.8";

    /**
     * The service pack version of this A-Select Server
     */
    private final static String SP      = "0";

    /**
     * The patch version of this A-Select Server
     */
    private final static String PATCH   = "0";

    /**
     * Returns the main version of this A-Select Server.
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
     * @return the full version of this A-Select Server
     */
    public static String getVersion()
    {
        StringBuffer sbVersion = new StringBuffer(COMPONENT);
        sbVersion.append(RELEASE);
        sbVersion.append(getSP());
        sbVersion.append(getPatch());
        return  sbVersion.toString();
    }
    
    /**
     * Returns the main release of this A-Select Server.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Static method that returns the main release as <code>String</code>.
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
     * @return the full release version of this A-Select Server
     */
    public static String getRelease()
    {
        return  RELEASE;
    }

    /**
     * Returns the service pack version of this A-Select Server.
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
     * @return the service pack version of this A-Select Server
     */
    public static String getSP()
    {
        if (!SP.equals("0"))
            return "." + SP;

        return "";
    }

    /**
     * Returns the patch version of this A-Select Server.
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
     * @return the pacth version of this A-Select Server
     */
    public static String getPatch()
    {
        if (!PATCH.equals("0"))
            return " (p. " + PATCH + ")";
        
        return "";
    }
}