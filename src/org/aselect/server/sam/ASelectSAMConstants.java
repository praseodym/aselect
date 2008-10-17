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
 * $Id: ASelectSAMConstants.java,v 1.4 2006/04/26 12:18:32 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectSAMConstants.java,v $
 * Revision 1.4  2006/04/26 12:18:32  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.3  2005/09/08 12:46:34  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/02/22 10:01:48  martijn
 * added java documentation
 *
 * Revision 1.1  2005/02/10 14:12:30  martijn
 * added constants with OID information
 *
 */

package org.aselect.server.sam;

/**
 * Class that contains static variables used by the A-Select SAM Service. 
 * <br><br>
 * <b>Description:</b><br>
 * Class that contains static variables containing all specific A-Select Server 
 * OID's used by the A-Select SAM Service.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class ASelectSAMConstants
{
    /**
     * OID for a-select.statistics.specific.maxsessions
     */
    public final static String OID_MAXSESSIONS = "1.3.6.1.4.1.15396.10.10.2.2.1.1";
    /**
     * Name for 1.3.6.1.4.1.15396.10.10.2.2.1.1
     */
    public final static String NAME_MAXSESSIONS = "a-select.statistics.specific.maxsessions";
    
    /**
     * OID for a-select.statistics.specific.cursessions
     */
    public final static String OID_CURSESSIONS = "1.3.6.1.4.1.15396.10.10.2.2.1.2";
    /**
     * Name for 1.3.6.1.4.1.15396.10.10.2.2.1.2
     */
    public final static String NAME_CURSESSIONS = "a-select.statistics.specific.cursessions";
    
    /**
     * OID for a-select.statistics.specific.sessionload
     */
    public final static String OID_SESSIONLOAD = "1.3.6.1.4.1.15396.10.10.2.2.1.3";
    /**
     * Name for 1.3.6.1.4.1.15396.10.10.2.2.1.3
     */
    public final static String NAME_SESSIONLOAD = "a-select.statistics.specific.sessionload";
    
    /**
     * OID for a-select.statistics.specific.authsps
     */
    public final static String OID_AUTHSPS = "1.3.6.1.4.1.15396.10.10.2.2.1.4";
    /**
     * Name for 1.3.6.1.4.1.15396.10.10.2.2.1.4
     */
    public final static String NAME_AUTHSPS = "a-select.statistics.specific.authsps";
    
    /**
     * OID for a-select.statistics.specific.processingTime
     */
    public final static String OID_PROCESSINGTIME = "1.3.6.1.4.1.15396.10.10.2.2.1.5";
    /**
     * Name for 1.3.6.1.4.1.15396.10.10.2.2.1.5
     */
    public final static String NAME_PROCESSINGTIME = "a-select.statistics.specific.processingTime";
    
    /**
     * OID for a-select.statistics.specific.sessionCount
     */
    public final static String OID_SESSIONCOUNT = "1.3.6.1.4.1.15396.10.10.2.2.1.6";
    /**
     * Name for 1.3.6.1.4.1.15396.10.10.2.2.1.6
     */
    public final static String NAME_SESSIONCOUNT = "a-select.statistics.specific.sessionCount";
    
    /**
     * OID for a-select.statistics.specific.TGTCount
     */
    public final static String OID_TGTCOUNT = "1.3.6.1.4.1.15396.10.10.2.2.1.7";
    /**
     * Name for 1.3.6.1.4.1.15396.10.10.2.2.1.7
     */
    public final static String NAME_TGTCOUNT = "a-select.statistics.specific.TGTCount";
    
    /**
     * OID for a-select.statistics.specific.curTGTs
     */
    public final static String OID_CURTGTS = "1.3.6.1.4.1.15396.10.10.2.2.1.8";
    /**
     * Name for 1.3.6.1.4.1.15396.10.10.2.2.1.8
     */
    public final static String NAME_CURTGTS = "a-select.statistics.specific.curTGTs";
    
    /**
     * OID for a-select.statistics.specific.maxTGTs
     */
    public final static String OID_MAXTGTS = "1.3.6.1.4.1.15396.10.10.2.2.1.9";
    /**
     * Name for 1.3.6.1.4.1.15396.10.10.2.2.1.9
     */
    public final static String NAME_MAXTGTS = "a-select.statistics.specific.maxTGTs";
}
