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
 * $Id: SAMService.java,v 1.13 2006/04/26 12:18:32 tom Exp $ 
 * 
 * Changelog:
 * $Log: SAMService.java,v $
 * Revision 1.13  2006/04/26 12:18:32  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.12  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.11.4.2  2006/01/25 15:35:19  martijn
 * TGTManager rewritten
 *
 * Revision 1.11.4.1  2006/01/13 08:36:49  martijn
 * requesthandlers seperated from core
 *
 * Revision 1.11  2005/09/08 12:46:34  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.10  2005/09/08 06:53:48  erwin
 * Added extra "up" check and improved sessionload. (bug #110)
 *
 * Revision 1.9  2005/03/11 21:24:08  martijn
 * config section: storagemanager id='ticket' is renamed to storagemanager id='tgt'
 *
 * Revision 1.8  2005/03/11 21:09:14  martijn
 * config item's max_tgt and max_sessions are renamed to 'max' in storagemanager sections
 *
 * Revision 1.7  2005/03/10 15:06:42  erwin
 * Improved error handling.
 *
 * Revision 1.6  2005/03/10 14:17:45  erwin
 * Improved Javadoc.
 *
 * Revision 1.5  2005/02/22 10:35:36  martijn
 * fixed typos in javadoc
 *
 * Revision 1.4  2005/02/22 10:01:48  martijn
 * added java documentation
 *
 * Revision 1.3  2005/02/10 14:14:05  martijn
 * changed all variable names to naming convention and made most of the public methods protected
 *
 */

package org.aselect.server.sam;

import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.service.SAMServiceServlet;

/**
 * The A-Select Server SAM Service servlet. <br>
 * <br>
 * <b>Description: </b> <br>
 * The SAM Servlet that is used for monitoring the A-Select Server. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class SAMService extends SAMServiceServlet
{
    /** The module name. */
    public static final String MODULE = "SAMService";
    
    /** The system logger. */
    private ASelectSystemLogger _systemLogger;
    
    private boolean _bASelectOK;
    
    /**
     * Initialize method for this Servlet, that starts the initialize of the 
     * super class and loads all specific A-Select Server OID's to the <i>_htOIDs
     * </i> <code>HashMap</code>
     * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
     */
    public void init(ServletConfig oServletConfig) throws ServletException
    {
        _systemLogger = ASelectSystemLogger.getHandle();
        super.init(oServletConfig);

        _htOIDs.put(ASelectSAMConstants.OID_MAXSESSIONS,
            ASelectSAMConstants.NAME_MAXSESSIONS);
        _htOIDs.put(ASelectSAMConstants.OID_CURSESSIONS,
            ASelectSAMConstants.NAME_CURSESSIONS);
        _htOIDs.put(ASelectSAMConstants.OID_SESSIONLOAD,
            ASelectSAMConstants.NAME_SESSIONLOAD);
        _htOIDs.put(ASelectSAMConstants.OID_AUTHSPS,
            ASelectSAMConstants.NAME_AUTHSPS);
        _htOIDs.put(ASelectSAMConstants.OID_PROCESSINGTIME,
            ASelectSAMConstants.NAME_PROCESSINGTIME);
        _htOIDs.put(ASelectSAMConstants.OID_SESSIONCOUNT,
            ASelectSAMConstants.NAME_SESSIONCOUNT);
        _htOIDs.put(ASelectSAMConstants.OID_TGTCOUNT,
            ASelectSAMConstants.NAME_TGTCOUNT);
        _htOIDs.put(ASelectSAMConstants.OID_CURTGTS,
            ASelectSAMConstants.NAME_CURTGTS);
        _htOIDs.put(ASelectSAMConstants.OID_MAXTGTS,
            ASelectSAMConstants.NAME_MAXTGTS);
        
        _bASelectOK = true;
        
        _systemLogger.log(Level.INFO, MODULE, "init()", 
            "Successfully started SAM Service.");
    }

    /**
     * Calls the destroy of the super class. 
     * @see org.aselect.system.sam.service.SAMServiceServlet#destroy()
     */
    public void destroy()
    {
        super.destroy();
    }

    /**
     * Returns the A-Select SystemLogger
     * @see org.aselect.system.sam.service.SAMServiceServlet#getSystemLogger()
     */
    protected SystemLogger getSystemLogger()
    {
        return _systemLogger;
    }

    /**
     * Adds all specific A-Select Server information to the common SAM 
     * information.
     * @see org.aselect.system.sam.service.SAMServiceServlet#getSAMInfo()
     */
    protected HashMap getSAMInfo()
    {
        String sMethod = "getSAMInfo()";
        HashMap htInfo = getCommonSAMInfo();
        long lMaxSessions = 0;
        long lMaxTGT = 0;
        _bASelectOK = true; //default true
        ASelectConfigManager oASelectConfigManager = 
            ASelectConfigManager.getHandle();
        if (oASelectConfigManager != null)
        {
            try
            {
                Object oSessionManagerSection = oASelectConfigManager.getSection(null,
                        "storagemanager", "id=session");
                
                lMaxSessions = (new Long(oASelectConfigManager.getParam(
                        oSessionManagerSection, "max")).longValue());
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod,
                    "Can't find 'max' config item in storagemanager section with id='sessions'", e);
            }
            catch (NumberFormatException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod,
                        "Can't convert value of 'max' config item in storagemanager with id='sessions' to a long value.");
            }
            catch (NullPointerException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod,
                        "Can't retrieve value of 'max' config item in storagemanager with id='sessions'.");
                _bASelectOK = false;
            }
            
            
            try
            {
                Object oTicketManagerSection = oASelectConfigManager.getSection(null,
                    "storagemanager", "id=tgt");
                
                lMaxTGT = (new Long(oASelectConfigManager.getParam(
                        oTicketManagerSection, "max")).longValue());
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod,
                    "Can't find 'max' config item in storagemanager section with id='tgt'", e);
            }
            catch (NumberFormatException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod,
                    "Can't convert value of 'max' config item in storagemanager with id='tgt' to a long value.");
            }
            catch (NullPointerException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod,
                        "Can't retrieve value of 'max' config item in storagemanager with id='tgt'.");
                _bASelectOK = false;
            }
        }

        long lSessions = -1;
        SessionManager oSessionManager = SessionManager.getHandle();
        if (oSessionManager != null)
        {
            HashMap htSessionContexts = null;
            try
            {
                htSessionContexts = oSessionManager.getAll();
                // TODO: cheaper version: lSessions = oSessionManager.getCount();
            }
            catch (Exception e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, 
                    "No contexts available", e);
            }
            if (htSessionContexts != null)
                lSessions = htSessionContexts.size();
        }

        //maxsessions
        htInfo.put(ASelectSAMConstants.OID_MAXSESSIONS, "" + lMaxSessions);

        //cursessions
        htInfo.put(ASelectSAMConstants.OID_CURSESSIONS, "" + lSessions);

        //sessionload
        double dLoad = lSessions >= 0 
        	? lSessions * ((double)100 / (double)lMaxSessions)
        	: -1;
        htInfo.put(ASelectSAMConstants.OID_SESSIONLOAD, "" + (int)dLoad);

        //authsps
        htInfo.put(ASelectSAMConstants.OID_AUTHSPS, resolveAuthSPs());

        //processingTime: last session lifetime
        long lTime = -1;
        if (oSessionManager != null)
            lTime = oSessionManager.getProcessingTime();
        htInfo.put(ASelectSAMConstants.OID_PROCESSINGTIME, "" + lTime);

        //sessionCount
        long lSessionCount = -1;
        oSessionManager = SessionManager.getHandle();
        if (oSessionManager != null)
            lSessionCount = oSessionManager.getCounter();
        htInfo.put(ASelectSAMConstants.OID_SESSIONCOUNT, "" + lSessionCount);

        //TGTCount
        long lTGTCount = -1;
        TGTManager oTGTManager = TGTManager.getHandle();
        if (oTGTManager != null)
            lTGTCount = oTGTManager.getTGTCounter();
        htInfo.put(ASelectSAMConstants.OID_TGTCOUNT, "" + lTGTCount);

        //Active TGTs
        long lActiveTGTs = -1;
        oTGTManager = TGTManager.getHandle();
        if (oTGTManager != null)
        {
            HashMap htTGTContexts = null;
            try
            {
                htTGTContexts = oTGTManager.getAll();
                // TODO: cheaper version: lActiveTGTs = oTGTManager.getTGTCounter();
            }
            catch (Exception e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, 
                    "No contexts available", e);
            }
            if (htTGTContexts != null)
                lActiveTGTs = htTGTContexts.size();
        }

        htInfo.put(ASelectSAMConstants.OID_CURTGTS, "" + lActiveTGTs);
        htInfo.put(ASelectSAMConstants.OID_MAXTGTS, "" + lMaxTGT);
        return htInfo;
    }

    /**
     * Checks if the A-Select Server Servlet is operational. 
     * @see org.aselect.system.sam.service.SAMServiceServlet#operational()
     */
    protected int operational()
    {
        if(!_bASelectOK)
            return 0;
        //checks if the A-Select Server context can be accessed.
        ServletContext oServletContext = this.getServletContext().getContext(
            super.getContextUrl() + "/server");
        if (oServletContext != null)
        {
            return 1;
        }
        return 0;
    }

    /**
     * Returns the A-Select Server discription represented as a <code>String</code>.
     * @see org.aselect.system.sam.service.SAMServiceServlet#getSysDescr()
     */
    protected String getSysDescr()
    {
        StringBuffer sbSysDescr = new StringBuffer("A-Select Server v");
        sbSysDescr.append(Version.getRelease());

        String sSP = Version.getSP();
        if (!sSP.equals(""))
        {
            sbSysDescr.append(" ,SP ");
            sbSysDescr.append(sSP);
        }

        String sPatch = Version.getPatch();
        if (!sPatch.equals(""))
        {
            sbSysDescr.append(" ,Patch ");
            sbSysDescr.append(sPatch);
        }

        return sbSysDescr.toString();
    }

    /**
     * Returns the A-Select Server version number.
     * @see org.aselect.system.sam.service.SAMServiceServlet#getVersion()
     */
    protected String getVersion()
    {
        return Version.getRelease();
    }

    /**
     * Resolves which authSPs are configured for this A-Select Server. 
     * <br><br>
     * <b>Description: </b> 
     * <br>
     * Resolves the AuthSP id's from the A-Select Server configuration. <br>
     * <br>
     * <b>Concurrency issues: </b> 
     * <br>
     * - <br>
     * <br>
     * <b>Preconditions: </b> 
     * <br>
     * - <br>
     * <br>
     * <b>Postconditions: </b> 
     * <br>
     * Will return an non breaking space HTML entity (&nbsp) if no AuthSPs can 
     * be resolved.<br>
     * 
     * @return <code>String</code> containing a representation of the AuthSP's 
     * that are configured in this A-Select Server.
     */
    private String resolveAuthSPs()
    {
        String sReturn = "";
        StringBuffer sbAuthSP = null;

        try
        {
            ASelectConfigManager oASelectConfigManager = ASelectConfigManager
                .getHandle();
            Object oAuthSP = oASelectConfigManager.getSection(
                oASelectConfigManager.getSection(null, "authsps"), "authsp");

            while (oAuthSP != null)
            {
                String sAuthSP = oASelectConfigManager.getParam(oAuthSP, "id");
                String sLevel = oASelectConfigManager
                    .getParam(oAuthSP, "level");

                if (sbAuthSP == null)
                    sbAuthSP = new StringBuffer();
                else
                    sbAuthSP.append(",");

                sbAuthSP.append(sAuthSP);
                sbAuthSP.append(" (level=");
                sbAuthSP.append(sLevel);
                sbAuthSP.append(")");

                oAuthSP = oASelectConfigManager.getNextSection(oAuthSP);
            }

            sReturn = sbAuthSP.toString();
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, "resolveAuthSPs()", 
                "Error retrieving AuthSP information", e);
            sReturn = "&nbsp;";
        }

        return sReturn;
    }
}