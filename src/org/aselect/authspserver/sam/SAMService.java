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
 * $Id: SAMService.java,v 1.8 2006/05/03 10:08:49 tom Exp $ 
 * 
 * Changelog:
 * $Log: SAMService.java,v $
 * Revision 1.8  2006/05/03 10:08:49  tom
 * Removed Javadoc version
 *
 * Revision 1.7  2005/09/08 12:47:54  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.6  2005/09/08 07:07:25  erwin
 * Improved operational() (bug #110)
 *
 * Revision 1.5  2005/04/01 12:21:45  erwin
 * Added success logging in init().
 *
 * Revision 1.4  2005/03/11 13:27:07  erwin
 * Improved error handling.
 *
 * Revision 1.3  2005/02/22 10:35:46  martijn
 * added java documentation
 *
 * Revision 1.2  2005/02/10 14:20:07  martijn
 * changed all variable names to naming convention and made most of the public methods protected
 *
 */

package org.aselect.authspserver.sam;

import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.aselect.authspserver.config.Version;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.service.SAMServiceServlet;

/**
 * The A-Select AuthSP Server SAM Service servlet. 
 * <br>
 * <br>
 * <b>Description: </b> <br>
 * The SAM Servlet that is used for monitoring the A-Select AuthSP Server. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>-<br>
 * 
 * @author Alfa & Ariss
 * 
 */
public class SAMService extends SAMServiceServlet
{
    
    /** The module name. */
    public static final String MODULE = "SAMService";
    
    /** The system logger. */
    private AuthSPSystemLogger _systemLogger;
    
    /**
     * Initialize method for this Servlet, that starts the initialize of the 
     * super class and loads all specific A-Select Server OID's to the <i>_htOIDs
     * </i> <code>HashMap</code>
     * <br><br>
     * @see org.aselect.system.sam.service.SAMServiceServlet#init(javax.servlet.ServletConfig)
     */
    public void init(ServletConfig oServletConfig) throws ServletException
    {
        _systemLogger = AuthSPSystemLogger.getHandle();
        super.init(oServletConfig);
        _systemLogger.log(Level.INFO, "SAMService", "init()", 
        "Successfully started SAM Service.");
    }

    /**
     * Calls the super class destroy method.
     * <br>
     * <br>
     * @see org.aselect.system.sam.service.SAMServiceServlet#destroy()
     */
    public void destroy()
    {
        super.destroy();
    }

    /**
     * Returns all information that can be resolved from this A-Select AuthSP 
     * Server that is usefull for monitoring.
     * <br><br>
     * At this moment no specific AuthSP Server monitoring information is 
     * available. Only the common SAM information will be returned.
     * <br>
     * @see org.aselect.system.sam.service.SAMServiceServlet#getSAMInfo()
     */
    protected HashMap getSAMInfo()
    {
        HashMap hInfo = getCommonSAMInfo();

        return hInfo;
    }

    /**
     * Returns the AuthSP Server system logger, used for logging.
     * <br>
     * <br>
     * @see org.aselect.system.sam.service.SAMServiceServlet#getSystemLogger()
     */
    protected SystemLogger getSystemLogger()
    {
        return _systemLogger;
    }

    /**
     * Checks if the A-Select AuthSP Server Servlet is operational.
     * <br>
     * <br>
     * @see org.aselect.system.sam.service.SAMServiceServlet#operational()
     */
    protected int operational()
    {
        int iOperational = 0; //default DOWN
        ServletContext servletContext = this.getServletContext().getContext(
            super.getContextUrl() + "/server");    
        if (servletContext != null)
        {
            Object oCryptoEngine = servletContext.getAttribute("CryptoEngine");     
            Object oWorkingDir = servletContext.getAttribute("working_dir");
            Object oFriendlyName = servletContext.getAttribute("friendly_name");
            if(oCryptoEngine != null &&
                oWorkingDir != null &&
                oFriendlyName != null)
            {                
               iOperational = 1; 
            }
            else
            {
                getSystemLogger().log(Level.WARNING, MODULE, "operational()",
                "Can't find AuthSP Server attributes in servlet context.");
            }
        }
        return iOperational;
    }

    /**
     * Returns the A-Select AuthSP Server discription represented as a <code>
     * String</code>.
     * <br>
     * <br>
     * 
     * @see org.aselect.system.sam.service.SAMServiceServlet#getSysDescr()
     */
    protected String getSysDescr()
    {
        StringBuffer sbSysDescr = new StringBuffer("A-Select AuthSP Server v");
        sbSysDescr.append(Version.getVersion());

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
     * Returns the A-Select AuthSP Server version number.
     * <br>
     * <br>
     * 
     * @see org.aselect.system.sam.service.SAMServiceServlet#getVersion()
     */
    protected String getVersion()
    {
        return Version.getVersion();
    }

}