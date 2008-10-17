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
 * $Id: DefaultSelectorHandler.java,v 1.6 2006/04/26 12:17:40 tom Exp $ 
 * 
 * Changelog:
 * $Log: DefaultSelectorHandler.java,v $
 * Revision 1.6  2006/04/26 12:17:40  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.5  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.4.4.2  2006/04/04 09:00:27  erwin
 * Added single-quotes in option values. (fixed bug #160)
 *
 * Revision 1.4.4.1  2006/03/20 11:09:17  martijn
 * added optional template tag support
 *
 * Revision 1.4  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/05/04 09:34:59  martijn
 * bugfixes, improved logging
 *
 * Revision 1.2  2005/04/15 14:02:23  peter
 * javadoc
 *
 * Revision 1.1  2005/04/07 06:27:06  peter
 * package rename
 *
 * Revision 1.1  2005/04/01 14:22:57  peter
 * cross aselect redesign
 *
 * Revision 1.1  2005/03/22 15:12:58  peter
 * Initial version
 *
 */

package org.aselect.server.cross.selectorhandler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.cross.ISelectorHandler;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * This class handles the remote A-Select Server selection by means of a user HTML form.
 * <br><br>
 * <b>Description:</b>
 * <br>
 * This handler will present the user a 'dropdown box' containing all configured
 * remote_servers.<br>
 * This Class is accessed two times within an cross authentication request.<br>
 * - In the first request a HTML form is presented with a list of all configured remote servers.<br>
 * - The HTML form will post the remote server selection and will be put here in a hashtable.
 * <br><br>
 * @author Alfa & Ariss
 * 
 */
public class DefaultSelectorHandler implements ISelectorHandler
{
    // Name of this module, used for logging
    private static final String  MODULE      = "DefaultSelectorHandler";

    private String _sHTMLSelectForm;

    private String               _sMyServerId;
    private String               _sFriendlyName;

    private CrossASelectManager  _crossASelectManager;
    private ASelectConfigManager _configManager;
    private ASelectSystemLogger  _systemLogger;

    /**
     * Initialization of this Handler.
     * Initializes global class-variables that are needed within the whole handler instance.<br>
     * 
     * <br>
     * 
     * @see org.aselect.server.cross.ISelectorHandler#init(java.lang.Object)
     */
    public void init(Object oHandlerConfig) throws ASelectException
    {
        String sMethod = "init()";
        try
        {
            _crossASelectManager = CrossASelectManager.getHandle();
            _configManager = ASelectConfigManager.getHandle();
            _systemLogger = ASelectSystemLogger.getHandle();

            Object oASelectConfig = _configManager.getSection(null, "aselect");
            _sMyServerId = _configManager.getParam(oASelectConfig, "server_id");
            _sFriendlyName = _configManager.getParam(oASelectConfig,
                "organization_friendly_name");
	        loadHTMLTemplates();
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, 
                "Could not initialize the default selector handler", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }

    /**
     * Returns the remote A-Select Server. 
     * This handler presents the user with a selection form that is used to determine the remote 
     * organization and returns the selected organization to the A-Select sub system.
     * <br>
     * 
     * @see org.aselect.server.cross.ISelectorHandler#getRemoteServerId(java.util.Hashtable,
     *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter)
     */
    public Hashtable getRemoteServerId(Hashtable htServiceRequest,
        HttpServletResponse servletResponse, PrintWriter pwOut)
    		throws ASelectException
    {
        Hashtable htResult = new Hashtable();

        Hashtable htServers = _crossASelectManager.getRemoteServers();
        String sRemoteId = null;
        sRemoteId = (String)htServiceRequest.get("remote_server");
        if (sRemoteId == null || sRemoteId.equalsIgnoreCase(""))
        {
            showSelectForm(htServiceRequest, pwOut, htServers);
            return null;
        }
        htResult.put("organization_id", sRemoteId);
        return htResult;
    }

    private void showSelectForm(Hashtable htServiceRequest, PrintWriter pwOut,
        Hashtable htServers)
    	throws ASelectException
    {
        String sMethod = "showSelectForm()";
        String sSelectForm = null;
        
        try
        {
            sSelectForm = _sHTMLSelectForm;
            _systemLogger.log(Level.INFO, MODULE, sMethod, "FORM "+"selectform"); 
    
            String sRid = (String)htServiceRequest.get("rid");
            sSelectForm = Utils.replaceString(sSelectForm, "[rid]", sRid);
            sSelectForm = Utils.replaceString(sSelectForm, "[aselect_url]",
                (String)htServiceRequest.get("my_url"));
            sSelectForm = Utils.replaceString(sSelectForm, "[request]",
                "cross_login");
            sSelectForm = Utils.replaceString(sSelectForm, "[a-select-server]",
                _sMyServerId);
            sSelectForm = Utils.replaceString(sSelectForm,
                "[available_remote_servers]", getRemoteServerHTML(htServers));
    
            StringBuffer sbUrl = new StringBuffer((String)htServiceRequest
                .get("my_url")).append("?request=error").append("&result_code=")
                .append(Errors.ERROR_ASELECT_SERVER_CANCEL).append(
                    "&a-select-server=").append(_sMyServerId).append("&rid=")
                .append((String)htServiceRequest.get("rid"));
    
            sSelectForm = Utils.replaceString(sSelectForm, "[cancel]", sbUrl
                .toString());
        
            Hashtable htSession = SessionManager.getHandle().getSessionContext(sRid);
            if (htSession != null)
                sSelectForm = _configManager.updateTemplate(sSelectForm, htSession);
            
            pwOut.println(sSelectForm);
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod, 
                "Could not show select form", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }

    private String getRemoteServerHTML(Hashtable htServers)
    {
        String sResult = new String();
        String sOrganization;
        String sFriendlyName;

        Enumeration enumRemoteServers = htServers.keys();
        while (enumRemoteServers.hasMoreElements())
        {
            sOrganization = (String)enumRemoteServers.nextElement();
            sFriendlyName = (String)htServers.get(sOrganization);
            sResult += "<OPTION VALUE='" + sOrganization + "'>" + sFriendlyName
                + "</OPTION>\n";
        }
        return sResult;
    }

    /**
	 * Loads all HTML Templates needed.
	 * <br><br>
	 * <b>Description:</b>
	 * <br>
	 * At initialization all HTML templates are loaded once.<br>
	 * @throws ASelectException
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * Run once at startup.
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br>
	 * Manager and ISelectorHandler should be initialized.
	 * <br><br>
	 * <b>Postconditions:</b>
	 * <br>
	 * Global Hashtable _htHtmlTemplates variabele contains the templates.
	 * <br>
	 * 
	 */
	private void loadHTMLTemplates()
		throws ASelectException
	{
	    String sWorkingdir = new StringBuffer(_configManager.getWorkingdir())
	    	.append(File.separator).append("conf").append(File.separator)
	    	.append("html").append(File.separator).toString();

	    _sHTMLSelectForm = loadHTMLTemplate(sWorkingdir
	      + "defaultcrossselect.html");
	    
	    _sHTMLSelectForm = Utils.replaceString(_sHTMLSelectForm, "[version]", Version
            .getVersion());
	    _sHTMLSelectForm = Utils.replaceString(_sHTMLSelectForm,
            "[organization_friendly]", _sFriendlyName);
	}

	private String loadHTMLTemplate(String sLocation)
		throws ASelectException
	{
		String sTemplate = new String();
		String sLine;
		BufferedReader brIn = null;
		String sMethod = "loadHTMLTemplate()";
		
        _systemLogger.log(Level.INFO, "DefaultSelectorHandler", "loadHTMLTemplate", "FORM "+sLocation); 
		try
		{
			brIn = new BufferedReader(
									new InputStreamReader(
										new FileInputStream(sLocation)));
			while ((sLine = brIn.readLine()) != null)
			{
				sTemplate += sLine +"\n";
			}
		}
		catch(Exception e)
		{
            StringBuffer sbError = new StringBuffer("Could not load '");
            sbError.append(sLocation).append("'HTML template.");
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                sbError.toString(),e);
            throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
        finally
        {
            try
            {
                brIn.close();
            }
            catch (Exception e)
            {
                StringBuffer sbError = new StringBuffer("Could not close '");
                sbError.append(sLocation).append("' FileInputStream.");
                _systemLogger.log(Level.WARNING, MODULE, sMethod,
                    sbError.toString(),e);
            }
        }
		return sTemplate;
	}
}