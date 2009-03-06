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
 * $Id: ShibbolethWAYFProfile.java,v 1.6 2006/05/03 10:11:08 tom Exp $ 
 */

package org.aselect.server.request.handler.shibboleth;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * Where are you from request handler.
 * <br><br>
 * <b>Description:</b><br>
 * WAYF request handler with a Shibboleth interface.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class ShibbolethWAYFProfile extends AbstractRequestHandler
{
    private final static String MODULE = "ShibbolethWAYFProfile";
    private final static String COOKIENAME = "idp";
    
    private String _sCookieDomain;
    private String _sTemplate;
    private long _lTimeOffset;
    private Vector _vIdPs;
    private HashMap _htIdPs;

    /**
     * Initializes the WAYF request handler.
     * <br><br>
     * <b>Description:</b><br>
     * Reads the following configuration:<br/><br/>
     * &lt;handler&gt;<br/>
     * &lt;template&gt;[template]&lt;/template&gt;<br/>
     * &lt;cookie domain='[domain]'/&gt;<br/>
     * &lt;time offset='[offset]'/&gt;<br/>
     * &lt;identity_providers&gt;<br/>
     * &lt;idp alias='[alias]' url='[url]'/&gt;<br/>
     * ...<br/>
     * &lt;/identity_providers&gt;<br/>
     * &lt;/handler&gt;<br/>
     * <ul>
     * <li><b>template</b> - file name of the WAYF template, the file must be 
     * located in [working_dir]/aselectserver/conf/html/</li>
     * <li><b>domain</b> - The cookie tag is optional, if avalable the domain is 
     * the domain on which the cookie will be set e.g. 'a-select.org'</li>
     * <li><b>offset</b> - time offset in seconds</li>
     * <li><b>alias</b> - the name that will be shown in the pulldown menu</li>
     * <li><b>url</b> - the IdP url to which the request must be redirected</li>
     * </ul>  
     * <br/>
     * The <code>_vIdPs</code> contains the sequence of the configured IdP's, 
     * according to this sequence the items will be shown in the pulldown.<br/>
     * The <code>_htIdPs</code> contains the IdP's with key=alias and value=url 
     * <br><br>
     * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
     */
    public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
	    String sMethod = "init()";
	    try
	    {
	        super.init(oServletConfig, oConfig);
            
            Object oTime = null;
            try
            {
                oTime = _configManager.getSection(oConfig, "time");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config section 'time' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            String sTimeOffset = null;
            try
            {
                sTimeOffset = _configManager.getParam(oTime, "offset");
                _lTimeOffset = Long.parseLong(sTimeOffset);
                _lTimeOffset = _lTimeOffset * 1000;
            }
            catch (NumberFormatException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "Configured time offset isn't a number: " + sTimeOffset, e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config item 'offset' found in section 'time'", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            // Bauke abbreviated a little
            _sCookieDomain = _configManager.getCookieDomain();
            _systemLogger.log(Level.INFO, MODULE, sMethod, "Use cookie domain "+_sCookieDomain);
/*            Object oCookie = null;
            try
            {
                oCookie = _configManager.getSection(oConfig, "cookie");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.CONFIG, MODULE, sMethod
                    , "No optional config section 'cookie' found", e);
            }
            
            try
            {
                if (oCookie != null)
                {
                    _sCookieDomain = _configManager.getCookieDomain();
                    //_sCookieDomain = _configManager.getParam(oCookie, "domain");
        			//if (!_sCookieDomain.startsWith("."))
        			//	_sCookieDomain = "." + _sCookieDomain;
                    
                    StringBuffer sbInfo = new StringBuffer("The following cookie domain will be used for setting cookies: ");
                    sbInfo.append(_sCookieDomain);
                    _systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
                }
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config item 'domain' found in section 'cookie'", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
*/            
            Object oIdentityProviders = null;
            try
            {
                oIdentityProviders = _configManager.getSection(oConfig, "identity_providers");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "No config section 'identity_providers' found", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            Object oIdP = null;
            try
            {
                oIdP = _configManager.getSection(oIdentityProviders, "idp");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "Not even one config section 'idp' found in the 'identity_providers' section", e);
                throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            _vIdPs = new Vector();
            _htIdPs = new HashMap();
            while (oIdP != null)
            {
                String sAlias = null;
                try
                {
                    sAlias = _configManager.getParam(oIdP, "alias");
                }
                catch (ASelectConfigException e)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "Not even one config item 'alias' found in 'idp' section", e);
                    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
                }
                
                String sIdPURL = null;
                try
                {
                    sIdPURL = _configManager.getParam(oIdP, "url");
                }
                catch (ASelectConfigException e)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "Not even one config item 'url' found in 'idp' section", e);
                    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
                }

                if (_htIdPs.containsValue(sAlias))
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "Identity Provider alias isn't unique: " + sAlias);
                    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR);
                }
                
                if (_htIdPs.containsKey(sIdPURL))
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod
                        , "Identity Provider url isn't unique: " + sIdPURL);
                    throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR);
                }
                
                _htIdPs.put(sIdPURL, sAlias);
                _vIdPs.add(sIdPURL);
                
                oIdP = _configManager.getNextSection(oIdP);
            }
            
            String sTemplateName = null;
            try
            {
                sTemplateName = _configManager.getParam(oConfig, "template");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'template' found", e);
                throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            String sWorkingDir = _configManager.getWorkingdir();
            StringBuffer sbTemplateFilename = new StringBuffer();
            sbTemplateFilename.append(sWorkingDir);
            if (!sWorkingDir.endsWith(File.separator))
                sbTemplateFilename.append(File.separator);
            sbTemplateFilename.append("conf");
            sbTemplateFilename.append(File.separator);
            sbTemplateFilename.append("html");
            sbTemplateFilename.append(File.separator);
            sbTemplateFilename.append(sTemplateName);
            
            File fTemplate = new File(sbTemplateFilename.toString());
            if (!fTemplate.exists())
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "Configured template does not exists: " + sbTemplateFilename.toString());
                throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
            }
            _sTemplate = readTemplate(fTemplate);
	    }
	    catch (ASelectException e)
	    {
	        throw e;
	    }
	    catch (Exception e)
	    {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	}
    
    /**
     * Processes the following requests:<br/>
     * <br/>
     * <b>a)</b>
     * <code>?providerId=[providerId]&shire=[shire]&target=[target]&time=[time]</code><br/>
     * The <code>time</code> parameter is optional, if available the request will be checked 
     * for expiration. A request is expired if the sent time has a bigger delay 
     * then the configured offset.<br/>
     * As result of this request, the WAYF page will be shown.<br/>
     * <b>b)</b>
     * <code>?providerId=[providerId]&shire=[shire]&target=[target]&idp=[idp]</code><br/>
     * This request results in a redirect to the 'idp'.<br/>
     * If a cookie is available with the name 'idp' then this idp will be 
     * selected in the pulldown.
     * <br/><br/>
     * During processing, the following steps are runned through:
     * <ul>
     * <li>checking validity of the request parameters</li>
     * <li>verify optional request time with configured offset</li>
     * <li>checks if idp parameter is available in request, if available the 
     * user will be redirected else the WAYF page will be shown</li>
     * </ul>
     * <br><br>
     * @see org.aselect.server.request.handler.AbstractRequestHandler#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public RequestState process(HttpServletRequest request, HttpServletResponse response) throws ASelectException
    {
        String sMethod = "process()";
        try
        {
	        String sProviderId = request.getParameter("providerId"); //application ID
	        if (sProviderId == null)
	        {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "Missing request parameter 'providerId'");
                throw new ASelectException (Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
	        }
	        
			String sShire = request.getParameter("shire"); //response address
			if (sShire == null)
	        {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "Missing request parameter 'shire'");
                throw new ASelectException (Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
	        }
			
			String sTarget = request.getParameter("target"); //information
			if (sTarget == null)
	        {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod
                    , "Missing request parameter 'target'");
                throw new ASelectException (Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
	        }
			
			String sTime = request.getParameter("time"); //current time at the application
			if (sTime != null)
	        {
			    long lOffset = 0;
			    try
			    {
			        long lTime = Long.parseLong(sTime);
			        lTime = lTime * 1000;
			        lOffset = System.currentTimeMillis() - lTime;
			        if (lOffset < 0)
			            lOffset = lOffset * -1;
			    }
			    catch(NumberFormatException e)
			    {
			        _systemLogger.log(Level.WARNING, MODULE, sMethod
	                    , "Request item 'time' isn't a number: " + sTime);
	                throw new ASelectException (Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST, e);
			    }
			    
			    if (lOffset > _lTimeOffset)
			    {
			        StringBuffer sbError = new StringBuffer();
			        sbError.append("Request not accepted; Time offset is '");
			        sbError.append(lOffset);
			        sbError.append("' , it may be: ");
			        sbError.append(_lTimeOffset);
			        _systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
			        
			        throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			    }
			}
			
            String sIdP = request.getParameter("idp");
            
            if (sIdP != null)
            {
                if (!_vIdPs.contains(sIdP))
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Unknown IdP in request: " + sIdP);
                    throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                }
                
                handleSubmit(sIdP, sTarget, sShire, sProviderId, response);
            }
            else
            {
                String sSelectedIdP = null;
        		String sCookieValue = HandlerTools.getCookieValue(request, COOKIENAME, _systemLogger);
/*                Cookie oCookie[] = request.getCookies();
                if (oCookie != null)
                {
                    for (int i = 0; i < oCookie.length; i++)
                    {
                        String sCookieName = oCookie[i].getName();
    
                        if (sCookieName.equals(COOKIENAME))
                        {
                            String sCookieValue = oCookie[i].getValue();
                            
                            //remove '"' surrounding the cookie if applicable
                            int iLength = sCookieName.length();
                            if(sCookieName.charAt(0) == '"' &&
                                sCookieName.charAt(iLength-1) == '"')
                            {
                                sCookieName = sCookieName.substring(1, iLength-1);
                            }
*/
                            
                if (sCookieValue==null || !_vIdPs.contains(sCookieValue))
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod,
                    		"Invalid '"+COOKIENAME+"'  cookie, unknown value: "+sCookieValue);
                    throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                }
                sSelectedIdP = sCookieValue;
/*                        }
                    }
                }
*/
                String sAction = request.getRequestURL().toString();
                handleShowForm(sSelectedIdP, sAction, sTarget, sShire, sProviderId, response);
            }
	    }
        catch (ASelectException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        
        return new RequestState(null);
    }

    /**
     * Clears class variables from memory.
     * <br><br>
     * @see org.aselect.server.request.handler.AbstractRequestHandler#destroy()
     */
    public void destroy()
    {
        //does nothing        
    }

    /**
     * Displays the WAYF selection page.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Replaces the following tags in the template:<br>
     * <li>[target]</li>
     * <li>[shire]</li>
     * <li>[providerid]</li>
     * <li>[action]</li>
     * <li>[options]</li>
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <li>sAction != null</li>
     * <li>sTarget != null</li>
     * <li>sShire != null</li>
     * <li>sProviderId != null</li>
     * <li>response != null</li>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br><br>
     * @param sSelectedIdP <code>null</code> or the idp alias that will be 
     * selected in the pulldown 
     * @param sAction the action field of the form
     * @param sTarget the target parameter, copied from the request
     * @param sShire the shire parameter, copied from the request
     * @param sProviderId the providerid parameter, copied from the request
     * @param response the HttpServletResponse to which the page will be shown
     * @throws ASelectException if the page can't be shown
     */
    private void handleShowForm(String sSelectedIdP
        , String sAction
        , String sTarget
        , String sShire
        , String sProviderId
        , HttpServletResponse response)
        throws ASelectException
    {
        String sMethod = "handleSubmit()";
        PrintWriter pwOut = null;
        
        try
        {
            pwOut = response.getWriter();
            String sTemplate = _sTemplate;
            
            StringBuffer sbSelection = new StringBuffer();
            for (int i = 0; i < _vIdPs.size(); i++)
            {
                String sURL = (String)_vIdPs.get(i);
                String sAlias = (String)_htIdPs.get(sURL);
                
                sbSelection.append("<OPTION VALUE=");
                sbSelection.append(sURL);

                if (sSelectedIdP != null && sURL.equals(sSelectedIdP))
                    sbSelection.append(" SELECTED");
                
                sbSelection.append(">");
                sbSelection.append(sAlias);
                sbSelection.append("</OPTION>");
            }
            
            sTemplate = Utils.replaceString(sTemplate, "[target]", sTarget);
            sTemplate = Utils.replaceString(sTemplate, "[shire]", sShire);
            sTemplate = Utils.replaceString(sTemplate, "[providerid]", sProviderId);
            sTemplate = Utils.replaceString(sTemplate, "[action]", sAction);
            sTemplate = Utils.replaceString(sTemplate, "[options]", sbSelection.toString());
            
            pwOut.print(sTemplate);
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not show form", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        finally
        {
            if (pwOut != null)
                pwOut.close();
        }
    }
    
    /**
     * Redirects the user to the selected IdP.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * <li>sets a cookie with the selected IdP</li>
     * <li>if cookie domain is configured, the cookie will be set to the 
     * configured domain</li>
     * <li>creates a new <code>time</code> parameter value</li>
     * <li>sends a redirect with the following parameters: 
     * <code>[idp]?target=[target]&shire=[shire]&providerId=[providerId]&time=[time]</code></li>
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * <li>sIdP != null</li>
     * <li>sTarget != null</li>
     * <li>sShire != null</li>
     * <li>sProviderId != null</li>
     * <li>response != null</li>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sIdP the URL to the IdP
     * @param sTarget the target parameter
     * @param sShire the shire parameter
     * @param sProviderId the providerId parameter
     * @param response the HttpServletResponse to which the redirect will be sent
     * @throws ASelectException if the cookie or the redirect fails
     */
    private void handleSubmit(String sIdP
        , String sTarget
        , String sShire
        , String sProviderId
        , HttpServletResponse response)
        throws ASelectException
    {
        String sMethod = "handleSubmit()";
        try {
        	HandlerTools.putCookieValue(response, COOKIENAME, sIdP, _sCookieDomain, -1, _systemLogger);
/*            Cookie oWAYFCookie = new Cookie(COOKIENAME, sIdP);
            
            if (_sCookieDomain != null)
                oWAYFCookie.setDomain(_sCookieDomain);
    
    		_systemLogger.log(Level.INFO, MODULE, sMethod, "Add Cookie="+oWAYFCookie.getName()+" domain="+_sCookieDomain);
            response.addCookie(oWAYFCookie);
*/                        
            //add a '?' char after the selected IdP URL
            if (!sIdP.endsWith("?"))
                sIdP = sIdP + "?";
            
            long lTime = System.currentTimeMillis() / 1000;
            
            StringBuffer sbRedirect = new StringBuffer(sIdP);
            sbRedirect.append("target=").append(URLEncoder.encode(sTarget, "UTF-8"));
            sbRedirect.append("&shire=").append(URLEncoder.encode(sShire, "UTF-8"));
            sbRedirect.append("&providerId=").append(URLEncoder.encode(sProviderId, "UTF-8"));
            sbRedirect.append("&time=").append(lTime);
            
            response.sendRedirect(sbRedirect.toString());
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not handle form request", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }

    /**
     * Reads the given file and returns it as String
     * <br><br>
    * @param fTemplate the full file name to the template
    * @return the template as String
    * @throws ASelectException if the file couldn't be read
    */
    protected String readTemplate(File fTemplate) throws ASelectException
	{
	    String sMethod = "readTemplate()";
	    BufferedReader brIn = null;
	    String sLine = null;
	    StringBuffer sbReturn = new StringBuffer();
	    try
	    {
	        brIn = new BufferedReader(
	            new InputStreamReader(new FileInputStream(fTemplate)));
	
	        while ((sLine = brIn.readLine()) != null)
	        {
	            sbReturn.append(sLine);
	            sbReturn.append("\n");
	        }
	    }
	    catch (Exception e)
	    {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not read template", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	    finally
	    {
	        try
	        {
	            if (brIn != null)
	                brIn.close();
	        }
	        catch (IOException e)
	        {
	            _systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close BufferedReader", e);
	        }
	    }
	    return sbReturn.toString();
	}
}
