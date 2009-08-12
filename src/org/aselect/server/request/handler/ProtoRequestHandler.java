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
 *
 * @author Bauke Hiemstra - www.anoigo.nl
 * 
 * Version 1.0 - 14-11-2007
 * Generic abstract request handler to support different protocols
 * Currently also collects methods that should go to a more general library (like system)
 */
package org.aselect.server.request.handler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xerces.parsers.DOMParser;
import org.apache.xml.security.signature.XMLSignature;
import org.aselect.server.attributes.AttributeGatherer;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.opensaml.SAMLSubject;
import org.opensaml.common.SignableSAMLObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.opensaml.xml.validation.ValidationException;

//
//
//
public abstract class ProtoRequestHandler extends AbstractRequestHandler
{
    public final static String MODULE = "ProtoRequestHandler";
    protected final static String DEFAULT_CHARSET = "UTF8";
    protected TGTManager _tgtManager;
    protected Saml11Builder _saml11Builder = null;
    protected String _sASelectServerID;
    protected String _sASelectOrganization;
	protected String _sServerUrl;

    protected Vector _vIdPUrls;
    protected HashMap _htIdPs;

    public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init()";
		try {
			super.init(oServletConfig, oConfig);

			_tgtManager = TGTManager.getHandle();
			_sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);
			_sASelectServerID = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);
			_sASelectOrganization = ASelectConfigManager.getParamFromSection(null, "aselect", "organization", true);

  			// Initialize assertion building, if needed
	        if (useConfigToCreateSamlBuilder())
        		_saml11Builder = createSAML11Builder(oConfig, getSessionIdPrefix());
	        else
		        _saml11Builder = new Saml11Builder();  // object only
		}
        catch (ASelectException e) {
            throw e;
        }
        catch (Exception e) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
	}

    // To be overridden
    public String serializeTheseAttributes(HashMap htAttribs)
    throws ASelectException
    {
        _systemLogger.log(Level.INFO, MODULE, "serializeTheseAttributes()", "No OVERRIDE for this method!!");
    	return "";
    }
    
    // Default implementation
    // In Subclasses you can redefine this method:
    // - return false if you need a SamlBuilder object only
    // - return true if you also want to recognize config parameters: 
    //		<assertion expire="600"/>
    //		<attribute namespace="..." send_statement="true"/>
    protected boolean useConfigToCreateSamlBuilder()
    {
    	return false;
    }
    
    // Define the prefix used to create a RID-key
    // Default is an empty prefix
    protected String getSessionIdPrefix()
    {
    	return "";
    }
    
    // Look for the "aselect_credentials" cookie
    // Retrieve TGT and TGT Context
    // Gather attributes and copy them over the TGT Context Attributes
    // Return all data as Credentials
    //
    // Bauke 20081209: getCredentialsFromCookie now returns a string
    //
    protected HashMap getASelectCredentials(HttpServletRequest servletRequest)
    throws ASelectException
    {
    	String sMethod = "getAselectCredentials";

        // Check for credentials that might be present
    	String sTgt = getCredentialsFromCookie(servletRequest);
        //if (htCredentialsParams == null)
        //    return null;
        
        //String sTgt = (String)htCredentialsParams.get("tgt");
        //String sUserId = (String)htCredentialsParams.get("uid");
        //String sServerId = (String)htCredentialsParams.get("a-select-server");
        if (sTgt == null) // || (sUserId == null) || (sServerId == null)
            return null;
        //if (!sServerId.equals(_sASelectServerID))
        //    return null;
        
        HashMap htTGTContext = getContextFromTgt(sTgt, true);  // Check expiration
        if (htTGTContext == null)
            return null;
        String sUserId = (String)htTGTContext.get("uid");
        if (sUserId == null)
        	return null;
        
        // Check corresponding parameters
        //if (!sUserId.equals(htTGTContext.get("uid"))) {
        //    _systemLogger.log(Level.INFO, MODULE, sMethod, "sUserId="+ sUserId+" != uid="+htTGTContext.get("uid"));
        //    return null;
        //}
        String sRid = (String)htTGTContext.get("rid");  // Bauke: added
        if (sRid == null) {
            _systemLogger.log(Level.INFO, MODULE, sMethod, "sRid="+ sUserId+" != uid="+htTGTContext.get("rid"));
        	return null;
        }
        _systemLogger.log(Level.INFO, MODULE, sMethod, "Attributes for sUserId="+ sUserId+" rid="+sRid);
        
        // Gather attributes, but also use the attributes from the ticket context
        HashMap htAllAttributes = getAttributesFromTgtAndGatherer(htTGTContext);

        // And assemble the credentials
        _systemLogger.log(Level.INFO, MODULE, sMethod, "Credentials for sUserId="+ sUserId+" rid="+sRid);
    	HashMap htCredentials = new HashMap();
        //htCredentials.put("aselect_credentials", sCredentialsCookie);  // not crypted
        htCredentials.put("rid", sRid);
        htCredentials.put("uid", sUserId);
        htCredentials.put("a-select-server", _sASelectServerID);  // sServerId);
        htCredentials.put("tgt", sTgt);
        String sPar = (String)htTGTContext.get("tgt_exp_time");
        if (sPar != null) htCredentials.put("tgt_exp_time", sPar);
        sPar = (String)htTGTContext.get("app_id");
        if (sPar != null) htCredentials.put("app_id", sPar);
        sPar = (String)htTGTContext.get("organization");
        if (sPar != null) htCredentials.put("organization", sPar);
        sPar = (String)htTGTContext.get("app_level");
        if (sPar != null) htCredentials.put("app_level", sPar);
        sPar = (String)htTGTContext.get("authsp_level");
        if (sPar != null) {
        	htCredentials.put("authsp_level", sPar);
            htAllAttributes.put("authsp_level", sPar);
        }
        sPar = (String)htTGTContext.get("authsp");
        if (sPar != null) htCredentials.put("authsp", sPar);
        sPar = (String)htTGTContext.get("authsp");
        if (sPar != null) htCredentials.put("authsp", sPar);

        // Bauke, 20081209 added for ADFS / WS-Fed
        String sPwreply = (String)htTGTContext.get("wreply");
        if (sPwreply != null) htCredentials.put("wreply", sPwreply);            
        String sPwtrealm = (String)htTGTContext.get("wtrealm");
        if (sPwtrealm != null) htCredentials.put("wtrealm", sPwtrealm);
        String sPwctx = (String)htTGTContext.get("wctx");
        if (sPwctx != null) htCredentials.put("wctx", sPwctx);
        
        // And put the attributes back where they belong
        String sSerializedAttributes = serializeTheseAttributes(htAllAttributes);
        if (sSerializedAttributes != null)
        	htCredentials.put("attributes", sSerializedAttributes);
        htCredentials.put("result_code", Errors.ERROR_ASELECT_SUCCESS);
        return htCredentials;
    }

	public HashMap getAttributesFromTgtAndGatherer(HashMap htTGTContext)
	throws ASelectException
	{
		String sMethod = "getAttributesFromTgtAndGatherer()";
        String sCtxAttribs = (String)htTGTContext.get("attributes");
        if (_saml11Builder == null) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "_saml11Builder not set");
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        HashMap htCtxAttribs = _saml11Builder.deserializeAttributes(sCtxAttribs);
        _systemLogger.log(Level.INFO, MODULE, sMethod, "Attributes from TGTContext="+htCtxAttribs);
        
        AttributeGatherer oAttributeGatherer = AttributeGatherer.getHandle();
        HashMap htAttribs = oAttributeGatherer.gatherAttributes(htTGTContext);
        if (htAttribs == null) htAttribs = new HashMap();
        _systemLogger.log(Level.INFO, MODULE, sMethod, "Attributes after Gathering="+htAttribs);  // can be empty
        
        // Copy the gathered attributes over the ticket context attributes
		Set keys = htAttribs.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
        //Enumeration eAttr = htAttribs.keys();
        //while (eAttr.hasMoreElements()) {
        	//String sKey = (String)eAttr.nextElement();
        	htCtxAttribs.put(sKey, htAttribs.get(sKey));
        }
        return htCtxAttribs;
	}

	public HashMap getContextFromTgt(String sTgt, boolean checkExpiration)
	throws ASelectException
	{
		String sMethod = "getContextFromTgt()";
		TGTManager _tgtManager = TGTManager.getHandle();
		
		int len = sTgt.length();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "getTGT("+sTgt.substring(0, (len<30)? len: 30)+"...)");
        HashMap htTGTContext = _tgtManager.getTGT(sTgt);
        if (htTGTContext == null)
            return null;
        
        if (checkExpiration) {
	        long lExpTime = 0;
	        try {
	            lExpTime = _tgtManager.getExpirationTime(sTgt);
	        }
	        catch(ASelectStorageException eAS) {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not fetch TGT timeout",eAS);
	            throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);   
	        }
	        if (lExpTime <= System.currentTimeMillis()) { // TGT no longer valid
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, "TGT expired");
	            return null;
	        }
	        // Pass along as well
	        htTGTContext.put("tgt_exp_time", new Long(lExpTime).toString());
        }
        return htTGTContext;
	}
	
    // Bauke 20081209: getCredentialsFromCookie now returns a string
	//
	public String getCredentialsFromCookie(HttpServletRequest servletRequest) 
	{
		String sMethod = "getCredentialsFromCookie";
		
		String sCredentialsCookie = HandlerTools.getCookieValue(servletRequest, "aselect_credentials", _systemLogger);
        if (sCredentialsCookie == null)
            return null;
        
        _systemLogger.log(Level.INFO, MODULE, sMethod, "sCredentialsCookie="+sCredentialsCookie);
        /* Bauke,  20081209: Cookie only contains tgt-value
        HashMap htCredentialsParams = Utils.convertCGIMessage(sCredentialsCookie);
        _systemLogger.log(Level.INFO, MODULE, sMethod, "CredentialsParams="+htCredentialsParams);
        return htCredentialsParams; */
        return sCredentialsCookie;
    }
        
    // Bauke: moved from ShibbolethWAYFProfile
	protected String readTemplate(File fTemplate)
	throws ASelectException
	{
	    String sMethod = "readTemplate()";
	    BufferedReader brIn = null;
	    String sLine = null;
	    StringBuffer sbReturn = new StringBuffer();
	    try {
	        brIn = new BufferedReader(
	            new InputStreamReader(new FileInputStream(fTemplate)));
	
	        while ((sLine = brIn.readLine()) != null)
	        {
	            sbReturn.append(sLine);
	            sbReturn.append("\n");
	        }
	    }
	    catch (Exception e) {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not read template", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	    finally {
	        try {
	            if (brIn != null)
	                brIn.close();
	        }
	        catch (IOException e) {
	            _systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close BufferedReader", e);
	        }
	    }
	    return sbReturn.toString();
	}

	// Bauke: added
	protected String readTemplateFromConfig(Object oConfig, String sName)
	throws ASelectException
	{
		String sMethod = "readTemplateFromConfig()";
		String sTemplateName = null;
	    try {
	        sTemplateName = _configManager.getParam(oConfig, sName);
	    }
	    catch (ASelectConfigException e) {
	        _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item '"+sName+"' found", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
	    }
	    _systemLogger.log(Level.INFO, MODULE, sMethod, "Read template: "+sTemplateName);
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
	        _systemLogger.log(Level.WARNING, MODULE, sMethod, "Configured template does not exists: " +
	        				sbTemplateFilename.toString());
	        throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
	    }
	    return readTemplate(fTemplate);
	}

	/* Read an xml config structure like: 
	    <authentication_method>
	            <security level=5 urn="urn:oasis:names:tc:SAML:1.0:cm:unspecified">
	            <security level=10 urn="urn:oasis:names:tc:SAML:1.0:cm:password">
	            <security level=20 urn="urn:oasis:names:tc:SAML:1.0:cm:sms">
	            <security level=30 urn="urn:oasis:names:tc:SAML:1.0:cm:smartcard">
	    </authentication_method>
	 */
	protected void getTableFromConfig(Object oConfig, Vector vAllKeys, HashMap htAllKeys_Values,
			String sMainSection, String sSubSection, String sKeyName, String sValueName,
			boolean mandatory, boolean uniqueValues)
	throws ASelectException, ASelectConfigException
	{
		String sMethod = "getProvidersFromConfig";
		
		Object oProviders = null;
	    try {
	        oProviders = _configManager.getSection(oConfig, sMainSection);
	    }
	    catch (ASelectConfigException e) {
	    	if (!mandatory)
	    		return;
	        _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section '"+sMainSection+"' found", e);
	        throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
	    }
	    
	    Object oProvider = null;
	    try {
	        oProvider = _configManager.getSection(oProviders, sSubSection);
	    }
	    catch (ASelectConfigException e) {
	        _systemLogger.log(Level.WARNING, MODULE, sMethod, "Not even one config section '"+sSubSection+"' found in the '"+sMainSection+"' section", e);
	        throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
	    }
	   while (oProvider != null)
	    {
	        String sValue = null;
	        try {
	            sValue = _configManager.getParam(oProvider, sValueName);
	        }
	        catch (ASelectConfigException e) {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item '"+sValueName+"' found in '"+sSubSection+"' section", e);
	            throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
	        }
	        
	        String sKey = null;
	        try {
	            sKey = _configManager.getParam(oProvider, sKeyName);
	        }
	        catch (ASelectConfigException e) {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item '"+sKeyName+"' found in '"+sSubSection+"' section", e);
	            throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
	        }
	
	        // Key must be unique
	        if (htAllKeys_Values.containsKey(sKey)) {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, "Provider '"+sKeyName+"' is not unique: " + sKey);
	            throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR);
	        }

	        if (uniqueValues) {
		        // Also check for unique values
		        if (htAllKeys_Values.containsValue(sValue)) {
		            _systemLogger.log(Level.WARNING, MODULE, sMethod, "Provider '"+sValueName+"' isn't unique: " + sValue);
		            throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR);
		        }
	        }
	        if (vAllKeys != null) vAllKeys.add(sKey);
	        htAllKeys_Values.put(sKey, sValue);
	        
	        oProvider = _configManager.getNextSection(oProvider);
	    }
	}
	
	/**
	 * Shows the main A-Select Error page with the approprate errors. <br>
	 * <br>
	 * @param sErrorCode
	 * @param htSessionContext
	 * @param pwOut
	 */
    protected void showErrorPage(String sErrorCode, HashMap htSessionContext, PrintWriter pwOut)
    {
        String sMethod = "showErrorPage()";
    	_systemLogger.log(Level.INFO, MODULE, sMethod, "FORM[error] "+sErrorCode+":"+
				_configManager.getErrorMessage(sErrorCode));
        try {
            String sErrorForm = _configManager.getForm("error");
            sErrorForm = Utils.replaceString(sErrorForm, "[error]", sErrorCode);
            sErrorForm = Utils.replaceString(sErrorForm, "[error_message]",
            				_configManager.getErrorMessage(sErrorCode));
            
            sErrorForm = _configManager.updateTemplate(sErrorForm, htSessionContext);           
            pwOut.println(sErrorForm);        
        }
        catch (Exception e) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not display error page, error=" + sErrorCode, e);
        }
    }   

	//
	// Present IdP choice to the user
	//
	protected void handleShowForm(String sTemplate, String sSelectedIdP, String sAction,
			String sPassContext, String sReplyTo, String sCurrentTime,
			String sAselectUrl, String sRid, String sAselectServer, HttpServletResponse response)
	throws ASelectException
	{
	    String sMethod = "handleShowForm()";
	    PrintWriter pwOut = null;
	    _systemLogger.log(Level.INFO, MODULE, sMethod, "Form Action="+sAction+" Context="+sPassContext+
	    		" ReplyTo="+sReplyTo+" AselectUrl="+sAselectUrl+" Rid="+sRid+" Server="+sAselectServer);
	    
	    try {
	    	response.setContentType("text/html");
	        pwOut = response.getWriter();
	        
	        StringBuffer sbSelection = new StringBuffer();
	        for (int i = 0; _vIdPUrls != null && i < _vIdPUrls.size(); i++)
	        {
	            String sURL = (String)_vIdPUrls.get(i);
	            String sAlias = (String)_htIdPs.get(sURL);
	            
	            sbSelection.append("<OPTION VALUE=");
	            sbSelection.append(sURL);
	
	            if (sSelectedIdP != null && sURL.equals(sSelectedIdP))
	                sbSelection.append(" SELECTED");
	            
	            sbSelection.append(">");
	            sbSelection.append(sAlias);
	            sbSelection.append("</OPTION>\n");
	        }
	        sTemplate = Utils.replaceString(sTemplate, "[form_action]", sAction);
	        if (sReplyTo != null) sTemplate = Utils.replaceString(sTemplate, "[reply_to]", sReplyTo);
	        if (sPassContext != null) sTemplate = Utils.replaceString(sTemplate, "[pass_context]", sPassContext);
	        if (sCurrentTime != null) sTemplate = Utils.replaceString(sTemplate, "[current_time]", sCurrentTime);
	        sTemplate = Utils.replaceString(sTemplate, "[options]", sbSelection.toString());

	        // DigiD and local login
	        sTemplate = Utils.replaceString(sTemplate, "[aselect_url]", sAselectUrl);
		    sTemplate = Utils.replaceString(sTemplate, "[rid]", sRid);
		    sTemplate = Utils.replaceString(sTemplate, "[a-select-server]", sAselectServer);
	        
		    _systemLogger.log(Level.INFO, MODULE, sMethod, "Form "+sTemplate);
	        pwOut.print(sTemplate);
	    }
	    catch (Exception e) {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not show form", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	    finally {
	        if (pwOut != null)
	            pwOut.close();
	    }
	}
	
	protected void handlePostForm(String sTemplate, String sAction, String sInputLines, HttpServletResponse response)
	throws ASelectException
	{
	    String sMethod = "handlePostForm()";
	    PrintWriter pwOut = null;
	    _systemLogger.log(Level.INFO, MODULE, sMethod, "POST Form: Action="+sAction);
	    
	    try {
	        sTemplate = Utils.replaceString(sTemplate, "[form_action]", sAction);
	        sTemplate = Utils.replaceString(sTemplate, "[input_area]", sInputLines);
		    _systemLogger.log(Level.FINER, MODULE, sMethod, "sTemplate="+sTemplate);
	        
	    	response.setContentType("text/html");
	        pwOut = response.getWriter();
	        pwOut.print(sTemplate);
	    }
	    catch (Exception e) {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not POST form", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	    }
	    finally {
	        if (pwOut != null)
	            pwOut.close();
	    }
	}

	// No longer used
	protected String extractAselectServerUrl(HttpServletRequest request)
	{
		String sRequestURL = request.getRequestURL().toString();
		String sContextPath = request.getContextPath();
		int iLocation = sRequestURL.indexOf(sContextPath);  // Initial URL part
		String sStartURL = sRequestURL.substring(0, iLocation);
		return sStartURL + sContextPath + request.getServletPath();
	}

	protected HashMap performAuthenticateRequest(String sASelectURL, String sPathInfo,
			String sReturnSuffix, String sAppId, boolean checkSignature, IClientCommunicator iClientComm)
	throws ASelectException
	{
		String sMethod = "performAuthenticateRequest()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "AUTHN { "+sASelectURL+" - "+sPathInfo+" - "+sReturnSuffix);

		HashMap<String, String> hmRequest = new HashMap<String, String>();
		hmRequest.put("request", "authenticate");
		hmRequest.put("app_id", sAppId);
		hmRequest.put("app_url", sASelectURL + sPathInfo + sReturnSuffix); // My return address
		hmRequest.put("a-select-server", _sASelectServerID);
		hmRequest.put("check-signature", "false");  // Boolean.toString(checkSignature));
		// 20090423, Bauke: check-signature set to false, needs signature otherwise
		// TODO: add signature when checkSignature is true
	
		// 20090606: Bauke: changed external call to direct method call
		_systemLogger.log(Level.INFO, MODULE, sMethod, "hmRequest=" + hmRequest);
		HashMap<String,String> hmResponse = handleAuthenticateAndCreateSession(hmRequest, null);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "hmResponse=" + hmResponse);
		
/*		try {
			hmResponse = iClientComm.sendMessage(hmRequest, sASelectURL);
		}
		catch (Exception e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "} AUTHN Could not send authentication request");
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}
*/	
		String sResultCode = (String) hmResponse.get("result_code");
		if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"} AUTHN Authentication request was not successful, result_code=" + sResultCode);
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "} AUTHN htResponse=" + hmResponse);
		return hmResponse;
	}

	// Convenience method
	protected IClientCommunicator initClientCommunicator(Object oConfig)
	throws ASelectException
	{
		return Tools.initClientCommunicator(ASelectConfigManager.getHandle(), _systemLogger, oConfig);
	}

	public String decryptCredentials(String encrypted)
	throws ASelectException
	{
    	String sMethod = "decryptCredentials()";
	    try
	    {
	        byte[] baTgtBytes = CryptoEngine.getHandle().decryptTGT(encrypted);
	        return Utils.toHexString(baTgtBytes);
	    }
	    catch(ASelectException eAC) //decrypt failed
	    {
	        _systemLogger.log(Level.WARNING, MODULE, sMethod, "could not decrypt TGT",eAC);
	        throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID,eAC);
	    }
	    catch(Exception e) //HEX conversion fails
	    {
	        _systemLogger.log(Level.WARNING, MODULE, sMethod, "could not decrypt TGT",e);
	        throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID,e);
	    }
	}

	protected void storeSessionDataWithRid(HttpServletResponse response, HashMap htSessionMoreData,
					String sPrefix, String sRid)
	{
		String sMethod = "storeRidSessionData()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Update Session: "+sPrefix+sRid+
				" htSessionMoreData="+htSessionMoreData);

		// RH, 20080619, sn
		// TODO, this method is now only used by idff and wsfed
		//		we might have to set the client_ip here as well
		//		but we need to get the client_ip address from somewhere
//        _systemLogger.log(Level.INFO, MODULE, sMethod, "htSessionData client_ip was "+ htSessionData.get("client_ip"));
//        htSessionData.put("client_ip", ???);
//        _systemLogger.log(Level.INFO, MODULE, sMethod, "htSessionData client_ip is now "+ htSessionData.get("client_ip"));
		// RH, 20080619, en
		
		// Bauke 20081209 Update the session instead of always creating a new one
		// This will also give you the "client_ip" Remy.
		HashMap htSessionData = _oSessionManager.getSessionContext(sPrefix + sRid);
		if (htSessionData == null)
			_oSessionManager.writeSession(sPrefix + sRid, htSessionMoreData);
		else {
			htSessionData.putAll(htSessionMoreData);
			_systemLogger.log(Level.INFO, MODULE, sMethod,"Update Session:"+htSessionData);
			_oSessionManager.updateSession(sPrefix + sRid, htSessionData);
		}
		
		// Also store the rid used
		String sCookieDomain = _configManager.getCookieDomain();
		HandlerTools.putCookieValue(response, sPrefix+"rid", sRid, sCookieDomain, -1, _systemLogger);
	}

	protected HashMap retrieveSessionDataFromRid(HttpServletRequest request, String sPrefix)
	{
		String sMethod = "retrieveRidSessionData()";
		
		String sRidCookie = HandlerTools.getCookieValue(request, sPrefix+"rid", _systemLogger);
		if (sRidCookie == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot find 'rid' in cookie '"+sPrefix+"rid'");
			return null;
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Find session:"+ sPrefix + sRidCookie);
		HashMap htSessionData = _oSessionManager.getSessionContext(sPrefix + sRidCookie);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "htSessionData="+ htSessionData);
		
		htSessionData.put("session_rid", sRidCookie);  // in case we need it
		return htSessionData;
	}

	protected Saml11Builder createSAML11Builder(Object oConfig, String sPrefix)
	throws ASelectException
	{
		String sMethod = "createSAML11Builder()";
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "sPrefix="+sPrefix);
		String sSendStatement = ASelectConfigManager.getParamFromSection(oConfig, "attribute", "send_statement", true);
		if (!sSendStatement.equalsIgnoreCase("true") &&	!sSendStatement.equalsIgnoreCase("false")) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Config item 'send_statement' in 'attribute' section must be 'true' or 'false'");
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}
		boolean bSendAttributeStatement = new Boolean(sSendStatement).booleanValue();
	
		String sAttrNameSpace = ASelectConfigManager.getParamFromSection(oConfig, "attribute", "namespace", true);		
		String sAssertionExpireTime = ASelectConfigManager.getParamFromSection(oConfig, "assertion", "expire", true);
		long lExpire = 0;
		try {
			lExpire = Long.parseLong(sAssertionExpireTime);
		}
		catch (NumberFormatException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Config item 'expire' in 'assertion' section isn't a number: " + sAssertionExpireTime);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		if (lExpire < 1) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Config item 'expire' in 'assertion' section must be higher than 0 and not: " + sAssertionExpireTime);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}
		return new Saml11Builder(sAttrNameSpace, bSendAttributeStatement, lExpire * 1000,
						_sASelectServerID, sPrefix);
	}

	public String buildHtmlInput(String sName, String sValue)
	{
		if (sValue == null)
			return "";
		return "<input type=\"hidden\" name=\""+sName+"\" value=\""+sValue+"\"/>\n";
	}

	// The policy to extract Uid and Attributes from an Assertion
	//
	protected HashMap extractUidAndAttributes(String sAssertion)
	{
		HashMap htAttributes = extractAllAttributes(sAssertion);
		String sUid = (String)htAttributes.get("digid_uid");
		if (sUid == null) sUid = (String)htAttributes.get("uid");
		if (sUid == null) sUid = (String)htAttributes.get("cn");
		if (sUid == null) {
			sUid = extractNameIdentifier(sAssertion);
		}
		if (sUid != null && htAttributes.get("uid") == null) {
			// We want at least the "uid" attribute, so other A-Select servers can work with the result
			htAttributes.put("uid", sUid);
		}
		_systemLogger.log(Level.INFO, MODULE, "extractUidAndAttributes()", "htAttributes=" + htAttributes);	
		return htAttributes;
	}
	
	protected String extractNameIdentifier(String sAssertion)
	{
		String sResult = Tools.extractFromXml(sAssertion, "saml:NameIdentifier", true);
		_systemLogger.log(Level.INFO, MODULE, "extractNameIdentifier", "sResult=" + sResult);
		if (sResult == null) {
			sResult = Tools.extractFromXml(sAssertion, "NameIdentifier", true);
			_systemLogger.log(Level.INFO, MODULE, "extractNameIdentifier", "sResult=" + sResult);
		}
		return sResult;
	}

	protected HashMap extractAllAttributes(String sAssertion)
	{
		final String ATTRNAME = "AttributeName=";
		final String ATTRVALUE = "AttributeValue>";
		final String ATTRVALUE2 = "saml:AttributeValue>";
		String sMethod = "extractAllAttributes";
		HashMap htResult = new HashMap();
		int nIdx, nEnd;
		String sAttrName, sAttrValue;
		int aNameLen = ATTRNAME.length();
		int aValueLen = ATTRVALUE.length();
	
		for (nIdx = 0; ; ) {
			nIdx = sAssertion.indexOf(ATTRNAME, nIdx);
			if (nIdx < 0) break;
			nIdx += aNameLen;
			if (sAssertion.charAt(nIdx) == '"')
				nIdx++;
			for (nEnd = nIdx; ; nEnd++) {
				if (sAssertion.charAt(nEnd) == '"' || sAssertion.charAt(nEnd) == ' ' ||
						sAssertion.charAt(nEnd) == '\t' || sAssertion.charAt(nEnd) == '\r' || sAssertion.charAt(nEnd) == '\n')
					break;
			}
			if (nEnd <= nIdx)
				continue;
			sAttrName = sAssertion.substring(nIdx, nEnd);
		    //_systemLogger.log(Level.INFO, MODULE, sMethod, "AttributeName="+sAttrName);
			
		    nIdx = sAssertion.indexOf(ATTRVALUE, nEnd);
			if (nIdx < 0) break;
			nIdx += aValueLen;  // Start of value
			nEnd = sAssertion.indexOf("</"+ATTRVALUE, nIdx);
			if (nEnd < 0) {
				nEnd = sAssertion.indexOf("</"+ATTRVALUE2, nIdx);
				if (nEnd < 0)
					continue;
			}
			sAttrValue = sAssertion.substring(nIdx, nEnd);
		    //_systemLogger.log(Level.INFO, MODULE, sMethod, "AttributeValue="+sAttrValue);
		    nIdx = nEnd + 2 + aValueLen;
			
		    htResult.put(sAttrName, sAttrValue);
		}
	    _systemLogger.log(Level.INFO, MODULE, sMethod, "htResult="+htResult);
		return htResult;
	}

	public String createContextAndIssueTGT(HttpServletResponse response, String sRid /* can be null */,
					String sServerId, String sOrg, String sAppId, String sTgt, HashMap htAttributes)
	throws ASelectException
	{
		String sMethod = "createContextAndIssueTGT()";
	    SessionManager _sessionManager = SessionManager.getHandle(); // RH, 20080617, n
	    HashMap htSession = null;
	    
		// Extract uid and security level
		String sUserId = (String)htAttributes.get("digid_uid");
		if (sUserId == null) sUserId = (String)htAttributes.get("uid");
		if (sUserId == null) sUserId = (String)htAttributes.get("cn");
	
		String sSecLevel = (String)htAttributes.get("digid_betrouwbaarheidsniveau");
		if (sSecLevel == null) sSecLevel = (String)htAttributes.get("betrouwbaarheidsniveau");
		if (sSecLevel == null) sSecLevel = (String)htAttributes.get("authsp_level");
		if (sSecLevel == null) sSecLevel = "5";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "UserId="+sUserId+", secLevel="+sSecLevel);
		
		htAttributes.put("uid", sUserId);
		htAttributes.put("betrouwbaarheidsniveau", sSecLevel);
	
		// TODO following code should go to tgt.TGTIssuer, RH 20080617
		HashMap htTGTContext = new HashMap();
        if (_saml11Builder == null) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "_saml11Builder not set");
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
		htTGTContext.put("attributes", _saml11Builder.serializeAttributes(htAttributes));
	
		htTGTContext.put("uid", sUserId);
		htTGTContext.put("betrouwbaarheidsniveau", sSecLevel);
		htTGTContext.put("organization", sOrg);
		htTGTContext.put("authsp_level", sSecLevel);
		htTGTContext.put("authsp", "SAML");
		htTGTContext.put("app_id", sAppId);
		htTGTContext.put("app_level", "2");
//		if (sRid != null) htTGTContext.put("rid", sRid); // RH, 20080617, o
		// RH, 20080617, sn
		if (sRid != null) {
			htTGTContext.put("rid", sRid);
			htSession = _sessionManager.getSessionContext(sRid);
			if (htSession != null) {
				Utils.copyHashmapValue("client_ip", htTGTContext, htSession);
				Utils.copyHashmapValue("user_agent", htTGTContext, htSession);
				Utils.copyHashmapValue("authsp_type", htTGTContext, htSession);
			}
		}
		// RH, 20080617, en
	    
		if (sTgt == null) {
			sTgt = _tgtManager.createTGT(htTGTContext);
		}
		else {
			_tgtManager.updateTGT(sTgt, htTGTContext);
		}
		
		// We don't need the session any more
		if (sRid != null) {  // Bauke, 20081209 added
			Tools.calculateAndReportSensorData(ASelectConfigManager.getHandle(), _systemLogger, htSession);
			_sessionManager.killSession(sRid);
		}

		// No effect, cross functionality??:
		//htTGTContext.put("aselect_credentials_tgt", sTgt);
		//htTGTContext.put("aselect_credentials_uid", sUserId);
		//htTGTContext.put("aselect_credentials_server_id", _sMyServerId);
		
		//create cookie if single sign-on is enabled
		if (_configManager.isSingleSignOn()) {
            TGTIssuer tgtIssuer = new TGTIssuer(sServerId);
		    tgtIssuer.setASelectCookie(sTgt, sUserId, response);
		}
		return sTgt;
	}

	protected String createRequestorToken(HttpServletRequest request, String sProviderId, String sUid,
		String sUserDomain, String sNameIdFormat, String sAudience, HashMap htAttributes, String sSubjConf)
	throws ASelectException, SAMLException
	{
		String sMethod = "createRequestorToken";
		String sIP = request.getRemoteAddr();
		String sHost = request.getRemoteHost();
		if (sSubjConf == null)
			sSubjConf = SAMLSubject.CONF_BEARER;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Uid="+sUid+" IP=" + sIP + " Host="+
						sHost+" _saml11Builder="+_saml11Builder+" SubjConf="+sSubjConf);
		
        if (_saml11Builder == null) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "_saml11Builder not set");
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        if (sUid.indexOf('@') < 0) {
        	sUid += ((sUserDomain.startsWith("@"))? "": "@") + sUserDomain;
        }
        SAMLAssertion oSAMLAssertion = _saml11Builder.createMySAMLAssertion(sProviderId,
				sUid, sNameIdFormat, sIP, sHost, sSubjConf, sAudience, htAttributes);
		_systemLogger.log(Level.INFO,MODULE,sMethod, "oSAMLAssertion="+oSAMLAssertion);
	
        // Sign the assertion
		Vector vCertificatesToInclude = new Vector();
		vCertificatesToInclude.add(_configManager.getDefaultCertificate());
		
		_systemLogger.log(Level.INFO,MODULE,sMethod, "Sign");
		oSAMLAssertion.sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, 
							_configManager.getDefaultPrivateKey(), vCertificatesToInclude);
		//String sAdfs = "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">" +
		//		"<wsa:EndpointReference xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">" +
		//		"<wsa:Address>http://www.anoigo.nl/wsfed_idp.xml</wsa:Address>" +
		//		"</wsa:EndpointReference></wsp:AppliesTo>";
		
		return "<wst:RequestSecurityTokenResponse " +
				"xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" " +
				"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
				"<wst:RequestedSecurityToken>" + oSAMLAssertion.toString() +
				"</wst:RequestedSecurityToken>" + // sAdfs +
				"</wst:RequestSecurityTokenResponse>";
	}
	
	// For the new opensaml20 library
	// /*
	public boolean checkSignature(SignableSAMLObject ssObject, PublicKey pKey) throws ASelectException
	{
		/* "old" opensaml20 library code:
	    ASelectConfigManager _oASelectConfigManager = ASelectConfigManager.getHandle();
		String sMethod = "checkSignature(SignableSAMLObject ssObject)";
		Signature sig = ssObject.getSignature();
		
	    _systemLogger.log(Level.INFO,MODULE,sMethod, "pkey="+pKey);

	    SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
	    try {
	        profileValidator.validate(sig);
	    } catch (ValidationException e) {
	        // Indicates signature did not conform to SAML Signature profile
	        _systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot validate signature, signature did not conform to SAML Signature profile", e);
	        return false;
	    }

		BasicCredential credential = new BasicCredential();
		credential.setPublicKey(pKey);

		SignatureValidator sigValidator = new SignatureValidator(credential);
		try {
		    sigValidator.validate(sig);
		} catch (ValidationException e) {
		    // Indicates signature was not cryptographically valid, or possibly a processing error
	        _systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot verify signature, signature was not cryptographically valid, or possibly a processing error");
	        return false;
		}

		return true;
		*/
		return SamlTools.checkSignature(ssObject, pKey);
	}
	// */

	// For the new opensaml20 library
    /**
     * Sign OpenSAML2 library objects (including both SAML versions 1 and 2).
     * 
     * @param obj                   The object to be signed
     * @return obj                  The signed object
     * @throws ValidationException  Thrown if an error occurs while signing
     */
    public SignableSAMLObject sign(SignableSAMLObject obj)
    throws ASelectException
    {	
    	return SamlTools.sign(obj);
    }
    
	// opensaml 1.0 version
	public boolean checkSignature(String sResults)
	throws ASelectException
	{
	    ASelectConfigManager _oASelectConfigManager;
		String sMethod = "checkSignature()";
		// The Assertion is the signed object, so get it first
		String sAssertion = Tools.extractFromXml(sResults, "saml:Assertion", false);
		if (sAssertion == null)
			sAssertion = Tools.extractFromXml(sResults, "Assertion", false);
	
		try {
		    Element domElement = this.parseSamlMessage(sAssertion);
		    
		    //Tools.visitNode(null, domElement, _systemLogger);
	        _systemLogger.log(Level.INFO,MODULE,sMethod, "Create Assertion");
	        //MySAMLAssertion oAssert = new MySAMLAssertion(domElement, _systemLogger);
	        // TODO this is SAML11, is it also SAML20?
	        SAMLAssertion oAssert = new SAMLAssertion(domElement);
	        _systemLogger.log(Level.INFO,MODULE,sMethod, "Created");
	
	        if (oAssert.isSigned()) {
		        _systemLogger.log(Level.INFO,MODULE,sMethod, "Signed!");
			    _oASelectConfigManager = ASelectConfigManager.getHandle();
		        String _sKeystoreName = new StringBuffer(_oASelectConfigManager.getWorkingdir()).   	
		        		append(File.separator).append("keystores").append(File.separator).
		        		append("providers.keystore").toString();
		        
			    // Extract the Issuer to retrieve associated public key
			    String sIssuer = domElement.getAttribute("Issuer");
			    _systemLogger.log(Level.INFO,MODULE,sMethod, "Issuer="+sIssuer);
			    
		        PublicKey pKey = loadPublicKeyFromKeystore(_sKeystoreName, sIssuer);
			    _systemLogger.log(Level.INFO,MODULE,sMethod, "pkey="+pKey);
		        oAssert.verify(pKey);
		    }
		    else {
		        _systemLogger.log(Level.INFO,MODULE,sMethod, "Not Signed!");
		    }
		    _systemLogger.log(Level.INFO,MODULE,sMethod, "Verified");
	        return true;
	    }
		catch (SAMLException e) {
	        _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Cannot check signature", e);
	        throw new ASelectException(Errors.ERROR_ASELECT_PARSE_ERROR, e);
		}
	}
    
    PublicKey loadPublicKeyFromKeystore(String sKeystoreName, String sAlias)
	throws ASelectException
	{
	    String sMethod = "loadPublicKeyFromKeystore";
	    _systemLogger.log(Level.INFO, MODULE, sMethod, "Loading public key "+sAlias+" from "+sKeystoreName);
	    try {
	        sAlias = sAlias.toLowerCase();
	        KeyStore ksJKS = KeyStore.getInstance("JKS");
	        ksJKS.load(new FileInputStream(sKeystoreName), null);
	
	        java.security.cert.X509Certificate x509Privileged = 
	            (java.security.cert.X509Certificate)ksJKS.getCertificate(sAlias);	        
	        return x509Privileged.getPublicKey();
	    }
	    catch (Exception e) {
		    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot load public key for: "+sAlias);
		    throw new ASelectException(Errors.ERROR_ASELECT_NOT_FOUND);
	    }
	}

    public Element parseSamlMessage(String sMessage)
    throws ASelectCommunicationException
    {
        Element elBody = null;
        String sMethod = "parse()";
        if (!sMessage.equals(""))
        {
            try {
                DOMParser parser = new DOMParser();
                _systemLogger.log(Level.INFO, MODULE, sMethod, "PARSE message: "+sMessage);
    	        StringReader sr = new StringReader(sMessage);
                InputSource is = new InputSource(sr);
    	        _systemLogger.log(Level.INFO,MODULE,sMethod, "parse: "+Tools.clipString(sMessage, 100, true));
    	        parser.parse(is);
    	        _systemLogger.log(Level.INFO,MODULE,sMethod, "parsed");
    	        
                // Get root XML tag
                Document doc = (Document)parser.getDocument();
                Element elem = doc.getDocumentElement();
                return elem;
            }                
            catch (org.xml.sax.SAXException eSaxE) {
                StringBuffer sbBuffer = new StringBuffer("Error during parsing: ");
                sbBuffer.append(eSaxE.getMessage());
                sbBuffer.append(" errorcode: ");
                sbBuffer.append(Errors.ERROR_ASELECT_PARSE_ERROR);
                _systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eSaxE);
                throw new ASelectCommunicationException(Errors.ERROR_ASELECT_PARSE_ERROR,eSaxE); 
            }
            catch (java.io.IOException eIO) {
                StringBuffer sbBuffer = new StringBuffer("Error reading message from inputstream: ");
                sbBuffer.append(eIO.getMessage());
                sbBuffer.append(" errorcode: ");
                sbBuffer.append(Errors.ERROR_ASELECT_IO);
                _systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eIO);
                throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, eIO);
            }
        }
        return elBody;
    }

    // Make timestamp readable
	public String getReadableDate(long timestamp)
	{
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(new Date(timestamp));
		StringBuffer tmp = new StringBuffer();

		tmp.append(calendar.get(Calendar.DAY_OF_MONTH));
		tmp.append('.').append(calendar.get(Calendar.MONTH) + 1);
		tmp.append('.').append(calendar.get(Calendar.YEAR));

		tmp.append(' ').append(calendar.get(Calendar.HOUR_OF_DAY));
		tmp.append(':').append(calendar.get(Calendar.MINUTE));
		tmp.append(':').append(calendar.get(Calendar.SECOND));

		return tmp.toString();
	}
	
	// Bauke: copied from AselectConfigManager (is private there), also present in AuthSPConfigManager
	// NO LONGER USED 20080623
	//
	public static String xxx_loadHTMLTemplate(ASelectSystemLogger systemLogger, String sWorkingDir, String sFileName)
		throws ASelectException
	{
		String sLine = null;
		String sTemplate = "";
		BufferedReader brIn = null;
		String sMethod = "loadHTMLTemplate()";

		try {
			StringBuffer sbFilePath = new StringBuffer(sWorkingDir);
			sbFilePath.append(File.separator).append("conf").append(File.separator).
						append("html").append(File.separator).append(sFileName);

			File fTemplate = new File(sbFilePath.toString());
			if (!fTemplate.exists()) {
				systemLogger.log(Level.WARNING, MODULE, sMethod, "Required template not found: "
						+ sbFilePath.toString());

				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
			systemLogger.log(Level.INFO, MODULE, sMethod, "HTML " + sbFilePath);

			brIn = new BufferedReader(new InputStreamReader(new FileInputStream(fTemplate)));

			while ((sLine = brIn.readLine()) != null) {
				sTemplate += sLine + "\n";
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not load '");
			sbError.append(sFileName).append("' HTML template.");
			systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		finally {
			try {
				if (brIn != null)
					brIn.close();
			}
			catch (Exception e) {
				StringBuffer sbError = new StringBuffer("Could not close '");
				sbError.append(sFileName).append("' FileInputStream");
				systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			}
		}
		return sTemplate;
	}

	public String readHttpPostData(HttpServletRequest request)
	throws ASelectException
	{
		String _sMethod = "readHttpPostData";
		try {
			/*
			ServletInputStream input = request.getInputStream();
			BufferedInputStream bufInput = new BufferedInputStream(input);
			char b = (char) bufInput.read();
			StringBuffer sb = new StringBuffer();
			while (bufInput.available() != 0) {
				sb.append(b);
				b = (char) bufInput.read();
			}
			return sb.toString();
			*/
			return Tools.stream2string(request.getInputStream());  // RH, 20080715, n
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "Read POST data failed", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	public synchronized String get_sASelectServerID() {
		return _sASelectServerID;
	}

	public synchronized void set_sASelectServerID(String selectServerID) {
		_sASelectServerID = selectServerID;
	}

	public synchronized String get_sASelectOrganization() {
		return _sASelectOrganization;
	}

	public synchronized void set_sASelectOrganization(String selectOrganization) {
		_sASelectOrganization = selectOrganization;
	}

	public void destroy()
	{
	}	
}
