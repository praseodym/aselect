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
 * $Id: JNDIAttributeRequestor.java,v 1.16 2006/05/03 09:32:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: JNDIAttributeRequestor.java,v $
 * Revision 1.16  2006/05/03 09:32:06  tom
 * Removed Javadoc version
 *
 * Revision 1.15  2006/04/12 06:07:26  jeroen
 * Fix in full uid check. Now also the index is checked > -1.
 *
 * Revision 1.14  2006/03/14 15:12:01  martijn
 * added support for multivalue attributes
 *
 * Revision 1.13  2006/03/09 12:49:39  jeroen
 * Bugfix for 141 AttributeMapping not optional in (JNDI)AttributeGatherer
 *
 * Revision 1.12  2006/02/28 09:01:24  jeroen
 * Adaptations to support multi-valued attributes.
 *
 * Bugfix for 134:
 *
 * The init of the JNDIAttributeRequestor checks and sets a boolean to the
 * configured value (if not configured the default value is false).
 * In the getAttributes:
 *
 * if (!_bUseFullUid)
 *       sUID = sUID.substring(0, sUID.indexOf('@'));
 *
 * Revision 1.11  2005/05/02 08:10:48  martijn
 * user attribute for jndi database is now retrieved from the udb connector's new method getUserAttribues();
 *
 * Revision 1.10  2005/04/27 13:56:09  erwin
 * Fixed internal error logging
 *
 * Revision 1.9  2005/03/31 08:27:22  martijn
 * The Vector containing the attributes can now be empty
 *
 * Revision 1.8  2005/03/31 08:06:25  martijn
 * config section attributes changed to attribute_mapping
 *
 * Revision 1.7  2005/03/30 14:44:26  martijn
 * the getAttributes() method needs an TGT context instead of the A-Select user id
 *
 * Revision 1.6  2005/03/24 13:21:29  tom
 * Realm is stripped from username before verification
 *
 * Revision 1.5  2005/03/18 08:34:38  martijn
 * sending a null instead of a Vector, will now return all attributes
 *
 * Revision 1.4  2005/03/18 08:15:39  martijn
 * The response attributes wil now be remapped to the convigured attribute id
 *
 * Revision 1.3  2005/03/17 15:14:44  martijn
 * if getAttributes(uid, null) is supplied, then all attributes will be returned
 *
 * Revision 1.2  2005/03/17 15:01:10  martijn
 * The setReturningAttributes() is used to set in the SearchControls to return only the requested attributes by the search call
 *
 * Revision 1.1  2005/03/17 13:32:34  martijn
 * added initial version of the JNDI Attribute Requestor
 *
 */

package org.aselect.server.attributes.requestors.jndi;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.util.logging.Level;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.InvalidSearchControlsException;
import javax.naming.directory.InvalidSearchFilterException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.aselect.server.attributes.requestors.GenericAttributeRequestor;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.server.udb.UDBConnectorFactory;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.exception.ASelectUDBException;
import org.aselect.system.sam.agent.SAMResource;

/**
 * The JNDI Attribute Requestor.
 * <br><br>
 * <b>Description:</b><br>
 * This class can be used as AttributeRequestor by the A-Select Server 
 * AttributeGatherer
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 * 14-11-2007 - Changes:
 * - DigiD Gateway integration
 *   Additional alt_user_dn configuration parameter
 * 
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright Gemeente Den Haag (http://www.denhaag.nl)
 */
public class JNDIAttributeRequestor extends GenericAttributeRequestor
{
    private static final String MODULE = "JNDIAttributeRequestor";
    
    private String _sResourceGroup;
    private String _sAuthSPUID;
    private String _sUserDN;
    private String _sAltUserDN;  // Bauke: attribute hack
    private String _sBaseDN;
    private Hashtable _htAttributes;
    private Hashtable _htReMapAttributes;
    private boolean _bUseFullUid = false;
    private boolean _bNumericalUid = false;
    
    /**
     * Initializes the JNDI Attribute Requestor.
     * <br>
     * Reads the 'main' section of the supplied configuration<br>
     * Reads the 'attributes' section of the supplied configuration<br>
     * Checks if there is at least one resource configured in the resourcegroup 
     * <br><br>
     * @see org.aselect.server.attributes.requestors.IAttributeRequestor#init(java.lang.Object)
     */
    public void init(Object oConfig) 
    	throws ASelectException
    {
        String sMethod = "init()";
        Object oMain = null;
        
        _htAttributes = new Hashtable();
        _htReMapAttributes = new Hashtable();
        
       try
        {
            try
            {
                _sResourceGroup = _configManager.getParam(oConfig, "resourcegroup");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'resourcegroup' config item found", e);
                throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            try
            {
                oMain = _configManager.getSection(oConfig, "main");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'main' config section found", e);
                throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            String sUseFullUid;
            try {
                sUseFullUid = _configManager.getParam(oMain, "full_uid");
                _bUseFullUid = new Boolean(sUseFullUid).booleanValue();
            }
            catch (ASelectConfigException e) {
                _systemLogger.log(Level.CONFIG, MODULE, sMethod, 
                    "No 'full_uid' config item in 'main' section found, using 'false'", e);
            }
            
            String sUseNumUid;
            try {
            	sUseNumUid = _configManager.getParam(oMain, "numerical_uid");
                _bNumericalUid = new Boolean(sUseNumUid).booleanValue();
            }
            catch (ASelectConfigException e) {
                _systemLogger.log(Level.CONFIG, MODULE, sMethod, 
                    "No 'num_uid' config item in 'main' section found, using 'false'", e);
            }
            
            try
            {
                _sAuthSPUID = _configManager.getParam(oMain, "authsp_uid");
            }
            catch (ASelectConfigException e)
            {
                _sAuthSPUID = null;
                _systemLogger.log(Level.CONFIG, MODULE, sMethod, 
                    "No valid 'authsp_uid' config item in 'main' section found, using the A-Select UID to retrieve the attributes", e);
            }
            
            try
            {
                _sUserDN = _configManager.getParam(oMain, "user_dn");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'user_dn' config item in 'main' section found", e);
                throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            
            try {  // Bauke: attribute hack
                _sAltUserDN = _configManager.getParam(oMain, "alt_user_dn");
            }
            catch (ASelectConfigException e) { _sAltUserDN = ""; }
            
            try
            {
                _sBaseDN = _configManager.getParam(oMain, "base_dn");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'base_dn' config item in 'main' section found", e);
                throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
            }
            _systemLogger.log(Level.INFO,MODULE,sMethod, "JNDIConf _sBaseDN="+_sBaseDN+
            		", _sUserDN="+_sUserDN+", _sAltUserDN="+_sAltUserDN+", _sAuthSPUID="+_sAuthSPUID+", _sResourceGroup="+_sResourceGroup);
            
            Object oAttributes = null;            
            try
            {
                oAttributes = _configManager.getSection(oConfig, "attribute_mapping");
            }
            catch (ASelectConfigException e)
            {
                _systemLogger.log(Level.CONFIG, MODULE, sMethod, "No valid 'attribute_mapping' config section found, no mapping used", e);             
            }            
                 
           if(oAttributes != null){
                
               _systemLogger.log(Level.INFO,MODULE,sMethod, "JNDIConf oAttributes="+oAttributes);
                Object oAttribute = null;    
                try
                {
                    oAttribute = _configManager.getSection(oAttributes, "attribute");
                }
                catch (ASelectConfigException e)
                {
                    _systemLogger.log(Level.CONFIG, MODULE, sMethod, "Not one valid 'attribute' config section in 'attributes' section found, no mapping used", e);
                }
                
                while (oAttribute != null)
                {
                    String sAttributeID = null;
                    String sAttributeMap = null;
                    try
                    {
                        sAttributeID = _configManager.getParam(oAttribute, "id");
                    }
                    catch (ASelectConfigException e)
                    {
                        _systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'id' config item in 'attribute' section found", e);
                        throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
                    }
                    
                    try
                    {
                        sAttributeMap = _configManager.getParam(oAttribute, "map");
                    }
                    catch (ASelectConfigException e)
                    {
                        _systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'map' config item in 'attribute' section found", e);
                        throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
                    }
                    
                    _htAttributes.put(sAttributeID, sAttributeMap);
                    _htReMapAttributes.put(sAttributeMap, sAttributeID);
                    
                    oAttribute = _configManager.getNextSection(oAttribute);
                }
            }
            
            //check if at least one resource is configured
            getConnection();
        }
        catch (ASelectAttributesException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize the Ldap attributes requestor", e);
            throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }

    /**
     * Resolves the attribute values from the JNDI backend.
     * <br>
     * A search will be done to search the user in the base dn.<br>
     * The attributes that are supplied to the method will directly be requested. 
     * <br>
     * If a '*' character is the first element of the supplied <code>Vector
     * </code>, then all attributes will be returned.
     * <br><br>
     * @see org.aselect.server.attributes.requestors.IAttributeRequestor#getAttributes(java.util.Hashtable, java.util.Vector)
     */
    public Hashtable getAttributes(Hashtable htTGTContext, Vector vAttributes) 
    	throws ASelectAttributesException
    {
        String sMethod = "getAttributes()";       
        Hashtable htResponse = new Hashtable();
        DirContext oDirContext = null;
        NamingEnumeration oSearchResults = null;
        StringBuffer sbQuery = null;
        Attributes oAttributes = null;
        Vector vMappedAttributes = new Vector();
        String sUID = null;
        
        _systemLogger.log(Level.INFO,MODULE,sMethod, "JNDIAttr htTGTContext="+htTGTContext + 
        		", _sAuthSPUID="+_sAuthSPUID+", _sUserDN="+_sUserDN);
        String sDigiDUid = (String)htTGTContext.get("digid_uid");
        if (sDigiDUid == null) sDigiDUid = "";  // Bauke: circumvent udb attribute problems
        
        try
        {
            sUID = (String)htTGTContext.get("uid");
            if (_bNumericalUid) {  // Uid must be treated as a number, so strip leading zeroes
            	sUID = sUID.replaceFirst("0*", "");
            }
            if (sDigiDUid.equals("") && _sAuthSPUID != null)  // Bauke: no DigiD uid
            {
                _systemLogger.log(Level.INFO,MODULE,sMethod, "JNDIAttr use UDB too (no DigiD uid)"); 
                IUDBConnector oUDBConnector = null;
                try
                {
                    oUDBConnector = UDBConnectorFactory.getUDBConnector();
                }
                catch (ASelectException e)
                {
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to connect with UDB.", e);
                    throw e;
                }
                try
                {
                    sUID = oUDBConnector.getUserAttributes(sUID, _sAuthSPUID);
                }
                catch (ASelectUDBException e)
                {
                    StringBuffer sbFailed = new StringBuffer("Could not retrieve user attributes (for authsp '");
                    sbFailed.append(_sAuthSPUID);
                    sbFailed.append("') user: ");
                    sbFailed.append(sUID);
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
    	            
                    throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
                }
                if (sUID == null)
                {
                    StringBuffer sbFailed = new StringBuffer("The configured authsp_uid '");
                    sbFailed.append(_sAuthSPUID);
                    sbFailed.append("' does not map to any configured AuthSP (authsp_id)");
                    _systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString());
    	            
                    throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
                }
            }
            
            SearchControls oScope = new SearchControls();
            oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            if (!vAttributes.isEmpty() && !vAttributes.firstElement().equals("*"))
            {
	            //convert the supplied attribute names to the mapped attribute names
	            Enumeration enumSuppliedAttribs = vAttributes.elements();
	            while (enumSuppliedAttribs.hasMoreElements())
	            {
	                String sSuppliedAttribute = (String)enumSuppliedAttribs.nextElement();
	                String sMappedAttribute = null;
	                if (_htAttributes.containsKey(sSuppliedAttribute))
	                    sMappedAttribute = (String)_htAttributes.get(sSuppliedAttribute);
	                else
	                    sMappedAttribute = sSuppliedAttribute;
	                    
	                vMappedAttributes.add(sMappedAttribute);
	            }
            
	            String[] saMappedAttributes = (String[])vMappedAttributes.toArray(new String[0]);
		        oScope.setReturningAttributes(saMappedAttributes);
            }
            
            if (!_bUseFullUid) {
                int iIndex = sUID.indexOf('@');
                if (iIndex > 0)
                    sUID = sUID.substring(0, iIndex);
            }
            
            // Bauke: Allow alternative user DN
            String useDnField = (sDigiDUid.equals(""))? _sUserDN: _sAltUserDN;            
            sbQuery = new StringBuffer("(").append(useDnField).append("=").append(sUID).append(")");
	        
	        oDirContext = getConnection();
	        try
	        {
	            _systemLogger.log(Level.INFO,MODULE,sMethod, "JNDIAttr BaseDN="+_sBaseDN +
	            		", sbQuery="+sbQuery+", oScope="+oScope.getSearchScope());
	            
	            oSearchResults = oDirContext.search(_sBaseDN, sbQuery.toString(), oScope);
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "Search-ed");
            }
	        catch (InvalidSearchFilterException e)
	        {
	            StringBuffer sbFailed = new StringBuffer("Wrong filter: ");
	            sbFailed.append(sbQuery.toString());
	            sbFailed.append(" with attributes: ");
	            sbFailed.append(vMappedAttributes.toString());
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);           
                throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	        }
	        catch (InvalidSearchControlsException e) {
	            _systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid search controls", e);           
                throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
	        }
	        catch (NamingException e)
	        {
	            StringBuffer sbFailed = new StringBuffer("User unknown: ");
	            sbFailed.append(sUID);
	            _systemLogger.log(Level.INFO, MODULE, sMethod, sbFailed.toString(), e);
	            throw new ASelectAttributesException(Errors.ERROR_ASELECT_UNKNOWN_USER, e);
	        }
	        
            _systemLogger.log(Level.INFO, MODULE, sMethod, "Check Result");
	        // Check if we got a result
            if (!oSearchResults.hasMore())
            {
                StringBuffer sbFailed = new StringBuffer("User '");
                sbFailed.append(sUID);
                sbFailed.append("' not found during LDAP search. The filter was: ");
                sbFailed.append(sbQuery.toString());
                _systemLogger.log(Level.INFO, MODULE, sMethod, sbFailed.toString());
	            throw new ASelectAttributesException(Errors.ERROR_ASELECT_UNKNOWN_USER);
            }
            
            while(oSearchResults.hasMore())
            {
                SearchResult oSearchResult = (SearchResult)oSearchResults.next();
                _systemLogger.log(Level.FINE, MODULE, sMethod, "Next search result "+oSearchResult+
                		" id="+oSearchResult.getName()+" full="+oSearchResult.getNameInNamespace());
                
                //retrieve all requested attributes
                oAttributes = oSearchResult.getAttributes();
                _systemLogger.log(Level.FINE, MODULE, sMethod, "Attrs "+oAttributes);

                NamingEnumeration oAttrEnum = oAttributes.getAll();
                while (oAttrEnum.hasMore())
                {
                    Attribute oAttribute = (Attribute)oAttrEnum.next();
                    String sAttributeName = oAttribute.getID();
                    try {   
                        if (oAttribute.size() > 1) {
                            Vector vMultiValues = new Vector();
                            _systemLogger.log(Level.FINEST, MODULE, sMethod, "multi");
                            for (int iCount = 0;  iCount < oAttribute.size(); iCount++)
                            {
                            	Object oValue = oAttribute.get(iCount);
                                _systemLogger.log(Level.FINEST, MODULE, sMethod, "multi"+iCount+"="+oValue);
                                vMultiValues.add(oAttribute.get(iCount));
                            }
                            
                            if (_htReMapAttributes.containsKey(sAttributeName))
                                sAttributeName = (String)_htReMapAttributes.get(sAttributeName);
                            
                            htResponse.put(sAttributeName, vMultiValues);                                                        
                        }
                        else {                      
                            String sAttributeValue = (String)oAttribute.get();
                            if (sAttributeValue == null) sAttributeValue ="";
                            _systemLogger.log(Level.FINEST, MODULE, sMethod, "single="+sAttributeValue);
                            
                            if (_htReMapAttributes.containsKey(sAttributeName))
                                sAttributeName = (String)_htReMapAttributes.get(sAttributeName);

                            htResponse.put(sAttributeName, sAttributeValue);
                        }                        
                    }
                    catch (Exception e) {}
                }
            }
            _systemLogger.log(Level.INFO, MODULE, sMethod, "End of Search results");

            // Bauke: 20080722: some applications want to know the base_dn and full_dn value
            // Replaced 20080908: String sCn = (String)(htResponse.get("cn"));
            htResponse.put("base_dn", _sBaseDN);
            Object oCn = htResponse.get("cn");
        	String sCn = null;
            if (oCn != null) {
            	// Search was on <useDnField>=<sUID>
            	if (oCn instanceof Vector) {  // multi-valued attribute
            		if ("cn".equals(useDnField))
            			sCn = sUID;
            		else
            			sCn = (String)((Vector)oCn).get(0);  // just grab the first
            	}
            	else if (oCn instanceof String)
            		sCn = (String)oCn;
            }
            if (sCn != null)
            	htResponse.put("full_dn", "cn="+sCn+","+_sBaseDN);
        }
        catch (ASelectAttributesException e) {
    		_systemLogger.log(Level.SEVERE, MODULE, sMethod, "AttributesException", e);
    		throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			try {
				if (oSearchResults != null) oSearchResults.close();
				if (oDirContext != null) oDirContext.close();
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close directory context", e);
			}
		}
		return htResponse;
	}

    /**
	 * Unused method. <br>
	 * <br>
	 * 
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#destroy()
	 */
    public void destroy()
    {
    }
    
    
    /**
     * Opens a new JNDI connection to the resource that is retrieved from the 
     * SAMAgent.
     * <br><br>
     * @return <code>DirContext</code> that contains the JNDI connection
     * @throws ASelectUDBException if the connection could not be opened
     * @throws ASelectSAMException if no valid resource could be found
     */
    private DirContext getConnection() throws ASelectUDBException, ASelectSAMException
    {
        String sMethod = "getConnection()";
        
        SAMResource oSAMResource = null;
        String sDriver = null;
        String sPrincipal = null;
        String sPassword = null;
        String sUseSSL = null;
        String sUrl = null;
        InitialDirContext oInitialDirContext = null;
        Object oResourceConfig = null;
        
		try
		{
		    oSAMResource = _samAgent.getActiveResource(_sResourceGroup);
		}
		catch (ASelectSAMException e)
		{
		    StringBuffer sbFailed = new StringBuffer(
				"No active resource found in udb resourcegroup: ");
		    sbFailed.append(_sResourceGroup);
		    _systemLogger.log(Level.WARNING, MODULE, sMethod,
		        sbFailed.toString(), e);
		    
		    throw e;
		}
		
		oResourceConfig = oSAMResource.getAttributes();
		
        try
        {
            sDriver = _configManager.getParam(oResourceConfig,
                "driver");
        }
        catch (ASelectConfigException e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "No valid config item 'driver' found in connector configuration", e);
            
            throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
        }

        try
        {
            sPrincipal = _configManager.getParam(oResourceConfig,
                "security_principal_dn");
        }
        catch (ASelectConfigException e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "No valid config item 'security_principal_dn' found in connector resource configuration", e);
            
            throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
        }

        try
        {
            sPassword = _configManager.getParam(oResourceConfig,
                "security_principal_password");
        }
        catch (ASelectConfigException e)
        {
            _systemLogger.log(Level.CONFIG, MODULE, sMethod, 
                "Invalid or empty config item 'security_principal_password' found in connector resource configuration, using empty password."
                , e);
        }

        try
        {
            sUseSSL = _configManager.getParam(oResourceConfig,
                "ssl");
        }
        catch (ASelectConfigException e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "No valid config item 'ssl' found in connector resource configuration", e);
            
            throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
        }

        try
        {
            sUrl = _configManager.getParam(oResourceConfig, "url");
        }
        catch (ASelectConfigException e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "No valid config item 'url' found in connector resource configuration", e);
            
            throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
        }
        
        try
        {
        	_systemLogger.log(Level.INFO, MODULE, sMethod,
            		"ATTR_CTX "+sDriver+"_"+sPrincipal+"_"+sPassword+"_"+sUseSSL+"_"+sUrl); 
            oInitialDirContext = new InitialDirContext(createJNDIEnvironment(
                sDriver, sPrincipal, sPassword, sUseSSL, sUrl));
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod, 
                "Could not create JNDI environment", e);
            throw new ASelectUDBException(Errors.ERROR_ASELECT_IO, e);
        }
        
        return oInitialDirContext;
    }
    
    /**
     * Creates an <code>Hashtable</code> containing the JNDI environment variables.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * -
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
     * @param sDriver The JNDI driver that must be used
     * @param sPrincipal The principal dn
     * @param sPassword The password to use while connecting
     * @param sUseSSL indicates if an ssl connection must be created
     * @param sUrl The connection url
     * @return a <code>Hastable</code> containing the JNDI environment variables
     */
    private Hashtable createJNDIEnvironment(String sDriver, String sPrincipal, 
        String sPassword, String sUseSSL, String sUrl)
    {
        Hashtable htEnvironment = new Hashtable(11);

        htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, sDriver);
        htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
        htEnvironment.put(Context.SECURITY_PRINCIPAL, sPrincipal);
        htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);

        if (sUseSSL.equalsIgnoreCase("true"))
        {
            htEnvironment.put(Context.SECURITY_PROTOCOL, "ssl");
        }
        
        htEnvironment.put(Context.PROVIDER_URL, sUrl);

        return htEnvironment;
    }
}
