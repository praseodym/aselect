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
 * $Id: LDAPProtocolHandlerFactory.java,v 1.14 2006/05/03 10:06:47 tom Exp $ 
 *
 * Changelog:
 * $Log: LDAPProtocolHandlerFactory.java,v $
 * Revision 1.14  2006/05/03 10:06:47  tom
 * Removed Javadoc version
 *
 * Revision 1.13  2006/04/12 13:29:35  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.12.2.2  2006/04/03 13:59:22  erwin
 * Fixed problem with unknown realm (bug #178)
 *
 * Revision 1.12.2.1  2006/03/09 14:35:05  martijn
 * added support for a wildcard as realm and a back-end_server without a realm
 *
 * Revision 1.12  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.11  2005/05/10 08:20:23  martijn
 * fixed bug in full_uid if it is not configured
 *
 * Revision 1.10  2005/05/10 08:12:57  martijn
 * changed logging in getContext()
 *
 * Revision 1.9  2005/04/29 12:28:07  martijn
 * fixed logging bug
 *
 * Revision 1.8  2005/04/29 11:38:22  martijn
 * added full_uid support
 *
 * Revision 1.7  2005/04/08 12:41:50  martijn
 * fixed todo's
 *
 * Revision 1.6  2005/03/29 13:47:24  martijn
 * config item port has been removed from the config, now using ldap://www.test.com:port instead
 *
 * Revision 1.5  2005/03/29 08:56:25  tom
 * Changed fixme into todo
 *
 * Revision 1.4  2005/03/23 09:48:38  erwin
 * - Applied code style
 * - Added javadoc
 * - Improved error handling
 *
 * Revision 1.3  2005/02/04 10:12:40  leon
 * code restyle and license added
 *
 */
package org.aselect.authspserver.authsp.ldap;

import java.util.Hashtable;
import java.util.logging.Level;

import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;

/**
 * A factory to create <code>ILDAPProtocolHandler</code> implementations.
 * <br><br>
 * <b>Description:</b><br>
 * The <code>LDAPProtocolHandlerFactory</code> can be used to instantiate
 * different types of <code>LDAPProtocolHandlers</code>.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * The created <code>ILDAPProtocolHandler</code> 
 * can be used for <u>one</u> request.
 * <br>
 * @author Alfa & Ariss
 * 
 * 
 * 14-11-2007 - Changes:
 * - Added default realm when the user does not have one.
 * 
 * @author Bauke Hiemstra - www.anoigo.nl
 * Copyright Gemeente Den Haag (http://www.denhaag.nl)
 * 
 */
public class LDAPProtocolHandlerFactory 
{
    /** The module name. */
    public static final String MODULE = "LDAPProtocolHandlerFactory";
    
    /**
     * Instantiate a new <code>ILDAPProtocolHandler</code> implementation.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Reads the context by calling 
     * {@link #getContext(Object, String, SystemLogger)} and determin the type 
     * of <code>ILDAPProtocolHandler</code>.
     * This class is instantiated and returned.
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
     * @param oConfig The configuration to be used.
     * @param sUid the LDAP user ID.
     * @param systemLogger The logger for system entries.
     * @return An  initialized <code>ILDAPProtocolHandler</code>.
     * @throws ASelectException If instantiation or initialisation fails.
     */
    public static ILDAPProtocolHandler instantiateProtocolHandler(Object oConfig, 
        String sUid, AuthSPSystemLogger systemLogger) throws ASelectException
    {
        String sMethod = "instantiateProtocolHandler()";
       
        try
        {
            Hashtable htContext = getContext(oConfig, sUid, systemLogger);             
            if(htContext == null)
            {
                systemLogger.log(Level.WARNING, MODULE, sMethod, 
                "Could not initialize LDAP protocol handler: no context available.");
                throw new ASelectException(
                    Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
            }
            
            String sLDAPUrl = (String)htContext.get("url");
            String sStorageDriver = (String)htContext.get("driver");
            String sUsersDn = (String)htContext.get("users_dn");
            String sUserIdDn = (String)htContext.get("uid_dn");
            String sProtocolHandlerName = (String)htContext.get("handler");
            String sPrincipalDn = (String)htContext.get("security_principal_dn");
            String sPrincipalPwd = (String)htContext.get("security_principal_password");
            Boolean boolFullUid = (Boolean)htContext.get("full_uid");
            
            Class cClass = Class.forName(sProtocolHandlerName);
            ILDAPProtocolHandler oProtocolHandler = 
                                (ILDAPProtocolHandler)cClass.newInstance();
            
            if (!oProtocolHandler.init(sLDAPUrl,  
                                       sStorageDriver, sUsersDn, sUserIdDn,
                                       boolFullUid.booleanValue(),
                                       sUid, sPrincipalDn, sPrincipalPwd, 
                                       systemLogger))
            {
                systemLogger.log(Level.WARNING, MODULE, sMethod, 
                "Could not initialize LDAP protocol handler.");
                throw new ASelectException(
                    Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
            }
            return oProtocolHandler;
            
        }
        catch(ASelectException eAS)
        {
            systemLogger.log(Level.WARNING, MODULE, sMethod, 
                "Could not instantiate LDAP protocol handler",eAS);
            throw eAS;
        }
        catch(ClassNotFoundException eCNF)
        {
            systemLogger.log(Level.SEVERE, MODULE, sMethod, 
        	    "Could not instantiate LDAP protocol handler. Class was not found",
        	    eCNF);
            throw new ASelectException(
                Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, eCNF);
        }
        catch (Exception e)
        {
        	systemLogger.log(Level.SEVERE, MODULE, sMethod, 
        	    "Could not instantiate LDAP protocol handler due to internal error",
        	    e);
        	throw new ASelectException(
                Errors.ERROR_LDAP_INTERNAL_ERROR, e);
        }
    }
    
    /**
     * retrieve the context attributes of the user.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Retrieve context attributes of the given user which are 
     * read from the configuration.
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
     * @param oConfig the configuration to be used.
     * @param sUid The LDAp user ID.
     * @param oSystemLogger The logger for system entries.
     * @return A <code>Hashtable</code> with the context.
     * @throws ASelectException If retrieving fails.
     */
    public static Hashtable getContext(Object oConfig, 
                                String sUid, SystemLogger oSystemLogger) 
    throws ASelectException
    {
        Hashtable htResponse = new Hashtable();
        StringBuffer sbTemp = null;
        String sMethod = "getContext()";
        String sTemp = null;
        AuthSPConfigManager oConfigManager = AuthSPConfigManager.getHandle();
        try
        {
            int iIndex = sUid.indexOf('@');
            String sRealm;
            if (iIndex <= 0)
            {
                //TODO this check is no longer valid when the realm is configurable (Erwin)
            	
            	// Bauke: Added, default_realm, used when a user does not type a realm when logging in
            	String sDefaultRealm = oConfigManager.getParam(oConfig, "default_realm");
            	if (sDefaultRealm != null && !sDefaultRealm.equals("")) {
            		sRealm = sDefaultRealm;
            	}
            	else { 
	            	sbTemp = new StringBuffer("Invalid user id '");
	                sbTemp.append(sUid);
	                sbTemp.append("' User id should be [user]@[realm].");
	                oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbTemp.toString());
	                throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
            	}
            }
            else {
            	sRealm = sUid.substring(iIndex);
            }
            if (sRealm.length() <= 0)
            {
                sbTemp = new StringBuffer("Could not determine realm for user id '");
                sbTemp.append(sUid);
                sbTemp.append("' User id should be [user]@[realm].");
                oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbTemp.toString());
                throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
            }

            Object oBackendServer = null;
            try
            {
                oBackendServer = oConfigManager.getSection(oConfig,
                    "back-end_server", "realm=" + sRealm);
            }
            catch (ASelectConfigException e)
            {
                oBackendServer = null;
                //no back-end_server found with specified realm
                //--
                //try to find a wildcard realm or a back-end_server without a 
                //realm configured
            }
            
            try
            {
                if (oBackendServer == null)
                    oBackendServer = oConfigManager.getSection(oConfig,
                        "back-end_server", "realm=*");
            }
            catch (ASelectConfigException e)
            {
                oBackendServer = null;
                //No back-end_server found with wildcard realm
                //--
                //Now try to find a back-end_server where no realm is configured
            }
            
            if (oBackendServer == null)
            {
                try
                {
                    oBackendServer = oConfigManager.getSection(oConfig, "back-end_server");
                }
                catch (ASelectConfigException e)
                {
                    oBackendServer = null;
                }
                
                while (oBackendServer != null)
                {
                    //check if there is a backend server configured without a 
                    //realm, that can used to authenticate the user
                    try
                    {
                        oConfigManager.getParam(oBackendServer, "realm");
                    }
                    catch (ASelectConfigException e)
                    {
                        //just a check if a realm is configured
                        //if no realm is configured this back-end_server will be 
                        //used, so stop the while loop
                        break;
                    }
                    oBackendServer = oConfigManager.getNextSection(oBackendServer);
                }

                if (oBackendServer == null)
                {
                    sbTemp = new StringBuffer("no ldap server defined for realm ");
                    sbTemp.append(sRealm).append(" while authenticating ");
                    sbTemp.append(sUid);

                    oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbTemp.toString());
                    return null;
                }
            }
            
            String sLDAPUrl = null;
            try
			{
            	sLDAPUrl = oConfigManager.getParam(oBackendServer, "url");
			}
            catch (ASelectConfigException eAC)
            {
                sbTemp = new StringBuffer("No url defined for realm '");
                sbTemp.append(sRealm);
                sbTemp.append("' while authenticating '");
                sbTemp.append(sUid).append("'");
                oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbTemp.toString(),eAC);
                throw new ASelectException(
                    Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, eAC);
            }
            
            String sStorageDriver = null;
            try
			{
            	sStorageDriver = oConfigManager.getParam(oBackendServer, "driver");
			}
            catch (ASelectConfigException eAC)
            {
                sbTemp = new StringBuffer("No driver defined for realm ");
                sbTemp.append(sRealm);
                sbTemp.append(" while authenticating '");
                sbTemp.append(sUid).append("'");
                oSystemLogger.log(
                    Level.WARNING, MODULE, sMethod, sbTemp.toString(), eAC);
                throw new ASelectException(
                    Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, eAC);
            }

            String sUsersDn = null;
            try
			{
            	sUsersDn = oConfigManager.getParam(oBackendServer, "base_dn");
			}
            catch (ASelectConfigException eAC)
            {
                sbTemp = new StringBuffer("No base_dn defined for realm '");
                sbTemp.append(sRealm);
                sbTemp.append("' while authenticating '");
                sbTemp.append(sUid).append("'");
                oSystemLogger.log(
                    Level.WARNING, MODULE, sMethod, sbTemp.toString(), eAC);
                throw new ASelectException(
                    Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, eAC);
            }
            
            String sUserIdDn = null;
            try
			{
            	sUserIdDn = oConfigManager.getParam(oBackendServer, "user_dn");
			}
            catch (ASelectConfigException eAC)
            {
                sbTemp = new StringBuffer("No user_dn defined for realm '");
                sbTemp.append(sRealm);
                sbTemp.append("' while authenticating '");
                sbTemp.append(sUid).append("'");
                oSystemLogger.log(
                    Level.WARNING, MODULE, sMethod, sbTemp.toString(), eAC);
                throw new ASelectException(
                    Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, eAC);
            }
            
            try
			{
            	sTemp = oConfigManager.getParam(oBackendServer, "method");
			}
            catch (ASelectConfigException eAC)
            {
                sbTemp = new StringBuffer("No method setting defined for realm '");
                sbTemp.append(sRealm);
                sbTemp.append("' while authenticating '");
                sbTemp.append(sUid).append("'");
                oSystemLogger.log(
                    Level.WARNING, MODULE, sMethod, sbTemp.toString(), eAC);
                throw new ASelectException(
                    Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, eAC);
            }

            String sProtocolHandlerName = null;
            try
			{
            	sProtocolHandlerName = oConfigManager.getParam(oConfig, sTemp + 
            	    "_protocolhandler");
			}
            catch (ASelectConfigException eAC)
            {
                sbTemp = new StringBuffer(
                    "No protocol handler defined for method '");
                sbTemp.append(sTemp);
                sbTemp.append("' while authenticating '");
                sbTemp.append(sUid).append("'");
                oSystemLogger.log(
                    Level.WARNING, MODULE, sMethod, sbTemp.toString(), eAC);
                throw new ASelectException(
                    Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, eAC);
            }

            String sPrincipalDn = null;
            try
			{
            	sPrincipalDn = oConfigManager.getParam(oBackendServer, 
            	    "security_principal_dn");
			}
            catch (ASelectConfigException e)
            {
				sPrincipalDn = "";   //use default       
            }
            
            String sPrincipalPwd = null;
            try
			{
            	sPrincipalPwd = oConfigManager.getParam(oBackendServer, "security_principal_password");
			}
            catch (ASelectConfigException e)
            {
				sPrincipalPwd = "";  //use default        
            }
            
            boolean bFullUid = false;
            String sFullUid = null;
            try
            {
                sFullUid = oConfigManager.getParam(oBackendServer, "full_uid");
            }
            catch (ASelectConfigException e)
            {
                sFullUid = "false";
                StringBuffer sbWarning = new StringBuffer("No 'full_uid' defined for realm ");
                sbWarning.append(sRealm);
                sbWarning.append("; using default: full_uid = ");
                sbWarning.append(sFullUid);
                oSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbWarning.toString(), e);
            }
            if (sFullUid.equalsIgnoreCase("true"))
                bFullUid = true;
            else if (sFullUid.equalsIgnoreCase("false"))
                bFullUid = false;
            else
            {
                StringBuffer sbConfig = new StringBuffer("Invalid 'full_uid' config item defined for realm ");
                sbConfig.append(sRealm);
                sbConfig.append(" : ");
                sbConfig.append(sFullUid);
                sbConfig.append("; using default: full_uid = false");
                oSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbConfig.toString());
            }
            
            htResponse.put("url", sLDAPUrl);
            htResponse.put("driver", sStorageDriver);
            htResponse.put("users_dn", sUsersDn); 
            htResponse.put("uid_dn", sUserIdDn);
            htResponse.put("handler", sProtocolHandlerName);
            htResponse.put("security_principal_dn", sPrincipalDn);
            htResponse.put("security_principal_password", sPrincipalPwd);
            htResponse.put("full_uid", new Boolean(bFullUid));

            return htResponse;
        }
        catch(ASelectException eAS)
        {
            //allready logged
            throw eAS;
        }
        catch (Exception e)
        {
            oSystemLogger.log(Level.SEVERE, MODULE, sMethod, 
                "Could not retrieve context due to internal error",e);
            throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR,e);
        }
    }
}
