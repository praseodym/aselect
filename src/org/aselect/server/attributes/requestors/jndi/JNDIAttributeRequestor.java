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
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
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
import org.aselect.server.config.ASelectConfigManager;
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
 * The JNDI Attribute Requestor. <br>
 * <br>
 * <b>Description:</b><br>
 * This class can be used as AttributeRequestor by the A-Select Server AttributeGatherer <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - DigiD Gateway integration Additional alt_user_dn configuration parameter
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl)
 */
public class JNDIAttributeRequestor extends GenericAttributeRequestor
{
	private static final String MODULE = "JNDIAttributeRequestor";

	private String _sResourceGroup;
	private String _sAuthSPUID;
	private String _sUserDN;
	private String _sAltUserDN; // Bauke: attribute feature
	private String _sBaseDN;
	private String _sSearchTree;
	private String _sOrgDN;
	private String _sOrgName;
	private HashMap<String, String> _htAttributes;
	private HashMap<String, String> _htReMapAttributes;
	private boolean _bUseFullUid = false;
	private boolean _bNumericalUid = false;
	
	// Store <sub_attributes> data
	protected HashMap<String,String> _hmAttributes = new HashMap<String,String>();
	protected HashMap<String,String> _hmSubs = new HashMap<String,String>();

	/**
	 * Initializes the JNDI Attribute Requestor. <br>
	 * Reads the 'main' section of the supplied configuration<br>
	 * Reads the 'attributes' section of the supplied configuration<br>
	 * Checks if there is at least one resource configured in the resourcegroup <br>
	 * <br>
	 * 
	 * @param oConfig
	 *            the o config
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#init(java.lang.Object)
	 */
	public void init(Object oConfig)
	throws ASelectException
	{
		String sMethod = "init()";
		Object oMain = null;
		_htAttributes = new HashMap<String, String>();
		_htReMapAttributes = new HashMap<String, String>();

		initSubAttributes(oConfig);
		try {
			try {
				_sResourceGroup = _configManager.getParam(oConfig, "resourcegroup");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'resourcegroup' config item found", e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				oMain = _configManager.getSection(oConfig, "main");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'main' config section found", e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sBaseDN = _configManager.getParam(oMain, "base_dn");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'base_dn' config item in 'main' section found", e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			String sUseFullUid;
			try {
				sUseFullUid = _configManager.getParam(oMain, "full_uid");
				_bUseFullUid = new Boolean(sUseFullUid).booleanValue();
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No 'full_uid' config item in 'main' section found, using 'false'");
			}

			String sUseNumUid;
			try {
				sUseNumUid = _configManager.getParam(oMain, "numerical_uid");
				_bNumericalUid = new Boolean(sUseNumUid).booleanValue();
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No 'numerical_uid' config item in 'main' section found, using 'false'");
			}

			try {
				_sAuthSPUID = _configManager.getParam(oMain, "authsp_uid");
			}
			catch (ASelectConfigException e) {
				_sAuthSPUID = null;
				_systemLogger.log(Level.INFO, MODULE, sMethod,
						"No valid 'authsp_uid' config item in 'main' section found, using the A-Select UID to retrieve the attributes");
			}

			try {
				_sUserDN = _configManager.getParam(oMain, "user_dn");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'user_dn' config item in 'main' section found", e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try { // Bauke: attribute feature
				_sAltUserDN = _configManager.getParam(oMain, "alt_user_dn");
			}
			catch (ASelectConfigException e) {
				_sAltUserDN = "";
			}
			
			// 20100201, Bauke: Organization Resolver additional items
			// Search tree until container starts with [search_tree]=
			_sSearchTree = ASelectConfigManager.getSimpleParam(oMain, "search_tree", false);
			_sOrgDN = ASelectConfigManager.getSimpleParam(oMain, "org_dn", false);
			_sOrgName = ASelectConfigManager.getSimpleParam(oMain, "org_name", false);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Config _sBaseDN=" + _sBaseDN + " _sUserDN=" + _sUserDN
					+ " _sAltUserDN=" + _sAltUserDN + " _sAuthSPUID=" + _sAuthSPUID + " _sResourceGroup="
					+ _sResourceGroup+" org_dn="+_sOrgDN+" org_name="+_sOrgName+" search_tree="+_sSearchTree);

			Object oAttributes = null;
			try {
				oAttributes = _configManager.getSection(oConfig, "attribute_mapping");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No valid 'attribute_mapping' config section found, no mapping used, cause="+e);
			}

			if (oAttributes != null) {

				_systemLogger.log(Level.INFO, MODULE, sMethod, "AttributeMapping oAttributes=" + oAttributes);
				Object oAttribute = null;
				try {
					oAttribute = _configManager.getSection(oAttributes, "attribute");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.CONFIG, MODULE, sMethod,
							"Not one valid 'attribute' config section in 'attributes' section found, no mapping used, cause="+e);
				}

				while (oAttribute != null) {
					String sAttributeID = null;
					String sAttributeMap = null;
					try {
						sAttributeID = _configManager.getParam(oAttribute, "id");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"No valid 'id' config item in 'attribute' section found", e);
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					try {
						sAttributeMap = _configManager.getParam(oAttribute, "map");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"No valid 'map' config item in 'attribute' section found", e);
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Map: id="+sAttributeID+" map="+sAttributeMap);
					_htAttributes.put(sAttributeID, sAttributeMap);
					_htReMapAttributes.put(sAttributeMap, sAttributeID);

					oAttribute = _configManager.getNextSection(oAttribute);
				}
			}
			// check if at least one resource is configured
			getConnection();
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize the Ldap attributes requestor", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Read <sub_attributes> from the configuration.
	 * 
	 * @param oConfig
	 *            the config object
	 * @throws ASelectException
	 */
	private void initSubAttributes(Object oConfig)
	throws ASelectException
	{
		final String sMethod = "initSubAttributes";
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "GAR");
		Object oSubAttributes = null;
		try {
			oSubAttributes = _configManager.getSection(oConfig, "sub_attributes");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "No 'sub_attributes' available");
		}

		if (oSubAttributes != null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "oSubAttributes=" + oSubAttributes);
			Object oSubAttribute = null;
			try {
				oSubAttribute = _configManager.getSection(oSubAttributes, "sub_attribute");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No 'sub_attribute' section in 'attributes' section");
			}

			while (oSubAttribute != null) {
				String sAttributeSub = null;
				String sAttribute = null;
				String sAttributeId = null;

				try {
					sAttributeId = _configManager.getParam(oSubAttribute, "id");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'id' config item in 'attribute' section found", e);
					throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				try {
					sAttributeSub = _configManager.getParam(oSubAttribute, "sub");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'sub' config item in 'attribute' section found", e);
					throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				try {
					sAttribute = _configManager.getParam(oSubAttribute, "attribute");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'attribute' config item in 'attribute' section found", e);
					throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "GAR id="+sAttributeId+" sub="+sAttributeSub+" attribute="+sAttribute);
				_hmSubs.put(sAttributeId, sAttributeSub);
				_hmAttributes.put(sAttributeId, sAttribute);

				oSubAttribute = _configManager.getNextSection(oSubAttribute);
			}
		}
	}
	
	/**
	 * Gather a user's organizations. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Use the normal gathering process to gather combinations of
	 * organization id and organization name <br>
	 * OVerrides the default from GenericAttributeRequestor.
	 * @param htTGTContext
	 *         the TGT context.
	 * @return The retrieved organizations as organization id, organization pairs.
	 * @throws ASelectAttributesException
	 *         If gathering fails.
	 */
	@Override
	public HashMap<String,String> getOrganizations(HashMap htTGTContext)
	throws ASelectAttributesException
	{
		HashMap<String,String> hOrganizations = new HashMap<String, String>();
		gatherAttributes(htTGTContext, null, null, hOrganizations);
		return hOrganizations;
	}

	/**
	 * Resolves the attribute values from the JNDI backend. <br>
	 * A search will be done to search the user in the base dn.<br>
	 * The attributes that are supplied to the method will directly be requested. <br>
	 * If a '*' character is the first element of the supplied <code>Vector
	 * </code>, then all attributes will be returned. <br>
	 * <br>
	 * 
	 * @param htTGTContext
	 *            the TGT context
	 * @param vAttributes
	 *            the requested attribute names
	 * @return the gathered attributes
	 * @throws ASelectAttributesException
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#getAttributes(java.util.HashMap,
	 *      java.util.Vector)
	 */
	public HashMap<String,Object> getAttributes(HashMap htTGTContext, Vector vAttributes)
	throws ASelectAttributesException
	{
		HashMap<String,Object> hAttrResponse = new HashMap<String,Object>();
		gatherAttributes(htTGTContext, vAttributes, hAttrResponse, null);
		return hAttrResponse;
	}
	
	/**
	 * Worker method for getAttributes() and getOrganizations()
	 * 
	 * @param htTGTContext - the TGT context
	 * @param vAttributes - the requested attribute names (getAttributes only)
	 * @param hAttrResponse - the requested attribute names (getAttributes only)
	 * @param hOrgResponse - the organizations found for this user (getOrganizations only)
	 * @throws ASelectAttributesException
	 */
	private void gatherAttributes(HashMap htTGTContext, Vector vAttributes,
			HashMap<String,Object> hAttrResponse, HashMap<String,String> hOrgResponse)
	throws ASelectAttributesException
	{		
		String sMethod = "gatherAttributes";
		
		DirContext oDirContext = null;
		StringBuffer sbQuery = null;
		Attributes oAttributes = null;
		Vector<String> vMappedAttributes = new Vector<String>();
		String sUID = null;
	
		_systemLogger.log(Level.INFO, MODULE, sMethod, "JNDIAttr htTGTContext=" + htTGTContext +
				", _sAuthSPUID=" + _sAuthSPUID + ", _sUserDN=" + _sUserDN);
		
		// Bauke: circumvent udb attribute problems
		String sAuthspType = (String) htTGTContext.get("authsp_type");
		Boolean bIsDigid = (sAuthspType != null && sAuthspType.equals("digid"));

		NamingEnumeration<SearchResult> oSearchResults = null;
		try {
			sUID = (String) htTGTContext.get("uid");
			if (_bNumericalUid) { // Uid must be treated as a number, so strip leading zeroes
				sUID = sUID.replaceFirst("0*", "");
			}

			if (!bIsDigid && _sAuthSPUID != null) // Bauke: not a DigiD authsp
			{
				_systemLogger.log(Level.INFO, MODULE, sMethod, "JNDIAttr use UDB too (no DigiD authsp)");
				IUDBConnector oUDBConnector = null;
				try {
					oUDBConnector = UDBConnectorFactory.getUDBConnector();
				}
				catch (ASelectException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to connect with UDB.", e);
					throw e;
				}
				try {
					sUID = oUDBConnector.getUserAttributes(sUID, _sAuthSPUID);
				}
				catch (ASelectUDBException e) {
					StringBuffer sbFailed = new StringBuffer("Could not retrieve user attributes (for authsp '");
					sbFailed.append(_sAuthSPUID);
					sbFailed.append("') user: ");
					sbFailed.append(sUID);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
					throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
				}
				if (sUID == null) {
					StringBuffer sbFailed = new StringBuffer("The configured authsp_uid '");
					sbFailed.append(_sAuthSPUID);
					sbFailed.append("' does not map to any configured AuthSP (authsp_id)");
					_systemLogger.log(Level.INFO, MODULE, sMethod, sbFailed.toString());
				}
			}

			// Regular JNDI gathering takes place here
			SearchControls oScope = new SearchControls();
			oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);

			if (vAttributes != null && !vAttributes.isEmpty() && !vAttributes.firstElement().equals("*")) {
				// convert the supplied attribute names to the mapped attribute names
				_systemLogger.log(Level.INFO, MODULE, sMethod, "vAttributes="+vAttributes);
				Enumeration enumSuppliedAttribs = vAttributes.elements();
				while (enumSuppliedAttribs.hasMoreElements()) {
					String sSuppliedAttribute = (String) enumSuppliedAttribs.nextElement();
					String sMappedAttribute = null;
					if (_htAttributes.containsKey(sSuppliedAttribute))
						sMappedAttribute = _htAttributes.get(sSuppliedAttribute);
					else
						sMappedAttribute = sSuppliedAttribute;

					vMappedAttributes.add(sMappedAttribute);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "vMappedAttributes="+vMappedAttributes);
				String[] saMappedAttributes = vMappedAttributes.toArray(new String[0]);
				oScope.setReturningAttributes(saMappedAttributes);
			}

			if (!_bUseFullUid) {
				int iIndex = sUID.indexOf('@');
				if (iIndex > 0)
					sUID = sUID.substring(0, iIndex);
			}

			// Bauke: Allow use of an alternative user DN when the DigiD AuthSP was used
			String useDnField = (bIsDigid) ? _sAltUserDN: _sUserDN;
			sbQuery = new StringBuffer("(").append(useDnField).append("=").append(sUID).append(")");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Search BaseDN=" + _sBaseDN +
					", sbQuery=" + sbQuery + ", oScope=" + oScope.getSearchScope());

			oDirContext = getConnection();
			try {
				oSearchResults = oDirContext.search(_sBaseDN, sbQuery.toString(), oScope);
			}
			catch (InvalidSearchFilterException e) {
				StringBuffer sbFailed = new StringBuffer("Wrong filter: ").append(sbQuery.toString());
				sbFailed.append(" with attributes: ").append(vMappedAttributes.toString());
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
			catch (InvalidSearchControlsException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid search controls", e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
			catch (NamingException e) {
				StringBuffer sbFailed = new StringBuffer("User unknown: ").append(sUID);
				_systemLogger.log(Level.INFO, MODULE, sMethod, sbFailed.toString(), e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_UNKNOWN_USER, e);
			}

			_systemLogger.log(Level.FINE, MODULE, sMethod, "Check Result");
			// Check if we got a result
			if (!oSearchResults.hasMore()) {
				StringBuffer sbFailed = new StringBuffer("User '").append(sUID);
				sbFailed.append("' not found during LDAP search. The filter was: ").append(sbQuery.toString());
				_systemLogger.log(Level.INFO, MODULE, sMethod, sbFailed.toString());
				return;
				// 20100318, was: throw new ASelectAttributesException(Errors.ERROR_ASELECT_UNKNOWN_USER);
			}

			// 2010-2-10, Bauke: support gathering for the chosen organization
			String sOrgId = (String) htTGTContext.get("org_id");
			String sFullDn = null;
			int cntResults = 0;
			if (_sOrgDN != null && _sOrgName != null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Looking for: org_dn="+_sOrgDN+" org_name="+_sOrgName);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "ReMapAttributes="+_htReMapAttributes);
			// For all search results
			while (oSearchResults.hasMore()) {
				SearchResult oSearchResult = (SearchResult) oSearchResults.next();
				sFullDn = oSearchResult.getNameInNamespace();
				String sSearchName = oSearchResult.getName(); 
				_systemLogger.log(Level.FINE, MODULE, sMethod, ">> id=" + sSearchName +" full=" + sFullDn + " Result=" + oSearchResult);
				cntResults++;

				// Compare the search result's name with the chosen organization (if specified)
				if (_sOrgDN != null && sOrgId != null && hAttrResponse != null) {
					String sOrg = _sOrgDN+"="+sOrgId;
					int iSrchLen = sSearchName.length();
					int iLen = sOrg.length();
					int idx = 0;
					for ( ; ; idx += iLen) {
						idx = sSearchName.indexOf(sOrg, idx);
						if (idx < 0)
							break;  // not found at al
						// idx >= 0
						if ((idx == 0 || sSearchName.charAt(idx-1) == ',') &&
							(idx+iLen >= iSrchLen || sSearchName.charAt(idx+iLen) == ','))
							break;  // yes, found
					}
					if (idx < 0) {  // Not found, skip this result, since it does not match the user's organization
						_systemLogger.log(Level.FINE, MODULE, sMethod, "Skip id="+sSearchName);
						continue;
					}
				}
				// else everything goes!
				
				// Retrieve all requested attributes
				oAttributes = oSearchResult.getAttributes();
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Attrs " + oAttributes);

				// For all attributes found in this search result
				String sDnValue = null;
				String sNameValue = null;
				NamingEnumeration oAttrEnum = oAttributes.getAll();
				while (oAttrEnum.hasMore()) {
					Attribute oAttribute = (Attribute) oAttrEnum.next();
					String sAttributeName = oAttribute.getID();
					String sUnmappedName = sAttributeName;
					//_systemLogger.log(Level.FINEST, MODULE, sMethod, "Attribute="+sAttributeName);
					if (_htReMapAttributes.containsKey(sAttributeName)) {
						sAttributeName = _htReMapAttributes.get(sAttributeName);
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Map "+sUnmappedName+" to "+sAttributeName);
					}

					try {
						if (oAttribute.size() > 1) {
							if (hAttrResponse != null) {
								Vector<Object> vMultiValues = new Vector<Object>();
								for (int iCount = 0; iCount < oAttribute.size(); iCount++) {
									Object oValue = oAttribute.get(iCount);
									//_systemLogger.log(Level.FINEST, MODULE, sMethod, sAttributeName+" multi" + iCount + "=" + oValue);
									vMultiValues.add(oAttribute.get(iCount));
								}
								hAttrResponse.put(sAttributeName, vMultiValues);
							}
						}
						else {
							String sAttributeValue = (String) oAttribute.get();
							if (sAttributeValue == null)
								sAttributeValue = "";
							//_systemLogger.log(Level.FINEST, MODULE, sMethod, sAttributeName+" single=" + sAttributeValue);
							if (hAttrResponse != null)
								hAttrResponse.put(sAttributeName, sAttributeValue);
							
							// Check Organization ID or Name (only for single valued attributes)
							if (_sOrgDN != null && _sOrgName != null) {
								if (sUnmappedName.equals(_sOrgDN))
									sDnValue = sAttributeValue;
								if (sUnmappedName.equals(_sOrgName))
									sNameValue = sAttributeValue;
							}
						}
					}
					catch (Exception e) {
					}
				}
				if (hOrgResponse != null)
					_systemLogger.log(Level.INFO, MODULE, sMethod, "1. OrgDN="+sDnValue+" OrgName="+sNameValue);
				
				// Look for attributes in sub containers specified in the <sub_containers> tag
				for(String sSubId : _hmSubs.keySet()) {
				    String sSubTree = _hmSubs.get(sSubId);
				    String sSubAttribute = _hmAttributes.get(sSubId);
				    _systemLogger.log(Level.INFO, MODULE, sMethod, "SUB id="+sSubId+" sub="+sSubTree+" attr="+sSubAttribute+" subSearch="+sSubTree+","+sSearchName);
				    
					oAttributes = getLdapEntry(oDirContext, sSubTree+","+sSearchName, _sBaseDN);
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Attrs " + oAttributes);
					if (oAttributes == null)
						continue;
					oAttrEnum = oAttributes.getAll();
					while (oAttrEnum.hasMore()) {
						Attribute oAttribute = (Attribute) oAttrEnum.next();
						String sAttributeName = oAttribute.getID();
						if (!sSubAttribute.equals(sAttributeName))
							continue;
						if (oAttribute.size() == 1) {
							String sAttributeValue = (String) oAttribute.get();
							if (sAttributeValue == null) sAttributeValue = "";
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Attribute="+sAttributeName+" Value="+sAttributeValue);
							if (hAttrResponse != null)
								hAttrResponse.put(sSubId, sAttributeValue);
						}
					}
				}

				// Look for attributes in parent containers
				// Example search name: cn=bauke,o=123456789
				while (_sSearchTree != null) {
					int idx = sSearchName.indexOf(',');
					if (idx < 0)  // no more parents
						break;
					sSearchName = sSearchName.substring(idx+1);
					oAttributes = getLdapEntry(oDirContext, sSearchName, _sBaseDN);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Tree Search: "+sSearchName+" Values: " + oAttributes);
					
					oAttrEnum = oAttributes.getAll();
					while (oAttrEnum.hasMore()) {
						Attribute oAttribute = (Attribute) oAttrEnum.next();
						
						String sAttributeName = oAttribute.getID();
						String sUnmappedName = sAttributeName;
						//_systemLogger.log(Level.INFO, MODULE, sMethod, "Attribute="+sAttributeName);
						if (_htReMapAttributes.containsKey(sAttributeName)) {
							sAttributeName = _htReMapAttributes.get(sAttributeName);
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Map "+sUnmappedName+" to "+sAttributeName);
						}

						// Handle the value, but only store attribute if not present yet!
						if (oAttribute.size() > 1) {
							if (hAttrResponse != null && !hAttrResponse.containsKey(sAttributeName)) {
								Vector<Object> vMultiValues = new Vector<Object>();
								for (int iCount = 0; iCount < oAttribute.size(); iCount++) {
									Object oValue = oAttribute.get(iCount);
									//_systemLogger.log(Level.FINEST, MODULE, sMethod, "Tree "+sAttributeName+" multi" + iCount + "=" + oValue);
									vMultiValues.add(oAttribute.get(iCount));
								}
								hAttrResponse.put(sAttributeName, vMultiValues);
							}
						}
						else {
							String sAttributeValue = (String)oAttribute.get();
							if (sAttributeValue == null)
								sAttributeValue = "";
							
							//_systemLogger.log(Level.FINEST, MODULE, sMethod, "Tree "+sAttributeName+" single="+sAttributeValue);
							if (hAttrResponse != null && !hAttrResponse.containsKey(sAttributeName))
								hAttrResponse.put(sAttributeName, sAttributeValue);
	
							// Check Organization ID or Name (only single valued attribute)
							if (_sOrgDN != null && _sOrgName != null) {
								if (sUnmappedName.equals(_sOrgDN))
									sDnValue = sAttributeValue;
								if (sUnmappedName.equals(_sOrgName))
									sNameValue = sAttributeValue;
							}
						}
					}
					if (_sSearchTree.length() > 0 && sSearchName.startsWith(_sSearchTree+"=")) {
						_systemLogger.log(Level.FINER, MODULE, sMethod, "Finished search, sSearchname="+sSearchName);
						break;
					}
					// Try next parent up
				}

				// Organization ID and Name found?
				if (hOrgResponse != null) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "2. OrgDN="+sDnValue+" OrgName="+sNameValue);
					if (_sOrgDN != null && _sOrgName != null && sDnValue != null && sNameValue != null) {
						hOrgResponse.put(sDnValue, sNameValue);
					}
				}
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Search End, found="+cntResults+((hOrgResponse==null)? "": " hOrg="+hOrgResponse));
			
			// 20080722: Bauke: some applications want to know the base_dn and full_dn value
			if (hAttrResponse != null) {
				hAttrResponse.put("base_dn", _sBaseDN);
				if (sFullDn != null)
					hAttrResponse.put("full_dn", sFullDn);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			try {
				if (oSearchResults != null)
					oSearchResults.close();
				if (oDirContext != null)
					oDirContext.close();
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close directory context", e);
			}
		}
	}

	// Expect "cn=<value>" or "o=<org>" in the cn arg
    // Return: attributes or null on errors
	private Attributes getLdapEntry(DirContext oDirContext, String sCn, String sBaseDN)
	{
		String userDN = sCn + "," + sBaseDN;
		try {
			return oDirContext.getAttributes(userDN); // Retrieve attributes belonging to 'sCn'
		}
		catch (NameNotFoundException e) {
			return null;
		}
		catch (NamingException e) {	// Other errors
			return null;
		}
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
	 * Opens a new JNDI connection to the resource that is retrieved from the SAMAgent. <br>
	 * <br>
	 * 
	 * @return <code>DirContext</code> that contains the JNDI connection
	 * @throws ASelectUDBException
	 *             if the connection could not be opened
	 * @throws ASelectSAMException
	 *             if no valid resource could be found
	 */
	private DirContext getConnection()
	throws ASelectUDBException, ASelectSAMException
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

		try {
			oSAMResource = _samAgent.getActiveResource(_sResourceGroup);
		}
		catch (ASelectSAMException e) {
			StringBuffer sbFailed = new StringBuffer("No active resource found in udb resourcegroup: ");
			sbFailed.append(_sResourceGroup);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
			throw e;
		}

		oResourceConfig = oSAMResource.getAttributes();

		try {
			sDriver = _configManager.getParam(oResourceConfig, "driver");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'driver' found in connector configuration", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			sPrincipal = _configManager.getParam(oResourceConfig, "security_principal_dn");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'security_principal_dn' found in connector resource configuration", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			sPassword = _configManager.getParam(oResourceConfig, "security_principal_password");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
					"Invalid or empty config item 'security_principal_password' found in connector resource configuration, using empty password.", e);
		}

		try {
			sUseSSL = _configManager.getParam(oResourceConfig, "ssl");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'ssl' found in connector resource configuration", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			sUrl = _configManager.getParam(oResourceConfig, "url");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'url' found in connector resource configuration", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "ATTR_CTX " + sDriver + "_" + sPrincipal + "_" + sPassword
					+ "_" + sUseSSL + "_" + sUrl);
			oInitialDirContext = new InitialDirContext(createJNDIEnvironment(sDriver, sPrincipal, sPassword, sUseSSL, sUrl));
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create JNDI environment", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_IO, e);
		}
		return oInitialDirContext;
	}

	/**
	 * Creates an <code>HashMap</code> containing the JNDI environment variables. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sDriver
	 *            The JNDI driver that must be used
	 * @param sPrincipal
	 *            The principal dn
	 * @param sPassword
	 *            The password to use while connecting
	 * @param sUseSSL
	 *            indicates if an ssl connection must be created
	 * @param sUrl
	 *            The connection url
	 * @return a <code>Hastable</code> containing the JNDI environment variables
	 */
	private Hashtable<String, String> createJNDIEnvironment(String sDriver, String sPrincipal, String sPassword, String sUseSSL,
			String sUrl)
	{
		Hashtable<String, String> htEnvironment = new Hashtable<String, String>(11);

		htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, sDriver);
		htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
		htEnvironment.put(Context.SECURITY_PRINCIPAL, sPrincipal);
		htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);

		if (sUseSSL.equalsIgnoreCase("true")) {
			htEnvironment.put(Context.SECURITY_PROTOCOL, "ssl");
		}
		htEnvironment.put(Context.PROVIDER_URL, sUrl);
		return htEnvironment;
	}
}
