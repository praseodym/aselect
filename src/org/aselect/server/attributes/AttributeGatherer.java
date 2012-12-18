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
 * $Id: AttributeGatherer.java,v 1.23.8.4 2006/12/21 14:28:57 maarten Exp $ 
 * 
 * Changelog:
 * $Log: AttributeGatherer.java,v $
 * Revision 1.23.8.4  2006/12/21 14:28:57  maarten
 * removed unused imports
 *
 * Revision 1.23.8.3  2006/12/14 14:16:26  maarten
 * Updated ARP
 *
 * Revision 1.23.8.2  2006/11/27 13:53:58  leon
 * Fixed SFS attribute release
 *
 * Revision 1.23.8.1  2006/11/22 09:25:42  maarten
 * Updated version
 * Attribute gathering by home_organization added
 *
 * Revision 1.23  2006/04/26 12:15:44  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.22  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.21.4.3  2006/03/16 08:48:17  martijn
 * instead of Application.getOptionalParameter() using Application.getAttributePolicy()
 *
 * Revision 1.21.4.2  2006/03/10 15:15:36  martijn
 * added support for multivalue attributes in filterAttributes()
 *
 * Revision 1.21.4.1  2006/03/09 12:41:26  jeroen
 * adaptation for multi-valued attributes feature
 *
 * Revision 1.21  2005/09/09 13:27:44  erwin
 * Fixed Javadoc
 *
 * Revision 1.20  2005/09/07 13:30:24  erwin
 * - Improved cleanup of the attribute gatherer (bug #93)
 * - Removed unnesserary HashMap in attribute gatherer (bug #94)
 *
 * Revision 1.19  2005/04/27 14:54:39  erwin
 * Fixed problem with restart update
 *
 * Revision 1.18  2005/04/08 12:41:12  martijn
 *
 * Revision 1.17  2005/04/07 13:14:39  erwin
 * Added "else" for adding redundant parameters.
 *
 * Revision 1.16  2005/04/07 08:57:38  erwin
 * Added gather atributes support for remote A-Select servers.
 *
 * Revision 1.15  2005/04/07 06:37:12  erwin
 * Renamed "attribute" -> "param" to be compatible with configManager.
 *
 * Revision 1.14  2005/03/30 15:15:44  martijn
 * changed variable names to coding standard
 *
 * Revision 1.13  2005/03/30 15:10:21  martijn
 * the filterAttributes() method now supports wildcards
 *
 * Revision 1.12  2005/03/30 14:44:26  martijn
 * the getAttributes() method needs an TGT context instead of the A-Select user id
 *
 * Revision 1.11  2005/03/30 13:49:09  martijn
 * If the AttributeGatherer.gatherAttributes() is used, the TGT context must be supplied instead of uid, app_id and udb info
 *
 * Revision 1.10  2005/03/24 14:36:58  erwin
 * Improved Javadoc.
 *
 * Revision 1.9  2005/03/24 08:33:01  tom
 * Fixed javadoc
 *
 * Revision 1.8  2005/03/21 07:50:24  tom
 * Fixed error handling
 *
 * Revision 1.7  2005/03/18 13:43:35  remco
 * made credentials shorter (base64 encoding instead of hex representation)
 *
 * Revision 1.6  2005/03/18 09:29:24  remco
 * moved attribute gathering tags to attribute_gathering section
 *
 * Revision 1.5  2005/03/18 08:11:03  remco
 * made AttributeGatherer singleton
 *
 * Revision 1.4  2005/03/17 16:05:48  remco
 * Exceptions during AR invocations are ignored
 *
 * Revision 1.3  2005/03/17 15:15:01  remco
 * exception when leaving out "uid_source" parameter
 *
 * Revision 1.2  2005/03/17 14:08:48  remco
 * changed attribute functionality
 *
 * Revision 1.1  2005/03/16 13:12:11  remco
 * added attributes (initial version)
 *
 */
package org.aselect.server.attributes;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.attributes.requestors.IAttributeRequestor;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * Gather and filter user attributes. <br>
 * <br>
 * <b>Description:</b> <br>
 * This class gathers user attributes after successful authentication using one or more configured AttributeRequestors.
 * It also filters out attributes based on the Attribute Release Policy. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - DigiD Gateway integration, pass attributes - PKI attributes Subject DN
 *         and Issuer DN also split in smaller pieces - Attribute added specifying which handler performed
 *         authentication
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl) and UMC Nijmegen
 *         (http://www.umcn.nl)
 */
public class AttributeGatherer
{
	private static final String _MODULE = "AttributeGatherer";

	private static AttributeGatherer _this;

	private ASelectConfigManager _configManager;
	private ASelectSystemLogger _systemLogger;

	/**
	 * Contains all requestor objects as requestor-id=requestor-hashtable Where requestor-hastable consists of
	 * "object"=requestor-object, "uid-source"=uid source
	 */
	private HashMap<String, Object> _htRequestors;
	
	/* 20100201, Bauke
	 * Store the organization resolver object
	 */
	private IAttributeRequestor _organizationResolver = null;
	
	/**
	 * Contains the set of release policies: key=policy-ID, value=mapping-hashtable. The mapping-hashtable consists of
	 * key=requestor-ID, value=vector of attributes.
	 */

	private HashMap _htReleasePolicies;

	/**
	 * Contains the set of release policies that merges attributes if they already exist
	 */
	private HashMap _htDuplicatePolicies;

	/**
	 * Use Vector for determining order of policies
	 */

	private Vector _vReleasePolicies;

	/**
	 * The "id" of the default release policy
	 */
	private String _sDefaultReleasePolicy;

	// Copy remote attributes after TGT attributes
	String _sRemoteLast = null;

	/**
	 * Is used to acquire an instance of the AttributeGatherer. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new static <code>AttributeGatherer</code> instance if it's not instantiated yet. The static instance is
	 * returned. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * One <code>AttributeGatherer</code> instance exists. <br>
	 * 
	 * @return Sattic handle to the <code>AttributeGatherer</code>.
	 */
	public static AttributeGatherer getHandle()
	{
		if (_this == null)
			_this = new AttributeGatherer();
		return _this;
	}

	/**
	 * Initialize the Attribute Gatherer. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Initializes the attribute gatherer by reading and validating the attributes configuration. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * none <br>
	 * <br>
	 * 
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	public void init()
	throws ASelectException
	{
		final String sMethod = "init";

		String sConfigItem = null;
		Object oAttributeGatheringConfig = null;
		Object oRequestorsSection = null;
		Object oReleasePoliciesSection = null;
		_htRequestors = null;
		_htReleasePolicies = null;
		_vReleasePolicies = null;
		_sDefaultReleasePolicy = null; // 1.5.4
		_htDuplicatePolicies = new HashMap(); // 1.5.4

		_configManager = ASelectConfigManager.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();

		try {
			try {
				oAttributeGatheringConfig = _configManager.getSection(null, "attribute_gathering");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, _MODULE, sMethod, "Attribute gathering disabled.");
			}

			if (oAttributeGatheringConfig != null) {  // Obtain and verify requestors

				oRequestorsSection = _configManager.getSection(oAttributeGatheringConfig, sConfigItem = "attribute_requestors");
				_htRequestors = new HashMap();
				Object oRequestorConfig = null;
				try {
					oRequestorConfig = _configManager.getSection(oRequestorsSection, "requestor");
				}
				catch (ASelectConfigException e) {
				}
				_sRemoteLast = ASelectConfigManager.getSimpleParam(oRequestorsSection, "remote", false);
				_systemLogger.log(Level.INFO, _MODULE, sMethod, "sRemoteLast="+_sRemoteLast);
				
				// For all attribute requestors
				while (oRequestorConfig != null) {
					// Load/verify a single requestor from config
					String sID = _configManager.getParam(oRequestorConfig, sConfigItem = "id");
					_systemLogger.log(Level.INFO, _MODULE, sMethod, "Requestor id="+sID);
					String sUsage = ASelectConfigManager.getSimpleParam(oRequestorConfig, sConfigItem = "usage", false);
					
					Object oRequestorSpecificSection;
					try {
						oRequestorSpecificSection = _configManager.getSection(null, "requestor", "id=" + sID);
					}
					catch (ASelectConfigException e) {
						sConfigItem = "requestor id=" + sID;
						throw e;
					}

					String sRequestorClassName = _configManager.getParam(oRequestorConfig, sConfigItem = "class");
					try {
						Class cRequestorClass = Class.forName(sRequestorClassName);
						IAttributeRequestor attributeRequestor = (IAttributeRequestor) cRequestorClass.newInstance();
						attributeRequestor.init(oRequestorSpecificSection);
						if ("org".equals(sUsage))
							_organizationResolver = attributeRequestor;
						else
							_htRequestors.put(sID, attributeRequestor);
					}
					catch (Exception e) {
						StringBuffer sb = new StringBuffer("Class \"").append(sRequestorClassName).append(
								"\" is not a valid attribute requestor");
						_systemLogger.log(Level.SEVERE, _MODULE, sMethod, sb.toString(), e);
						throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					// Obtain handle to the next requestor
					try {
						oRequestorConfig = _configManager.getNextSection(oRequestorConfig);
					}
					catch (ASelectConfigException e) {
						oRequestorConfig = null;
					}
				}

				// Obtain and verify attribute release policies
				oReleasePoliciesSection = _configManager.getSection(oAttributeGatheringConfig,
						sConfigItem = "attribute_release_policies");
				try {
					_sDefaultReleasePolicy = _configManager.getParam(oReleasePoliciesSection, "default");
				}
				catch (ASelectConfigException e) {  // The "default" release policy is optional
				}

				Object oReleasePolicyConfig = null;
				_htReleasePolicies = new HashMap();
				_vReleasePolicies = new Vector();
				try {
					oReleasePolicyConfig = _configManager.getSection(oReleasePoliciesSection, "release_policy");
				}
				catch (ASelectConfigException e) {
				}
				
				// For all release policies
				while (oReleasePolicyConfig != null) {
					String sID = _configManager.getParam(oReleasePolicyConfig, sConfigItem = "id");
					if (_htReleasePolicies.containsKey(sID)) {
						StringBuffer sb = new StringBuffer("Release policy \"").append(sID).append("\" is defined more than once.");
						_systemLogger.log(Level.SEVERE, _MODULE, sMethod, sb.toString());
						throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
					}
					Object oAttribute = _configManager.getSection(oReleasePolicyConfig, sConfigItem = "attribute");
					HashMap htAttributes = new HashMap();
					while (oAttribute != null) {
						String sAttribute = _configManager.getParam(oAttribute, sConfigItem = "id");
						String sRequestor = _configManager.getParam(oAttribute, sConfigItem = "requestor");

						Vector vAttributes = (Vector) htAttributes.get(sRequestor);
						if (vAttributes == null)
							vAttributes = new Vector();
						vAttributes.add(sAttribute);
						htAttributes.put(sRequestor, vAttributes);
						try {
							oAttribute = _configManager.getNextSection(oAttribute);
						}
						catch (ASelectConfigException e) {
						}
					}
					_htReleasePolicies.put(sID, htAttributes);
					_vReleasePolicies.add(sID);

					try {
						String sDuplicateOption = _configManager.getParam(oReleasePolicyConfig, sConfigItem = "duplicate");
						_htDuplicatePolicies.put(sID, sDuplicateOption);
					}
					catch (ASelectConfigException e) {
					}

					// Obtain handle to the next release policy
					try {
						oReleasePolicyConfig = _configManager.getNextSection(oReleasePolicyConfig);
					}
					catch (ASelectConfigException e) {
						oReleasePolicyConfig = null;
					}
				}
				_systemLogger.log(Level.INFO, _MODULE, sMethod, "Successfully parsed attributes configuration.");
			}
		}
		catch (ASelectConfigException e) {
			StringBuffer sb = new StringBuffer("Configuration parameter or section \"").append(sConfigItem).append("\" not found.");
			_systemLogger.log(Level.WARNING, _MODULE, sMethod, sb.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (ASelectException ase) {
			throw ase;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, _MODULE, sMethod, "Unexpected error while initializing", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Get Organization ID and Name combinations for the given user. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Use the gathering process to retrieve organizations.
	 * Allows the caller to let the user choose which organization to represent.
	 * 
	 * @param htTGTContext
	 *            The TGT context.
	 * @return A <code>HashMap</code> containing the gathered organizations.
	 * @throws ASelectException
	 *             If attribute gathering fails.
	 */
	public HashMap<String,String> gatherOrganizations(HashMap htTGTContext)
	{
		final String sMethod = "gatherOrganizations";
		String sUid = (String) htTGTContext.get("uid");
		
		if (_organizationResolver == null) {
			_systemLogger.log(Level.INFO, _MODULE, sMethod, "No OrganizationResolver defined");
			return null;
		}

		// Let the specific attribute gatherer do it's work
		HashMap<String,String> hOrganizations = null;
		try {
			hOrganizations = _organizationResolver.getOrganizations(htTGTContext);
		}
		catch (ASelectAttributesException e) {
			_systemLogger.log(Level.WARNING, _MODULE, sMethod, "Could not gather Organizations for user '"+sUid+"'", e);
		}
		_systemLogger.log(Level.INFO, _MODULE, sMethod, "GATHER-ed Organizations=" + hOrganizations);
		return hOrganizations;
	}
	
	/**
	 * Gather all attributes for the given user. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Performs the following steps:
	 * <ul>
	 * <li>Determine the release policy</li>
	 * <li>Use the configured attribute requestors to gather attributes</li>
	 * <li>Merge the returned attributes</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * <br>
	 * 
	 * @param htTGTContext
	 *            The TGT context.
	 * @return A <code>HashMap</code> containing all gathered attributes.
	 * @throws ASelectException
	 *             If attribute gathering fails.
	 */
	public HashMap gatherAttributes(HashMap htTGTContext)
	throws ASelectException
	{
		final String sMethod = "gatherAttributes";
		HashMap<String, Object> htAttributes = new HashMap<String, Object>();
		String sArpTarget = null;
		boolean bFound = false;

		_systemLogger.log(Level.INFO, _MODULE, sMethod, "GATHER BEGIN _htReleasePolicies=" + _htReleasePolicies);
		//_systemLogger.log(Level.INFO, _MODULE, sMethod, "GATHER TGTContext=" + htTGTContext);

		// Release policies available?
		if (_vReleasePolicies == null || _htReleasePolicies == null) {
			_systemLogger.log(Level.INFO, _MODULE, sMethod, "No release policies available");
			return null;
		}

		// Get user ID
		String sUid = (String) htTGTContext.get("uid");
		sArpTarget = (String) htTGTContext.get("arp_target"); // added 1.5.4

		if (sArpTarget != null) {
			try {
				sArpTarget = URLDecoder.decode(sArpTarget, "UTF-8");
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, _MODULE, sMethod, "Error decoding arp_target parameter, e");
			}
		}
		else {
			_systemLogger.log(Level.CONFIG, _MODULE, sMethod, "No 'arp_target' parameter defined");
			sArpTarget = null;
		} // end of 1.5.4

		// 2010-2-10, Bauke: support gathering for a specific chosen organization
		String sOrgId = (String)htTGTContext.get("org_id");
		if (sOrgId != null && sOrgId.equals("")) {
			_systemLogger.log(Level.INFO, _MODULE, sMethod, "No organization choice was made, refusing to GATHER");
			return null;
		}

		// First, determine our release policy because this can
		// potentially save us some work
		String sReleasePolicy = null;
		String sLocalOrg = (String) htTGTContext.get("local_organization");
		String sAppID = (String) htTGTContext.get("app_id");

		_systemLogger.log(Level.INFO, _MODULE, sMethod, "GATHER == sUid=" + sUid + " sLocalOrg=" + sLocalOrg + " user organization="+sOrgId);
		if (sLocalOrg != null) {
			// use specific attribute policy, 1.5.4
			// Enumeration enumPolicies = _htReleasePolicies.keys();
			// while (enumPolicies.hasMoreElements() && !bFound)
			if (sArpTarget != null) {
				Enumeration enumPolicies = _vReleasePolicies.elements();
				while (enumPolicies.hasMoreElements() && !bFound) {
					String sKey = (String) enumPolicies.nextElement();
					if (Utils.matchWildcardMask(sArpTarget, sKey)) {
						sReleasePolicy = sKey;
						bFound = true;
					}
				}
			} // end of 1.5.4
			if (sReleasePolicy == null && !bFound) {
				sReleasePolicy = CrossASelectManager.getHandle().getOptionalLocalParam(sLocalOrg, "attribute_policy");
			}
		}
		else { // use application attribute release policy
			sReleasePolicy = ApplicationManager.getHandle().getAttributePolicy(sAppID);
		}

		if (sReleasePolicy == null) { // use default policy
			sReleasePolicy = _sDefaultReleasePolicy;
		}
		if (sReleasePolicy == null) { // No release policy -> no attributes
			return htAttributes;
		}

		HashMap htReleasePolicy = (HashMap) _htReleasePolicies.get(sReleasePolicy);
		if (htReleasePolicy == null) {
			// Unknown release policy -> log warning; no attributes
			StringBuffer sb = new StringBuffer("Unknown release policy '").append(sReleasePolicy).append(
					"' configured for application '").append(sAppID).append("'");
			_systemLogger.log(Level.WARNING, _MODULE, sMethod, sb.toString());
		}
		else {
			try {
				// Use all configured attribute requestors to gather attributes
				Set keys = htReleasePolicy.keySet();
				for (Object s : keys) {
					String sRequestorID = (String) s;
					Vector vAttributes = (Vector) htReleasePolicy.get(sRequestorID);
					_systemLogger.log(Level.INFO, _MODULE, sMethod, "GATHER << Requestor=" + sRequestorID+" vAttr="+vAttributes);
					
					IAttributeRequestor attributeRequestor = (IAttributeRequestor) _htRequestors.get(sRequestorID);
					if (attributeRequestor == null) {
						StringBuffer sb = new StringBuffer("Unknown requestor \"").append(sRequestorID).append("\"");
						throw new Exception(sb.toString());
					}

					// Let the specific attribute gatherer do it's work
					// The Attribute Requestor is responsible for using the organization's id in the gathering process
					HashMap htAttrsFromAR = null;
					try {
						// 20120627, Bauke: added attributes gathered so far, allows us to use a gathered attribute later on
						htAttrsFromAR = attributeRequestor.getAttributes(htTGTContext, vAttributes, htAttributes);
					}
					catch (ASelectAttributesException eA) {
						StringBuffer sb = new StringBuffer("Could not gather attributes for user \"").append(sUid).append("\"");
						_systemLogger.log(Level.WARNING, _MODULE, sMethod, sb.toString(), eA);
					}
					_systemLogger.log(Level.INFO, _MODULE, sMethod, "GATHER >> Requestor=" + sRequestorID + " htAttrsFromAR="+htAttrsFromAR);

					// Merge the returned attributes with our set
					if (htAttrsFromAR != null) {
						// Remove unwanted attributes (those not in our policy)
						htAttrsFromAR = filterAttributes(htAttrsFromAR, vAttributes);

						Set keys1 = htAttrsFromAR.keySet();
						for (Object s1 : keys1) {
							String sKey = (String) s1;
							if (htAttributes.containsKey(sKey)) {
								String sDuplicateOption = (String) _htDuplicatePolicies.get(sReleasePolicy);
								StringBuffer sb = new StringBuffer("Attribute \"").append(sKey).append(
										"\" returned by attribute requestor \"").append(sRequestorID).append(
										"\" already exists (\"duplicate\"=\"" + sDuplicateOption + "\").");
								_systemLogger.log(Level.INFO, _MODULE, sMethod, sb.toString());

								// add 1.5.4
								if (sDuplicateOption != null) {
									if (sDuplicateOption.equals("merge")) {
										Object oValue1 = htAttributes.get(sKey);
										Vector oVector1 = null;
										if (oValue1 instanceof String) {
											oVector1 = new Vector();
											oVector1.add(oValue1);
										}
										else if (oValue1 instanceof Vector) {
											oVector1 = (Vector) oValue1;
										}
										else {
											_systemLogger.log(Level.WARNING, _MODULE, sMethod,
													"Attribute value (existing) neither String nor Vector!");
										}
										if (oVector1 != null) {
											Object oValue2 = htAttrsFromAR.get(sKey);
											if (oValue2 instanceof String) {
												oVector1.add(oValue2);
											}
											else if (oValue2 instanceof Vector) {
												oVector1.addAll((Vector) oValue2);
											}
											else {
												_systemLogger.log(Level.WARNING, _MODULE, sMethod,
														"Attribute value (to-be-added) neither String nor Vector!");
											}
											htAttributes.put(sKey, oVector1);
										}
									}
									else if (sDuplicateOption.equals("replace")) {
										htAttributes.put(sKey, htAttrsFromAR.get(sKey));
									}
									else if (sDuplicateOption.equals("delete")) {
										htAttributes.remove(sKey);
									}
									else {
										// unknown option: no action
										_systemLogger.log(Level.WARNING, _MODULE, sMethod,
												"Unknown attribute policy \"duplicate\" option: \"" + sDuplicateOption
														+ "\"!");
									}
								} // else: backwards compatibility: no action,
								// end of 1.5.4
							}
							else
								htAttributes.put(sKey, htAttrsFromAR.get(sKey));
						}
						_systemLogger.log(Level.INFO, _MODULE, sMethod, "GATHER -- htAttributes="+htAttributes);
					}
				}
			}
			catch (Exception e) {
				_systemLogger.log(Level.SEVERE, _MODULE, sMethod, "Error while gathering attributes", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
		}

		// Considered using the TGTAttributeRequestor for this,
		// but attribute requestors are not handled in a defined order
		if (!"last".equals(_sRemoteLast))
			addRemoteAttributesFromTgt(htAttributes, htTGTContext);

		// Bauke: added additional attributes, they can take precedence over the values in "attributes"
		_systemLogger.log(Level.INFO, _MODULE, sMethod, "Add additional attributes from TGT");
		Utils.copyHashmapValue("uid", htAttributes, htTGTContext);
		Utils.copyHashmapValue("sel_uid", htAttributes, htTGTContext);
		// 20120606, Bauke: Certainly not, is added by the filter: Utils.copyHashmapValue("usi", htAttributes, htTGTContext);

		String sAuthsp = (String) htTGTContext.get("authsp");
		if (sAuthsp != null)
			htAttributes.put("sel_authsp", sAuthsp);
		String sAuthspLevel = (String) htTGTContext.get("authsp_level");
		if (sAuthsp != null) {
			htAttributes.put("authsp_level", sAuthspLevel);
			htAttributes.put("sel_level", sAuthspLevel);
		}
		Utils.copyHashmapValue("sel_level", htAttributes, htTGTContext);  // if present, overrides authsp_level
		Utils.copyHashmapValue("authsp_type", htAttributes, htTGTContext);
		
		Utils.copyHashmapValue("client_ip", htAttributes, htTGTContext);
		Utils.copyHashmapValue("user_agent", htAttributes, htTGTContext);
		Utils.copyHashmapValue("language", htAttributes, htTGTContext);
		Utils.copyHashmapValue("sms_phone", htAttributes, htTGTContext);

		String sSubjectDN = (String) htTGTContext.get("pki_subject_dn");
		String sToken;
		int idx;
		if (sSubjectDN != null) {
			// Subject: C=NL, O=Test-academisch ziekenhuis, CN=Agnes.
			// Testzorgverlener-14, SERIALNUMBER=000001788, T=Cardioloog
			htAttributes.put("pki_subject_dn", sSubjectDN);
			StringTokenizer st = new StringTokenizer(sSubjectDN, ",");
			_systemLogger.log(Level.INFO, _MODULE, sMethod, "Tokens=" + st.countTokens() + " sSubjectDN=" + sSubjectDN);
			while (st.hasMoreTokens()) {
				sToken = st.nextToken(); // C=NL
				idx = sToken.indexOf('=');
				if (idx > 0)
					htAttributes.put("pki_subject_" + sToken.substring(0, idx).trim().toLowerCase(), sToken
							.substring(idx + 1));
			}
		}
		String sIssuerDN = (String) htTGTContext.get("pki_issuer_dn");
		if (sIssuerDN != null) {
			htAttributes.put("pki_issuer_dn", sIssuerDN);
			StringTokenizer st = new StringTokenizer(sIssuerDN, ",");
			_systemLogger.log(Level.INFO, _MODULE, sMethod, "Tokens=" + st.countTokens() + " sIssuerDN=" + sIssuerDN);
			while (st.hasMoreTokens()) {
				sToken = st.nextToken(); // C=NL
				idx = sToken.indexOf('=');
				if (idx > 0)
					htAttributes.put("pki_issuer_" + sToken.substring(0, idx).trim().toLowerCase(), sToken
							.substring(idx + 1));
			}
		}

		String sSubjectId = (String) htTGTContext.get("pki_subject_id");
		if (sSubjectId != null) {
			htAttributes.put("pki_subject_id", sSubjectId);
			StringTokenizer st = new StringTokenizer(sSubjectId, "-");
			_systemLogger.log(Level.INFO, _MODULE, sMethod, "Tokens=" + st.countTokens() + " sSubjectId=" + sSubjectId);
			for (int fldnr = 1; st.hasMoreTokens(); fldnr++) {
				sToken = st.nextToken(); // 01.001
				String sFld = "pki_subject_id" + Integer.toString(fldnr);
				// _systemLogger.log(Level.INFO, _MODULE, sMethod, "Field="+sFld+" Token="+sToken);
				htAttributes.put(sFld, sToken);
			}
		}
		// End of additions
		
		if ("last".equals(_sRemoteLast))
			addRemoteAttributesFromTgt(htAttributes, htTGTContext);

		_systemLogger.log(Level.INFO, _MODULE, sMethod, "Try authsp with id: " + sAuthsp); // if present
		try {
			Object authSPs = Utils.getSimpleSection(_configManager, _systemLogger, null, "authsps", true);
			Object authSPsection = Utils.getSectionFromSection(_configManager, _systemLogger, authSPs, "authsp", "id=" + sAuthsp, false);
			if (authSPsection != null) {
				String sHandler = _configManager.getParam(authSPsection, "handler");
				int iDot = sHandler.lastIndexOf(".");
				sHandler = sHandler.substring(iDot + 1, sHandler.length());

				_systemLogger.log(Level.INFO, _MODULE, sMethod, "sHandler=" + sHandler);
				htAttributes.put("handler", sHandler);
			}
			else
				_systemLogger.log(Level.INFO, _MODULE, sMethod, "Authsp " + sAuthsp + " not present");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, _MODULE, sMethod, "Failed to retrieve config for AuthSPs.", e);
			htAttributes.put("handler", sAuthsp);
		}

		_systemLogger.log(Level.INFO, _MODULE, sMethod, "GATHER END htAttributes=" + htAttributes);
		return htAttributes;
	}

	/**
	 * Add remote attributes from TGT.<br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Add the attributes to 'htAttributes'. They are taken from the 'attributes' field in the TGT
	 * 
	 * @param htAttributes - Add attributes to.
	 * @param htTGTContext - The TGT context.
	 * @throws ASelectException - When attribute retrieval fails.
	 */
	private void addRemoteAttributesFromTgt(HashMap<String, Object> htAttributes, HashMap htTGTContext)
	throws ASelectException
	{
		String sMethod = "addRemoteAttributesFromTgt";
		String fld = (String) htTGTContext.get("attributes");
		if (fld != null) {
			HashMap htTgtAttributes = org.aselect.server.utils.Utils.deserializeAttributes(fld);
			_systemLogger.log(Level.INFO, _MODULE, sMethod, "GATHER (remote)TGT \"attributes\"=" + htTgtAttributes);
			Set keys = htTgtAttributes.keySet();
			for (Object s : keys) {
				String sKey = (String) s;
				Object oValue = htTgtAttributes.get(sKey);
				//if (!(oValue instanceof String))
				//	continue;
				htAttributes.put(sKey, oValue);
			}
		}
	}

	/**
	 * Destroys the objects in this class that need to be destroyed carefully. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Calls the destroy of the attribute requestors in the <code>_htRequestors</code> HashMap. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * The <code>_htRequestors</code> contains attribute requestors that aren't destroyed <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * All attribute requestors in <code>_htRequestors</code> are destroyed. <br>
	 */
	public void destroy()
	{
		String sMethod = "destroy()";
		try {
			if (_htRequestors != null) {
				for (Map.Entry<String, Object> entry : _htRequestors.entrySet()) {
					IAttributeRequestor oAttributeRequestor = (IAttributeRequestor) entry.getValue();
					oAttributeRequestor.destroy();
				}
				/*
				 * Enumeration enumRequestors = _htRequestors.elements(); while (enumRequestors.hasMoreElements()) {
				 * IAttributeRequestor oAttributeRequestor = (IAttributeRequestor) enumRequestors.nextElement();
				 * oAttributeRequestor.destroy(); }
				 */
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, _MODULE, sMethod, "Error during the process of the destroy", e);
		}
	}

	/**
	 * private constructor, class is Singleton.
	 */
	private AttributeGatherer() {
	}

	// Filter the attributes
	/**
	 * Filter attributes.
	 * 
	 * @param htAttributes
	 *            the ht attributes
	 * @param vRequestedAttributes
	 *            the v requested attributes
	 * @return the hash map
	 */
	private HashMap filterAttributes(HashMap htAttributes, Vector vRequestedAttributes)
	{
		if (htAttributes == null || vRequestedAttributes == null)
			return htAttributes;
		HashMap htFiltered = new HashMap();

		Set keys = htAttributes.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
			// for (Enumeration enumRetrievedAttributes = htAttributes.keys();
			// enumRetrievedAttributes.hasMoreElements();) {
			// String sKey = (String) enumRetrievedAttributes.nextElement();
			for (Enumeration enumRequestedAttributes = vRequestedAttributes.elements(); enumRequestedAttributes
					.hasMoreElements();) {
				String sRequestedAttribute = (String) enumRequestedAttributes.nextElement();
				if (Utils.matchWildcardMask(sKey, sRequestedAttribute)) {
					// The value can be a String or a Vector
					Object oValue = htAttributes.get(sKey);
					if (oValue != null)
						htFiltered.put(sKey, oValue);
				}
			}
		}
		return htFiltered;
	}
}
