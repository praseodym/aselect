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
 * $Id: AuthorizationEngine.java,v 1.10 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthorizationEngine.java,v $
 * Revision 1.10  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.9  2006/02/28 08:06:44  leon
 * Fixed bug #112 Filter logs wrong configuration parameter name.
 *
 * Revision 1.8  2005/09/09 09:52:34  erwin
 * Changed configuration names conform standard.
 *
 * Revision 1.7  2005/09/02 14:44:29  erwin
 * - Added Authorization Rule ID
 * - Added ip parameter in request=verify_ticket
 *
 * Revision 1.6  2005/09/01 10:12:31  erwin
 *
 * Revision 1.5  2005/08/30 08:13:46  erwin
 * Improved init()
 *
 * Revision 1.4  2005/08/29 10:04:26  erwin
 * Implemented the reading of the configuration of authorization rules
 *
 * Revision 1.3  2005/08/25 15:22:40  erwin
 * Added support for multiple time and dat formats
 *
 * Revision 1.2  2005/08/25 09:50:52  erwin
 * Implemented engine
 *
 * Revision 1.1  2005/08/19 08:34:57  erwin
 * Initial version
 *
 * 
 */
package org.aselect.agent.authorization;

import java.io.StringReader;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.agent.authorization.evaluation.AuthorizationRuleEvaluator;
import org.aselect.agent.authorization.parsing.AuthorizationRule;
import org.aselect.agent.authorization.parsing.AuthorizationRuleParser;
import org.aselect.agent.authorization.parsing.AuthorizationRuleScanner;
import org.aselect.agent.authorization.parsing.EvaluationTree;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectAuthorizationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Utils;

/**
 * A-Select Agent authorization engine. <br>
 * <br>
 * <b>Description:</b><br>
 * The <code>AuthorizationEngine</code> contains functionality for authorizing users by means of A-Select attributes.
 * This components reads authorization rules from the configuration and can add more evaluation rules during runtime
 * using the <code>addAuthorizationRule</code> method. <br>
 * The <code>AuthorizationEngine</code> is implemented using the Singleton design pattern. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - Config parameter: need_filter_rules Agent will only allow access after
 *         the Filter rules have been sent. Otherwise, when the Agent is started after the filter the rules are not
 *         enforced (Security Hole).
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl)
 */
public class AuthorizationEngine
{
	/** The module name. */
	private final String MODULE = "AuthorizationEngine";

	/**
	 * The array for rules and URI's.
	 */
	private final String[] ARRAY_TYPE = new String[0];

	/** The singleton instance. */
	private static AuthorizationEngine _instance;

	/** The configuration manager */
	private ConfigManager _configManager;

	/** The system logger */
	private SystemLogger _systemLogger;

	/**
	 * Contains all evaluation trees.
	 */
	private HashMap _htEvaluationForest;

	/**
	 * Can be used to evaluate the authorization rules.
	 */
	private AuthorizationRuleEvaluator _oEvaluator;

	// Agent will only allow access after the Filter rules have been sent
	// Otherwise, when the Agent is started after the filter the rules are not enforced (Security Hole)
	boolean _bNeedFilterRules = false;

	/**
	 * Get a static handle to the <code>AuthorizationEngine</code> instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if a static instance exists, otherwise it is created. This instance is returned. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * One instance of the <code>AuthorizationEngine</code> exists.
	 * 
	 * @return A static handle to the <code>AuthorizationEngine</code>.
	 */
	public static AuthorizationEngine getHandle()
	{
		if (_instance == null)
			_instance = new AuthorizationEngine();
		return _instance;
	}

	/**
	 * Initializes the <code>AuthorizationEngine</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Read configuration settings and initializes the components. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The instance variables and components are initialized. <br>
	 * 
	 * @param oAuthorizationConfig
	 *            The authorization configuration section.
	 * @param configManager
	 *            The configuration manager.
	 * @param systemlogger
	 *            The systemlogger.
	 * @return true if initialization succeeds, otherwise false.
	 */
	public boolean init(Object oAuthorizationConfig, ConfigManager configManager, SystemLogger systemlogger)
	{
		final String sMethod = "init()";
		Object oAuthorizationApplicationsSection = null;
		Object oAuthorizationApplicationSection = null;
		Object oRulesSection = null;
		Object oRuleSection = null;
		boolean bRet = false;
		// set system components
		_systemLogger = systemlogger;
		_configManager = configManager;
		_oEvaluator = new AuthorizationRuleEvaluator(_systemLogger);

		// create new forest
		_htEvaluationForest = new HashMap();

		try {
			// Bauke: added
			try {
				Object _oAgentSection = _configManager.getSection(null, "agent");
				String sTemp = _configManager.getParam(_oAgentSection, "need_filter_rules");
				if (sTemp.equalsIgnoreCase("true")) {
					_bNeedFilterRules = true;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "need_filter_rules=" + _bNeedFilterRules);
			}
			catch (ASelectException e) { // OK too
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Exception=" + e);
			}
			// read evaluation trees from configuration and add to forrest
			try {
				oAuthorizationApplicationsSection = _configManager.getSection(oAuthorizationConfig, "policies");
			}
			catch (ASelectConfigException e) {
				// policies section may be omitted.
			}

			if (oAuthorizationApplicationsSection != null)

				try {  // Get first policy
					oAuthorizationApplicationSection = _configManager.getSection(oAuthorizationApplicationsSection, "policy");
				}
				catch (ASelectConfigException e) {  // zero or more policies may be configured.
				}

			// For all policies
			while (oAuthorizationApplicationSection != null) {
				String sAppId = null;
				try {
					sAppId = _configManager.getParam(oAuthorizationApplicationSection, "app_id");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Invalid policy section: missing 'app_id' parameter", e);
					throw e;
				}
				// Get first rule
				try {
					oRulesSection = _configManager.getSection(oAuthorizationApplicationSection, "rules");
					oRuleSection = _configManager.getSection(oRulesSection, "rule");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing or invalid authorization rules section", e);
					throw e;
				}

				Vector vRuleIDs = new Vector();
				Vector vRules = new Vector();
				Vector vURIs = new Vector();
				// For all rules
				while (oRuleSection != null) {
					String sRuleId = null;
					String sRuledata = null;
					String sURI = null;

					// Get mandatory ID parameter
					try {
						sRuleId = _configManager.getParam(oRuleSection, "id");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Invalid authorization rule section: missing 'id' parameter", e);
						throw e;
					}

					try {
						sRuledata = _configManager.getParam(oRuleSection, "condition");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Invalid authorization rule section: missing 'condition' parameter", e);
						throw e;
					}

					// get optional uri paramater
					try {
						sURI = _configManager.getParam(oRuleSection, "target");
					}
					catch (ASelectConfigException e) {
						// No logging; data may be null
					}
					// add id, rule and URI
					vRuleIDs.add(sRuleId);
					vRules.add(sRuledata);
					vURIs.add(sURI);

					// next rule
					oRuleSection = _configManager.getNextSection(oRuleSection);
				}

				// add rules for the given application
				setAuthorizationRules(sAppId, (String[]) vRuleIDs.toArray(ARRAY_TYPE), (String[]) vRules
						.toArray(ARRAY_TYPE), (String[]) vURIs.toArray(ARRAY_TYPE));

				// next application
				oAuthorizationApplicationSection = _configManager.getNextSection(oAuthorizationApplicationSection);
			}

			bRet = true;
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully started");

		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error in authorization configuration", e);
			bRet = false;

		}
		catch (ASelectAuthorizationException e) {

			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Error in authorization configuration: invalid authorization rule", e);
			bRet = false;
		}
		return bRet;
	}

	/**
	 * Set authorization rules for an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Adds a new authorization rule to the given application. If the application allready contains rules, the rule is
	 * appended to this application. <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>sAppId != null</code></li>
	 * <li><code>saRules != null</code></li>
	 * <li><code>saURIs != null</code></li>
	 * <li><code>saRules.length == saURIs.length</code></li> *
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The rules are added to the given application in the evaluation rules forrest. <br>
	 * <br>
	 * 
	 * @param sAppId
	 *            The application ID.
	 * @param saIDs
	 *            The rules ID's.
	 * @param saRules
	 *            The authorization rules.
	 * @param saURIs
	 *            The authorization rule URI's.
	 * @throws ASelectAuthorizationException
	 *             If one or more of the supplied rules are not valid authorization rules.
	 */
	public synchronized void setAuthorizationRules(String sAppId, String[] saIDs, String[] saRules, String[] saURIs)
	throws ASelectAuthorizationException
	{
		final String sMethod = "addAuthorizationRules";
		String sId = null;
		String sRule = null;
		String sURI = null;
		HashMap htEvaluationTrees = new HashMap();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "sAppID=" + sAppId + ", Set " + saRules.length + " rule(s)");
		try {
			for (int i = 0; i < saRules.length; i++) {
				sRule = saRules[i];
				sURI = saURIs[i];
				sId = saIDs[i];
				_systemLogger.log(Level.INFO, MODULE, sMethod, "RULE=" + sRule + " URI=" + sURI + " Id=" + sId);
				AuthorizationRuleScanner oScanner = new AuthorizationRuleScanner(new StringReader(sRule));
				AuthorizationRuleParser oParser = new AuthorizationRuleParser(oScanner, _systemLogger);

				oParser.parse();
				EvaluationTree eTree = oParser.getEvaluationTree();
				AuthorizationRule oRule = new AuthorizationRule(sRule, sURI, eTree);
				htEvaluationTrees.put(sId, oRule);
			}
			_htEvaluationForest.put(sAppId, htEvaluationTrees);
		}
		catch (ASelectAuthorizationException e) {
			StringBuffer sb = new StringBuffer("Error parsing authorization rule : \"");
			sb.append(sRule).append("\"");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sb.toString(), e);
			throw e;
		}
	}

	/**
	 * Check if a user is authorized. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Evaluates the rules of the given application by subtitution of the given
	 * user attributrs and validating all rules. <br>
	 * The user is only authorized if all rules of the application apply. <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>sAppId != null</code></li>
	 * <li><code>htUserAttributes != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * <br>
	 * 
	 * @param sAppId
	 *          The app_id of the application that the user is authorized for.
	 * @param sURI
	 *          The URI for which the user is authorized.
	 * @param htUserAttributes
	 *          The user attributes.
	 * @return
	 * 			-1: no rules received, 0: ok, 1: not authorized 
	 * @throws ASelectAuthorizationException
	 *             If evalution of the rule fails.
	 */
	public int checkUserAuthorization(String sAppId, String sURI, HashMap htUserAttributes)
	throws ASelectAuthorizationException
	{
		final String sMethod = "checkUserAuthorization";
		StringBuffer sb = null;
		int iResult = 0;
		// get all evaluation trees of the given application
		HashMap htEvaluationTrees = (HashMap) _htEvaluationForest.get(sAppId);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "sAppID=" + sAppId
				+ ((_bNeedFilterRules) ? " need_filter_rules" : "") + ", sURI=" + sURI);

		if (htEvaluationTrees == null) // no evaluation trees
		{
			// No rules so user is authorized, unless NeedFilterRules was set
			_systemLogger.log(Level.INFO, MODULE, sMethod, "No Rules -> "
					+ ((_bNeedFilterRules) ? "NOT OK (filter did not send them)" : "OK"));
			iResult = (_bNeedFilterRules)? -1: 0;
		}
		else {
			Set keys = htEvaluationTrees.keySet();
			for (Object s : keys) {
				String sRuleId = (String) s;
				AuthorizationRule oRule = (AuthorizationRule) htEvaluationTrees.get(sRuleId);
				EvaluationTree eTree = oRule.getEvaluationTree();

				String sURIMask = oRule.getURI();
				_systemLogger.log(Level.FINER, MODULE, sMethod, "sRuleId=" + sRuleId + " sURIMask=" + sURIMask
						+ " sURI=" + sURI);

				if (sURIMask == null || (sURI != null && Utils.matchWildcardMask(sURI, sURIMask)))
				// This URI obliges authorization
				{
					try {
						_systemLogger.log(Level.FINER, MODULE, sMethod, "Need AUTH");
						if (!_oEvaluator.evaluate(htUserAttributes, eTree)) {
							iResult = 1;  // rejected
							sb = new StringBuffer("User attributes not sufficient for rule: '");
							sb.append(sRuleId).append("' ('");
							sb.append(oRule.getPlainTextRule()).append("').");
							_systemLogger.log(Level.WARNING, MODULE, sMethod, sb.toString());
						}
					}
					catch (ASelectAuthorizationException e) {
						sb = new StringBuffer("Error evaluating authorization rule: '");
						sb.append(sRuleId).append("' ('");
						sb.append(oRule.getPlainTextRule()).append("')");
						_systemLogger.log(Level.WARNING, MODULE, sMethod, sb.toString(), e);
						throw e;
					}
				}
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, (iResult==0) ? "OK" : (iResult==-1)? "NO RULES": "NOT OK");
		return iResult;
	}

	/**
	 * Retrieve a String represenattion of this <code>AuthorizationEngine</code>.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString()
	{
		StringBuffer sb = new StringBuffer();
		Set keys = _htEvaluationForest.keySet();
		for (Object s : keys) {
			String sAppId = (String) s;
			// Enumeration eApplications = _htEvaluationForrest.keys();
			// while (eApplications.hasMoreElements()) {
			// String sAppId = (String) eApplications.nextElement();
			sb.append(sAppId).append(": ");
			HashMap htRule = (HashMap) _htEvaluationForest.get(sAppId);
			sb.append(htRule.keySet());
			sb.append("\n");
		}
		return sb.toString();
	}

	/**
	 * Private default constructor.
	 */
	private AuthorizationEngine() {
	}
}
