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
 * $Id: AuthorizationRuleEvaluator.java,v 1.7 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthorizationRuleEvaluator.java,v $
 * Revision 1.7  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.6  2006/04/04 13:09:30  erwin
 * aplied code format.
 *
 * Revision 1.5  2006/03/10 15:18:35  martijn
 * added support for multivalue attributes
 *
 * Revision 1.4  2006/03/09 12:43:45  jeroen
 * adaptations for multi-valued attributes feature
 *
 * Revision 1.3  2005/08/25 15:22:40  erwin
 * Added support for multiple time and dat formats
 *
 * Revision 1.2  2005/08/24 14:27:13  erwin
 * Implemented evaluator
 *
 * Revision 1.1  2005/08/19 08:34:57  erwin
 * Initial version
 *
 * 
 */
package org.aselect.agent.authorization.evaluation;

import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Vector;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.aselect.agent.authorization.parsing.AuthorizationRuleToken;
import org.aselect.agent.authorization.parsing.EvaluationTree;
import org.aselect.agent.authorization.parsing.types.IPv4Address;
import org.aselect.agent.authorization.parsing.types.IPv6Address;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthorizationException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Utils;

// TODO: Auto-generated Javadoc
/**
 * Evaluator for authorization rules. <br>
 * <br>
 * <b>Description:</b> <br>
 * The <code>AuthorizationRuleEvaluator</code> evaluates authorization rules for given user attributes. The input of the
 * AuthorizationEvaluator is an evaluation tree created by the
 * {@link org.aselect.agent.authorization.parsing.AuthorizationRuleParser} and the user attributes of a user. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class AuthorizationRuleEvaluator
{
	/**
	 * The module name.
	 */
	public static final String MODULE = "AuthorizationRuleEvaluator";

	/**
	 * The logger for system entries.
	 */
	private SystemLogger _systemLogger;

	/**
	 * Create a new <code>AuthorizationRuleEvaluator</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Create a new instance of the <code>AuthorizationRuleEvaluator</code> with the given logger. <br>
	 * <br>
	 * 
	 * @param systemLoger
	 *            The system logger to be used.
	 */
	public AuthorizationRuleEvaluator(SystemLogger systemLoger) {
		_systemLogger = systemLoger;
	}

	/**
	 * Evaluate a authorization rule. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * this method uses the given evaluation tree and fills in the user attributes if all the expressions in the
	 * evaluation tree are valid for the user attributes this method returns true, otherwise false. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * <br>
	 * 
	 * @param htAttributes
	 *            The user attributes.
	 * @param tEvaluation
	 *            The evaluation tree to evaluate upon.
	 * @return <code>true</code> if the tree evaluates to <code>true</code> for the given user attributes, otherwise
	 *         false.
	 * @throws ASelectAuthorizationException
	 *             If evaluating fails.
	 */
	public boolean evaluate(HashMap htAttributes, EvaluationTree tEvaluation)
		throws ASelectAuthorizationException
	{
		final String sMethod = "evaluate()";
		boolean bAuthorized = false;
		// check not empty
		if (tEvaluation == null || tEvaluation.isEmpty()) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Evaluation tree not available or empty.");
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}

		// get token
		AuthorizationRuleToken oToken = (AuthorizationRuleToken) tEvaluation._oNode;
		// check group
		_systemLogger.log(Level.FINE, MODULE, sMethod, "Group=" + oToken._iGroup);
		switch (oToken._iGroup) {
		case AuthorizationRuleToken.LOGIC_OPERATOR_GROUP: {
			bAuthorized = evaluateLogic(htAttributes, tEvaluation);
			break;
		}
		case AuthorizationRuleToken.OPERATOR_GROUP: {
			// simple expression with operator
			bAuthorized = evaluateSimple(htAttributes, tEvaluation);
			break;
		}
		case AuthorizationRuleToken.DATA_GROUP: {
			// simple expression with just a key
			bAuthorized = evaluateSimple(htAttributes, tEvaluation);
			break;
		}
		default: {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid evaluation tree: unknown token group.");
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}
		}
		return bAuthorized;
	}

	/**
	 * Evaluate a simple expression.
	 * 
	 * @param htAttributes
	 *            The user attributes.
	 * @param tEvaluation
	 *            The evaluation tree to evaluate upon.
	 * @return <code>true</code> if the simple expression tree evaluates to <code>true</code> for the given user
	 *         attributes, otherwise false.
	 * @throws ASelectAuthorizationException
	 *             If evaluating fails.
	 */
	private boolean evaluateSimple(HashMap htAttributes, EvaluationTree tEvaluation)
		throws ASelectAuthorizationException
	{
		final String sMethod = "evaluateSimple()";
		boolean bAuthorized = false;
		AuthorizationRuleToken oToken = (AuthorizationRuleToken) tEvaluation._oNode;

		if (tEvaluation.isLeaf()) // simple expression with just a key
		{
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Leaf " + oToken.getValue());
			bAuthorized = htAttributes.containsKey(oToken.getValue());
		}
		else
		// simple expression with operator
		{
			// Get key
			AuthorizationRuleToken oKey = (AuthorizationRuleToken) tEvaluation._tLeft._oNode;
			String sKey = (String) oKey.getValue();

			Object oValue = htAttributes.get(sKey);
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Expr key=" + sKey + " value=" + oValue);

			if (oValue == null) // attribute not available
				bAuthorized = false;
			else {

				AuthorizationRuleToken oExpectedValue = (AuthorizationRuleToken) tEvaluation._tRight._oNode;

				if (oValue instanceof Vector) {
					bAuthorized = evaluateSimpleMultiValuedAttribute(oToken, oExpectedValue, (Vector) oValue);

				}
				else if (oValue instanceof String) {
					String sValue = (String) oValue;

					_systemLogger.log(Level.FINE, MODULE, sMethod, "Expr kind=" + oToken._iKind + " exp="
							+ oExpectedValue);
					switch (oToken._iKind) {

					case AuthorizationRuleToken.EQUAL_TO: {
						Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
						Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
						_systemLogger.log(Level.FINER, MODULE, sMethod, "EqualTo exp=" + oExpectedValue);
						bAuthorized = cExpectedValue.compareTo(cValue) == 0;
						break;
					}
					case AuthorizationRuleToken.NOT_EQUAL_TO: {
						Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
						Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
						bAuthorized = cExpectedValue.compareTo(cValue) != 0;
						break;
					}
					case AuthorizationRuleToken.GREATER_THEN: {
						Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
						Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
						bAuthorized = cExpectedValue.compareTo(cValue) < 0;
						break;
					}
					case AuthorizationRuleToken.GREATER_THEN_OR_EQUAL_TO: {
						Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
						Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
						bAuthorized = cExpectedValue.compareTo(cValue) <= 0;
						break;
					}
					case AuthorizationRuleToken.LESS_THEN: {
						Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
						Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
						bAuthorized = cExpectedValue.compareTo(cValue) > 0;
						break;
					}
					case AuthorizationRuleToken.LESS_THEN_OR_EQUAL_TO: {
						Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
						Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
						bAuthorized = cExpectedValue.compareTo(cValue) >= 0;
						break;
					}
					case AuthorizationRuleToken.IN: {
						List lExpected = (List) oExpectedValue.getValue();
						bAuthorized = lExpected.contains(sValue);
						break;
					}
					case AuthorizationRuleToken.MATCH_REGULAR_EXPRESSION: {
						Pattern p = (Pattern) oExpectedValue.getValue();
						Matcher m = p.matcher(sValue);
						bAuthorized = m.matches();
						break;
					}
					case AuthorizationRuleToken.MATCH_WILDCARD_EXPRESSION: {
						String sExpectedValue = (String) oExpectedValue.getValue();
						bAuthorized = Utils.matchWildcardMask(sValue, sExpectedValue);
						break;
					}
					default: {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Invalid evaluation tree: invalid token kind.");
						throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
					}
					}
				}
			}
		}
		return bAuthorized;
	}

	/**
	 * Evaluate a simple expression for multi-valued attributes.
	 * 
	 * @param oToken
	 *            Authorization rule token which represents different types of tokens from an authorization rule.
	 * @param oExpectedValue
	 *            The expected authorization token.
	 * @param vValue
	 *            The multi-values to evaluate.
	 * @return <code>true</code> if the simple expression tree evaluates to <code>true</code> if one of the given values
	 *         of the mutli-valued user attribute matches the rule, otherwise false.
	 * @throws ASelectAuthorizationException
	 *             If evaluating fails.
	 */
	private boolean evaluateSimpleMultiValuedAttribute(AuthorizationRuleToken oToken,
			AuthorizationRuleToken oExpectedValue, Vector vValue)
		throws ASelectAuthorizationException
	{
		final String sMethod = "evaluateSimpleMultiValuedAttribute()";
		boolean bAuthorized = false;
		Enumeration eEnum = vValue.elements();

		String sValue = "";

		switch (oToken._iKind) {

		case AuthorizationRuleToken.EQUAL_TO: {
			// If one of the values of the multi-valued attribute is equal to than true is returned
			while (eEnum.hasMoreElements() && bAuthorized == false) {
				sValue = (String) eEnum.nextElement();
				Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
				Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
				bAuthorized = cExpectedValue.compareTo(cValue) == 0;
			}
			break;
		}
		case AuthorizationRuleToken.NOT_EQUAL_TO: {
			// If one of the values of the multi-valued attribute is not equal to than true is returned
			while (eEnum.hasMoreElements() && bAuthorized == false) {
				sValue = (String) eEnum.nextElement();
				Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
				Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
				bAuthorized = cExpectedValue.compareTo(cValue) != 0;
			}
			break;
		}
		case AuthorizationRuleToken.GREATER_THEN: {
			// If one of the values of the multi-valued attribute is greater then true is returned
			while (eEnum.hasMoreElements() && bAuthorized == false) {
				sValue = (String) eEnum.nextElement();
				Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
				Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
				bAuthorized = cExpectedValue.compareTo(cValue) < 0;
			}
			break;
		}
		case AuthorizationRuleToken.GREATER_THEN_OR_EQUAL_TO: {
			// If one of the values of the multi-valued attribute is greater then or equal to true is returned
			while (eEnum.hasMoreElements() && bAuthorized == false) {
				sValue = (String) eEnum.nextElement();
				Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
				Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
				bAuthorized = cExpectedValue.compareTo(cValue) <= 0;
			}
			break;
		}
		case AuthorizationRuleToken.LESS_THEN: {
			// If one of the values of the multi-valued attribute is less then true is returned
			while (eEnum.hasMoreElements() && bAuthorized == false) {
				sValue = (String) eEnum.nextElement();
				Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
				Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
				bAuthorized = cExpectedValue.compareTo(cValue) > 0;
			}
			break;
		}
		case AuthorizationRuleToken.LESS_THEN_OR_EQUAL_TO: {
			// If one of the values of the multi-valued attribute is less then or equal to true is returned
			while (eEnum.hasMoreElements() && bAuthorized == false) {
				sValue = (String) eEnum.nextElement();
				Comparable cExpectedValue = (Comparable) oExpectedValue.getValue();
				Comparable cValue = convertAttributeValue(cExpectedValue, sValue);
				bAuthorized = cExpectedValue.compareTo(cValue) >= 0;
			}
			break;
		}
		case AuthorizationRuleToken.IN: {
			// returns true if one of the values of the multi-valued attribute is inside the list
			while (eEnum.hasMoreElements() && bAuthorized == false) {
				sValue = (String) eEnum.nextElement();
				List lExpected = (List) oExpectedValue.getValue();
				bAuthorized = lExpected.contains(sValue);
			}
			break;
		}
		case AuthorizationRuleToken.MATCH_REGULAR_EXPRESSION: {
			// returns true if one of the values of the multi-valued attribute matches the regular expression
			while (eEnum.hasMoreElements() && bAuthorized == false) {
				sValue = (String) eEnum.nextElement();
				Pattern p = (Pattern) oExpectedValue.getValue();
				Matcher m = p.matcher(sValue);
				bAuthorized = m.matches();
			}
			break;
		}
		case AuthorizationRuleToken.MATCH_WILDCARD_EXPRESSION: {
			// returns true if one of the values of the multi-valued attribute matches the wildcard expression
			while (eEnum.hasMoreElements() && bAuthorized == false) {
				sValue = (String) eEnum.nextElement();
				String sExpectedValue = (String) oExpectedValue.getValue();
				bAuthorized = Utils.matchWildcardMask(sValue, sExpectedValue);
			}
			break;
		}
		default: {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Invalid evaluation tree: invalid token kind for multi-attribute.");
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}
		}
		return bAuthorized;
	}

	/**
	 * Evaluate a logic expression.
	 * 
	 * @param htAttributes
	 *            The user attributes.
	 * @param tEvaluation
	 *            The evaluation tree to evaluate upon.
	 * @return <code>true</code> if the logic expression tree evaluates to <code>true</code> for the given user
	 *         attributes, otherwise false.
	 * @throws ASelectAuthorizationException
	 *             If evaluating fails.
	 */
	private boolean evaluateLogic(HashMap htAttributes, EvaluationTree tEvaluation)
		throws ASelectAuthorizationException
	{
		final String sMethod = "evaluateLogic()";
		boolean bAuthorized = false;
		AuthorizationRuleToken oToken = (AuthorizationRuleToken) tEvaluation._oNode;
		_systemLogger.log(Level.FINE, MODULE, sMethod, "Kind=" + oToken._iKind);
		switch (oToken._iKind) {
		case AuthorizationRuleToken.NOT: {
			bAuthorized = !evaluate(htAttributes, tEvaluation._tLeft);
			break;
		}
		case AuthorizationRuleToken.AND: {
			bAuthorized = evaluate(htAttributes, tEvaluation._tLeft) && evaluate(htAttributes, tEvaluation._tRight);
			break;
		}
		case AuthorizationRuleToken.OR: {
			bAuthorized = evaluate(htAttributes, tEvaluation._tLeft) || evaluate(htAttributes, tEvaluation._tRight);
			break;
		}

		default: {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid evaluation tree: invalid token kind.");
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}

		}
		return bAuthorized;
	}

	/**
	 * Converts a attribute value to the same type as the expected value.
	 * 
	 * @param cExpected
	 *            The expected object to which the value is compared.
	 * @param sValue
	 *            De value of the attribute as String.
	 * @return The value as a comparable type.
	 * @throws ASelectAuthorizationException
	 *             If the value can not be converted to the same type as the expected value.
	 */
	private Comparable convertAttributeValue(Comparable cExpected, String sValue)
		throws ASelectAuthorizationException
	{
		final String sMethod = "convertAttributeValue()";
		StringBuffer sb = null;
		Comparable cRet = null;

		try {
			// convert value
			if (cExpected instanceof IPv4Address) {
				cRet = new IPv4Address(sValue);
			}
			else if (cExpected instanceof IPv6Address) {
				cRet = new IPv6Address(sValue);
			}
			else if (cExpected instanceof Date) {
				// get all local datetime formats
				Locale[] lc = DateFormat.getAvailableLocales();
				boolean bConverted = false;

				// try DateTime
				for (int i = 0; i < lc.length && !bConverted; i++) {
					DateFormat oDateTimeFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT,
							lc[i]);
					try {
						cRet = oDateTimeFormat.parse(sValue);
						bConverted = true;
					}
					catch (ParseException e) {
						// try next format
					}
				}
				// try Date
				for (int i = 0; i < lc.length && !bConverted; i++) {
					DateFormat oDateFormat = DateFormat.getDateInstance(DateFormat.SHORT, lc[i]);
					try {
						cRet = oDateFormat.parse(sValue);
						bConverted = true;
					}
					catch (ParseException e) {
						// try next format
					}
				}

				// try Time
				for (int i = 0; i < lc.length && !bConverted; i++) {
					DateFormat oTimeFormat = DateFormat.getTimeInstance(DateFormat.SHORT, lc[i]);
					try {
						cRet = oTimeFormat.parse(sValue);
						bConverted = true;
					}
					catch (ParseException e) {
						// try next format
					}
				}

				if (!bConverted) {
					throw new Exception("Not a valid date or time format.");
				}
			}
			else if (cExpected instanceof Integer) {
				cRet = new Integer(sValue);
			}
			else {
				cRet = sValue;
			}
		}
		catch (NumberFormatException e) {
			sb = new StringBuffer("Invalid attribute value: '");
			sb.append(sValue).append("'. Could not compare to a number.");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sb.toString());
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR, e);
		}
		catch (Exception e) {
			sb = new StringBuffer("Invalid attribute value: '");
			sb.append(sValue).append("'. Could not compare to a an '");
			sb.append(cExpected.getClass().getName()).append("' value");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sb.toString(), e);
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR, e);
		}
		return cRet;
	}
}
