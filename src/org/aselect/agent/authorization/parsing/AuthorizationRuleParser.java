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
 * $Id: AuthorizationRuleParser.java,v 1.6 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthorizationRuleParser.java,v $
 * Revision 1.6  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.5  2005/08/25 09:50:42  erwin
 * Only '=' and '!=' are valid operators for ip addresses check improved
 *
 * Revision 1.4  2005/08/24 08:55:48  erwin
 * Improved error handling and Javadoc.
 *
 * Revision 1.3  2005/08/24 07:46:35  erwin
 * Improved look-ahead parsing
 *
 * Revision 1.2  2005/08/23 15:31:19  erwin
 * Implemented the parser
 *
 * Revision 1.1  2005/08/19 08:34:57  erwin
 * Initial version
 *
 */
package org.aselect.agent.authorization.parsing;

import java.io.IOException;
import java.util.logging.Level;
import java.util.regex.Pattern;

import org.aselect.agent.authorization.parsing.types.IPv4Address;
import org.aselect.agent.authorization.parsing.types.IPv6Address;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthorizationException;
import org.aselect.system.logging.SystemLogger;


/**
 * Parser for evaluation rules. <br>
 * <br>
 * <b>Description:</b><br>
 * This LL(1) Parser uses a {@link AuthorizationRuleScanner} to parse authorization rules. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>AuthorizationRuleParser</code> per authorization rule. <br>
 * 
 * @author Alfa & Ariss
 */
public class AuthorizationRuleParser
{
	/**
	 * The module name.
	 */
	public static final String MODULE = "AuthorizationRuleParser";
	/**
	 * The logger for system entries.
	 */
	private SystemLogger _systemLoger;

	/**
	 * The lexical analyser (scanner).
	 */
	private AuthorizationRuleScanner _oScanner;

	/**
	 * The token which was accepted.
	 */
	private AuthorizationRuleToken _oCurrentToken;

	/**
	 * The tree that is build during parsing.
	 */
	private EvaluationTree _tEvaluation;

	/**
	 * Create a new <code>AuthorizationRuleParser</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Create a new <code>AuthorizationRuleParser</code> with the given <code>SystemLogger</code> and using the given
	 * <code>AuthorizationRuleScanner</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * Use one <code>AuthorizationRuleParser</code> per authorization rule. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * Then scanner and system logger are set. <br>
	 * 
	 * @param oScanner
	 *            The scanner which scans the authorization rule.
	 * @param systemLoger
	 *            The logger for system entries.
	 */
	public AuthorizationRuleParser(AuthorizationRuleScanner oScanner, SystemLogger systemLoger) {
		// set components
		_systemLoger = systemLoger;
		_oScanner = oScanner;
		// default empty tree
		_tEvaluation = new EvaluationTree(null, null, null);
	}

	/**
	 * Parse a Evaluation Rule. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method parses the evaluation rule recursively using the followoing methods:
	 * <ul>
	 * <li><code>parseExpression()</code></li>
	 * <li><code>parseSimpleExpression()</code></li>
	 * <li><code>parseLogicExpression()</code></li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The evaluation tree is parsed and the {@link #getEvaluationTree} method returns the parsed evaluation rule. <br>
	 * 
	 * @throws ASelectAuthorizationException
	 *             If parsing fails.
	 */
	public void parse()
	throws ASelectAuthorizationException
	{
		final String sMethod = "parse";
		try {
			// scan first token
			_oCurrentToken = _oScanner.scan();
			// parse rule
			_tEvaluation = parseExpression();
		}
		catch (ASelectAuthorizationException e) {
			// allready logged
			throw e;
		}
		catch (IOException e) {
			_systemLoger.log(Level.WARNING, MODULE, sMethod, "Error scanning authorization rule", e);
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_IO);
		}
	}

	/**
	 * Retrieve the authorization tree. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Retrieve the constructed evaluation tree. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * The evaluation tree should be parsed by calling the {@link #parse} method. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return The evaluation tree containing the complete authorization rule.
	 */
	public EvaluationTree getEvaluationTree()
	{
		return _tEvaluation;
	}

	/**
	 * Parse an Expression.
	 * 
	 * @return The Expression.
	 * @throws ASelectAuthorizationException
	 *             If parsing fails.
	 */
	private EvaluationTree parseExpression()
	throws ASelectAuthorizationException
	{
		final String sMethod = "parseExpression";
		// Parse SimpleExpression
		EvaluationTree tNew = parseSimpleExpression();
		// Parse LogicAndExpression or LogicOrExpression
		if (_oCurrentToken != null && _oCurrentToken._iKind != AuthorizationRuleToken.GROUP_END)
		// more tokens available and not end of group token
		{
			if (_oCurrentToken._iKind == AuthorizationRuleToken.AND) {
				tNew = parseLogicExpression(tNew);
			}
			else if (_oCurrentToken._iKind == AuthorizationRuleToken.OR) {
				tNew = parseLogicExpression(tNew);
			}
			else {
				StringBuffer sb = new StringBuffer("Unexpected token: '");
				sb.append(_oCurrentToken).append("' expected was '&', '|', or ')'.");
				_systemLoger.log(Level.WARNING, MODULE, sMethod, sb.toString());
				throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
			}
		}
		return tNew;
	}

	/**
	 * Parse a SimpleExpression.
	 * 
	 * @return The simple expression.
	 * @throws ASelectAuthorizationException
	 *             If parsing fails.
	 */
	private EvaluationTree parseSimpleExpression()
	throws ASelectAuthorizationException
	{
		final String sMethod = "parseSimpleExpression";
		StringBuffer sb = null;
		EvaluationTree tNew = null;
		// accept first token
		AuthorizationRuleToken oToken = acceptIt();

		if (oToken._iKind == AuthorizationRuleToken.NOT) {

			tNew = new EvaluationTree(parseSimpleExpression(), null, oToken);
		}
		else if (oToken._iKind == AuthorizationRuleToken.GROUP_START) {
			tNew = parseExpression();
			acceptKind(AuthorizationRuleToken.GROUP_END);
		}
		else if (oToken._iKind == AuthorizationRuleToken.UNQUOTED_STRING) {
			EvaluationTree tKey = new EvaluationTree(null, null, oToken);
			// try to get next token
			if (_oCurrentToken != null && _oCurrentToken._iGroup == AuthorizationRuleToken.OPERATOR_GROUP) {
				// accept operator token
				AuthorizationRuleToken oOperator = acceptIt();
				// accept value
				AuthorizationRuleToken oValue = acceptGroup(AuthorizationRuleToken.DATA_GROUP);
				if (oOperator._iKind == AuthorizationRuleToken.IN) {
					if (oValue._iKind != AuthorizationRuleToken.LIST) {
						sb = new StringBuffer("Unexpected token after 'in' operator: '");
						sb.append(oToken).append("', in operator can only be followed by a value list.");
						_systemLoger.log(Level.WARNING, MODULE, sMethod, sb.toString());
						throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
					}
				}
				else if (oOperator._iKind == AuthorizationRuleToken.MATCH_REGULAR_EXPRESSION) {
					// check Pattern for regular expression
					try {
						String sRegularExpression = (String) oValue.getValue();
						Pattern oPattern = Pattern.compile(sRegularExpression);
						oValue.setValue(oPattern);
					}
					catch (IllegalArgumentException e) {
						sb = new StringBuffer("Unexpected token: '");
						sb.append(oValue);
						sb.append("'. Invalid regular expression");
						_systemLoger.log(Level.WARNING, MODULE, sMethod, sb.toString(), e);
						throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
					}
				}
				else {
					// Convert value if applicable
					oValue.setValue(AuthorizationRuleToken.convertToKnownType(oValue.getValue()));
					// ip operator check
					if (oValue.getValue() instanceof IPv4Address || oValue.getValue() instanceof IPv6Address) {
						if (oOperator._iKind != AuthorizationRuleToken.EQUAL_TO
								&& oOperator._iKind != AuthorizationRuleToken.NOT_EQUAL_TO) {
							Object oOperatorValue = oOperator.getValue();
							sb = new StringBuffer("Unexpected token: '");
							sb.append(oValue).append("'. ");
							sb.append(oOperatorValue);
							sb.append(" operator is not applicable for IP adresses.");
							_systemLoger.log(Level.WARNING, MODULE, sMethod, sb.toString());
							throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
						}
					}
				}
				// create value tree
				EvaluationTree tValue = new EvaluationTree(null, null, oValue);
				// create new SimpleExpression tree
				tNew = new EvaluationTree(tKey, tValue, oOperator);
			}
			else {
				tNew = tKey;
			}
		}
		else {
			sb = new StringBuffer("Unexpected token kind: '");
			sb.append(oToken).append("' start of a simple expression expected.");
			_systemLoger.log(Level.WARNING, MODULE, sMethod, sb.toString());
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}
		return tNew;
	}

	/**
	 * parse a logic expression: LogicAndExpression or LogicOrExpression.
	 * 
	 * @param tLeft
	 *            the left tree of the logic expression.
	 * @return A tree containing constructeded logic expressions (recursive)
	 * @throws ASelectAuthorizationException
	 *             If parsing fails.
	 */
	private EvaluationTree parseLogicExpression(EvaluationTree tLeft)
	throws ASelectAuthorizationException
	{
		final String sMethod = "parseLogicExpression";
		// accept is '&' or '|'
		AuthorizationRuleToken oToken = acceptIt();
		EvaluationTree tRight = parseSimpleExpression();
		EvaluationTree tNew = new EvaluationTree(tLeft, tRight, oToken);
		// check if next logic expression is avaliable
		if (_oCurrentToken != null && _oCurrentToken._iKind != AuthorizationRuleToken.GROUP_END)
		// more tokens available and not end of group token
		{
			if (_oCurrentToken._iKind == oToken._iKind)
				tNew = parseLogicExpression(tNew);
			else {
				StringBuffer sb = new StringBuffer("Unexpected token: '");
				sb.append(_oCurrentToken).append("' expected '");
				sb.append(oToken).append("' or ')'.");
				_systemLoger.log(Level.WARNING, MODULE, sMethod, sb.toString());
				throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
			}
		}
		return tNew;
	}

	/**
	 * Accept all tokens from the scanner except for <code>null</code>.
	 * 
	 * @return The next token from the scanner.
	 * @throws ASelectAuthorizationException
	 *             If scanning fails or no token available (<code>null</code>).
	 */
	private AuthorizationRuleToken acceptIt()
	throws ASelectAuthorizationException
	{
		final String sMethod = "acceptIt";
		AuthorizationRuleToken oToken = _oCurrentToken;
		if (_oCurrentToken != null) {
			try {
				// Scan next token
				_oCurrentToken = _oScanner.scan();
			}
			catch (IOException e) {
				_systemLoger.log(Level.WARNING, MODULE, sMethod, "Error scanning authorization rule", e);
				throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_IO);
			}
		}
		else {
			_systemLoger.log(Level.WARNING, MODULE, sMethod, "Unexpected end of authorization rule.");
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}
		return oToken;
	}

	/**
	 * Accept a specific kind of token from the scanner.
	 * 
	 * @param iExpectedKind
	 *            The expected kind of token.
	 * @return The next token from the scanner if the kind matches.
	 * @throws ASelectAuthorizationException
	 *             If no token available (<code>null</code>), scan error, or invalid kind.
	 */
	private AuthorizationRuleToken acceptKind(int iExpectedKind)
	throws ASelectAuthorizationException
	{
		final String sMethod = "acceptKind";
		AuthorizationRuleToken oToken = _oCurrentToken;
		if (_oCurrentToken != null && _oCurrentToken._iKind == iExpectedKind) {
			// Scan next token
			try {
				_oCurrentToken = _oScanner.scan();
			}
			catch (IOException e) {
				_systemLoger.log(Level.WARNING, MODULE, sMethod, "Error scanning authorization rule", e);
				throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_IO);
			}
		}
		else {
			StringBuffer sb = new StringBuffer("Unexpected token: '");
			sb.append(oToken).append("' expected kind was: '");
			sb.append(iExpectedKind).append("'.");
			_systemLoger.log(Level.WARNING, MODULE, sMethod, sb.toString());
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}
		return oToken;
	}

	/**
	 * Accept a specific group from the scanner.
	 * 
	 * @param iExpectedGroup
	 *            The expected group type.
	 * @return The next token from the scanner if the group matches.
	 * @throws ASelectAuthorizationException
	 *             If no token available (<code>null</code>), scan error, or invalid group.
	 */
	private AuthorizationRuleToken acceptGroup(int iExpectedGroup)
	throws ASelectAuthorizationException
	{
		final String sMethod = "acceptGroup";
		AuthorizationRuleToken oToken = _oCurrentToken;
		if (_oCurrentToken != null && _oCurrentToken._iGroup == iExpectedGroup) {
			try {
				// scan next token
				_oCurrentToken = _oScanner.scan();
			}
			catch (IOException e) {
				_systemLoger.log(Level.WARNING, MODULE, sMethod, "Error scanning authorization rule", e);
				throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_IO);
			}
		}
		else {
			StringBuffer sb = new StringBuffer("Unexpected token: '");
			sb.append(oToken).append("' expected group was: '");
			sb.append(iExpectedGroup).append("'.");
			_systemLoger.log(Level.WARNING, MODULE, sMethod, sb.toString());
			throw new ASelectAuthorizationException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}
		return oToken;
	}
}
