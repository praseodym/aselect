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
 * $Id: AuthorizationRule.java,v 1.2 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthorizationRule.java,v $
 * Revision 1.2  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.1  2005/09/02 14:44:29  erwin
 * - Added Authorization Rule ID
 * - Added ip parameter in request=verify_ticket
 *
 */
 
package org.aselect.agent.authorization.parsing;

/**
 * An A-Select Authorization rule.
 * <br><br>
 * <b>Description:</b>
 * <br>
 * Contains the parsed authorization rules as well as the <code>String</code> 
 * representation and the URI.<br>
 * <br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class AuthorizationRule
{
    /**
     * The URI that this rule belongs to.
     * This URI can contain wildcards.
     */
    private String _sURI;
    
    /**
     * The Rule as plain text.
     */
    private String _sPlainTextRule;
    
    /**
     * The evaluation tree of this rule.
     */
    private EvaluationTree _tEvaluation;
    
    /**
     * Create a new <code>AuthorizationRule</code>.
     * <br>
     * @param sPlainTextRule The rule in plain text.
     * @param sURI The request URI for this rule.
     * @param tEvaluation The parsed evaluation rule.
     */
    public AuthorizationRule(String sPlainTextRule, String sURI, EvaluationTree tEvaluation)
    {
        _sPlainTextRule = sPlainTextRule;
        _sURI = sURI;
        _tEvaluation = tEvaluation;
    }

    /**
     * Retrieve the Rule in plain text.
     * @return Returns the Plain Text Rule.
     */
    public String getPlainTextRule()
    {
        return _sPlainTextRule;
    }
    /**
     * Retrieve the URI that this rule belongs to.
     * @return Returns the _sURI.
     */
    public String getURI()
    {
        return _sURI;
    }
    /**
     * retrieve the parsed evaluation tree.
     * @return Returns the evaluation tree.
     */
    public EvaluationTree getEvaluationTree()
    {
        return _tEvaluation;
    }
}
