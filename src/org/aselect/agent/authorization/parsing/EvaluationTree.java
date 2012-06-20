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
 * $Id: EvaluationTree.java,v 1.6 2006/04/14 13:42:48 tom Exp $ 
 * 
 * Changelog:
 * $Log: EvaluationTree.java,v $
 * Revision 1.6  2006/04/14 13:42:48  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.5  2005/09/02 14:44:29  erwin
 * - Added Authorization Rule ID
 * - Added ip parameter in request=verify_ticket
 *
 * Revision 1.4  2005/08/29 10:04:26  erwin
 * Implemented the reading of the configuration of authorization rules
 *
 * Revision 1.3  2005/08/24 08:55:48  erwin
 * Improved error handling and Javadoc.
 *
 * Revision 1.2  2005/08/23 15:31:19  erwin
 * Implemented the parser
 *
 * Revision 1.1  2005/08/19 08:34:57  erwin
 * Initial version
 *
 * 
 */
package org.aselect.agent.authorization.parsing;


/**
 * A binary tree that is constructed during evaluating rule parsing. <br>
 * <br>
 * <b>Description:</b><br>
 * Represents a recursive tree data structure in which each node has at most two children. The node contains data as an
 * {@link java.lang.Object} and can have children left and right. <br>
 * <br>
 * This binary tree is created by the {@link AuthorizationRuleParser} and used by the
 * {@link org.aselect.agent.authorization.evaluation.AuthorizationRuleEvaluator} to evaluate authorization rules. <br>
 * <br>
 * <i>Note: To improve performance the node and the child trees variables can be accessed directly.</i> <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>EvaluationTree</code> per authorization rule. <br>
 * 
 * @author Alfa & Ariss
 */
public class EvaluationTree
{
	/**
	 * The tree node its left children.
	 */
	public EvaluationTree _tLeft;
	/**
	 * The tree node its right children.
	 */
	public EvaluationTree _tRight;

	/**
	 * The tree node its value (data).
	 */
	public Object _oNode;

	/**
	 * Creates a simple recursive binary tree. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Create a tree with the given data and children. <br>
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
	 * @param tLeft
	 *            The left children of this tree.
	 * @param tRight
	 *            The right children of this tree.
	 * @param oNode
	 *            The node its value (data).
	 */
	public EvaluationTree(EvaluationTree tLeft, EvaluationTree tRight, Object oNode) {
		_tLeft = tLeft;
		_tRight = tRight;
		_oNode = oNode;
	}

	/**
	 * Determine if this tree node is empty. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Check if this tree node contains a value. <br>
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
	 * @return true if this node has no value (data), otherwise false.
	 */
	public boolean isEmpty()
	{
		return _oNode == null;
	}

	/**
	 * Determine if this tree node is a leaf. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * A node that has no children is called a leaf. <br>
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
	 * @return <code>true</code> if this node of the tree is a leaf, otherwise false.
	 */
	public boolean isLeaf()
	{
		return _tLeft == null && _tRight == null;
	}

	/**
	 * Retrieve a String representation of this <code>EvaluationTree</code>.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString()
	{
		StringBuffer sb = new StringBuffer();
		sb.append("\n");
		toString(this, sb, 0);
		return sb.toString();
	}

	/**
	 * Is used to create a <code>String</code> representation of this tree.
	 * 
	 * @param root
	 *            the root tree.
	 * @param sb
	 *            Is used to construct the representation.
	 * @param indent
	 *            The number of spaces.
	 */
	private void toString(EvaluationTree root, StringBuffer sb, int indent)
	{
		sb.append(createSpaces(indent));

		if (isEmpty()) {
			sb.append("[]");
		}
		else {
			sb.append(root._oNode);
			sb.append("\n");
			if (root._tLeft != null) {
				toString(root._tLeft, sb, indent + 4);
			}
			else if (root._tRight != null) {
				sb.append(createSpaces(indent + 4)).append("{}\n");
			}

			if (root._tRight != null) {
				toString(root._tRight, sb, indent + 4);
			}
			else if (root._tLeft != null) {
				sb.append(createSpaces(indent + 4)).append("{}\n");
			}
		}
	}

	/**
	 * Is used to create spaces in the <code>String</code> representation of this tree.
	 * 
	 * @param indent
	 *            The number of spaces.
	 * @return A <code>String</code> with a <code>indent</code> number of spaces.
	 */
	private String createSpaces(int indent)
	{
		StringBuffer sb = new StringBuffer(indent);
		for (int i = 0; i < indent; i++)
			sb.append(" ");
		return sb.toString();
	}

}
