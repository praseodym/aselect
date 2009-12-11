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
 * $Id: ASOAPException.java,v 1.5 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASOAPException.java,v $
 * Revision 1.5  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.4  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.3  2005/02/15 10:52:37  erwin
 * Improved documentation
 *
 * Revision 1.2  2005/02/14 13:54:29  erwin
 * Applied code style and added Javadoc.
 *
 *
 */

package org.aselect.system.communication.server.soap11;

// TODO: Auto-generated Javadoc
/**
 * An exception that is used to create SOAP fault elements. <br>
 * <br>
 * <b>Description: </b> <br>
 * An <code>ASOAPException</code> represents SOAP faults. If processing an incomming SOAP message fails, an
 * <code>ASOAPException</code> can be throwed. After catching a <code>ASOAPException</code> it can be converted to a
 * SOAP response message containing a SOAP fault. <br>
 * <br>
 * <i>For more info see: <a href='http://www.w3.org/TR/2003/REC-soap12-part0-20030624/#L11549' target='_new'>SOAP fault
 * handling </a> </i> <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public class ASOAPException extends Exception
{

	/** Version mismatch fault */
	public static final int VERSION_MISMATCH = 1;

	/** must understand fault */
	public static final int MUST_UNDERSTAND = 2;

	/** Sender fault */
	public static final int CLIENT = 3;

	/** Receiver fault */
	public static final int SERVER = 4;

	/** Unsupported content type fault */
	public static final int UNSUPPORTED_CONTENT_TYPE = 6;

	/** internal server error fault */
	public static final int INTERNAL_SERVER_ERROR = 7;

	/** fault code */
	private int _iCode;

	/** fault reason */
	private String _sReason;

	/**
	 * Creates a new intance. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a new <code>ASOAPException</code> with the given code, reason and message. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * <li><code>iCode</code> should be a vaild SOAP 1.1 fault code.
	 * <li><code>sReason</code> should be a valid SOAP 1.1 fault reason.
	 * <li><code>sMessage</code> should contain additional information.
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All instance variables are set with the given values. <br>
	 * 
	 * @param iCode
	 *            The code for the new <code>ASOAPException</code>.
	 * @param sReason
	 *            The reason for the new <code>ASOAPException</code>.
	 * @param sMessage
	 *            The detail message for the new <code>ASOAPException</code>.
	 */
	ASOAPException(int iCode, String sReason, String sMessage) {
		super(sMessage);
		_iCode = iCode;
		_sReason = sReason;
	}

	/**
	 * Creates a new intance from a base Exception. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a new <code>ASOAPException</code> from the base <code>Exception</code> and with the given code, reason
	 * and message. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * <li><code>iCode</code> should be a vaild SOAP 1.1 fault code.
	 * <li><code>sReason</code> should be a valid SOAP 1.1 fault reason.
	 * <li><code>eCause</code> should be a base Exception.
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All instance variables are set with the given values. <br>
	 * 
	 * @param iCode
	 *            The code for the new <code>ASOAPException</code>.
	 * @param sReason
	 *            The reason for the new <code>ASOAPException</code>.
	 * @param eCause
	 *            The <code>Exception</code> that caused this <code>ASOAPException</code>.
	 */
	ASOAPException(int iCode, String sReason, Exception eCause) {
		super(eCause);
		_iCode = iCode;
		_sReason = sReason;
	}

	/**
	 * Get the exceptions fault code.
	 * 
	 * @return The SOAP 1.1 fault code.
	 */
	public int getCode()
	{
		return _iCode;
	}

	/**
	 * Get the exceptions reason.
	 * 
	 * @return The SOAP 1.1 fault reason.
	 */
	public String getReason()
	{
		return _sReason;
	}

}