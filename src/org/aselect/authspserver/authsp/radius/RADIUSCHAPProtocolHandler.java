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
 * $Id: RADIUSCHAPProtocolHandler.java,v 1.11 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $Log: RADIUSCHAPProtocolHandler.java,v $
 * Revision 1.11  2006/05/03 10:07:31  tom
 * Removed Javadoc version
 *
 * Revision 1.10  2006/04/12 13:29:35  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.9.2.1  2006/04/12 06:08:51  jeroen
 * Fix in full uid check. Now also the index is checked > -1.
 *
 * Revision 1.9  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.8  2005/04/29 11:46:37  martijn
 * fixed bugs in logging
 *
 * Revision 1.7  2005/03/29 12:39:26  erwin
 * Improved logging.
 *
 * Revision 1.6  2005/03/14 07:30:54  tom
 * Minor code style changes
 *
 * Revision 1.5  2005/03/10 07:48:20  tom
 * Added new Logger functionality
 * Added new Configuration functionality
 * Fixed small bug in Authenticator verification
 *
 * Revision 1.4  2005/03/07 15:57:40  leon
 * - New Failure Handling
 * - Extra Javadoc
 *
 * Revision 1.3  2005/02/09 09:17:04  leon
 * added License
 * code restyle
 *
 */

package org.aselect.authspserver.authsp.radius;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.util.Random;
import java.util.logging.Level;

import org.aselect.system.utils.Utils;

// TODO: Auto-generated Javadoc
/**
 * The Radius Protocol Handler which handles the Radius CHAP requests. <br>
 * <br>
 * <b>Description:</b><br>
 * This Radius Protocol handler handles Authentication requests using Radius CHAP <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss
 */
public class RADIUSCHAPProtocolHandler extends AbstractRADIUSProtocolHandler
{
	private byte _bIdentifier;
	private byte[] _baRandom;
	private DatagramSocket _listenSocket = null;
	private int _iSocketTimeout = 10000; // (154)
	private String _sErrorCode;
	private final String MODULE = "RADIUSPAPProtocolHandler";

	/**
	 * . <br>
	 * <br>
	 * 
	 * @param sPassword
	 *            the s password
	 * @return the string
	 * @see org.aselect.authspserver.authsp.radius.IRADIUSProtocolHandler#authenticate(java.lang.String)
	 */
	@Override
	public String authenticate(String sPassword)
	{
		String sMethod = "authenticate()";
		_sErrorCode = Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER;

		_systemLogger.log(Level.INFO, MODULE, sMethod, "CHAPP uid=" + _sUid);
		try {
			DatagramPacket oRADIUSPacket;
			byte[] baRadiusPacketBuffer = new byte[MAX_RADIUS_PACKET_SIZE];
			_baRandom = new byte[16];

			if (!_bFullUid) {
				int iIndex = _sUid.indexOf('@');
				if (iIndex > 0)
					_sUid = _sUid.substring(0, iIndex);
			}

			_listenSocket = new DatagramSocket();
			oRADIUSPacket = new DatagramPacket(baRadiusPacketBuffer, baRadiusPacketBuffer.length);

			composeRequest(sPassword, oRADIUSPacket);
			if (_sErrorCode != Errors.ERROR_RADIUS_SUCCESS) {
				try {
					_listenSocket.close();
				}
				catch (Exception e) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "exception while closing connection with "
							+ "RADIUS server at " + _sRadiusServer + ": ", e);
				}
				return _sErrorCode;
			}
			_listenSocket.setSoTimeout(_iSocketTimeout); // added timeout (154)
			_listenSocket.send(oRADIUSPacket);
			_listenSocket.receive(oRADIUSPacket);
			handleResponse(oRADIUSPacket);

			try {
				_listenSocket.close();
			}
			catch (Exception e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "exception while closing connection with "
						+ "RADIUS server at " + _sRadiusServer + ": ", e);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "error in Radius communication", e); // (154)
			try {
				_listenSocket.close();
			}
			catch (Exception e2) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "exception while closing connection with RADIUS "
						+ " server at " + _sRadiusServer + ": ", e2);
			}
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "exception while authenticating user " + _sUid
					+ " with with RADIUS " + "server at " + _sRadiusServer + ": ", e);
			_sErrorCode = Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER;
		}

		return _sErrorCode;
	}

	/**
	 * This methods composes a RADIUS <code>access-request</code> packet and sends it to the RADIUS Server. <br>
	 * <br>
	 * 
	 * @param sPassword
	 *            the s password
	 * @param oRADIUSPacket
	 *            the o radius packet
	 * @throws Exception
	 *             the exception
	 */
	public void composeRequest(String sPassword, DatagramPacket oRADIUSPacket)
		throws Exception
	{
		String sMethod = "composeRequest()";
		_sErrorCode = Errors.ERROR_RADIUS_INTERNAL_ERROR;

		_systemLogger.log(Level.INFO, MODULE, sMethod, "uid=" + _sUid);
		try {
			Random randomGenerator;
			byte[] baTempBuffer;
			byte[] baChallenge = new byte[16];
			byte[] baOutputBuffer;
			byte bChapID = 0;
			int iIndex = 0;

			MessageDigest md5Object = MessageDigest.getInstance("MD5");

			oRADIUSPacket.setAddress(InetAddress.getByName(_sRadiusServer));
			oRADIUSPacket.setPort(_iPort);

			randomGenerator = new Random();
			randomGenerator.nextBytes(_baRandom);
			_bIdentifier = (byte) randomGenerator.nextInt();

			// Generate the challenge
			randomGenerator.nextBytes(baChallenge);

			// Calculate response
			md5Object.update(bChapID); // CHAP ID
			md5Object.update(sPassword.getBytes()); // password
			md5Object.update(baChallenge); // challenge
			byte[] xResponse = md5Object.digest();

			baOutputBuffer = oRADIUSPacket.getData();
			baOutputBuffer[iIndex++] = ACCESS_REQUEST;
			baOutputBuffer[iIndex++] = _bIdentifier;
			baOutputBuffer[iIndex++] = 0; // hibyte length
			baOutputBuffer[iIndex++] = 0; // lobyte length
			// 16 bytes random ; aka authenticator
			System.arraycopy(_baRandom, 0, baOutputBuffer, iIndex, _baRandom.length);
			iIndex += _baRandom.length;

			baOutputBuffer[iIndex++] = RADIUS_ATTRIBUTE_TYPE_USER_NAME;
			baOutputBuffer[iIndex++] = (byte) (_sUid.length() + 2);
			baTempBuffer = _sUid.getBytes();
			System.arraycopy(baTempBuffer, 0, baOutputBuffer, iIndex, _sUid.length());
			iIndex += _sUid.length();

			// Build CHAP-Password
			baOutputBuffer[iIndex++] = RADIUS_ATTRIBUTE_TYPE_CHAP_PASSWORD;
			baOutputBuffer[iIndex++] = (byte) (16 + 3); // length
			baOutputBuffer[iIndex++] = bChapID; // CHAP ID
			// response
			System.arraycopy(xResponse, 0, baOutputBuffer, iIndex, 16);
			iIndex += 16;

			// Build CHAP-Challenge
			baOutputBuffer[iIndex++] = RADIUS_ATTRIBUTE_TYPE_CHAP_CHALLENGE;
			baOutputBuffer[iIndex++] = (byte) (16 + 2); // length
			// challenge
			System.arraycopy(baChallenge, 0, baOutputBuffer, iIndex, 16);
			iIndex += 16;

			baOutputBuffer[2] = (byte) (iIndex >> 8);
			baOutputBuffer[3] = (byte) (iIndex & 0x00ff);

			oRADIUSPacket.setData(baOutputBuffer);
			_sErrorCode = Errors.ERROR_RADIUS_SUCCESS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR", e);
			throw e;
		}
	}

	/**
	 * This methods handles the response comming from the Radius Server.
	 * 
	 * @param oRADIUSPacket
	 *            the o radius packet
	 */
	public void handleResponse(DatagramPacket oRADIUSPacket)
	{
		byte[] baAuthenticator;
		byte[] baAttributes;
		byte[] baHash;
		int iLength;
		int iReponseBufferIndex;

		String sMethod = "handleResponse()";
		_sErrorCode = Errors.ERROR_RADIUS_INTERNAL_ERROR;

		_systemLogger.log(Level.INFO, MODULE, sMethod, "uid=" + _sUid);
		try {
			byte[] baResponseBuffer = oRADIUSPacket.getData();

			// check code
			iReponseBufferIndex = 0;
			if (baResponseBuffer[iReponseBufferIndex++] != ACCESS_ACCEPT) {
				StringBuffer sbFine = new StringBuffer("RADIUS returned ACCESS DENIED for user: ");
				sbFine.append(_sUid);
				_systemLogger.log(Level.FINE, MODULE, sMethod, sbFine.toString());
				_sErrorCode = Errors.ERROR_RADIUS_ACCESS_DENIED;
				return;
			}
			// check identifier
			if (baResponseBuffer[iReponseBufferIndex++] != _bIdentifier) {
				StringBuffer sbFine = new StringBuffer("RADIUS Identifier mismatch for user: ");
				sbFine.append(_sUid);
				_systemLogger.log(Level.FINE, MODULE, sMethod, sbFine.toString());
				_sErrorCode = Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER;
				return;
			}

			// length
			iLength = ((baResponseBuffer[2] & 255) * 256) + (baResponseBuffer[3] & 255);

			// skip length
			iReponseBufferIndex += 2;

			// copy authenticator field
			baAuthenticator = new byte[16];
			System.arraycopy(baResponseBuffer, iReponseBufferIndex, baAuthenticator, 0, 16);

			// copy attributes field
			// attributeslength = totallength - header - authenticatorlength
			baAttributes = new byte[iLength - 4 - 16];
			System.arraycopy(baResponseBuffer, 20, baAttributes, 0, baAttributes.length);

			// verify authenticity
			MessageDigest md5Object = MessageDigest.getInstance("MD5");
			md5Object.update(ACCESS_ACCEPT);
			md5Object.update(_bIdentifier);
			md5Object.update(baResponseBuffer[2]);
			md5Object.update(baResponseBuffer[3]);
			md5Object.update(_baRandom);
			md5Object.update(baAttributes);
			md5Object.update(_sSharedSecret.getBytes());
			baHash = md5Object.digest();

			for (int i = 0; i < 16; i++) {
				if (baAuthenticator[i] != baHash[i]) {
					StringBuffer sbTemp = new StringBuffer("RADIUS Authenticator mismatchnServer\r\n");
					sbTemp.append("Authenticator: ");
					sbTemp.append(Utils.byteArrayToHexString(baAuthenticator));
					sbTemp.append("\r\n Computed Authenticator: ");
					sbTemp.append(Utils.byteArrayToHexString(baHash));

					_systemLogger.log(Level.FINE, MODULE, sMethod, sbTemp.toString());
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "RADIUS Authenticator mismatch");
					_sErrorCode = Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER;
					return;
				}
			}
			_sErrorCode = Errors.ERROR_RADIUS_SUCCESS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR", e);
			_sErrorCode = Errors.ERROR_RADIUS_INTERNAL_ERROR;
		}
	}
}