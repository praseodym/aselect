/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license. See the included
 * LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE please contact SURFnet bv.
 * (http://www.surfnet.nl)
 */

/*
 * $Id: ASelectBrowserHandler.java,v 1.2 2006/05/03 10:10:18 tom Exp $
 * 
 * Changelog: 
 * $Log: ASelectBrowserHandler.java,v $
 * Revision 1.2  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.2  2006/02/08 08:07:34  martijn
 * getSession() renamed to getSessionContext()
 *
 * Revision 1.1  2006/01/13 08:40:26  martijn
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.21  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.20  2005/05/04 14:22:06  martijn
 * updates logging
 *
 * Revision 1.19  2005/04/15 14:03:28  peter
 * javadoc and comment
 *
 * Revision 1.18  2005/04/11 09:36:31  erwin
 * Added useRemoteSigning() as check.
 *
 * Revision 1.17  2005/04/11 08:57:29  erwin
 * Added local A-Select signing support for cross A-Select.
 *
 * Revision 1.16  2005/04/07 07:35:39  peter
 * issueCrossTGT now needs optional oldTGT
 *
 * Revision 1.15  2005/04/07 06:37:12  erwin
 * Renamed "attribute" -> "param" to be compatible with configManager.
 *
 * Revision 1.14  2005/04/06 08:58:12  martijn
 * code updates needed because of TGTIssuer code restyle
 *
 * Revision 1.13  2005/04/05 09:07:18  peter
 * added cross proxy logica in authentication logging
 *
 * Revision 1.12  2005/04/01 14:25:38  peter
 * cross aselect redesign
 *
 * Revision 1.11  2005/03/24 13:23:45  erwin
 * Improved URL encoding/decoding
 * (this is handled in communication package for API calls)
 *
 * Revision 1.10  2005/03/17 15:27:58  tom
 * Fixed javadoc
 *
 * Revision 1.9  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.8  2005/03/17 07:58:43  erwin
 * The A-Select server ID is now set with the constructor,
 * instead of reading it from the configuration.
 *
 * Revision 1.7  2005/03/16 12:52:10  tom
 * - Fixed javadoc
 *
 * Revision 1.6  2005/03/15 16:05:15  peter
 * bug solved in signature checking
 *
 * Revision 1.5  2005/03/15 16:01:25  peter
 * AuthenticationLogger was not initiated
 *
 * Revision 1.3  2005/03/15 14:16:51  peter
 * CrossAuthenticateResponse now makes use of new  CryptoEngine Function to verify siganture.
 *
 * Revision 1.2  2005/03/15 10:51:22  tom
 * - Added new Abstract class functionality
 * - Added Javadoc
 *
 * Revision 1.1  2005/03/15 08:21:47  tom
 * - Redesign of request handling
 *
 *  
 */

package org.aselect.server.request.handler.aselect.authentication;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.utils.Tools;

/**
 * This class handles requests coming from a a-select server through a users browser. <br>
 * <br>
 * <b>Description:</b> <br>
 * If this A-Select Servers is acting as Local Server and forwards authentication requests to other A-Select Servers
 * (cross A-Select), the following browser requests of Remote Servers are handled here:
 * <ul>
 * <li><code>aselect_credentials</code>
 * </ul>
 * 
 * @author Alfa & Ariss 20080918, tolk code removed 14-11-2007 - Changes: - DigiD Gateway integration, support
 *         tolk_fromdigid request pass DigiD attributes in the context
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl)
 */
public class ASelectBrowserHandler extends AbstractBrowserRequestHandler
{
	private ASelectAuthenticationLogger _authenticationLogger;
	private CrossASelectManager _crossASelectManager;
	private CryptoEngine _cryptoEngine;

	/**
	 * Constructor for ASelectBrowserHandler. <br>
	 * 
	 * @param servletRequest
	 *            The request.
	 * @param servletResponse
	 *            The response.
	 * @param sMyServerId
	 *            The A-Select Server ID.
	 * @param sMyOrg
	 *            The A-Select Server organisation.
	 */
	public ASelectBrowserHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sMyServerId, String sMyOrg)
	{
		super(servletRequest, servletResponse, sMyServerId, sMyOrg);
		_sModule = "ASelectBrowserHandler";
		_authenticationLogger = ASelectAuthenticationLogger.getHandle();
		_crossASelectManager = CrossASelectManager.getHandle();
		_cryptoEngine = CryptoEngine.getHandle();
	}

	/**
	 * process a-select browser requests <br>
	 * <br>
	 * .
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.aselect.authentication.AbstractBrowserRequestHandler#processBrowserRequest(java.util.HashMap,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter)
	 */
	@Override
	public void processBrowserRequest(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		if (htServiceRequest.get("aselect_credentials") != null) {
			handleCrossAuthenticateResponse(htServiceRequest, _servletResponse, pwOut);
		}
		else
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
	}

	/**
	 * A response of a remote server (aselect_credentials) is verified here. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * After forwarding a user to a remote server, the remote server will redirect the user back to this A-Select Server
	 * with credentials. The response and credentials are verified here. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleCrossAuthenticateResponse(HashMap htServiceRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleCrossAuthenticateResponse";

		try {
			String sRemoteRid = null;
			String sLocalRid = null;
			String sCredentials = null;
			
			// check parameters
			sRemoteRid = (String) htServiceRequest.get("rid");
			sLocalRid = (String) htServiceRequest.get("local_rid");
			sCredentials = (String) htServiceRequest.get("aselect_credentials");

			if ((sCredentials == null) || (sRemoteRid == null) || (sLocalRid == null)) {
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Invalid parameters");

				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			_htSessionContext = _sessionManager.getSessionContext(sLocalRid);
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unknown session in response from cross aselect server");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}

			Tools.resumeSensorData(_configManager, _systemLogger, _htSessionContext);  // 20111102
			String sRemoteOrg = (String) _htSessionContext.get("remote_organization");

			_systemLogger.log(Level.INFO, _sModule, sMethod, "AselBrowREQ sRemoteRid=" + sRemoteRid + ", sLocalRid="
					+ sLocalRid + ", sRemoteOrg=" + sRemoteOrg + " forced_uid=" + _htSessionContext.get("forced_uid"));

			// Retrieve backchannel data from the Remote Organization
			HashMap htRemoteAttributes;
			// verify the credentials at the remote server
			htRemoteAttributes = verifyRemoteCredentials(sCredentials, sRemoteRid, sRemoteOrg);

			// for authentication logging
			String sOrg = (String) htRemoteAttributes.get("organization");
			if (!sRemoteOrg.equals(sOrg))
				sRemoteOrg = sOrg + "@" + sRemoteOrg;

			String sResultCode = (String) htRemoteAttributes.get("result_code");
			String sUID = (String) htRemoteAttributes.get("uid");

			_systemLogger.log(Level.INFO, _sModule, sMethod, "AselBrowREQ sOrg=" + sOrg + ", sRemoteOrg=" + sRemoteOrg
					+ ", sResultCode=" + sResultCode + ", sUID=" + sUID);

			if (sResultCode != null && !sResultCode.equals("0000")) // Bauke: also skip OK
			{
				if (sResultCode.equals(Errors.ERROR_ASELECT_SERVER_CANCEL)) {
					_authenticationLogger.log(new Object[] {
						"Cross", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
						_htSessionContext.get("app_id"), "denied", sResultCode
					});
					// Issue 'CANCEL' TGT
					TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
					tgtIssuer.issueErrorTGTandRedirect(sLocalRid, _htSessionContext, sResultCode, servletResponse);
				}
				else {
					// remote server returned error
					_authenticationLogger.log(new Object[] {
						"Cross", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
						_htSessionContext.get("app_id"), "denied", sResultCode
					});
					throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
				}
			}
			else {
				// Log succesful authentication
				_authenticationLogger.log(new Object[] {
					"Cross", sUID, (String) htServiceRequest.get("client_ip"), sRemoteOrg,
					_htSessionContext.get("app_id"), "granted"
				});

				// Issue a cross TGT since we do not know the AuthSP
				// and we might have received remote attributes.
				TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
				String sOldTGT = (String) htServiceRequest.get("aselect_credentials_tgt");
				oTGTIssuer.issueCrossTGTandRedirect(sLocalRid, _htSessionContext, null, htRemoteAttributes, servletResponse, sOldTGT);
			}
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * A response of a remote server (aselect_credentials) is verified here. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * After forwarding a user to a remote server, the remote server will redirect the user back to this A-Select Server
	 * with credentials. The response and credentials are verified here. <br>
	 * <br>
	 * 
	 * @param sCredentials
	 *            the s credentials
	 * @param sRemoteRid
	 *            the s remote rid
	 * @param sRemoteOrg
	 *            the s remote org
	 * @return HashMap
	 * @throws ASelectException
	 *             the a select exception
	 */
	private HashMap verifyRemoteCredentials(String sCredentials, String sRemoteRid, String sRemoteOrg)
	throws ASelectException
	{
		String sMethod = "verifyRemoteCredentials";
		Object oRemoteServer;
		String sRemoteAsUrl;
		String sRemoteServer;
		try {
			CrossASelectManager oCrossASelectManager = CrossASelectManager.getHandle();
			String sResourcegroup = oCrossASelectManager.getRemoteParam(sRemoteOrg, "resourcegroup");
			SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
			oRemoteServer = oSAMResource.getAttributes();
			sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
			sRemoteServer = oCrossASelectManager.getRemoteParam(sRemoteOrg, "server");
		}
		catch (ASelectSAMException ase) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM", ase);

			throw ase;
		}
		catch (ASelectConfigException ace) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read config", ace);

			throw ace;
		}
		RawCommunicator oCommunicator = new RawCommunicator(_systemLogger); // Default = API communciation
		HashMap htRequestTable = new HashMap();
		HashMap htResponseTable = new HashMap();
		htRequestTable.put("request", "verify_credentials");
		htRequestTable.put("rid", sRemoteRid);
		htRequestTable.put("aselect_credentials", sCredentials);
		htRequestTable.put("a-select-server", sRemoteServer);
		Object oASelectConfig = ASelectConfigManager.getHandle().getSection(null, "aselect");
		String sMyOrgId = ASelectConfigManager.getHandle().getParam(oASelectConfig, "organization");
		htRequestTable.put("local_organization", sMyOrgId);

		if (_crossASelectManager.useRemoteSigning()) {
			_cryptoEngine.signRequest(htRequestTable);
		}

		_systemLogger.log(Level.INFO, _sModule, sMethod, "VfyREMOTE htRequestTable=" + htRequestTable);

		htResponseTable = oCommunicator.sendMessage(htRequestTable, sRemoteAsUrl);

		if (htResponseTable.isEmpty()) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not reach remote A-Select Server: "
					+ sRemoteAsUrl);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		_systemLogger.log(Level.INFO, _sModule, sMethod, "VfyREMOTE htResponseTable=" + htResponseTable);

		String sResultCode = (String) htResponseTable.get("result_code");
		if (sResultCode == null) {
			StringBuffer sbWarning = new StringBuffer("Invalid response from remote A-Select Server '");
			sbWarning.append(sRemoteServer);
			sbWarning.append("' (missing: 'result_code')");
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		// Uid needed for authentication logging if access denied.;
		String sUID = (String) htResponseTable.get("uid");
		if (sUID != null) {
			// RM_29_01
			try {
				sUID = URLDecoder.decode(sUID, "UTF-8");
				sUID = URLDecoder.decode(sUID, "UTF-8");
			}
			catch (UnsupportedEncodingException ee) {
			}
		}

		if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
			StringBuffer sbWarning = new StringBuffer("Remote A-Select Server '");
			sbWarning.append(sRemoteServer);
			sbWarning.append("' returned error: ");
			sbWarning.append(sResultCode);
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
			HashMap htTicketContext = new HashMap();
			htTicketContext.put("result_code", sResultCode);

			if (sUID != null) {
				htTicketContext.put("uid", sUID);
			}
			else {
				htTicketContext.put("uid", "");
			}
			return htTicketContext;
		}

		if (sUID == null) {
			StringBuffer sbWarning = new StringBuffer("Remote A-Select Server '");
			sbWarning.append(sRemoteServer);
			sbWarning.append("' did not return 'uid'");
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}
		// RM_29_02
		try {
			sUID = URLDecoder.decode(sUID, "UTF-8");
			sUID = URLDecoder.decode(sUID, "UTF-8");
		}
		catch (UnsupportedEncodingException ee) {
		}

		String sOrg = (String) htResponseTable.get("organization");
		if (sOrg == null) {
			StringBuffer sbWarning = new StringBuffer("Remote A-Select Server '");
			sbWarning.append(sRemoteServer);
			sbWarning.append("' did not return 'organization'");
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}
		String sAL = (String) htResponseTable.get("authsp_level");
		if (sAL == null) {
			StringBuffer sbWarning = new StringBuffer("Remote A-Select Server '");
			sbWarning.append(sRemoteServer);
			sbWarning.append("' did not return 'authsp_level'");
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}
		String sASP = (String) htResponseTable.get("authsp");
		if (sASP == null) {
			StringBuffer sbWarning = new StringBuffer("Remote A-Select Server '");
			sbWarning.append(sRemoteServer);
			sbWarning.append("' did not return 'authsp'");
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}
		String sAppLevel = (String) htResponseTable.get("app_level");
		if (sAppLevel == null) {
			StringBuffer sbWarning = new StringBuffer("Remote A-Select Server '");
			sbWarning.append(sRemoteServer);
			sbWarning.append("' did not return 'app_level'");
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}
		String sTgtExp = (String) htResponseTable.get("tgt_exp_time");
		if (sTgtExp == null) {
			StringBuffer sbWarning = new StringBuffer("Remote A-Select Server '");
			sbWarning.append(sRemoteServer);
			sbWarning.append("' did not return 'tgt_exp_time'");
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}

		// all parameters are there; create a ticket for this user and
		// store it in a ticket context
		HashMap htTicketContext = new HashMap();
		htTicketContext.put("uid", sUID);
		htTicketContext.put("organization", sOrg);
		htTicketContext.put("authsp_level", sAL);
		htTicketContext.put("authsp", sASP);
		htTicketContext.put("app_level", sAppLevel);
		htTicketContext.put("a-select-server", sRemoteServer);
		htTicketContext.put("tgt_exp_time", new Long(sTgtExp));
		// The attributes parameter is optional.
		String sAttributes = (String) htResponseTable.get("attributes");
		if (sAttributes != null)
			htTicketContext.put("attributes", sAttributes);
		return htTicketContext;
	}
}
