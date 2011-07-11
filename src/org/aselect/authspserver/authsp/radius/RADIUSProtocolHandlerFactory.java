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
 * $Id: RADIUSProtocolHandlerFactory.java,v 1.7 2006/05/03 10:07:31 tom Exp $ 
 *
 * $log:$
 *
 */

package org.aselect.authspserver.authsp.radius;

import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.logging.SystemLogger;

/**
 * The Radius Protocol Handler Factory. <br>
 * <br>
 * <b>Description: </b> <br>
 * Creates and Returns the correct Radius Protocol Handler PAP or CHAP based on the provided configuration. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * None<br>
 * 
 * @author Alfa & Ariss
 */
public class RADIUSProtocolHandlerFactory
{
	private final static String MODULE = "RADIUSProtocolHandlerFactory";

	/**
	 * Instantiate protocol handler.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sUid
	 *            the s uid
	 * @param oSystemLogger
	 *            the o system logger
	 * @return the iRADIUS protocol handler
	 */
	static IRADIUSProtocolHandler instantiateProtocolHandler(Object oConfig, String sUid, SystemLogger oSystemLogger)
	{
		String sMethod = "instantiateProtocolHandler()";

		try {
			HashMap htContext;
			htContext = getContext(oConfig, sUid, oSystemLogger);
			if (htContext == null) {
				return null;
			}

			String sRadiusServer = (String) htContext.get("radius_server");
			Integer iPort = (Integer) htContext.get("port");
			String sSharedSecret = (String) htContext.get("shared_secret");
			Boolean boolFullUid = (Boolean) htContext.get("full_uid");
			String sProtocolHandlerName = (String) htContext.get("handler");

			Class cProtocolHandler = Class.forName(sProtocolHandlerName);
			IRADIUSProtocolHandler oProtocolHandler = (IRADIUSProtocolHandler) cProtocolHandler.newInstance();
			if (!oProtocolHandler.init(sRadiusServer, iPort.intValue(), sSharedSecret, boolFullUid.booleanValue(),
					sUid, oSystemLogger)) {
				return null;
			}
			return oProtocolHandler;
		}
		catch (Exception e) {
			oSystemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR", e);
		}
		return null;
	}

	/**
	 * Gets the context.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sUid
	 *            the s uid
	 * @param oSystemLogger
	 *            the o system logger
	 * @return the context
	 */
	static HashMap getContext(Object oConfig, String sUid, SystemLogger oSystemLogger)
	{
		HashMap htResponse = new HashMap();
		StringBuffer sbTemp;
		String sMethod = "getContext()";

		AuthSPConfigManager oConfigManager = AuthSPConfigManager.getHandle();
		try {
			int iIndex = sUid.indexOf('@');
			if (iIndex <= 0) {
				sbTemp = new StringBuffer("invalid user id (").append(sUid).append(") ");
				sbTemp.append("User id should be [user]@[realm].");
				oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbTemp.toString());
				return null;
			}

			String sRealm = sUid.substring(iIndex);
			if (sRealm.length() <= 0) {
				sbTemp = new StringBuffer("could not determine realm for user id ");
				sbTemp.append(sUid).append(". Should be [user]@[realm].");
				oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbTemp.toString());
				return null;
			}

			Object oBackendServer = null;
			try {
				oBackendServer = oConfigManager.getSection(oConfig, "back-end_server", "realm=" + sRealm);
			}
			catch (ASelectConfigException e) {
				oBackendServer = null;
				// no back-end_server found with specified realm
				// --
				// try to find a wildcard realm or a back-end_server without a
				// realm configured
			}

			try {
				if (oBackendServer == null)
					oBackendServer = oConfigManager.getSection(oConfig, "back-end_server", "realm=*");
			}
			catch (ASelectConfigException e) {
				oBackendServer = null;
				// No back-end_server found with wildcard realm
				// --
				// Now try to find a back-end_server where no realm is configured
			}

			if (oBackendServer == null) {
				try {
					oBackendServer = oConfigManager.getSection(oConfig, "back-end_server");
				}
				catch (ASelectConfigException e) {
					oBackendServer = null;
				}

				while (oBackendServer != null) {
					try {
						oConfigManager.getParam(oBackendServer, "realm");
					}
					catch (ASelectConfigException e) {
						// just a check if a realm is configured
						// if no realm is configured this back-end_server will be
						// used, so stop the while loop
						break;
					}
					oBackendServer = oConfigManager.getNextSection(oBackendServer);
				}

				if (oBackendServer != null) {
					sbTemp = new StringBuffer("no radius server defined for realm ");
					sbTemp.append(sRealm).append(" while authenticating ");
					sbTemp.append(sUid);

					oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbTemp.toString());
					return null;
				}
			}

			String sRadiusServer = null;
			try {
				sRadiusServer = oConfigManager.getParam(oBackendServer, "host");
			}
			catch (ASelectConfigException e) {
				sbTemp = new StringBuffer("no radius server defined for realm ");
				sbTemp.append(sRealm).append(" while authenticating ");
				sbTemp.append(sUid);

				oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbTemp.toString());
				return null;
			}

			int iPort;
			String sTemp = null;
			try {
				sTemp = oConfigManager.getParam(oBackendServer, "port");
				iPort = Integer.parseInt(sTemp);
			}
			catch (ASelectConfigException e) {
				iPort = IRADIUSProtocolHandler.RADIUS_PORT;
			}

			String sSharedSecret = null;
			try {
				sSharedSecret = oConfigManager.getParam(oBackendServer, "shared_secret");
			}
			catch (ASelectConfigException e) {
				sbTemp = new StringBuffer("no shared_secret defined for realm ");
				sbTemp.append(sRealm).append(" while authenticating ");
				sbTemp.append(sUid);
				oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbTemp.toString());
				return null;
			}

			boolean bFullUid = false;
			String sFullUid = null;
			try {
				sFullUid = oConfigManager.getParam(oBackendServer, "full_uid");
			}
			catch (ASelectConfigException e) {
				sFullUid = "false";
				StringBuffer sbWarning = new StringBuffer("No 'full_uid' defined for realm ");
				sbWarning.append(sRealm);
				sbWarning.append("; using default: full_uid = ");
				sbWarning.append(sFullUid);
				oSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbWarning.toString(), e);
			}
			if (sFullUid.equalsIgnoreCase("true"))
				bFullUid = true;
			else if (sFullUid.equalsIgnoreCase("false"))
				bFullUid = false;
			else {
				StringBuffer sbConfig = new StringBuffer("Invalid 'full_uid' config item defined for realm ");
				sbConfig.append(sRealm);
				sbConfig.append(" : ");
				sbConfig.append(sFullUid);
				sbConfig.append("; using default: full_uid = false");
				oSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbConfig.toString());
			}

			try {
				sTemp = oConfigManager.getParam(oBackendServer, "method");
			}
			catch (ASelectConfigException e) {
				sbTemp = new StringBuffer("no method defined for realm ");
				sbTemp.append(sRealm).append(" while authenticating ");
				sbTemp.append(sUid);
				oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbTemp.toString());
				return null;
			}
			String sProtocolHandlerName = null;
			try {
				sProtocolHandlerName = oConfigManager.getParam(oConfig, sTemp + "_protocolhandler");
			}
			catch (ASelectConfigException e) {
				sbTemp = new StringBuffer("no protocol handler defined for realm");
				sbTemp.append(sRealm).append(" while authenticating ");
				sbTemp.append(sUid);
				oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbTemp.toString());
				return null;
			}

			htResponse.put("radius_server", sRadiusServer);
			htResponse.put("port", new Integer(iPort));
			htResponse.put("shared_secret", sSharedSecret);
			htResponse.put("full_uid", new Boolean(bFullUid));
			htResponse.put("handler", sProtocolHandlerName);
			return htResponse;
		}
		catch (Exception e) {
			oSystemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR", e);
		}
		return null;
	}
}