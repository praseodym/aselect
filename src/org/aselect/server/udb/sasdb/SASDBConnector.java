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
 * $Id: SASDBConnector.java,v 1.13 2006/05/03 10:11:56 tom Exp $ 
 * 
 * Changelog:
 * $Log: SASDBConnector.java,v $
 * Revision 1.13  2006/05/03 10:11:56  tom
 * Removed Javadoc version
 *
 * Revision 1.12  2005/09/08 13:08:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.11  2005/05/02 09:36:26  peter
 * Added isUserEnabled() and getUserAttributes() functionality
 *
 * Revision 1.10  2005/04/29 11:37:53  erwin
 * Added isUserEnabled() and getUserAttributes() functionality
 *
 * Revision 1.9  2005/04/15 12:07:42  tom
 * Removed old logging statements
 *
 * Revision 1.8  2005/03/29 13:01:18  martijn
 * now logging the same authentication information as all other udb connectors
 *
 * Revision 1.7  2005/03/14 15:22:54  martijn
 * The UDBConnector init method expects the connector config section instead of a resource config section. The resource config will now be resolved when the connection with the resource must be opened.
 *
 * Revision 1.6  2005/03/11 14:04:45  martijn
 * moved config item resourcegroup from udb config section to connector config section
 *
 * Revision 1.5  2005/03/09 10:24:26  erwin
 * Renamed and moved errors.
 *
 * Revision 1.4  2005/03/07 15:02:59  martijn
 * renamed variables to coding standard
 *
 * Revision 1.3  2005/03/07 15:01:00  martijn
 * updated authentication log information
 *
 * Revision 1.2  2005/03/02 16:27:13  martijn
 * added javadoc / renamed vars to code standard / made compatible with A-Select 1.4.1
 *
 */

package org.aselect.server.udb.sasdb;

import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectUDBException;

// TODO: Auto-generated Javadoc
/**
 * SASDB UDB connection. <br>
 * <br>
 * <b>Description:</b><br>
 * The SASDB first checks if a user exists in the configured database.<br>
 * If the user doesn't exist in that database, default user attributes will be generated for the authsps configured in
 * the SASDB config section. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class SASDBConnector implements IUDBConnector
{
	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "SASDBConnector";

	/**
	 * Logger used for system logging
	 */
	private ASelectSystemLogger _oASelectSystemLogger;
	/**
	 * Logger used for authentication logging
	 */
	private ASelectAuthenticationLogger _oASelectAuthenticationLogger;

	/**
	 * The udb storages configured
	 */
	private IUDBConnector _oIUDBConnector;

	/**
	 * The configured filters that must match the user id
	 */
	private HashMap _htFilters;

	/**
	 * The configured SASDB authsps
	 */
	private Vector _vAuthSPs;

	/**
	 * Reads the SASSB configuration and initializes the SASDB udb storage. <br>
	 * <br>
	 * The following configuration is read: - The udb storage which optional - No filter has to be configured - Every
	 * filter must have an unique id, starting with 1 and increased by one - One or more authsps must be configured were
	 * the user attribute will be generated for <br>
	 * <br>
	 * 
	 * @param oConfigSection
	 *            the o config section
	 * @throws ASelectUDBException
	 *             the a select udb exception
	 * @see org.aselect.server.udb.IUDBConnector#init(java.lang.Object)
	 */
	public void init(Object oConfigSection)
		throws ASelectUDBException
	{
		String sMethod = "init()";

		ASelectConfigManager oASelectConfigManager = null;
		Object oUdbStorage = null;
		String sUdbStorageConnector = null;
		Object oFiltersSection = null;
		Object oAuthSPsSection = null;
		String sStorageClass = null;
		Object oUdbSection = null;
		Object oUdbStorageSection = null;
		Object oFilterSection = null;

		try {
			oASelectConfigManager = ASelectConfigManager.getHandle();
			_oASelectSystemLogger = ASelectSystemLogger.getHandle();
			_oASelectAuthenticationLogger = ASelectAuthenticationLogger.getHandle();

			try {
				oUdbStorage = oASelectConfigManager.getSection(oConfigSection, "udb_storage");
			}
			catch (Exception e) {
				oUdbStorage = null;

				_oASelectSystemLogger
						.log(
								Level.CONFIG,
								MODULE,
								sMethod,
								"No valid 'udb_storage' config section found in 'connector', disabling secondary user database.",
								e);
			}

			if (oUdbStorage != null) {
				try {
					sUdbStorageConnector = oASelectConfigManager.getParam(oUdbStorage, "connector");
				}
				catch (ASelectConfigException e) {
					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
							"No valid 'connector' config section found in 'udb_storage'", e);
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					oUdbSection = oASelectConfigManager.getSection(null, "udb");
				}
				catch (ASelectConfigException e) {
					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
							"No valid 'udb' config section found in A-Select config", e);
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					oUdbStorageSection = oASelectConfigManager.getSection(oUdbSection, "connector", "id="
							+ sUdbStorageConnector);
				}
				catch (ASelectConfigException e) {
					StringBuffer sbError = new StringBuffer("No valid 'connector' config section with id='");
					sbError.append(sUdbStorageConnector);
					sbError.append("' in 'udb' config section, as configured as 'udb_storage'");
					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbError.toString(), e);

					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					sStorageClass = oASelectConfigManager.getParam(oUdbStorageSection, "class");
				}
				catch (Exception e) {
					StringBuffer sbFailed = new StringBuffer(
							"No valid 'class' config section found in 'connector' section with id='");
					sbFailed.append(sUdbStorageConnector);
					sbFailed.append("'");

					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbFailed.toString(), e);
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					Class oClass = Class.forName(sStorageClass);
					_oIUDBConnector = (IUDBConnector) oClass.newInstance();
				}
				catch (Exception e) {
					StringBuffer sbFailed = new StringBuffer("Invalid 'class' config item isn't a valid class: ");
					sbFailed.append(sStorageClass);
					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbFailed.toString(), e);
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					_oIUDBConnector.init(oUdbStorageSection);
				}
				catch (Exception e) {
					StringBuffer sbFailed = new StringBuffer("Could not initialize the configured UDB Connector: ");
					sbFailed.append(sStorageClass);

					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbFailed.toString(), e);
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
			}

			// reading filters
			_htFilters = new HashMap();

			try {
				oFiltersSection = oASelectConfigManager.getSection(oConfigSection, "filters");
			}
			catch (Exception e) {
				oFiltersSection = null;

				_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid 'filters' config section found in 'connector' section", e);
				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				oFilterSection = oASelectConfigManager.getSection(oFiltersSection, "filter");
			}
			catch (Exception e) {
				oFilterSection = null;

				_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid 'filter' config section found in 'filters' section, disabling filters", e);
			}

			while (oFilterSection != null) {
				String sID = null;
				String sPattern = null;
				try {
					sID = oASelectConfigManager.getParam(oFilterSection, "id");
				}
				catch (Exception e) {
					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
							"No valid 'id' config item found in 'filter' config section", e);
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				try {
					Integer.parseInt(sID);
				}
				catch (Exception e) {
					StringBuffer sbFailed = new StringBuffer("'id' config item is not an integer value: ");
					sbFailed.append(sID);

					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbFailed.toString(), e);
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				if (_htFilters.containsKey(sID)) {
					StringBuffer sbFailed = new StringBuffer("'id' config item already exists: ");
					sbFailed.append(sID);

					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbFailed.toString());
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR);
				}

				try {
					sPattern = oASelectConfigManager.getParam(oFilterSection, "pattern");
				}
				catch (Exception e) {
					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
							"No valid 'pattern' config item found in 'filter' config section", e);
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				if (!sPattern.startsWith("uid=") && !sPattern.startsWith("uid!=")) {
					StringBuffer sbFailed = new StringBuffer(
							"No valid 'pattern' config item found in 'filter' config section: ");
					sbFailed.append(sPattern);

					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbFailed.toString());
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR);
				}

				_htFilters.put(sID, sPattern);
				oFilterSection = oASelectConfigManager.getNextSection(oFilterSection);
			}

			// reading authsps
			_vAuthSPs = new Vector();

			try {
				oAuthSPsSection = oASelectConfigManager.getSection(oConfigSection, "authsps");
			}
			catch (Exception e) {
				oAuthSPsSection = null;

				_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid 'authsps' config section found in 'connector' section", e);
				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			Object oAuthSPSection = null;
			try {
				oAuthSPSection = oASelectConfigManager.getSection(oAuthSPsSection, "authsp");
			}
			catch (Exception e) {
				oFilterSection = null;

				_oASelectSystemLogger
						.log(
								Level.CONFIG,
								MODULE,
								sMethod,
								"No valid 'authsp' config section found in 'authsps' config section within 'connector' config section",
								e);
				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			while (oAuthSPSection != null) {
				String sAuthSPID = null;
				try {
					sAuthSPID = oASelectConfigManager.getParam(oAuthSPSection, "id");
				}
				catch (Exception e) {
					_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
							"No valid 'id' config item found in 'authsp' config section", e);
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				_vAuthSPs.add(sAuthSPID);
				oAuthSPSection = oASelectConfigManager.getNextSection(oAuthSPSection);
			}
		}
		catch (ASelectUDBException e) {
			throw e;
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize SASDB connector", e);

			throw new ASelectUDBException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

	}

	/**
	 * Resolves the user attributes for the supplied user id. <br>
	 * <br>
	 * - It first checks if the user exists in the configured udb (udb_storage)<br>
	 * - Checks if the user id matches all configured filters<br>
	 * - Creates user attributes for all authsps configured in the sas db connector<br>
	 * <br>
	 * The user attribute that is set is always the user id.<br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the s user id
	 * @return the user profile
	 * @see org.aselect.server.udb.IUDBConnector#getUserProfile(java.lang.String)
	 */
	public HashMap getUserProfile(String sUserId)
	{
		String sMethod = "getUserProfile()";

		HashMap htResponse = new HashMap();
		HashMap htUserAttributes = new HashMap();

		try {
			// Try to find the user in the "normal" UDB first
			if (_oIUDBConnector != null) {
				HashMap htUDBStorageProfile = _oIUDBConnector.getUserProfile(sUserId);
				String sErrorCode = (String) htUDBStorageProfile.get("result_code");
				if (sErrorCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
					htResponse = htUDBStorageProfile;
				}
			}

			if (htResponse.isEmpty()) {
				// No luck, so see if we can use the SASDB
				int iFilterCount = _htFilters.size();
				boolean bMatch = false;
				for (int i = 1; i <= iFilterCount; i++) {
					String sPattern = (String) _htFilters.get("" + i);
					if (sPattern == null) {
						StringBuffer sbBuffer = new StringBuffer(
								"SASDB filters are not configured in a following order.");
						_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbBuffer.toString());
						break;
					}
					if (sPattern.startsWith("uid="))
						bMatch = matchFilter(sUserId, sPattern.substring(4));
					else if (sPattern.startsWith("uid!="))
						bMatch = !matchFilter(sUserId, sPattern.substring(5));
					if (!bMatch) {
						// a user id must match ALL configured filters
						StringBuffer sbBuffer = new StringBuffer("User is not allowed to use the SASDBHandler: ");
						sbBuffer.append(sUserId);
						_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());

						logAuthentication(sUserId, Errors.ERROR_ASELECT_UDB_UNKNOWN_USER, "User unknown");

						throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_UNKNOWN_USER);
					}
				}

				Enumeration enumAuthSPs = _vAuthSPs.elements();
				while (enumAuthSPs.hasMoreElements()) {
					String sAuthSP = (String) enumAuthSPs.nextElement();
					htUserAttributes.put(sAuthSP, sUserId);
				}

				if (htUserAttributes.isEmpty()) {
					StringBuffer sbBuffer = new StringBuffer("No user attributes found for user: ");
					sbBuffer.append(sUserId);
					_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());

					throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
				}

				htResponse.put("result_code", Errors.ERROR_ASELECT_SUCCESS);
				htResponse.put("user_authsps", htUserAttributes);
			}
		}
		catch (ASelectUDBException e) {
			htResponse.put("result_code", e.getMessage());
		}
		catch (Exception e) {
			StringBuffer sbBuffer = new StringBuffer("Failed to fetch profile of user ");
			sbBuffer.append(sUserId);
			sbBuffer.append(": ");
			sbBuffer.append(e.getMessage());
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), e);

			htResponse.put("result_code", Errors.ERROR_ASELECT_UDB_INTERNAL);
		}

		return htResponse;
	}

	/**
	 * Retrieve the A-Select user attributes. <br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the s user id
	 * @param sAuthSPId
	 *            the s auth sp id
	 * @return the user attributes
	 * @throws ASelectUDBException
	 *             If database fails.
	 * @see org.aselect.server.udb.IUDBConnector#getUserAttributes(java.lang.String, java.lang.String)
	 */
	public String getUserAttributes(String sUserId, String sAuthSPId)
		throws ASelectUDBException
	{
		String sMethod = "getUserAttributes()";

		// HashMap htResponse = new HashMap();
		String sUserAttribute = null;

		try {
			// Try to find the user in the "normal" UDB first
			if (_oIUDBConnector != null) {
				sUserAttribute = _oIUDBConnector.getUserAttributes(sUserId, sAuthSPId);
			}

			if (sUserAttribute == null) {
				// No luck, so see if we can use the SASDB
				int iFilterCount = _htFilters.size();
				boolean bMatch = false;
				for (int i = 1; i <= iFilterCount; i++) {
					String sPattern = (String) _htFilters.get("" + i);
					if (sPattern == null) {
						StringBuffer sbBuffer = new StringBuffer(
								"SASDB filters are not configured in a following order.");
						_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbBuffer.toString());
						break;
					}
					if (sPattern.startsWith("uid="))
						bMatch = matchFilter(sUserId, sPattern.substring(4));
					else if (sPattern.startsWith("uid!="))
						bMatch = !matchFilter(sUserId, sPattern.substring(5));
					if (!bMatch) {
						i = iFilterCount;
					}
				}
				if (!bMatch) {
					// a user id must match ALL configured filters
					StringBuffer sbBuffer = new StringBuffer("User is not allowed to use the SASDBHandler: ");
					sbBuffer.append(sUserId);
					_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				}
				else {
					sUserAttribute = sUserId;
				}
			}
		}
		catch (ASelectUDBException e) {
			throw e;
		}
		return sUserAttribute;
	}

	/**
	 * Check if user is A-Select enabled. <br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the s user id
	 * @return true, if checks if is user enabled
	 * @throws ASelectUDBException
	 *             If database fails.
	 * @see org.aselect.server.udb.IUDBConnector#isUserEnabled(java.lang.String)
	 */
	public boolean isUserEnabled(String sUserId)
		throws ASelectUDBException
	{
		String sMethod = "isUserEnabled()";

		boolean bEnabled = false;

		try {
			// Try to find the user in the "normal" UDB first
			if (_oIUDBConnector != null) {
				bEnabled = _oIUDBConnector.isUserEnabled(sUserId);
			}

			if (!bEnabled) {
				// No luck, so see if we can use the SASDB
				int iFilterCount = _htFilters.size();
				boolean bMatch = false;
				for (int i = 1; i <= iFilterCount; i++) {
					String sPattern = (String) _htFilters.get("" + i);
					if (sPattern == null) {
						StringBuffer sbBuffer = new StringBuffer(
								"SASDB filters are not configured in a following order.");
						_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod, sbBuffer.toString());
						break;
					}
					if (sPattern.startsWith("uid="))
						bMatch = matchFilter(sUserId, sPattern.substring(4));
					else if (sPattern.startsWith("uid!="))
						bMatch = !matchFilter(sUserId, sPattern.substring(5));
					if (!bMatch) {
						i = iFilterCount;
					}
				}
				bEnabled = bMatch;
				if (!bEnabled) {
					// a user id must match ALL configured filters
					StringBuffer sbBuffer = new StringBuffer("User is not allowed to use the SASDBHandler: '");
					sbBuffer.append(sUserId).append("'");
					_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				}
			}
		}
		catch (ASelectUDBException e) {
			throw e;
		}

		return bEnabled;
	}

	// Compare sData against sFilterPattern, which may contain
	// wildcards (* and ?)
	//
	/**
	 * Match filter.
	 * 
	 * @param sData
	 *            the s data
	 * @param sFilterPattern
	 *            the s filter pattern
	 * @return true, if successful
	 */
	private boolean matchFilter(String sData, String sFilterPattern)
	{
		char c = 0;
		int i = 0;

		StringCharacterIterator iter = new StringCharacterIterator(sFilterPattern);

		for (c = iter.first(); c != CharacterIterator.DONE && i < sData.length(); c = iter.next()) {
			if (c == '?')
				i++;
			else if (c == '*') {
				int j = iter.getIndex() + 1;
				if (j >= sFilterPattern.length())
					return true;
				String sSubFilter = sFilterPattern.substring(j);
				while (i < sData.length()) {
					if (matchFilter(sData.substring(i), sSubFilter))
						return true;
					i++;
				}
				return false;
			}
			else if (c == sData.charAt(i)) {
				i++;
			}
			else
				return false;
		}

		return (i == sData.length());
	}

	/**
	 * Sorts authentication logging parameters and logs them. <br>
	 * <br>
	 * 
	 * @param sUserID
	 *            The A-Select user id
	 * @param sErrorCode
	 *            The error code of the error that occured
	 * @param sMessage
	 *            The authentication log message
	 */
	private void logAuthentication(String sUserID, String sErrorCode, String sMessage)
	{
		_oASelectAuthenticationLogger.log(new Object[] {
			MODULE, sUserID, null, null, null, sMessage, sErrorCode
		});
	}
}
