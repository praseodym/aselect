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
 * $Id: FlatFileConnector.java,v 1.14 2006/05/03 10:11:56 tom Exp $ 
 * 
 * Changelog:
 * $Log: FlatFileConnector.java,v $
 * Revision 1.14  2006/05/03 10:11:56  tom
 * Removed Javadoc version
 *
 * Revision 1.13  2005/09/08 13:08:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.12  2005/04/29 11:37:53  erwin
 * Added isUserEnabled() and getUserAttributes() functionality
 *
 * Revision 1.11  2005/04/15 12:06:08  tom
 * Removed old logging statements
 *
 * Revision 1.10  2005/03/15 16:30:04  tom
 * Fixed comment
 *
 * Revision 1.9  2005/03/15 16:29:28  tom
 * Fixed Javadoc
 *
 * Revision 1.8  2005/03/14 14:25:24  martijn
 * The UDBConnector init method expects the connector config section instead of a resource config section. The resource config will now be resolved when the connection with the resource must be opened.
 *
 * Revision 1.7  2005/03/10 16:19:38  tom
 * Updated Javadoc
 *
 * Revision 1.6  2005/03/10 16:18:18  tom
 * Added new Authentication Logger
 *
 * Revision 1.5  2005/03/09 09:24:19  erwin
 * Renamed and moved errors.
 *
 * Revision 1.4  2005/03/07 15:01:00  martijn
 * updated authentication log information
 *
 * Revision 1.3  2005/02/28 09:49:38  martijn
 * changed all variable names to naming convention and added java documentation
 *
 * Revision 1.2  2005/02/25 12:33:44  martijn
 * changed all variable names to naming convention and added java documentation
 *
 */

package org.aselect.server.udb.noudb;

import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.exception.ASelectUDBException;
import org.aselect.system.sam.agent.SAMResource;

/**
 * No-database connector. <br>
 * <br>
 * <b>Description:</b><br>
 * Database connector that uses no database as physical storage. <br>
 * <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author R. Hanswijk
 */
public class NoUDBConnector implements IUDBConnector
{
	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "NoUDBConnector";

	/**
	 * The A-Select config manager used for reading config parameters
	 */
	private ASelectConfigManager _oASelectConfigManager;
	/**
	 * The logger that is used for system logging
	 */
	private ASelectSystemLogger _oASelectSystemLogger;
	/**
	 * Logger used for authentication logging
	 */
	private ASelectAuthenticationLogger _oASelectAuthenticationLogger;
	/**
	 * The UDB flatfile
	 */
	private Properties _propFlatFile;

	/**
	 * Initializes managers and loads the A-Select user db flatfile into a <code>Properties</code> object. <br>
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
		String sMethod = "init";
		String sUDBResourceGroup = null;
		
		_oASelectSystemLogger = ASelectSystemLogger.getHandle();
		_oASelectSystemLogger.log(Level.INFO, MODULE, sMethod, "NoUDB");

		_oASelectConfigManager = ASelectConfigManager.getHandle();
		_oASelectAuthenticationLogger = ASelectAuthenticationLogger.getHandle();
		ASelectSAMAgent oASelectSAMAgent = ASelectSAMAgent.getHandle();

		try {
			try {
				sUDBResourceGroup = _oASelectConfigManager.getParam(oConfigSection, "resourcegroup");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
						"No 'resourcegroup' config item found in udb 'connector' config section.", e);
				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			SAMResource oSAMResource = null;
			try {
				oSAMResource = oASelectSAMAgent.getActiveResource(sUDBResourceGroup);
			}
			catch (ASelectSAMException e) {
				StringBuffer sbFailed = new StringBuffer("No active resource found in udb resourcegroup: ");
				sbFailed.append(sUDBResourceGroup);
				_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbFailed.toString(), e);
				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		catch (ASelectUDBException e) {
			throw e;
		}
		catch (Exception e) {
			StringBuffer sbBuffer = new StringBuffer("Could not initialize the noUDB connector: ");
			sbBuffer.append(e.getMessage());
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Returns a hashtable with the user's record. <br>
	 * <br>
	 * <b>Description</b>: <br>
	 * The returned hashtable contains a <code>result_code</code> and <code>user_authsps</code> which is a hashtable
	 * containing the AuthSP's that the user is registered for. Within this hashtable each AuthSP has an entry with the
	 * value of the user attributes that specific AuthSP. <br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the s user id
	 * @return the user profile
	 * @see org.aselect.server.udb.IUDBConnector#getUserProfile(java.lang.String)
	 */
	public HashMap getUserProfile(String sUserId)
	{
		String sMethod = "getUserProfile";

		_oASelectSystemLogger.log(Level.INFO, MODULE, sMethod, "user=" + sUserId);
		HashMap htResponse = new HashMap();
		HashMap htUserAttributes = new HashMap();
		Object oAuthSPsSection = null;
		Object oAuthSP = null;
		String sAuthSPID = null;

		try {
			htResponse.put("result_code", Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
			htResponse.put("udb_type", "noudb");
			try {
				oAuthSPsSection = _oASelectConfigManager.getSection(null, "authsps");
			}
			catch (Exception e) {
				_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Config section 'authsps' not found.");
				throw new ASelectUDBException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			try {
				oAuthSP = _oASelectConfigManager.getSection(oAuthSPsSection, "authsp");
			}
			catch (Exception e) {
				_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
						"Not even one config section 'authsp' found in config section 'authsps'.");
				throw new ASelectUDBException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			// Loop through all available authsp's
			while (oAuthSP != null) {
				try {
					sAuthSPID = _oASelectConfigManager.getParam(oAuthSP, "id");
				}
				catch (Exception e) {
					_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
							"No config item 'id' found in 'authsp' config section.");
					throw new ASelectUDBException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}
				htUserAttributes.put(sAuthSPID, ""); // 20090422, Bauke: sUserId == null ? "" : sUserId);
				oAuthSP = _oASelectConfigManager.getNextSection(oAuthSP);
			}

			if (htUserAttributes.size() == 0) {
				StringBuffer sbBuffer = new StringBuffer("No user attributes found for user: ");
				sbBuffer.append(sUserId);
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
			}
			htResponse.put("user_authsps", htUserAttributes);
			htResponse.put("result_code", Errors.ERROR_ASELECT_SUCCESS);
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
	 * Check if user is A-Select enabled. <br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the user id
	 * @param hmInfo
	 *            the resulting user info
	 * @return true, if checks if is user enabled
	 * 
	 * @see org.aselect.server.udb.IUDBConnector#isUserEnabled()
	 */
	public boolean isUserEnabled(String sUserId, HashMap<String, String> hmInfo)
	{
		String sMethod = "isUserEnabled";
		
		boolean bEnabled = true;
		_oASelectSystemLogger.log(Level.INFO, MODULE, sMethod, "user=" + sUserId);
		return bEnabled;
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
	 * @see org.aselect.server.udb.IUDBConnector#getUserAttributes(java.lang.String, java.lang.String)
	 */
	public String getUserAttributes(String sUserId, String sAuthSPId)
	{
		String sMethod = "getUserAttributes()";
		_oASelectSystemLogger.log(Level.INFO, MODULE, sMethod, "User=" + sUserId + " Authsp=" + sAuthSPId);
		String sAttributesValue = sUserId == null ? "" : sUserId;
		return sAttributesValue;
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
