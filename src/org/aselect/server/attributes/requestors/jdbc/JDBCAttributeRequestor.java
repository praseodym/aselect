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
package org.aselect.server.attributes.requestors.jdbc;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.attributes.requestors.GenericAttributeRequestor;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.sam.agent.SAMResource;

import com.mysql.jdbc.ResultSetMetaData;

public class JDBCAttributeRequestor extends GenericAttributeRequestor
{
	private final static String MODULE = "JDBCAttributeRequestor";
	private String _sResourceGroup = null;
	private String _sQuery;
	private String _sAttrNames;
	private Vector _vTGTParameters;
	//private HashMap _htConfigParameters;
	//private HashMap _htReMapAttributes;

	public void init(Object oConfig)
	throws ASelectException
	{
		String sMethod = "init()";
		//_htReMapAttributes = new HashMap();

		try {
			try {
				_sResourceGroup = _configManager.getParam(oConfig, "resourcegroup");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'resourcegroup' config item found", e);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			_vTGTParameters = new Vector();
			//_htConfigParameters = new HashMap();
			Object oParameterConfiguration = null;
			try {
				oParameterConfiguration = _configManager.getSection(oConfig, "parameters");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Could not retrieve 'parameters' configuration section; no parameters will be send", eAC);
			}

			if (oParameterConfiguration != null) {
				Object oParameter = null;
				try {
					oParameter = _configManager.getSection(oParameterConfiguration, "parameter");
				}
				catch (ASelectConfigException eAC) {
					_systemLogger.log(Level.CONFIG, MODULE, sMethod,
							"Could not retrieve one 'parameter' in 'parameters' configuration section", eAC);
				}
				while (oParameter != null) {  // for all parameters
					try {
						String sParameterName = _configManager.getParam(oParameter, "id");
						_vTGTParameters.add(sParameterName);
						// check if the parameter is a session parameter
						/*boolean bSession = false;
						try {
							String sAttributeMapping = _configManager.getParam(oParameter, "session");
							if (sAttributeMapping.equals("true"))
								bSession = true;
						}
						catch (ASelectConfigException eAC) {
							// bSession is already false
						}

						if (bSession)
							_vTGTParameters.add(sParameterName);
						else {  // retrieve value
							String sParameterValue = _configManager.getParam(oParameter, "value");
							_htConfigParameters.put(sParameterName, sParameterValue);
						}*/

					}
					catch (ASelectConfigException eAC) {
						_systemLogger.log(Level.CONFIG, MODULE, sMethod,
								"Could not retrieve mandatory parameter in attribute", eAC);
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
					}
					oParameter = _configManager.getNextSection(oParameter);
				}
			}

			try {
				_sQuery = _configManager.getParam(oConfig, "query");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'query' parameter found in configuration", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			try {
				_sAttrNames = _configManager.getParam(oConfig, "attribute_names");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'attribute_names' parameter found in configuration", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			/*Object oAttributes = null;
			try {
				oAttributes = _configManager.getSection(oConfig, "attribute_mapping");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No valid 'attribute_mapping' config section found, no mapping used", e);
			}

			if (oAttributes != null) {
				Object oAttribute = null;
				try {
					oAttribute = _configManager.getSection(oAttributes, "attribute");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.CONFIG, MODULE, sMethod,
							"Not one valid 'attribute' config section in 'attributes' section found, no mapping used",
							e);
				}

				while (oAttribute != null) {
					String sAttributeID = null;
					String sAttributeMap = null;
					try {
						sAttributeID = _configManager.getParam(oAttribute, "id");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"No valid 'id' config item in 'attribute' section found", e);
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					try {
						sAttributeMap = _configManager.getParam(oAttribute, "map");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"No valid 'map' config item in 'attribute' section found", e);
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					_htReMapAttributes.put(sAttributeMap, sAttributeID);
					oAttribute = _configManager.getNextSection(oAttribute);
				}
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "map="+_htReMapAttributes);
			}*/
			
			getConnection();
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to instantiate JDBCAttributeRequestor", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	public HashMap getAttributes(HashMap htTGTContext, Vector vAttributes)
	throws ASelectAttributesException
	{
		String sMethod = "getAttributes()";
		HashMap htAttributes = new HashMap();
		Connection oConnection = null;

		try {
			oConnection = getConnection();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Prepare: "+_sQuery);
			PreparedStatement oStatement = oConnection.prepareStatement(_sQuery);
			ResultSet oResultSet = null;

			// Inject TGT parameter values (or constant values) into the SELECT query
			Enumeration e = _vTGTParameters.elements();
			int index = 1;
			while (e.hasMoreElements()) {
				String sName = (String) e.nextElement();
				String sValue = (String) htTGTContext.get(sName);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Param["+index+"]="+sName+" Value="+sValue);
				if (sValue == null) {
					StringBuffer sbError = new StringBuffer("Error retrieving '");
					sbError.append(sName);
					sbError.append("' parameter from session context.");
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
					throw new ASelectAttributesException(Errors.ERROR_ASELECT_CONFIG_ERROR);
				}
				oStatement.setString(index, sValue);
				index++;
			}

			String[] sAttrNames = _sAttrNames.split(" *, *");
			// Retrieve all columns from the result, every column is stored as an attribute
			try {
				oResultSet = oStatement.executeQuery();
				ResultSetMetaData rsmt = (ResultSetMetaData)oResultSet.getMetaData();
				int nrColumns = rsmt.getColumnCount();
				while (oResultSet.next()) {
					Vector vVector = null;
					//String sStatusKey = oResultSet.getString(1);
					//String sStatusValue = oResultSet.getString(2);
					// 20090902, Bauke replaced by a more useful mechanism
					for (int i = 1; i <= nrColumns; i++) {
						String sStatusKey = (i-1 < sAttrNames.length)? sAttrNames[i-1]: rsmt.getColumnName(i);
						String sStatusValue = oResultSet.getString(i);
						if (htAttributes.containsKey(sStatusKey)) {
							Object oTemp = htAttributes.get(sStatusKey);
							if (oTemp instanceof Vector) {  // Already has 2 or more values
								vVector = (Vector) oTemp;
							}
							else {  // Single value so far
								if (sStatusValue.equals((String)oTemp))  // This value is already present
									continue;
								vVector = new Vector();  // Make it multi-valued
								vVector.add((String)oTemp);
							}
							vVector.add(sStatusValue);
							htAttributes.put(sStatusKey, vVector);
						}
						else {
							htAttributes.put(sStatusKey, sStatusValue);  // first value
						}
					}
					break;  // we don't want multi-valued attributes just now
				}
				
				// Remap attribute names (from "map" to "id" value)
				/*_systemLogger.log(Level.INFO, MODULE, sMethod, "htAttributes"+htAttributes+" htRemap="+_htReMapAttributes);
				HashMap htMapped = new HashMap();
				Set keys = htAttributes.keySet();
				for (Object s : keys) {
					String sStatusKey = (String) s;
					Object sStatusValue = htAttributes.get(sStatusKey);
					if (_htReMapAttributes.containsKey(sStatusKey)) {
						sStatusKey = (String) _htReMapAttributes.get(sStatusKey);
					}
					htMapped.put(sStatusKey, sStatusValue);
				}
				htAttributes = htMapped;*/
			}
			catch (Exception ex) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not execute query: " + _sQuery, ex);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, ex);
			}
			finally {
				try {// RH, 20090605, n
					if (oResultSet != null)
						oResultSet.close();
					}
				catch (Exception e2) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not close resultset");
				}
				oResultSet = null; // RH, 20090605, n
				try {// RH, 20090605, n
					if (oStatement != null)
						oStatement.close();
					}
				catch (Exception e2) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not close statement");
				}
				oStatement = null; // RH, 20090605, n
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to resolve attributes", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		// RH, 20090605, sn
		finally {
			try {
				if (oConnection != null)
					oConnection.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not close connection");
			}
			oConnection = null;
		}
		// RH, 20090605, en
		return htAttributes;
	}

	public void destroy()
	{
		// Does nothing
	}

	private Connection getConnection()
		throws ASelectSAMException
	{
		String sMethod = "getConnection()";

		Connection oConnection = null;
		SAMResource oSAMResource = null;
		String sDriver = null;
		String sUsername = null;
		String sPassword = null;
		String sUrl = null;
		Object oResourceConfig = null;

		try {
			oSAMResource = _samAgent.getActiveResource(_sResourceGroup);
		}
		catch (ASelectSAMException e) {
			StringBuffer sbFailed = new StringBuffer(
					"No active resource found in JDBCAttributeRequestor resourcegroup: ");
			sbFailed.append(_sResourceGroup);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
			throw e;
		}
		oResourceConfig = oSAMResource.getAttributes();
		
		try {
			sDriver = _configManager.getParam(oResourceConfig, "driver");
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'driver' found", e);
			throw new ASelectSAMException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			// initialize driver
			Class.forName(sDriver);
		}
		catch (Exception e) {
			StringBuffer sbFailed = new StringBuffer("Can't initialize driver: ");
			sbFailed.append(sDriver);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
			throw new ASelectSAMException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		try {
			sUrl = _configManager.getParam(oResourceConfig, "url");
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'url' found", e);
			throw new ASelectSAMException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			sUsername = _configManager.getParam(oResourceConfig, "username");
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'username' found", e);
			throw new ASelectSAMException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			sPassword = _configManager.getParam(oResourceConfig, "password");
		}
		catch (Exception e) {
			sPassword = "";
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No or empty config item 'security_principal_password' found, using empty password. Don't use this in a live production environment.", e);
		}

		try {
			oConnection = DriverManager.getConnection(sUrl, sUsername, sPassword);
		}
		catch (SQLException e) {
			StringBuffer sbFailed = new StringBuffer("Could not open connection to: ");
			sbFailed.append(sUrl);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
			throw new ASelectSAMException(Errors.ERROR_ASELECT_IO, e);
		}

		return oConnection;
	}

	public static void main(String[] args)
	{
		// String url = "jdbc:mysql://localhost/aselect";

		// String query = "SELECT name, value FROM TBL_ATTRIBUTES WHERE " + "(
		// uid=? OR uid='*' ) AND"
		// + "( organization=? OR organization='*' ) AND" + "( app_id=? OR
		// app_id='*' ) AND"
		// + "( authsp=? OR authsp='*' )";

		// _htReMapAttributes = new HashMap();
		// _htReMapAttributes.put("match",
		// "urn:mace:attribute-def:nl.surffederatie:nlEduPersonHomeOrganization");

		try {
			Class.forName("com.mysql.jdbc.Driver");
			// Connection con = DriverManager.getConnection(url, "aselect_user",
			// "changeit");
			HashMap tgtContext = new HashMap();
			tgtContext.put("uid", "zandbelt");
			tgtContext.put("organization", "SURFnetSG");
			tgtContext.put("app_id", "federatiedemo");
			tgtContext.put("authsp", "radius");
			Vector parms = new Vector();
			parms.add("uid");
			parms.add("organization");
			parms.add("app_id");
			parms.add("authsp");
			// HashMap ht = getAttributes2(tgtContext , null, con, parms, query);
			HashMap ht = new HashMap();
			Set keys = ht.keySet();
			for (Object s : keys) {
				String key = (String) s;
				// Enumeration e = ht.keys();
				// while (e.hasMoreElements()) {
				// String key = (String) e.nextElement();
				Object o = ht.get(key);
				if (o instanceof String) {
					System.out.println(" key: \"" + key + "\", value: \"" + o + "\"");
				}
				else {
					Vector v = (Vector) o;
					Enumeration e2 = v.elements();
					System.out.print(" key: \"" + key + "\", value: [");
					while (e2.hasMoreElements()) {
						System.out.print("\"" + e2.nextElement() + "\" ");
					}
					System.out.println("]");
				}
			}
		}
		catch (Exception e1) {
			e1.printStackTrace();
		}
	}
}
