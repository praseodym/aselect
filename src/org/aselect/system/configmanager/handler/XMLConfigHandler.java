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
 * $Id: XMLConfigHandler.java,v 1.17 2006/05/03 09:30:33 tom Exp $ 
 * 
 * Changelog:
 * $Log: XMLConfigHandler.java,v $
 * Revision 1.17  2006/05/03 09:30:33  tom
 * Removed Javadoc version
 *
 * Revision 1.16  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.15  2005/09/07 14:42:55  erwin
 * Fixed table name. (bug #103 and #104)
 *
 * Revision 1.14  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.13  2005/04/06 10:25:40  erwin
 * Fixed problem with setting section/parameter and saving configuration.
 *
 * Revision 1.12  2005/03/09 09:22:13  erwin
 * Renamed errors.
 *
 * Revision 1.11  2005/03/07 13:31:52  remco
 * fixed bug in getNextSection()
 *
 * Revision 1.10  2005/03/04 09:12:39  peter
 * Replaced deprecated call "Date.toLocaleString()" in saveConfig()
 *
 * Revision 1.9  2005/03/01 15:13:11  martijn
 * getNextSection() will now return only a section with the same node name
 *
 * Revision 1.8  2005/03/01 14:50:32  martijn
 * fixed typo in logging
 *
 * Revision 1.7  2005/03/01 08:03:33  erwin
 * _sModule -> MODULE and levels improved.
 *
 * Revision 1.6  2005/02/25 15:53:03  erwin
 * Added fine logging for getParam().
 *
 * Revision 1.5  2005/02/21 14:21:28  erwin
 * Applied code style and improved JavaDoc.
 *
 * Revision 1.4  2005/02/10 15:45:39  martijn
 * fixed bug that in the two getSection() methods
 *
 * Revision 1.3  2005/02/08 10:15:53  martijn
 * added javadoc
 *
 * Revision 1.2  2005/02/07 15:14:15  martijn
 * changed all variable names to naming convention
 *
 */

package org.aselect.system.configmanager.handler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.DateFormat;
import java.util.Date;
import java.util.logging.Level;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.aselect.system.configmanager.IConfigHandler;
import org.aselect.system.db.SQLDatabaseConnector;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectDatabaseException;
import org.aselect.system.logging.SystemLogger;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

// TODO: Auto-generated Javadoc
/**
 * ConfigHandler that reads and writes configuration items as XML data. <br>
 * <br>
 * <b>Description: </b> <br>
 * ConfigHandler that reads and writes configuration files located on harddisk or JDBC database. This class can handle
 * XML configuration files that are located in a file or a JDBC database, like: <br>
 * table_name -> [id][XML data] where id is unique within the table. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * This <code>IConfigHandler</code> is threadsafe. <br>
 * 
 * @author Alfa & Ariss
 */
public class XMLConfigHandler implements IConfigHandler
{
	/**
	 * The name of this module, that is used as location in the system logging.
	 */
	private static final String MODULE = "XMLConfigHandler";

	/**
	 * The name of the database column that indicates the configuration that must be read by this config handler.
	 */
	private static final String ID_COLUMN = "id";

	/**
	 * The name of the database column that is used to store the XML configuration in the configuration table.
	 */
	private static final String DATA_COLUMN = "data";

	/**
	 * The XML DOM Document that contains the configuration
	 */
	private Document _oDomDocument;

	/**
	 * The configuration file containing the XML config, if a file is used as physical storage.
	 */
	private File _fConfig;

	/**
	 * The database table of the configuration in the database.
	 */
	private String _sDatabaseTableName;

	/**
	 * The id of the configuration that indicates the configuration in the database.
	 */
	private String _sConfigId;

	/**
	 * The SystemLogger used for logging
	 */
	private SystemLogger _oSystemLogger;

	/**
	 * SQL JDBC Database connection that is used by this class.
	 */
	private SQLDatabaseConnector _sdcConnector;

	/**
	 * Default constructor. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Default constructor for <code>XMLConfigHandler</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>oSystemLogger</code> should be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The system logger is set. <br>
	 * 
	 * @param oSystemLogger
	 *            The system logger that should be used.
	 */
	public XMLConfigHandler(SystemLogger oSystemLogger) {
		_oSystemLogger = oSystemLogger;
		_oDomDocument = null;
	}

	/**
	 * Parses an XML config File to an XML DOM Object. <br>
	 * <br>
	 * 
	 * @param fConfig
	 *            the f config
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#init(java.io.File)
	 */
	public void init(File fConfig)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = ".init()";

		try {
			_fConfig = fConfig;
			_oDomDocument = parseXML(_fConfig);
		}
		catch (ParserConfigurationException e) {
			sbError.append("Parser incorrect configured.");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_READ, e);

		}
		catch (SAXException e) {
			sbError.append("Error during SAX Parsing.");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_READ, e);
		}
		catch (IOException e) {
			sbError.append("Error while opening XML config file.");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN, e);
		}
		catch (Exception e) {
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Parses the XML configuration located in a JDBC database to an XML Dom object. <br>
	 * <br>
	 * 
	 * @param sUser
	 *            the s user
	 * @param sPassword
	 *            the s password
	 * @param sDatabaseURL
	 *            the s database url
	 * @param sDatabaseTable
	 *            the s database table
	 * @param sDriverName
	 *            the s driver name
	 * @param sConfigId
	 *            the s config id
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#init(java.lang.String, java.lang.String, java.lang.String,
	 *      java.lang.String, java.lang.String, java.lang.String)
	 */
	public void init(String sUser, String sPassword, String sDatabaseURL, String sDatabaseTable, String sDriverName,
			String sConfigId)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "init()";

		String sData = null;
		Statement oStatement = null;

		try {
			_sdcConnector = new SQLDatabaseConnector(sDriverName, sUser, sPassword, sDatabaseURL, _oSystemLogger);
			_sConfigId = sConfigId;
			_sDatabaseTableName = sDatabaseTable;
			// create query
			StringBuffer sbQuery = new StringBuffer("Select ");
			sbQuery.append(DATA_COLUMN);
			sbQuery.append(" FROM ");
			sbQuery.append(_sDatabaseTableName);
			sbQuery.append(" WHERE ").append(ID_COLUMN);
			sbQuery.append("='").append(_sConfigId).append("'");

			// open DB connection
			oStatement = _sdcConnector.connect();
			if (oStatement != null) {
				ResultSet rsResponse = _sdcConnector.executeQuery(oStatement, sbQuery.toString());

				if (rsResponse.next())
					sData = rsResponse.getString(1);

				_sdcConnector.disconnect(oStatement);
				_oDomDocument = parseXML(sData.getBytes("UTF-8"));
			}
			else {
				sbError.append("Could not connect to database: ");
				sbError.append(sDatabaseURL);
				_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
				throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN);
			}

		}
		catch (ParserConfigurationException e) {
			sbError.append("Parser configuration is wrong: ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_READ, e);
		}
		catch (SAXException e) {
			sbError.append("Error during SAX parsing: ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_READ, e);
		}
		catch (IOException e) {
			sbError.append("Could not open XML object: ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_READ, e);
		}
		catch (ASelectDatabaseException e) {
			sbError.append("Could connect to database: ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN, e);
		}
		catch (SQLException e) {
			sbError.append("Could not execute database query: ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN, e);
		}
		catch (Exception e) {
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Retrieves a config section by it's type and id. <br>
	 * <br>
	 * 
	 * @param oRootSection
	 *            the o root section
	 * @param sSectionType
	 *            the s section type
	 * @param sSectionID
	 *            the s section id
	 * @return the section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#getSection(java.lang.Object, java.lang.String,
	 *      java.lang.String)
	 */
	public synchronized Object getSection(Object oRootSection, String sSectionType, String sSectionID)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "getSection()";

		Node nSection = null;
		Node nRoot = null;

		// rootSection can be null if the first section is requested
		if (oRootSection != null) {
			if (oRootSection instanceof Element)
				nRoot = (Element) oRootSection;
			else {
				sbError.append("Root section invalid, is not of type: Element");
				_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
		}
		else
			nRoot = _oDomDocument.getDocumentElement();

		if (sSectionID != null)
			nSection = getSubSectionByID(nRoot, sSectionType, sSectionID);
		else {
			sbError.append("No section ID supplied.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		if (nSection == null) {
			sbError.append("Section not found, rootSection=");
			sbError.append(nRoot.getNodeName());
			sbError.append(", section type=");
			sbError.append(sSectionType);
			sbError.append(", section id=");
			sbError.append(sSectionID);
			_oSystemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}
		return nSection;
	}

	/**
	 * Retrieves a config section by it's type. <br>
	 * <br>
	 * 
	 * @param oRootSection
	 *            the o root section
	 * @param sSectionType
	 *            the s section type
	 * @return the section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#getSection(java.lang.Object, java.lang.String)
	 */
	public synchronized Object getSection(Object oRootSection, String sSectionType)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "getSection()";

		Node nSection = null;
		Node nRoot = null;

		// rootSection can be null if the first section is requested
		if (oRootSection != null)
			if (oRootSection instanceof Element)
				nRoot = (Element) oRootSection;
			else {
				sbError.append("Root section invalid, is not of type: Element");
				_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
		else
			nRoot = _oDomDocument.getDocumentElement();

		if (sSectionType != null)
			nSection = getSubSection(nRoot, sSectionType);
		else {
			sbError.append("No section Type supplied.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		if (nSection == null) {
			sbError.append("Section not found, rootSection=");
			sbError.append(nRoot.getNodeName());
			sbError.append(" sectionType=");
			sbError.append(sSectionType);
			_oSystemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}
		return nSection;
	}

	/**
	 * Adds a config section (empty tag) with section type as it's name (tagname) and returns the new section. <br>
	 * <br>
	 * 
	 * @param oRootSection
	 *            the o root section
	 * @param sSectionType
	 *            the s section type
	 * @return the object
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#setSection(java.lang.Object, java.lang.String)
	 */
	public synchronized Object setSection(Object oRootSection, String sSectionType)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "setSection()";

		Node nRoot = null;
		Node nValue = null;

		// rootSection can be null if the first section is requested
		if (oRootSection != null) {
			if (oRootSection instanceof Element)
				nRoot = (Element) oRootSection;
			else {
				sbError.append("Root section invalid, is not of type: Element");
				_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
		}
		else
			nRoot = _oDomDocument.getDocumentElement();

		if (sSectionType != null)
			// create new section
			nValue = _oDomDocument.createElement(sSectionType);
		else {
			sbError.append("No section Type supplied.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		try {
			nRoot.appendChild(nValue);
			return nValue;

		}
		catch (DOMException e) {
			sbError.append("Error setting section: ");
			sbError.append(sSectionType);
			sbError.append(": ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		catch (Exception e) {
			sbError.append("Error setting section: ");
			sbError.append(sSectionType);
			sbError.append(": ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Retrieves the value of the config parameter from the config section that is supplied. <br>
	 * <br>
	 * 
	 * @param oSection
	 *            the o section
	 * @param sConfigItem
	 *            the s config item
	 * @return the param
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#getParam(java.lang.Object, java.lang.String)
	 */
	public synchronized String getParam(Object oSection, String sConfigItem)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "getParam()";
		String sId = null;

		String sValue = null;
		Node nAttribute = null;
		Node nSection = null;
		Node nTemp = null;
		Node nTemp2 = null;
		NodeList nlSubNodes = null;
		NodeList nlChilds = null;
		NamedNodeMap nnmAttributes = null;

		if (oSection == null) {
			sbError.append("Supplied section is null.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}
		if (!(oSection instanceof Node)) {
			sbError.append("Supplied section is not of type Node. Looking for:"+sConfigItem);
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}

		try {
			// first check all attributes for the specific sConfigItem
			nSection = (Node) oSection;

			// get all attributes
			if (nSection.hasAttributes()) {
				nnmAttributes = nSection.getAttributes();
				if (nnmAttributes != null) {
					nAttribute = nnmAttributes.getNamedItem(sConfigItem);
					Node nId = nnmAttributes.getNamedItem("id");
					if (nId != null)
						sId = nId.getNodeValue();
					if (nAttribute != null) { // Requested param is an attribute
						sValue = nAttribute.getNodeValue();
					}
				}
			}

			// check sub tagnames for the specific sConfigItem
			if (sValue == null) { // Check if param = sub node
				nlChilds = nSection.getChildNodes();
				for (int i = 0; i < nlChilds.getLength(); i++) {
					nTemp = nlChilds.item(i);
					// check if tagname = sConfigItem
					if (nTemp != null && nTemp.getNodeName().equalsIgnoreCase(sConfigItem)) {
						nlSubNodes = nTemp.getChildNodes();

						if (nlSubNodes.getLength() == 0) { // Node contains no data
							if (sValue == null)
								sValue = new String("");
						}
						else {
							for (int xI = 0; xI < nlSubNodes.getLength(); xI++) {
								nTemp2 = nlSubNodes.item(xI);
								if (nTemp2 != null && nTemp2.getNodeType() == Node.TEXT_NODE) {
									sValue = nTemp2.getNodeValue();
									// Handle empty parameter value (tom)
									if (sValue == null)
										sValue = new String("");
								}
							}
						}
					}
				}
			}
		}
		catch (Exception e) {
			sbError.append("NO parameter: ").append(sConfigItem);
			if (sId != null)
				sbError.append(", id=").append(sId);
			_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		if (sValue == null) {
			sbError.append("NO parameter: ").append(sConfigItem);
			if (sId != null)
				sbError.append(", id=").append(sId);
			_oSystemLogger.log(Level.FINEST, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}
		return sValue;
	}

	/**
	 * Puts a new parameter into the given section like <param>value </param>. <br>
	 * <br>
	 * 
	 * @param oRootSection
	 *            the o root section
	 * @param sConfigItem
	 *            the s config item
	 * @param sConfigValue
	 *            the s config value
	 * @param bMandatory
	 *            the b mandatory
	 * @return true, if sets the param
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#setParam(java.lang.Object, java.lang.String,
	 *      java.lang.String, boolean)
	 */
	public synchronized boolean setParam(Object oRootSection, String sConfigItem, String sConfigValue,
			boolean bMandatory)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "setParam()";

		boolean bReturn = false;

		if (oRootSection == null) {
			sbError.append("Supplied oRootSection is null.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}

		if (!(oRootSection instanceof Element)) {
			sbError.append("Supplied oRootSection is not a Element.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}

		if (sConfigItem == null) {
			sbError.append("Supplied sConfigItem is null.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}

		if (sConfigValue == null) {
			sbError.append("Supplied sConfigValue is null.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}

		try {
			if (bMandatory) {
				setParamAsAtribute(oRootSection, sConfigItem, sConfigValue);
				bReturn = true;
			}
			else {
				setParamAsChild(oRootSection, sConfigItem, sConfigValue);
				bReturn = true;
			}
		}
		catch (DOMException e) {
			sbError.append("XML DOM Error while setting parameter: ");
			sbError.append(sConfigItem);
			sbError.append(": ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		catch (Exception e) {
			sbError.append("Error while setting parameter: ");
			sbError.append(sConfigItem);
			sbError.append(": ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return bReturn;
	}

	/**
	 * Resolve the next section (XML tag) which has the same type as the supplied section, it will be the follow-up tag.
	 * The sections must be located in the same root section (root tag). It returns the next section or null if their is
	 * no next section. <br>
	 * <br>
	 * 
	 * @param oSection
	 *            the o section
	 * @return the next section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#getNextSection(java.lang.Object)
	 */
	public synchronized Object getNextSection(Object oSection)
		throws ASelectConfigException
	{
		String sMethod = "getNextSection()";

		Node nNext = null;

		if (oSection == null) {
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, "Supplied section is null.");
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		nNext = (Node) oSection;
		String sRequestedNodeName = nNext.getNodeName();
		nNext = nNext.getNextSibling();
		while (nNext != null) {
			if (nNext.getNodeType() == Node.ELEMENT_NODE && nNext.getNodeName().equals(sRequestedNodeName))
				break;
			nNext = nNext.getNextSibling();
		}
		return nNext;
	}

	/**
	 * Removes the section (XML tag) from the supplied root section which has the type that is supplied. <br>
	 * <br>
	 * 
	 * @param oRootSection
	 *            the o root section
	 * @param sSectionType
	 *            the s section type
	 * @return true, if removes the section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#removeSection(java.lang.Object, java.lang.String)
	 */
	public synchronized boolean removeSection(Object oRootSection, String sSectionType)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "removeSection()";

		Node nSection = null;
		Node nRoot = null;
		boolean bRet = false;

		try {
			// rootSection can be null if the first section is requested
			if (oRootSection != null)
				if (nRoot instanceof Element)
					nRoot = (Element) oRootSection;
				else {
					_oSystemLogger.log(Level.WARNING, MODULE, sMethod, "Root section invalid, is not of type: Element");
					throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}
			else
				nRoot = _oDomDocument.getDocumentElement();

			if (sSectionType == null) {
				_oSystemLogger.log(Level.WARNING, MODULE, sMethod, "Section type is null.");
				throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			nSection = getSubSection(nRoot, sSectionType);
			if (nSection == null) {
				sbError.append("Section not found. Root: '");
				sbError.append(nRoot);
				sbError.append("' section type: '");
				sbError.append(sSectionType);
				sbError.append("'.");
				_oSystemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
				throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
			}

			// remove section
			nRoot.removeChild(nSection);
			bRet = true;
		}
		catch (ASelectConfigException e) {
			throw e;
		}
		catch (DOMException e) {
			sbError.append("XML DOM error while removing section '");
			sbError.append(sSectionType);
			sbError.append("': \"");
			sbError.append(e.getMessage());
			sbError.append("\"");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_READ, e);

		}
		catch (Exception e) {
			sbError.append("Error removing section: ");
			sbError.append(sSectionType);
			sbError.append(": ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return bRet;
	}

	/**
	 * Removes the section (XML tag) from the supplied root section which has the type and the ID that is supplied. The
	 * ID must be an XML attribute like: <section id="id"> should be supplied as id=id <br>
	 * <br>
	 * 
	 * @param oRootSection
	 *            the o root section
	 * @param sSectionType
	 *            the s section type
	 * @param sSectionID
	 *            the s section id
	 * @return true, if removes the section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#removeSection(java.lang.Object, java.lang.String,
	 *      java.lang.String)
	 */
	public synchronized boolean removeSection(Object oRootSection, String sSectionType, String sSectionID)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "removeSection()";

		Node nSection = null;
		Node nRoot = null;
		boolean bRet = false;

		try {
			if (oRootSection != null)
				if (nRoot instanceof Element)
					nRoot = (Element) oRootSection;
				else {
					sbError.append("Root section invalid, is not of type: Element");
					_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
					throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}
			else
				nRoot = _oDomDocument.getDocumentElement();

			nSection = this.getSubSectionByID(nRoot, sSectionType, sSectionID);

			if (nSection == null) {
				sbError.append("Section not found. Root: '");
				sbError.append(nRoot);
				sbError.append("' section type: '");
				sbError.append(sSectionType);
				sbError.append("' section id: '");
				sbError.append("'.");
				_oSystemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
				throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
			}

			// remove section
			nRoot.removeChild(nSection);
			bRet = true;
		}
		catch (ASelectConfigException e) {
			throw e;
		}
		catch (DOMException e) {
			sbError.append("XML DOM error while removing section: sSectionType=");
			sbError.append(sSectionType);
			sbError.append(", sSectionID=");
			sbError.append(sSectionID);
			sbError.append(": ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		catch (Exception e) {
			sbError.append("Error removing section: sSectionType=");
			sbError.append(sSectionType);
			sbError.append(", sSectionID=");
			sbError.append(sSectionID);
			sbError.append(": ");
			sbError.append(e.getMessage());
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return bRet;
	}

	/**
	 * Saves the configuration to the physical storage from which it is retrieved. It supports file and JDBC database. <br>
	 * <br>
	 * 
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#saveConfig()
	 */
	public synchronized void saveConfig()
		throws ASelectConfigException
	{
		String sMethod = "saveConfig()";

		// add date to configuration
		boolean bFound = false;
		Date dNow = null;
		StringBuffer sbComment = null;
		Element elRoot = null;
		Node nCurrent = null;
		Node nComment = null;
		OutputStream oStream = null;
		Statement oStatement = null;
		String sValue = null;

		dNow = new Date(System.currentTimeMillis());

		sbComment = new StringBuffer(" Configuration changes saved on ");
		sbComment.append(DateFormat.getDateInstance().format(dNow));
		sbComment.append(". ");

		elRoot = _oDomDocument.getDocumentElement();
		nCurrent = elRoot.getFirstChild();
		while (!bFound && nCurrent != null) // all elements
		{
			if (nCurrent.getNodeType() == Node.COMMENT_NODE) {
				// check if it's a "save changes" comment
				sValue = nCurrent.getNodeValue();
				if (sValue.trim().startsWith("Configuration changes saved on")) {
					// overwrite message
					nCurrent.setNodeValue(sbComment.toString());
					bFound = true;
				}
			}
			nCurrent = nCurrent.getNextSibling();
		}
		if (!bFound) // no comment found: adding new
		{
			// create new comment node
			nComment = _oDomDocument.createComment(sbComment.toString());
			// insert comment before first node
			elRoot.insertBefore(nComment, elRoot.getFirstChild());
		}

		if (_fConfig == null) // the confighandler uses raw data
		{
			oStream = new ByteArrayOutputStream();
			serializeTo(oStream);

			StringBuffer sbQuery = new StringBuffer("UPDATE ");
			sbQuery.append(_sDatabaseTableName).append(" SET ");
			sbQuery.append(DATA_COLUMN).append("='");
			sbQuery.append(oStream.toString()).append("' WHERE ");
			sbQuery.append(ID_COLUMN).append("='");
			sbQuery.append(_fConfig).append("'");
			try {
				oStream.close();
			}
			catch (IOException eIO) {
				_oSystemLogger.log(Level.WARNING, MODULE, sMethod, "Error closing XML outputstream", eIO);
				throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_CLOSE, eIO);
			}

			try {
				oStatement = _sdcConnector.connect();
				if (oStatement != null) {
					_sdcConnector.executeUpdate(oStatement, sbQuery.toString());
					_sdcConnector.disconnect(oStatement);
				}
				else {
					_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, "No SQL statement could be created.");
					throw new ASelectConfigException(Errors.ERROR_ASELECT_IO);
				}
			}
			catch (ASelectDatabaseException e) {
				_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Database error while writing XML configuration", e);
				throw new ASelectConfigException(Errors.ERROR_ASELECT_IO, e);
			}
		}
		else {
			try {
				oStream = new FileOutputStream(_fConfig);
				serializeTo(oStream);
				oStream.close();
			}
			catch (FileNotFoundException eFNF) {
				StringBuffer sbError = new StringBuffer("Error while opening XML config file: \"");
				sbError.append(_fConfig.getPath()).append("\"");
				_oSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), eFNF);

				throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN, eFNF);
			}
			catch (IOException eIO) {
				StringBuffer sbError = new StringBuffer("Error while closing XML config file: \"");
				sbError.append(_fConfig.getPath()).append("\"");
				_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), eIO);
				throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_CLOSE, eIO);
			}

		}
	}

	/**
	 * Import configuration items into this configuration. <br>
	 * <br>
	 * 
	 * @param configFile
	 *            the config file
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @see org.aselect.system.configmanager.IConfigHandler#importConfig(java.io.File)
	 * @deprecated All config should be stored in only one config file.
	 */
	public synchronized void importConfig(File configFile)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "importConfig()";

		try {
			Document _oNewDomDocument = parseXML(configFile);
			importConfig(_oNewDomDocument);
		}
		catch (ParserConfigurationException e) {
			sbError.append("Wrong parse configuration, while parsing the XML config file.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		catch (SAXException e) {
			sbError.append("Error while SAX parsing the XML config file.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN);
		}
		catch (IOException e) {
			sbError.append("Error while opening XML config file.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_CANT_OPEN);
		}

	}

	/**
	 * Adds a parameter as an XML attribute. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Adds a parameter as an XML attribute <br>
	 * for example: &lt;section parameter="value"&gt; <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * Has been made Threadsafe by making it synchronized <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <i>oSection </i> must be of type <code>Element</code> and not <code>null
	 * </code>.<br>
	 * - <i>sConfigItem </i> may not be <code>null</code><br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oSection
	 *            The section to which the config param will be added
	 * @param sConfigItem
	 *            The name of the config parameter
	 * @param sConfigValue
	 *            The value of the config parameter
	 * @throws DOMException
	 *             If setting fails.
	 */
	private synchronized void setParamAsAtribute(Object oSection, String sConfigItem, String sConfigValue)
		throws DOMException
	{
		Element elSection = (Element) oSection;
		elSection.setAttribute(sConfigItem, sConfigValue);
	}

	/**
	 * Adds a parameter to the given section <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Will add a new XML tag as a child of the given XML tag ( <i>oSection </i>), with the given name ( <i>sConfigItem
	 * </i>) and value ( <i>sConfigValue </i>). For example: <br>
	 * &lt;section&gt; <br>
	 * &nbsp;&nbsp;&nbsp;&lt;parameter&gt;value&lt;/parameter&gt; <br>
	 * &lt;/section&gt; <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * Is made Threadsafe by making it synchronized. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <i>oSection </i> must be of type <code>Element</code> and may not be <code>null</code>.<br>
	 * - <i>sConfigItem </i> may not be <code>null</code>.<br>
	 * - <i>sConfigValue </i> may not be <code>null</code>.<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The updated <code>Element</code> oSection will contain the new XML tag. <br>
	 * 
	 * @param oSection
	 *            The section (XML tag) to which the parameter must be added as child.
	 * @param sConfigItem
	 *            The name of the config parameter (XML tag name)
	 * @param sConfigValue
	 *            The value of the config paramter
	 * @throws DOMException
	 *             If setting fails.
	 */
	private synchronized void setParamAsChild(Object oSection, String sConfigItem, String sConfigValue)
		throws DOMException
	{
		boolean bFound = false;
		Element elSection = null;
		NodeList nlChilds = null;
		Node nTemp = null;
		Node nTemp2 = null;
		NodeList nlSubNodes = null;
		Node nValue = null;
		Element nConfigItem = null;

		elSection = (Element) oSection;

		// check if child allready exists
		nlChilds = elSection.getChildNodes();
		for (int i = 0; i < nlChilds.getLength(); i++) {
			nTemp = nlChilds.item(i);
			// check if tagname = configItem
			if (nTemp != null && nTemp.getNodeName().equalsIgnoreCase(sConfigItem)) {
				nlSubNodes = nTemp.getChildNodes();
				for (int iIter2 = 0; iIter2 < nlSubNodes.getLength(); iIter2++) {
					nTemp2 = nlSubNodes.item(iIter2);
					if (nTemp2.getNodeType() == Node.TEXT_NODE) {
						nTemp2.setNodeValue(sConfigValue);
						bFound = true;
					}
				}
			}
		}

		if (!bFound) // add new child
		{
			// create new child
			nValue = _oDomDocument.createTextNode(sConfigValue);
			nConfigItem = _oDomDocument.createElement(sConfigItem);
			nConfigItem.appendChild(nValue);

			// append child
			elSection.appendChild(nConfigItem);
		}
	}

	/**
	 * Serializes the XML data to the given <code>OutputStream</code>. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Uses indent and line width to serialze the XML DOM Document to the <code>OutputStream</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The <code>osOutput</code> may not be closed. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <i>osOutput </i> may not be <code>null</code><br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The XML DOM Document is written to the given <code>OutputStream</code>. <br>
	 * 
	 * @param osOutput
	 *            The <code>OutputStream</code> to which the XML DOM Object will be written.
	 * @throws ASelectConfigException
	 *             If serialization fails
	 */
	private void serializeTo(OutputStream osOutput)
		throws ASelectConfigException
	{
		String sMethod = "serializeTo()";

		try {
			// create output format which uses new lines and tabs
			OutputFormat oFormat = new OutputFormat(_oDomDocument);
			oFormat.setIndenting(true);
			oFormat.setLineWidth(80);

			// Create serializer
			XMLSerializer oSerializer = new XMLSerializer(osOutput, oFormat);
			oSerializer.setNamespaces(true);

			// serialize outputmessage to the writer object
			oSerializer.serialize(_oDomDocument.getDocumentElement());
		}
		catch (IOException eIO) // I/O error while serializing, should not occur
		{
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, "Error serializing XML data.", eIO);
			throw new ASelectConfigException(Errors.ERROR_ASELECT_IO, eIO);
		}
	}

	/**
	 * Parses the given <code>File</code> to an XML DOM Object. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Will parse the XML configuration to an XML DOM Object and checks if the file is correct XML. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <i>fConfig </i> may not be <code>null</code><br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param fConfig
	 *            <code>File</code> object containing XML information.
	 * @return The XML DOM Object containing the XML information from the given <code>File</code>.
	 * @throws ParserConfigurationException
	 *             If parsing configuration is invalid.
	 * @throws SAXException
	 *             If parsing fails
	 * @throws IOException
	 *             If an error occurs during I/O
	 */
	private Document parseXML(File fConfig)
		throws ParserConfigurationException, SAXException, IOException
	{
		// create DocumentBuilderFactory to parse config file.
		DocumentBuilderFactory oDocumentBuilderFactory = DocumentBuilderFactory.newInstance();

		// Create parser
		DocumentBuilder oDocumentBuilder = oDocumentBuilderFactory.newDocumentBuilder();

		// parse
		return oDocumentBuilder.parse(fConfig);
	}

	/**
	 * Parses the given <code>byte[]</code> to an XML DOM Object. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Will parse the XML information to an XML DOM Object and checks if the given byte array is correct XML. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * baData may not be <code>null</code><br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param baData
	 *            byte array containing XML data
	 * @return An XML DOM document containing the parsed data from the given byte array
	 * @throws ParserConfigurationException
	 *             If parsing configuration is invalid.
	 * @throws SAXException
	 *             If parsing fails
	 * @throws IOException
	 *             If an error occurs during I/O
	 */
	private Document parseXML(byte[] baData)
		throws ParserConfigurationException, SAXException, IOException
	{
		// create DocumentBuilderFactory to parse config file.
		DocumentBuilderFactory oDocumentBuilderFactory = DocumentBuilderFactory.newInstance();

		// Create parser
		DocumentBuilder oDocumentBuilder = oDocumentBuilderFactory.newDocumentBuilder();

		ByteArrayInputStream oByteArrayInputStream = new ByteArrayInputStream(baData);

		InputSource oInputSource = new InputSource(oByteArrayInputStream);

		// parse
		return oDocumentBuilder.parse(oInputSource);
	}

	/**
	 * Retrieve an XML tag with given <code>sSectionID</code> as an attribute. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The <i>nRootSection </i> will be searched for an XML tag with the given type and id. The found XML tag will be
	 * returned. For example: <br>
	 * &lt;type id_key="id_value"&gt; <br>
	 * &lt;/type&gt; <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param nRootSection
	 *            The XML tag that is searched for the XML sub tag specified by the given ID.
	 * @param sSectionType
	 *            The name of the XML tag that is searched for.
	 * @param sSectionID
	 *            The XML attribute name and value as [name]=[value] without surrounding quotes.
	 * @return A sub section (<code>Node</code>) from the config file with a specific attribute
	 * @throws ASelectConfigException
	 *             If retrieving fails
	 */
	private Node getSubSectionByID(Node nRootSection, String sSectionType, String sSectionID)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "getSubSectionByID()";

		// split sectionID (id=ticket) to key/value pair
		Element elReturn = null;
		Element elCurrent = null;
		Node nCurrent = null;
		String sID[] = null;

		if (nRootSection == null) {
			sbError.append("Supplied nRootSection is null.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}

		if (sSectionType == null) {
			sbError.append("Supplied sSectionType is null.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}

		sID = sSectionID.split("=");
		if (sID.length != 2) {
			sbError.append("sSectionID isn't correct (must contain only one '='): ");
			sbError.append(sID);
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}

		String sKey = sID[0];
		String sValue = sID[1];

		// get all childnodes
		NodeList nlChilds = nRootSection.getChildNodes();
		for (int i = 0; i < nlChilds.getLength(); i++) {
			nCurrent = nlChilds.item(i);
			if (nCurrent.getNodeType() == Node.ELEMENT_NODE) {
				elCurrent = (Element) nCurrent;
				if (elCurrent.getNodeName().equalsIgnoreCase(sSectionType) && elCurrent.hasAttributes()) {
					// check if node has the strKey attribute and check if
					// its value = strvalue
					if (elCurrent.getAttribute(sKey).equalsIgnoreCase(sValue)) {
						elReturn = elCurrent;
						i = nlChilds.getLength();
					}
				}
			}
			else {
				// nothing to do, because it are
				// only Text Nodes (white spaces or unsupported text between
				// tags)
			}
		}

		return elReturn;
	}

	/**
	 * Retrieve an XML tag of the given type. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The <i>nRootSection </i> will be searched for an XML tag of the given type (tag name is type name). The found XML
	 * tag will be returned. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param nRootSection
	 *            The XML tag that is searched for the XML sub tag specified by the given type (tag name).
	 * @param sSectionType
	 *            The name of the XML tag that is searched for.
	 * @return A sub section from the given root section (XML Element)
	 * @throws ASelectConfigException
	 *             If retrieving fails
	 */
	private Node getSubSection(Node nRootSection, String sSectionType)
		throws ASelectConfigException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "getSubSection()";

		Element elTemp = null;
		Node nTemp = null;

		if (nRootSection == null) {
			sbError.append("Supplied nRootSection is null.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}

		if (nRootSection.getNodeType() != Node.ELEMENT_NODE) {
			sbError.append("The supplied root section has an incorrect type: ");
			sbError.append(nRootSection.getNodeType());
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		if (sSectionType == null) {
			sbError.append("Supplied sSectionType is null.");
			_oSystemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
			throw new ASelectConfigException(Errors.ERROR_ASELECT_NOT_FOUND);
		}

		elTemp = (Element) nRootSection;
		if (elTemp.hasChildNodes()) {
			nTemp = elTemp.getFirstChild();
			while (nTemp != null) {
				if (nTemp.getNodeType() == Node.ELEMENT_NODE && nTemp.getNodeName().equals(sSectionType)) {
					return nTemp;
				}
				nTemp = nTemp.getNextSibling();
			}
		}
		return null;
	}

	/**
	 * Adds the given XML document to the existing XML document. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Adds the given XML document to the XML document known within this <code>XMLConfigHandler</code> Object. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - The <code>XMLConfigHandler.init()</code> must be succesfully called before using this method. The class
	 * variable <i>_oDomDocument </i> may not be <code>null</code>.<br>
	 * - The given XML document must contain a root tagname that is unique within the XML DOM document in
	 * <i>oDomDocument </i>. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The <i>_oDomDocument </i> class variable contains the given XML document at the end of the already present
	 * document. <br>
	 * 
	 * @param docNew
	 *            The new XML document that must be added to the existing
	 */
	private void importConfig(Document docNew)
	{
		NodeList nlChilds = docNew.getDocumentElement().getChildNodes();
		for (int i = 0; i < nlChilds.getLength(); i++) {
			Node nTemp = nlChilds.item(i);
			if (nTemp.getNodeType() == Node.ELEMENT_NODE) {
				// appends every sub element of the document root element of
				// the new config file to the <xml> tag of the initialized
				// config file
				_oDomDocument.getDocumentElement().appendChild(_oDomDocument.importNode(nTemp, true));
			}
		}
	}

}