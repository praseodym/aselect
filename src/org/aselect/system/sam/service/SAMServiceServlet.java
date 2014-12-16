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
 * $Id: SAMServiceServlet.java,v 1.17 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: SAMServiceServlet.java,v $
 * Revision 1.17  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.16  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.15  2005/09/08 07:08:19  erwin
 * Improved error handling (bug #110)
 *
 * Revision 1.14  2005/04/14 08:43:47  tom
 * Removed old logging statements
 *
 * Revision 1.13  2005/03/31 10:03:08  erwin
 * ".*" wildcards are now supported.
 *
 * Revision 1.12  2005/03/30 12:03:58  martijn
 * changed wildcard handling in processRequest()
 *
 * Revision 1.11  2005/03/04 12:03:26  tom
 * SAMService configuration now appends html/ to the working dir
 *
 * Revision 1.10  2005/03/02 15:12:07  martijn
 * bugfix setContentType("text/html") is now set when showing the SAMService status page
 *
 * Revision 1.9  2005/03/01 15:29:25  erwin
 * Fixed Javadoc warnings
 *
 * Revision 1.8  2005/02/22 12:03:43  martijn
 * moved org.aselect.utils to org.aselect.system.utils
 *
 * Revision 1.7  2005/02/22 10:01:27  martijn
 * removed unused vars
 *
 * Revision 1.6  2005/02/21 16:28:53  martijn
 * added javadoc
 *
 * Revision 1.5  2005/02/10 16:10:25  erwin
 * Refactor interface names (added 'I')
 *
 * Revision 1.4  2005/02/10 14:11:25  martijn
 * Removed HTMLHandler class and replaced it's functionality by html form support.
 *
 * Revision 1.3  2005/02/09 15:31:29  martijn
 * changed all variable names to naming convention
 *
 * Revision 1.2  2005/02/09 14:32:33  martijn
 * changed all variable names to naming convention
 *
 */

package org.aselect.system.sam.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.system.communication.server.Communicator;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.communication.server.IMessageCreatorInterface;
import org.aselect.system.communication.server.IOutputMessage;
import org.aselect.system.communication.server.IProtocolRequest;
import org.aselect.system.communication.server.IProtocolResponse;
import org.aselect.system.communication.server.ServletRequestWrapper;
import org.aselect.system.communication.server.ServletResponseWrapper;
import org.aselect.system.communication.server.raw.RawMessageCreator;
import org.aselect.system.communication.server.soap11.SOAP11MessageCreator;
import org.aselect.system.communication.server.soap12.SOAP12MessageCreator;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Utils;

/**
 * Abstract class for the SAM Service servlets like in A-Select Server and A-Select AuthSPServer. <br>
 * <br>
 * <b>Description: </b> <br>
 * The SAM Service Abstract class, that contains basic information <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public abstract class SAMServiceServlet extends HttpServlet
{
	/**
	 * Contains all known OID's, has to be expanded with specific OID's.
	 */
	protected HashMap _htOIDs;
	/**
	 * The directory that contains the html templates: samservice.html and samservice_status.html.
	 */
	protected String _sWorkingDir;
	/**
	 * Contains the samservice.html HTML template if it was found during initialize.
	 */
	protected String _sSAMServiceForm;
	/**
	 * Contains the samservice_status.html HTML template if it was found during initialize.
	 */
	protected String _sSAMServiceStatusForm;

	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "SAMServiceServlet";

	/**
	 * The url to the context of this servlet.
	 */
	private String _sContextUrl;

	/**
	 * The initialize method for initializing the SAM Service. <b>Description: </b> <br>
	 * The following templates will be loaded:<br>
	 * - samservice.html <br>
	 * - - samservice_status.html <br>
	 * The <code>_htOIDs</code> will be filled with the default OID's. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <b>Preconditions: </b> <br>
	 * It needs an working_dir parameter in the <i>web.xml</i> containing the directory where the HTML template for the
	 * SAM Service can be found. <br>
	 * <b>Postconditions: </b> <br>
	 * - <br>
	 * 
	 * @param oServletConfig
	 *            the o servlet config
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	@Override
	public void init(ServletConfig oServletConfig)
	throws ServletException
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "init";

		try {
			super.init(oServletConfig);

			// Get: workingdir/html/samservice.html
			// and: workingdir/html/samservice_status.html
			//
			// NOTE: we're not using Utils.loadHTMLTemplate()
			//
			_sWorkingDir = oServletConfig.getInitParameter("working_dir");
			if (_sWorkingDir == null) {
				throw new Exception("No working_dir init-param found in web.xml");
			}
			if (!_sWorkingDir.endsWith(File.separator))
				_sWorkingDir += File.separator;
			_sWorkingDir += "html" + File.separator;
			
			File fWorkingDir = new File(_sWorkingDir);
			if (!fWorkingDir.exists()) {
				StringBuffer sbTemp = new StringBuffer("No valid template directory found: ");
				sbTemp.append(_sWorkingDir);
				throw new Exception(sbTemp.toString());
			}

			String sSAMServiceForm = _sWorkingDir + "samservice.html";
			File fSAMService = new File(sSAMServiceForm);
			if (!fSAMService.exists()) {
				StringBuffer sbTemp = new StringBuffer("No valid samservice template directory found: ");
				sbTemp.append(sSAMServiceForm);
				throw new Exception(sbTemp.toString());
			}
			// loading the html template: samservice.html
			_sSAMServiceForm = loadTemplateFile(sSAMServiceForm);

			String sSAMServiceStatusForm = _sWorkingDir + "samservice_status.html";
			File fSAMServiceStatus = new File(sSAMServiceStatusForm);
			if (!fSAMServiceStatus.exists()) {
				StringBuffer sbTemp = new StringBuffer("No valid samservice status template directory found: ");
				sbTemp.append(sSAMServiceStatusForm);
				throw new Exception(sbTemp.toString());
			}
			// loading the html template: samservice_status.html
			_sSAMServiceStatusForm = loadTemplateFile(sSAMServiceStatusForm);

			this.getServletContext().setAttribute("inittime", new Long(System.currentTimeMillis()));

			// putting all known OID's with their names from the SAMConstants in
			// the _htOIDs
			_htOIDs = new HashMap();
			_htOIDs.put(SAMConstants.OID_SYSDESCR, SAMConstants.NAME_SYSDESCR);
			_htOIDs.put(SAMConstants.OID_VERSION, SAMConstants.NAME_VERSION);
			_htOIDs.put(SAMConstants.OID_OPERATIONAL, SAMConstants.NAME_OPERATIONAL);
			_htOIDs.put(SAMConstants.OID_UPTIME, SAMConstants.NAME_UPTIME);
			_htOIDs.put(SAMConstants.OID_LOAD, SAMConstants.NAME_LOAD);
			_htOIDs.put(SAMConstants.OID_WWWDESCR, SAMConstants.NAME_WWWDESCR);
			_htOIDs.put(SAMConstants.OID_CPUS, SAMConstants.NAME_CPUS);
			_htOIDs.put(SAMConstants.OID_FREEMEM, SAMConstants.NAME_FREEMEM);
			_htOIDs.put(SAMConstants.OID_MAXMEM, SAMConstants.NAME_MAXMEM);
			_htOIDs.put(SAMConstants.OID_TOTALMEM, SAMConstants.NAME_TOTALMEM);

		}
		catch (Exception e) {
			sbError.append(e.getMessage());
			getSystemLogger().log(Level.SEVERE, MODULE, sMethod, sbError.toString());
			throw new ServletException(sbError.toString(), e);
		}
	}

	/**
	 * Calls the default destroy method of the super class. <br>
	 * 
	 * @see javax.servlet.GenericServlet#destroy()
	 */
	@Override
	public void destroy()
	{
		super.destroy();
	}

	/**
	 * Method that enforces to set the <code>SystemLogger</code> by the sub class. <br>
	 * <b>Description: </b> <br>
	 * The SystemLogger that is returned will be used to send logging information to.<br>
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
	 * @return the SystemLogger object
	 */
	protected abstract SystemLogger getSystemLogger();

	/**
	 * Used to retrieve all SAM information. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method should be overridden to supply all known the statistics. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * - <br>
	 * 
	 * @return <code>HashMap</code> that contains the OID (as key) and the OID value (as value).
	 */
	protected abstract HashMap getSAMInfo();

	/**
	 * Used to retrieve the URL of the context where this servlet is located. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The URL context that will be checked if it is up.<br>
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
	 * @return <code>String</code> representaion of the context URL of this servlet.
	 */
	protected String getContextUrl()
	{
		return _sContextUrl;
	}

	/**
	 * Used to check if the servlet is operational or not. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Checks if the servlet is <br>
	 * operational: 1 <br>
	 * or not operational: -1 <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <br>
	 * 
	 * @return <code>int<code> that represents if the servlet is operational (1)
	 * or not (-1).
	 */
	protected abstract int operational();

	/**
	 * Used to retrieve the system description. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Must be overidden by the sub class<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @return <code>String</code> that contains a description of the system.
	 */
	protected abstract String getSysDescr();

	/**
	 * Used to retrieve the version of the component. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Used to retrieve the A-Select component version.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * - <br>
	 * 
	 * @return <code>String</code> containing version information
	 */
	protected abstract String getVersion();

	/**
	 * Returns a <code>HashMap</code> containing common statistics. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The OID's of the common statistics can be found in the SAMConstants class . <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * - <br>
	 * 
	 * @return <code>HashMap</code> containing the OID (as key) and OID value (as value).
	 */
	protected HashMap getCommonSAMInfo()
	{
		HashMap htCommon = new HashMap();
		// sysDescr
		htCommon.put(SAMConstants.OID_SYSDESCR, getSysDescr());

		// version
		htCommon.put(SAMConstants.OID_VERSION, getVersion());

		// operational
		htCommon.put(SAMConstants.OID_OPERATIONAL, "" + operational());

		// uptime
		Long longInitTime = (Long) this.getServletContext().getAttribute("inittime");
		long lTime = (System.currentTimeMillis() - longInitTime.longValue());
		long lDay = lTime / (24 * 3600000);
		long lHr = (lTime % (24 * 3600000)) / 3600000;
		long lMin = (lTime % 3600000) / 60000;
		long lSec = ((lTime % 3600000) % 60000) / 1000;

		StringBuffer sbTemporary = new StringBuffer();
		sbTemporary.append(lDay);
		sbTemporary.append(":");
		sbTemporary.append(lHr);
		sbTemporary.append(":");
		sbTemporary.append(lMin);
		sbTemporary.append(":");
		sbTemporary.append(lSec);
		htCommon.put(SAMConstants.OID_UPTIME, sbTemporary.toString());

		// cpu load
		htCommon.put(SAMConstants.OID_LOAD, "-1");

		// wwwDescr
		htCommon.put(SAMConstants.OID_WWWDESCR, this.getServletContext().getServerInfo());

		// cpus
		htCommon.put(SAMConstants.OID_CPUS, "" + Runtime.getRuntime().availableProcessors());

		// free mem
		htCommon.put(SAMConstants.OID_FREEMEM, "" + Runtime.getRuntime().freeMemory());

		// max mem
		htCommon.put(SAMConstants.OID_MAXMEM, "" + Runtime.getRuntime().maxMemory());

		// total mem
		htCommon.put(SAMConstants.OID_TOTALMEM, "" + Runtime.getRuntime().totalMemory());

		return htCommon;
	}

	/**
	 * Handles incoming HTTP GET and POST requests. <br>
	 * <br>
	 * Supports SOAP 1.1, SOAP 1.2 requests as a HTTP POST and supports HTTP GET with an empty query string to show the
	 * SAM statistics page or a RAW SAM request message. <br>
	 * 
	 * @param oHttpServletRequest
	 *            the o http servlet request
	 * @param oHttpServletResponse
	 *            the o http servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#service(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void service(HttpServletRequest oHttpServletRequest, HttpServletResponse oHttpServletResponse)
	throws ServletException, IOException
	{
		String sMethod = "service";
		IMessageCreatorInterface oMsgCreator = null;
		Communicator oCommunicator = null;

		try {
			setDisableCachingHttpHeaders(oHttpServletRequest, oHttpServletResponse);
			_sContextUrl = oHttpServletRequest.getContextPath();

			String sHTTPMethod = oHttpServletRequest.getMethod();
			if (sHTTPMethod.equalsIgnoreCase("GET"))// if request is a HTTP GET
			{
				String sQueryString = oHttpServletRequest.getQueryString();
				if (sQueryString != null) {
					if (sQueryString.equalsIgnoreCase("status")) {
						oHttpServletResponse.setContentType("text/html; charset=utf-8");
						// display status info
						showSAMStatusPage(oHttpServletResponse.getWriter(), getSAMInfo());
					}
					else {
						// SAM uses RawCommunication
						oMsgCreator = new RawMessageCreator(getSystemLogger());
						oCommunicator = new Communicator(oMsgCreator);
						processRequest(oCommunicator, oHttpServletRequest, oHttpServletResponse);
					}
				}
				else {
					oHttpServletResponse.setContentType("text/html; charset=utf-8");
					// display status refresh page
					String sTargetUrl = oHttpServletRequest.getRequestURL().append("?status").toString();
					showSAMPage(oHttpServletResponse.getWriter(), sTargetUrl);
				}
			}
			else if (sHTTPMethod.equalsIgnoreCase("POST"))// if request is a HTTP
			// POST
			{
				String sContentType = oHttpServletRequest.getContentType();
				String sRequestUrl = oHttpServletRequest.getRequestURL().toString();

				if (sContentType.indexOf("text/xml") > -1) {// must be a SOAP11 message
					oMsgCreator = new SOAP11MessageCreator(sRequestUrl, "Status", getSystemLogger());
				}
				else if (sContentType.indexOf("application/soap+xml") > -1) {// must be a SOAP12 message
					oMsgCreator = new SOAP12MessageCreator(sRequestUrl, "Status", getSystemLogger());
				}
				oCommunicator = new Communicator(oMsgCreator);
				processRequest(oCommunicator, oHttpServletRequest, oHttpServletResponse);
			}
		}
		catch (Exception e) {
			getSystemLogger().log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			if (!oHttpServletResponse.isCommitted()) {
				// send response if no headers have been written
				oHttpServletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal error");
			}
		}
	}

	/**
	 * Processes the incoming SAM request message. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Reads the incoming SAM message and responds with a response message.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <i>oCommunicator</i> != null<br>
	 * - <i>oHttpServletRequest</i> != null<br>
	 * - <i>oHttpServletResponse</i> != null<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * -<br>
	 * 
	 * @param oCommunicator
	 *            <code>Communicator</code> object that is used for reading and writing incoming and outgoing SAM
	 *            messages.
	 * @param oHttpServletRequest
	 *            <code>HttpServletRequest</code> the request stream containing the incoming message.
	 * @param oHttpServletResponse
	 *            <code>HttpServletResponse</code> is the response stream that will be used to write the response
	 *            message to.
	 */
	private void processRequest(Communicator oCommunicator, HttpServletRequest oHttpServletRequest,
			HttpServletResponse oHttpServletResponse)
	{
		StringBuffer sbError = new StringBuffer();
		String sMethod = "processRequest";

		IProtocolRequest protRequest = new ServletRequestWrapper(oHttpServletRequest);
		IProtocolResponse protResponse = new ServletResponseWrapper(oHttpServletResponse);

		try {
			if (!oCommunicator.init(protRequest, protResponse)) {
				throw new Exception("Could not parse SAM Request");
			}
			// read input message
			IInputMessage oInputMessage = oCommunicator.getInputMessage();

			String[] saRequested = oInputMessage.getArray("get");

			HashMap htInfo = getSAMInfo();
			HashMap htResult = new HashMap();
			for (int i = 0; i < saRequested.length; i++) {
				// check if wildcard, wildcards are endings with '.' or ".*"
				if (saRequested[i].endsWith(".*"))
					saRequested[i] = saRequested[i].substring(0, saRequested[i].length() - 1);
				if (saRequested[i].endsWith(".")) {
					Set keys = htInfo.keySet();
					for (Object s : keys) {
						String sKey = (String) s;
						// for (Enumeration enumInfo = htInfo.keys(); enumInfo.hasMoreElements();)
						// {
						// String sKey = (String)enumInfo.nextElement();
						// sKey strippen
						if (sKey.startsWith(saRequested[i]))
							htResult.put(sKey, htInfo.get(sKey));
					}
				}
				else {
					if (htInfo.containsKey(saRequested[i]))
						htResult.put(saRequested[i], htInfo.get(saRequested[i]));
				}
			}
			// write output message
			IOutputMessage oOutputMessage = oCommunicator.getOutputMessage();

			// convert resultTable to String[]
			int i = 0;
			int iCount = htResult.size();
			String[] saResult = new String[iCount];
			Set keys = htResult.keySet();
			for (Object s : keys) {
				String sKey = (String) s;
				// Enumeration enumKeys = htResult.keys();
				// for (int i = 0; i < iCount; i++)
				// {
				// String sKey = (String)enumKeys.nextElement();
				StringBuffer sbResult = new StringBuffer(sKey);
				sbResult.append("=");
				sbResult.append((String) htResult.get(sKey));
				saResult[i++] = sbResult.toString();
			}

			oOutputMessage.setParam("samversion", "1.0");
			oOutputMessage.setParam("get", saResult);
			if (!oCommunicator.send()) {
				throw new Exception("Could not send response message");
			}
		}
		catch (ASelectCommunicationException e) {
			sbError.append("could not read incomming message");
			getSystemLogger().log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
		}
		catch (Exception e) {
			sbError.append(e.getMessage());
			getSystemLogger().log(Level.WARNING, MODULE, sMethod, sbError.toString());
		}
	}

	/**
	 * Creates HTTP headers for disabling caching. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Sets the following HTTP headers:<br>
	 * If the request is HTTP 1.0:<br>
	 * - Pragma = no-cache<br>
	 * If the request is HTTP 1.1:<br>
	 * - Cache-Control = no-store, no-cache, must-revalidate<br>
	 * Set's always:<br>
	 * - Expires = -1<br>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <i>oHttpServletRequest</i> != null<br>
	 * - <i>oHttpServletResponse</i> != null<br>
	 * <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oHttpServletRequest
	 *            the HTTP(S) request.
	 * @param oHttpServletResponse
	 *            the HTTP(S) respons.
	 */
	private void setDisableCachingHttpHeaders(HttpServletRequest oHttpServletRequest,
			HttpServletResponse oHttpServletResponse)
	{
		// turn off caching
		if (oHttpServletRequest.getProtocol().equalsIgnoreCase("HTTP/1.0")) {
			oHttpServletResponse.setHeader("Pragma", "no-cache");
		}
		else if (oHttpServletRequest.getProtocol().equalsIgnoreCase("HTTP/1.1")) {
			oHttpServletResponse.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
		}
		oHttpServletResponse.setHeader("Expires", "-1"); // for proxy
	}

	/**
	 * Shows the SAM status page. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Fills the tags [oid.name] and [oid.value] template samservice_status.html and displays this page.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <i>pwOut</i> != null<br>
	 * - <i>htSAMInfo</i> != null<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * - <br>
	 * 
	 * @param pwOut
	 *            <code>PrintWriter</code> whereto the output message can be written
	 * @param htSAMInfo
	 *            <code>HashMap</code> containing the SAM information that will be displayed in the page.
	 */
	private void showSAMStatusPage(PrintWriter pwOut, HashMap htSAMInfo)
	{
		String sTemplate = _sSAMServiceStatusForm;

		Set keys = htSAMInfo.keySet();
		for (Object s : keys) {
			String sOID = (String) s;
			// Enumeration enumInfo = htSAMInfo.keys();
			// while (enumInfo.hasMoreElements())
			// {
			// String sOID = (String)enumInfo.nextElement();

			StringBuffer sbOIDName = new StringBuffer("[");
			sbOIDName.append(sOID);
			sbOIDName.append(".name]");
			String sOIDName = "";
			if (_htOIDs.containsKey(sOID))
				sOIDName = (String) _htOIDs.get(sOID);

			sTemplate = Utils.replaceString(sTemplate, sbOIDName.toString(), sOIDName);

			StringBuffer sbOIDValue = new StringBuffer("[");
			sbOIDValue.append(sOID);
			sbOIDValue.append(".value]");
			String sOIDValue = (String) htSAMInfo.get(sOID);
			sTemplate = Utils.replaceString(sTemplate, sbOIDValue.toString(), sOIDValue);
		}

		pwOut.println(sTemplate);
	}

	/**
	 * Shows the SAM page. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * The SAM page must contain an inline Frame that displays that contains the SAM status info. The URL to the SAM
	 * status info page will be located in the tag: [samservice_status_url]<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <i>pwOut</i> != null<br>
	 * - <i>sIFrameUrl</i> != null<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * - <br>
	 * 
	 * @param pwOut
	 *            <code>PrintWriter</code> whereto the output message can be written
	 * @param sIFrameUrl
	 *            <code>String</code> that contains the URL to the samservice.html (url of this servlet + ?status)
	 */
	private void showSAMPage(PrintWriter pwOut, String sIFrameUrl)
	{
		String sTemplate = _sSAMServiceForm;
		sTemplate = Utils.replaceString(sTemplate, "[samservice_status_url]", sIFrameUrl);

		pwOut.println(sTemplate);
	}

	/**
	 * Reads an HTML template from physical storage. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Reades the html template with name <i>sTemplateName</i> from the working directory line by line.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * - <i>sTemplateName</i> != null<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * - <br>
	 * 
	 * @param sTemplateName
	 *            the s template name
	 * @return a <code>String</code> containing the HTML template
	 * @throws Exception
	 *             if the template located in <i>sTemplateName</i> can't be accessed or read.
	 */
	private String loadTemplateFile(String sTemplateName)
	throws Exception
	{
		String sLine = null;
		String sLineSep = null;

		BufferedReader bfTemplate = new BufferedReader(new InputStreamReader(new FileInputStream(sTemplateName)));

		// to make the html human readable
		sLineSep = "\r\n";
		StringBuffer sbTemplate = new StringBuffer();
		while ((sLine = bfTemplate.readLine()) != null) {
			sbTemplate.append(sLine).append(sLineSep);
		}

		bfTemplate.close();
		return sbTemplate.toString();
	}

}