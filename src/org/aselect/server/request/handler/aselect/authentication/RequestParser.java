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
 * $Id: RequestParser.java,v 1.3 2006/05/03 10:10:18 tom Exp $ 
 * 
 * Changelog:
 * $Log: RequestParser.java,v $
 * Revision 1.3  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.2  2006/03/16 08:14:16  leon
 * changes for direct login
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.1  2006/01/13 08:40:26  martijn
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.12  2005/04/11 09:08:02  remco
 * removed request=forced_authenticate
 *
 * Revision 1.11  2005/04/05 11:31:00  martijn
 * added support for forced_authenticate
 *
 * Revision 1.10  2005/04/04 13:21:55  erwin
 * "create_tgt" is now an Application browser request.
 *
 * Revision 1.9  2005/04/01 14:25:59  peter
 * cross aselect redesign
 *
 * Revision 1.8  2005/03/15 15:00:50  martijn
 * renamed special authsp to privileged application
 *
 * Revision 1.7  2005/03/15 11:16:03  peter
 * "request=cross_login" added to parseRequest()
 *
 * Revision 1.6  2005/03/11 15:48:18  erwin
 * Moved getParameter() for SOAP compatibility.
 *
 * Revision 1.5  2005/03/11 14:01:08  tom
 * Added missing javadoc
 *
 * Revision 1.4  2005/03/09 17:33:34  remco
 * "cancel" request -> "error" request (with mandatory parameter "result_code")
 *
 * Revision 1.3  2005/03/08 09:51:42  remco
 * added javadoc
 *
 * Revision 1.2  2005/03/07 08:19:26  remco
 * resolved bug
 *
 * Revision 1.1  2005/03/04 14:59:43  remco
 * Initial version
 *
 */
package org.aselect.server.request.handler.aselect.authentication;

import javax.servlet.http.HttpServletRequest;

/**
 * The <code>RequestParser</code> determines the type, origin, and protocol of any request arriving at the A-Select
 * Server. The A-Select Server routes the request through its request handlers based on the classification made by the
 * <code>RequestParser</code>. Therefore, this class <i>must</i> be able to recognize <i>all</i> types of incoming
 * requests and classify them correctly. <br>
 * Use the <code>parseRequest()</code> method to parse an incoming request. After that, use the <code>getX()</code>
 * methods to determine the type of the request. <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - Allow tolk_fromdigid request to be recognized
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl)
 */
public class RequestParser
{
	private String _sMethod = null;
	private String _sRequest = null;
	private int _iRequestType = REQTYPE_UNKNOWN;
	private int _iRequestOrigin = ORIGIN_UNKNOWN;
	private int _iRequestProtocol = PROTOCOL_UNKNOWN;

	/**
	 * Unknown request type
	 */
	public static final int REQTYPE_UNKNOWN = -1;
	/**
	 * API call (server to server communication)
	 */
	public static final int REQTYPE_API_CALL = 0;
	/**
	 * Request via browser (client to server communication)
	 */
	public static final int REQTYPE_BROWSER = 1;

	/**
	 * Unknown origin
	 */
	public static final int ORIGIN_UNKNOWN = -1;
	/**
	 * Request originated from an application (or the Agent)
	 */
	public static final int ORIGIN_APPLICATION = 0;
	/**
	 * Request originated from an AuthSP (or application acting as an AuthSP)
	 */
	public static final int ORIGIN_AUTHSP = 1;
	/**
	 * Request originated from another A-Select Server (cross)
	 */
	public static final int ORIGIN_ASELECTSERVER = 2;
	/**
	 * Request originated directly from the user, or is a redirect from the application to the logout page
	 */
	public static final int ORIGIN_USER = 3;

	/**
	 * Unknown protocol
	 */
	public static final int PROTOCOL_UNKNOWN = -1;
	/**
	 * CGI protocol
	 */
	public static final int PROTOCOL_CGI = 0;
	/**
	 * Soap 1.1 Protocol
	 */
	public static final int PROTOCOL_SOAP11 = 1;
	/**
	 * Soap 1.2 Protocol
	 */
	public static final int PROTOCOL_SOAP12 = 2;

	/**
	 * Constructor. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Constructs a <code>RequestParser</code> object from a <code>HttpServletRequest</code> object. <br>
	 * <br>
	 * 
	 * @param request
	 *            the request
	 */
	public RequestParser(HttpServletRequest request) {
		parseRequest(request);
	}

	/**
	 * Retrieve the request type (one of REQTYPE_xxx). <br>
	 * <br>
	 * 
	 * @return the request type (REQTYPE_xxx).
	 */
	public int getRequestType()
	{
		return _iRequestType;
	}

	/**
	 * Retrieve the origin of the request (one of ORIGIN_xxx). <br>
	 * <br>
	 * 
	 * @return the request origin (ORIGIN_xxx).
	 */
	public int getRequestOrigin()
	{
		return _iRequestOrigin;
	}

	/**
	 * Retrieve protocol used to send the request (one of PROTOCOL_xxx). <br>
	 * <br>
	 * 
	 * @return the request protocol (PROTOCOL_xxx).
	 */
	public int getRequestProtocol()
	{
		return _iRequestProtocol;
	}

	/**
	 * Retrieve the value of the <code>request</code> parameter. If the <code>request</code> parameter is not present,
	 * an empty string (not <code>null</code>!) is returned. <br>
	 * <br>
	 * 
	 * @return The value of the <code>request</code> parameter as a <code>String</code>
	 */
	public String getRequest()
	{
		return _sRequest;
	}

	/**
	 * Determine the request type, origin, and protocol <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method parses the request to the point that it can determine the type (API call or user/browser request),
	 * origin (user, authsp, application, or remote a-select server), and the protocol (CGI or SOAP 1.1/1.2). The
	 * A-Select Server will route the request through its request handlers based on the output of this method.
	 * Therefore, this method must be able to recognize <i>all</i> types of requests that can arrive at the A-Select
	 * Server and classify them correctly. <br>
	 * After parsing a request, you can use the <code>getX()</code> methods to determine the request type. <br>
	 * 
	 * @param request
	 *            The incoming <code>HttpServletRequest</code>
	 */
	private void parseRequest(HttpServletRequest request)
	{
		_sMethod = request.getMethod();

		if (_sMethod.equalsIgnoreCase("GET")) {
			_iRequestProtocol = PROTOCOL_CGI;
			_sRequest = request.getParameter("request");
			if (_sRequest == null) {
				if (request.getParameter("authsp") != null)
					_iRequestOrigin = ORIGIN_AUTHSP;
				else if (request.getParameter("aselect_credentials") != null)
					_iRequestOrigin = ORIGIN_ASELECTSERVER;
				else
					// Unknown GET request, which shows the info or logout page
					_iRequestOrigin = ORIGIN_USER;
				_iRequestType = REQTYPE_BROWSER;
			}
			else {
				// API call from application (or cross A-Select Server)?
				if (_sRequest.equals("verify_credentials") || _sRequest.equals("authenticate")
						|| _sRequest.equals("upgrade_tgt")) {
					if (request.getParameter("local_organization") != null)
						_iRequestOrigin = ORIGIN_ASELECTSERVER;
					else
						_iRequestOrigin = ORIGIN_APPLICATION;

					_iRequestType = REQTYPE_API_CALL;
				}
				// 20090522, Bauke added: lets another process determine alive-ness of the server
				if (_sRequest.equals("alive")) {
					_iRequestOrigin = ORIGIN_APPLICATION; // actually any client
					_iRequestType = REQTYPE_BROWSER;
				}
				// API call from application (or Agent)?
				if (_sRequest.equals("kill_tgt") || _sRequest.equals("get_app_level")) {
					_iRequestOrigin = ORIGIN_APPLICATION;
					_iRequestType = REQTYPE_API_CALL;
				}
				else
				// Redirect from application?
				if (_sRequest.equals("login1")) {
					_iRequestOrigin = ORIGIN_APPLICATION;
					_iRequestType = REQTYPE_BROWSER;
				}
				else if (_sRequest.equals("cross_login")) {
					_iRequestOrigin = ORIGIN_APPLICATION;
					_iRequestType = REQTYPE_BROWSER;
				}
				else if (_sRequest.equals("direct_login1")) {
					_iRequestOrigin = ORIGIN_APPLICATION;
					_iRequestType = REQTYPE_BROWSER;
				}
				else if (_sRequest.equals("direct_login2")) {
					_iRequestOrigin = ORIGIN_APPLICATION;
					_iRequestType = REQTYPE_BROWSER;
				}
				else if (_sRequest.equals("error")) {
					_iRequestOrigin = ORIGIN_AUTHSP;
					_iRequestType = REQTYPE_BROWSER;
				}
				else if (_sRequest.equals("create_tgt")) {
					_iRequestOrigin = ORIGIN_APPLICATION;
					_iRequestType = REQTYPE_BROWSER;
				}
				else
				// API call from an AuthSP?
				if (_sRequest.equals("kill_session")) {
					_iRequestOrigin = ORIGIN_AUTHSP;
					_iRequestType = REQTYPE_API_CALL;
				}
				// RH, 20100895, sn, support logout GET request
				else
				if (_sRequest.equals("logout")) {
					_iRequestOrigin = ORIGIN_USER;
					_iRequestType = REQTYPE_BROWSER;
				}
				// RH, 20100895, en
				
			}
		}
		else if (_sMethod.equalsIgnoreCase("POST")) {
			// Process HTTP POST request
			String xContentType = request.getContentType();
			if (xContentType.indexOf("text/xml") > -1) {
				// SOAP11 request
				_iRequestType = REQTYPE_API_CALL;
				_iRequestOrigin = ORIGIN_APPLICATION;
				_iRequestProtocol = PROTOCOL_SOAP11;
			}
			else if (xContentType.indexOf("application/soap+xml") > -1) {
				// SOAP11 request
				_iRequestType = REQTYPE_API_CALL;
				_iRequestOrigin = ORIGIN_APPLICATION;
				_iRequestProtocol = PROTOCOL_SOAP12;
			}
			else {
				_sRequest = request.getParameter("request");
				// Is this a POST (via browser) from an AuthSP?
				if (_sRequest != null && _sRequest.indexOf("login") > -1)
					_iRequestOrigin = ORIGIN_USER;
				else if (request.getParameter("authsp") != null) {
					_iRequestOrigin = ORIGIN_AUTHSP;
				}
				else
					// The user submitted a form
					_iRequestOrigin = ORIGIN_USER;
				_iRequestType = REQTYPE_BROWSER;
				_iRequestProtocol = PROTOCOL_CGI;
			}
		}

		// We do this to prevent NullPointerExceptions
		if (_sRequest == null)
			_sRequest = "";
	}
}
