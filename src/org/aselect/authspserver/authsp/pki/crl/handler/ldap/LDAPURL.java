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
 * $Id: LDAPURL.java,v 1.3 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $log$
 *
 */
package org.aselect.authspserver.authsp.pki.crl.handler.ldap;

import java.util.StringTokenizer;


/**
 * a LDAP URL Wrapper Class. <br>
 * <br>
 * <b>Description:</b><br>
 * The constructor expects one String containing the whole URL. the URL is parsed and divided in the following sections:
 * <ul>
 * <li>String URL (including 'dn')
 * <li>String Attributes
 * <li>String searchScope
 * <li>String searchFilter
 * <li>String Extensions
 * <li>String ServerURL (without 'dn') <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss
 */
public class LDAPURL
{
	private String _sLdapUrl = null;
	private String _sAttributes = null;
	private String _sScope = null;
	private String _sFilter = null;
	private String _sExtensions = null;
	private String _sDn = null;
	private String _sServerUrl = null;

	/**
	 * Instantiates a new lDAPURL.
	 */
	private LDAPURL() {
	}

	/**
	 * The LDAP URL Constructor. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Divides the given URI in useful parts. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * none <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * sUri may not be null <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None <br>
	 * 
	 * @param sUri
	 *            the complete URI
	 */
	public LDAPURL(String sUri) {
		StringTokenizer oStrTok = new StringTokenizer(sUri, "?");

		if (oStrTok.hasMoreTokens()) {
			_sLdapUrl = oStrTok.nextToken();
			int iDnStart = _sLdapUrl.lastIndexOf("/");
			if (iDnStart >= 0) {
				_sDn = _sLdapUrl.substring(iDnStart + 1);
				_sServerUrl = _sLdapUrl.substring(0, iDnStart);
			}
		}
		if (oStrTok.hasMoreTokens())
			_sAttributes = oStrTok.nextToken();
		if (oStrTok.hasMoreTokens())
			_sScope = oStrTok.nextToken();
		if (oStrTok.hasMoreTokens())
			_sFilter = oStrTok.nextToken();
		if (oStrTok.hasMoreTokens())
			_sExtensions = oStrTok.nextToken();
	}

	/**
	 * Gets The Url. <br>
	 * 
	 * @return the URL
	 */
	public String getUrl()
	{
		return _sLdapUrl;
	}

	/**
	 * Get the name of the Attribute part from th original. <br>
	 * <br>
	 * 
	 * @return The attribute name
	 */
	public String getAttributes()
	{
		return _sAttributes;
	}

	/**
	 * Get The search scope part from the original. <br>
	 * <br>
	 * 
	 * @return the Scope
	 */
	public String getScope()
	{
		return _sScope;
	}

	/**
	 * Get The filter part from the original URI. <br>
	 * <br>
	 * 
	 * @return The Filter
	 */
	public String getFilter()
	{
		return _sFilter;
	}

	/**
	 * Get The extentions part from the original URI. <br>
	 * <br>
	 * 
	 * @return The extentions
	 */
	public String getExtensions()
	{
		return _sExtensions;
	}

	/**
	 * Get The Server URL part from the original URI. <br>
	 * <br>
	 * <br>
	 * 
	 * @return server URL
	 */
	public Object getServerUrl()
	{
		return _sServerUrl;
	}

	/**
	 * get the DN part from the original URI. <br>
	 * <br>
	 * 
	 * @return The DN
	 */
	public String getDn()
	{
		return _sDn;
	}
}
