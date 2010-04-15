/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.server.request.handler.xsaml20.idp;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

//import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.xsaml20.ServiceProvider;

public class UserSsoSession implements Serializable
{
	private static final long serialVersionUID = -9091687141883681342L;

	// The id of the TGT that belongs to this user
	private String tgtId; // NOT USED

	// the user belonging to this sesison
	private String userId; // NOT USED

	// The service provider that initiated the logout
	private String logoutInitiator = "";

	// The service provider that initiated the logout
	private String logoutInitiatingID = "";

	// the service providers that are involved in this SSO session
	private List<ServiceProvider> serviceProviders;

	// The credentials that were provided by the authSp
	private String aspCredentials = ""; // NOT USED

	/**
	 * Instantiates a new user sso session.
	 * 
	 * @param userId
	 *            the user id
	 * @param tgtId
	 *            the tgt id
	 */
	public UserSsoSession(String userId, String tgtId) {
		// ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		this.userId = userId;
		this.tgtId = tgtId;
		this.serviceProviders = new ArrayList<ServiceProvider>();
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString()
	{
		String sTgtId = (tgtId.length() > 30) ? tgtId.substring(0, 30) + "..." : tgtId;
		String sCred = (aspCredentials.length() > 30) ? aspCredentials.substring(0, 30) + "..." : aspCredentials;
		String result = "{userId=" + userId + ", tgtId=" + sTgtId + ", aspCred=" + sCred + ", logoutInit="
				+ logoutInitiator + " sps=";

		for (ServiceProvider sp : serviceProviders) {
			result += " {url=" + sp.getServiceProviderUrl() + ", lastsync=" + sp.getLastSessionSync() + "}";
		}
		result += "}";
		return result;
	}

	// some convenience methods to deal with the service providers list
	/**
	 * Add the given url to the list. No duplicates!
	 * 
	 * @param serviceProvider
	 *            the service provider
	 */
	public void addServiceProvider(ServiceProvider serviceProvider)
	{
		// ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		String sUrl = serviceProvider.getServiceProviderUrl();

		for (ServiceProvider sp : serviceProviders) {
			if (sUrl.equals(sp.getServiceProviderUrl())) {
				return; // already present
			}
		}
		serviceProviders.add(serviceProvider);
	}

	/**
	 * Removes the specified record from the list.
	 * 
	 * @param serviceProviderUrl
	 *            the service provider url
	 */
	public void removeServiceProvider(String serviceProviderUrl)
	{
		ServiceProvider toRemove = null;
		for (ServiceProvider sp : serviceProviders) {
			if (serviceProviderUrl.equals(sp.getServiceProviderUrl())) {
				toRemove = sp;
				break;
			}
		}
		serviceProviders.remove(toRemove);
	}

	/**
	 * Gets the tgt id.
	 * 
	 * @return the tgt id
	 */
	public String getTgtId()
	{
		return tgtId;
	}

	/**
	 * Sets the tgt id.
	 * 
	 * @param tgtId
	 *            the new tgt id
	 */
	public void setTgtId(String tgtId)
	{
		this.tgtId = tgtId;
	}

	/**
	 * Gets the user id.
	 * 
	 * @return the user id
	 */
	public String getUserId()
	{
		return userId;
	}

	/**
	 * Sets the user id.
	 * 
	 * @param userId
	 *            the new user id
	 */
	public void setUserId(String userId)
	{
		this.userId = userId;
	}

	/**
	 * Gets the service providers.
	 * 
	 * @return the service providers
	 */
	public List<ServiceProvider> getServiceProviders()
	{
		return serviceProviders;
	}

	/**
	 * Gets the asp credentials.
	 * 
	 * @return the asp credentials
	 */
	public String getAspCredentials()
	{
		return aspCredentials;
	}

	/**
	 * Sets the asp credentials.
	 * 
	 * @param aspCredentials
	 *            the new asp credentials
	 */
	public void setAspCredentials(String aspCredentials)
	{
		this.aspCredentials = aspCredentials;
	}

	/**
	 * Gets the logout initiator.
	 * 
	 * @return the logout initiator
	 */
	public String getLogoutInitiator()
	{
		return logoutInitiator;
	}

	/**
	 * Sets the logout initiator.
	 * 
	 * @param logoutInitiator
	 *            the new logout initiator
	 */
	public void setLogoutInitiator(String logoutInitiator)
	{
		this.logoutInitiator = logoutInitiator;
	}

	/**
	 * Gets the logout initiating id.
	 * 
	 * @return the logout initiating id
	 */
	public String getLogoutInitiatingID()
	{
		return logoutInitiatingID;
	}

	/**
	 * Sets the logout initiating id.
	 * 
	 * @param logoutInitiatingID
	 *            the new logout initiating id
	 */
	public void setLogoutInitiatingID(String logoutInitiatingID)
	{
		this.logoutInitiatingID = logoutInitiatingID;
	}
}
