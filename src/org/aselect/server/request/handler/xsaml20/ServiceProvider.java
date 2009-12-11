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
package org.aselect.server.request.handler.xsaml20;

import java.io.Serializable;
import java.util.Date;

// TODO: Auto-generated Javadoc
//
// Store Service Provider Data
// Used by Identity Providers
//
public class ServiceProvider implements Serializable
{
	private static final long serialVersionUID = -8145120672989460952L;

	// Url of the service provider
	private String serviceProviderUrl;

	// Timestamp of last session sync
	private long lastSessionSync;

	/**
	 * Instantiates a new service provider.
	 * 
	 * @param spUrl
	 *            the sp url
	 */
	public ServiceProvider(String spUrl) {
		setServiceProviderUrl(spUrl);
		setLastSessionSync(new Date().getTime());
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString()
	{
		return getServiceProviderUrl() + getLastSessionSync();
	}

	/**
	 * Gets the service provider url.
	 * 
	 * @return the service provider url
	 */
	public String getServiceProviderUrl()
	{
		return serviceProviderUrl;
	}

	/**
	 * Sets the service provider url.
	 * 
	 * @param serviceProviderUrl
	 *            the new service provider url
	 */
	public void setServiceProviderUrl(String serviceProviderUrl)
	{
		this.serviceProviderUrl = serviceProviderUrl;
	}

	/**
	 * Gets the last session sync.
	 * 
	 * @return the last session sync
	 */
	public long getLastSessionSync()
	{
		return lastSessionSync;
	}

	/**
	 * Sets the last session sync.
	 * 
	 * @param lastSessionSync
	 *            the new last session sync
	 */
	public void setLastSessionSync(long lastSessionSync)
	{
		this.lastSessionSync = lastSessionSync;
	}
}
