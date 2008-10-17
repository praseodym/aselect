package org.aselect.server.request.handler.saml20.idp.authentication;

import java.io.Serializable;

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

	public long getLastSessionSync()
	{
		return lastSessionSync;
	}

	public void setLastSessionSync(long lastSessionSync)
	{
		this.lastSessionSync = lastSessionSync;
	}

	public String getServiceProviderUrl()
	{
		return serviceProviderUrl;
	}

	public void setServiceProviderUrl(String serviceProviderUrl)
	{
		this.serviceProviderUrl = serviceProviderUrl;
	}
}
