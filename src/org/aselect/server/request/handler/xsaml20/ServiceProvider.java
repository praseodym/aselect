package org.aselect.server.request.handler.xsaml20;

import java.io.Serializable;
import java.util.Date;

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

	public ServiceProvider(String spUrl)
	{
		setServiceProviderUrl(spUrl);
		setLastSessionSync(new Date().getTime());
	}
	
	public String toString()
	{
		return getServiceProviderUrl()+getLastSessionSync();
	}
	
	public String getServiceProviderUrl()
	{
		return serviceProviderUrl;
	}

	public void setServiceProviderUrl(String serviceProviderUrl)
	{
		this.serviceProviderUrl = serviceProviderUrl;
	}

	public long getLastSessionSync()
	{
		return lastSessionSync;
	}

	public void setLastSessionSync(long lastSessionSync)
	{
		this.lastSessionSync = lastSessionSync;
	}
}
