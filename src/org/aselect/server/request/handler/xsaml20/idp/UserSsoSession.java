package org.aselect.server.request.handler.xsaml20.idp;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.xsaml20.ServiceProvider;

public class UserSsoSession implements Serializable
{
	private static final long serialVersionUID = -9091687141883681342L;

	// The id of the TGT that belongs to this user
	private String tgtId;  // NOT USED

	// the user belonging to this sesison
	private String userId;  // NOT USED

	// The service provider that initiated the logout
	private String logoutInitiator = "";

	// the service providers that are involved in this SSO session
	private List<ServiceProvider> serviceProviders;

	// The credentials that were provided by the authSp
	private String aspCredentials = "";  // NOT USED

	public UserSsoSession(String userId, String tgtId)
	{
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		this.userId = userId;
		this.tgtId = tgtId;
		this.serviceProviders = new ArrayList<ServiceProvider>();
	}

	public String toString()
	{
		String sTgtId = (tgtId.length() > 30) ? tgtId.substring(0, 30) + "..." : tgtId;
		String sCred = (aspCredentials.length() > 30) ? aspCredentials.substring(0, 30) + "..." : aspCredentials;
		String result = "{userId=" + userId + ", tgtId=" + sTgtId + ", aspCred=" + sCred + ", logoutInit="
				+ logoutInitiator;

		for (ServiceProvider sp : serviceProviders) {
			result += " {url=" + sp.getServiceProviderUrl() + ", sync=" + sp.getLastSessionSync() + "}";
		}
		result += "}";
		return result;
	}

	// some convenience methods to deal with the service providers list
	/**
	 * Add the given url to the list. No duplicates!
	 */
	public void addServiceProvider(ServiceProvider serviceProvider)
	{
//		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		String sUrl = serviceProvider.getServiceProviderUrl();
		
		for (ServiceProvider sp : serviceProviders) {
			if (sUrl.equals(sp.getServiceProviderUrl())) {
				return;  // already present
			}
		}
        serviceProviders.add(serviceProvider);
	}
	
	/**
	 * Removes the specified record from the list
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

	public String getTgtId()
	{
		return tgtId;
	}

	public void setTgtId(String tgtId)
	{
		this.tgtId = tgtId;
	}

	public String getUserId()
	{
		return userId;
	}

	public void setUserId(String userId)
	{
		this.userId = userId;
	}

	public List<ServiceProvider> getServiceProviders()
	{
		return serviceProviders;
	}

	public String getAspCredentials()
	{
		return aspCredentials;
	}

	public void setAspCredentials(String aspCredentials)
	{
		this.aspCredentials = aspCredentials;
	}

	public String getLogoutInitiator()
	{
		return logoutInitiator;
	}

	public void setLogoutInitiator(String logoutInitiator)
	{
		this.logoutInitiator = logoutInitiator;
	}
}
