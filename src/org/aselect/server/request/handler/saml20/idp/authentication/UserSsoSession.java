package org.aselect.server.request.handler.saml20.idp.authentication;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class UserSsoSession implements Serializable
{
	private static final long serialVersionUID = -9091687141883681342L;

	// the user belonging to this sesison
	private String userId;

	// the service providers that are involved in this SSO session
	private List<ServiceProvider> serviceProviders;

	// The id of the TGT that belongs to this user
	private String tgtId;

	// The credentials that were provided by the authSp
	private String aspCredentials;

	// The service provider that initiated the logout
	private String logoutInitiator;

	public UserSsoSession(String userId, String tgtId) {
		this.userId = userId;
		this.tgtId = tgtId;
		this.serviceProviders = new ArrayList<ServiceProvider>();
	}

	public String toString()
	{
		String sTgtId = (tgtId.length() > 30) ? tgtId.substring(0, 30) + "..." : tgtId;
		String sCred = (aspCredentials.length() > 30) ? aspCredentials.substring(0, 30) + "..." : aspCredentials;
		String result = "{userId=" + userId + ", tgtId=" + sTgtId + ", aspCred=" + sCred + ", logoutInit="
				+ logoutInitiator + "}";

		for (ServiceProvider sp : serviceProviders) {
			result += " {url=" + sp.getServiceProviderUrl() + ", sync=" + sp.getLastSessionSync() + "}";
		}
		return result;
	}

	// some convenience methods to deal with the service providers list
	/**
	 * add the given url to the list. Duplicates are allowed (for the time
	 * being)
	 */
	public void addServiceProvider(ServiceProvider serviceProvider)
	{
		serviceProviders.add(serviceProvider);
	}

	/**
	 * removes the specified record from the list
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
