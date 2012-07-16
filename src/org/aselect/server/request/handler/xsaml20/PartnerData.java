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

import java.util.Vector;

/**
 * Store all data for an IdP or SP partner
 * @author bauke
 *
 */
public class PartnerData
{
	private String partnerID = null;
	private String metadataUrl = null;
	private String sessionSyncUrl = null;
	private String specialSettings = null;
	private String sRedirectSyncTime = null;
	private String sRedirectPostForm = null;

	private String localIssuer = null;
	private String destination = null;
	private String assertionconsumerserviceindex = null;
	private String attributeconsumerserviceindex = null;
	private String addkeyname = null;
	private String addcertificate = null;
	
	private String federationurl = null;
	private Metadata4Partner metadata4partner = null;
	private Testdata4Partner testdata4partner = null;
		
	public PartnerData(String sId)
	{
		partnerID = sId;
	}

	public String toString()
	{
		return "IdPData["+partnerID+"] meta="+metadataUrl+" sync="+sessionSyncUrl+" spec="+specialSettings+" acsi="+assertionconsumerserviceindex;
	}

	public String getPartnerID() {
		return partnerID;
	}

	public void setPartnerID(String partnerId) {
		this.partnerID = partnerId;
	}

	public String getMetadataUrl() {
		return metadataUrl;
	}

	public void setMetadataUrl(String metadataUrl) {
		this.metadataUrl = metadataUrl;
	}

	public String getSessionSyncUrl() {
		return sessionSyncUrl;
	}

	public void setSessionSyncUrl(String sessionSyncUrl) {
		this.sessionSyncUrl = sessionSyncUrl;
	}

	public String getSpecialSettings() {
		return specialSettings;
	}
	public void setSpecialSettings(String special) {
		this.specialSettings = special;
	}
	
	public String getRedirectSyncTime() {
		return sRedirectSyncTime;
	}
	public void setRedirectSyncTime(String sRedirectSyncTime) {
		this.sRedirectSyncTime = sRedirectSyncTime;
	}

	public String getRedirectPostForm() {
		return sRedirectPostForm;
	}
	public void setRedirectPostForm(String sRedirectPostForm) {
		this.sRedirectPostForm = sRedirectPostForm;
	}

	public String getLocalIssuer() {
		return localIssuer;
	}

	public void setLocalIssuer(String issuer) {
		this.localIssuer = issuer;
	}

	public synchronized String getDestination()
	{
		return destination;
	}

	public synchronized void setDestination(String destination)
	{
		this.destination = destination;
	}

	public synchronized String getFederationurl()
	{
		return federationurl;
	}

	public synchronized void setFederationurl(String federationurl)
	{
		this.federationurl = federationurl;
	}

	public synchronized String getAssertionConsumerServiceindex()
	{
		return assertionconsumerserviceindex;
	}

	public synchronized void setAssertionConsumerServiceindex(String serviceindex)
	{
		this.assertionconsumerserviceindex = serviceindex;
	}

	public synchronized String getAddkeyname()
	{
		return addkeyname;
	}

	public synchronized void setAddkeyname(String addkeyname)
	{
		this.addkeyname = addkeyname;
	}

	public synchronized String getAddcertificate()
	{
		return addcertificate;
	}

	public synchronized void setAddcertificate(String addcertificate)
	{
		this.addcertificate = addcertificate;
	}

	public synchronized String getAttributeConsumerServiceindex()
	{
		return attributeconsumerserviceindex;
	}

	public synchronized void setAttributeConsumerServiceindex(String attributeconsumerserviceindex)
	{
		this.attributeconsumerserviceindex = attributeconsumerserviceindex;
	}

	/**
	 * @return the metadata4partner
	 */
	public synchronized Metadata4Partner getMetadata4partner()
	{
		if (metadata4partner == null) {
			metadata4partner = new Metadata4Partner();
		}
		return metadata4partner;
	}

	
	
	// Simple wrapper for handler info
	public class HandlerInfo
	{
		private String type = null;
		private String binding = null;
		private Boolean isdefault = null;
		private Integer index =  null;
		private String responselocation =  null;
		private String location =  null;

		private HandlerInfo()
		{
			// hide this constructor
		}

		public HandlerInfo(String type, String binding, Boolean isdefault, Integer index, String responselocation, String location)
		{
			this.type = type;
			this.binding = binding;
			this.isdefault = isdefault;
			this.index =  index;
			this.responselocation = responselocation;
			this.location = location;
		}

		/**
		 * @return the type
		 */
		public synchronized String getType()
		{
			return type;
		}

		/**
		 * @return the binding
		 */
		public synchronized String getBinding()
		{
			return binding;
		}

		/**
		 * @return the isdefault
		 */
		public synchronized Boolean getIsdefault()
		{
			return isdefault;
		}

		/**
		 * @return the index
		 */
		public synchronized Integer getIndex()
		{
			return index;
		}

		/**
		 * @return the responselocation
		 */
		public synchronized String getResponselocation()
		{
			return responselocation;
		}

		public synchronized String getLocation()
		{
			return location;
		}

		public synchronized void setLocation(String location)
		{
			this.location = location;
		}


		
	}
	
	// SImple wrapper class for specific data 
	public class Metadata4Partner {

		// signing information
		private String addkeyname= null;
		private String addcertificate = null;
		private String specialsettings = null;
		private Vector<HandlerInfo> handlers = new Vector<HandlerInfo>();
		
		
		// organization data
		private String metaorgname = null;
		private String metaorgnamelang = null;
		private String metaorgdisplname = null;
		private String metaorgdisplnamelang = null;
		private String metaorgurl = null;
		private String metaorgurllang = null;
		
		// contact data
		String metacontacttype = null;
		
		String metacontactname = null;
		String metacontactsurname = null;
		String metacontactemail = null;
		String metacontactephone = null;
		
		// Set Organization info, only change values if not null
		public void setOrganizationInfo(		String metaorgname, String metaorgnamelang,
																		String metaorgdisplname, String metaorgdisplnamelang,
																		String metaorgurl, String metaorgurllang) {
			if (metaorgname != null) {
				this.metaorgname = metaorgname;
			}
			if (metaorgnamelang != null) {
				this.metaorgnamelang = metaorgnamelang;
			}
			if (metaorgdisplname != null) {
				this.metaorgdisplname = metaorgdisplname;
			}
			if (metaorgdisplnamelang != null) {
				this.metaorgdisplnamelang = metaorgdisplnamelang;
			}
			if (metaorgurl != null) {
				this.metaorgurl = metaorgurl;
			}
			if (metaorgurllang != null) {
				this.metaorgurllang = metaorgurllang;
			}
			
		}

		// Set Contact info, only change values if not null
		public void setContactInfo(		String metacontacttype,	String metacontactname, String metacontactsurname,
																String metacontactemail, String metacontactephone) {
			if (metacontacttype != null) {
				this.metacontacttype = metacontacttype;
			}
			if (metacontactname != null) {
				this.metacontactname = metacontactname;
			}
			if (metacontactsurname != null) {
				this.metacontactsurname = metacontactsurname;
			}
			if (metacontactemail != null) {
				this.metacontactemail = metacontactemail;
			}
			if (metacontactephone != null) {
				this.metacontactephone = metacontactephone;
			}
			
			
		}

		/**
		 * @return the metaorgname
		 */
		public synchronized String getMetaorgname()
		{
			return metaorgname;
		}

		/**
		 * @return the metaorgnamelang
		 */
		public synchronized String getMetaorgnamelang()
		{
			return metaorgnamelang;
		}

		/**
		 * @return the metaorgdisplname
		 */
		public synchronized String getMetaorgdisplname()
		{
			return metaorgdisplname;
		}

		/**
		 * @return the metaorgdisplnamelang
		 */
		public synchronized String getMetaorgdisplnamelang()
		{
			return metaorgdisplnamelang;
		}

		/**
		 * @return the metaorgurl
		 */
		public synchronized String getMetaorgurl()
		{
			return metaorgurl;
		}

		/**
		 * @return the metaorgurllang
		 */
		public synchronized String getMetaorgurllang()
		{
			return metaorgurllang;
		}

		/**
		 * @return the metacontacttype
		 */
		public synchronized String getMetacontacttype()
		{
			return metacontacttype;
		}

		/**
		 * @return the metacontactname
		 */
		public synchronized String getMetacontactname()
		{
			return metacontactname;
		}

		/**
		 * @return the metacontactsurname
		 */
		public synchronized String getMetacontactsurname()
		{
			return metacontactsurname;
		}

		/**
		 * @return the metacontactemail
		 */
		public synchronized String getMetacontactemail()
		{
			return metacontactemail;
		}

		/**
		 * @return the metacontactephone
		 */
		public synchronized String getMetacontactephone()
		{
			return metacontactephone;
		}

		/**
		 * @return the addkeyname
		 */
		public synchronized String getAddkeyname()
		{
			return addkeyname;
		}

		/**
		 * @param addkeyname the addkeyname to set
		 */
		public synchronized void setAddkeyname(String addkeyname)
		{
			this.addkeyname = addkeyname;
		}

		/**
		 * @return the addcertificate
		 */
		public synchronized String getAddcertificate()
		{
			return addcertificate;
		}

		/**
		 * @param addcertificate the addcertificate to set
		 */
		public synchronized void setAddcertificate(String addcertificate)
		{
			this.addcertificate = addcertificate;
		}

		/**
		 * @return the specialsettings
		 */
		public synchronized String getSpecialsettings()
		{
			return specialsettings;
		}

		/**
		 * @param specialsettings the specialsettings to set
		 */
		public synchronized void setSpecialsettings(String specialsettings)
		{
			this.specialsettings = specialsettings;
		}

		/**
		 * @return the handlers
		 */
		public synchronized Vector<HandlerInfo> getHandlers()
		{
			return handlers;
		}

		/**
		 * @param handler the handler to add
		 */
		public void addHandlerInfo(HandlerInfo handler) {
			handlers.addElement(handler);
		}
		
		/**
		 * @param handler the handler to remove
		 * @return true if handler was present
		 */
		public boolean removeHandlerInfo(HandlerInfo handler) {
			return handlers.removeElement(handler);
		}
		
	}

	// SImple wrapper class for test data 
	public class Testdata4Partner {

		private String IssueInstant= null;
		private String Issuer = null;
		private String AuthnContextClassRefURI = null;
		private String AuthnContextComparisonTypeEnumeration= null;
		private String ForceAuthn = null;
		private String ProviderName = null;
		private String AssertionConsumerServiceIndex= null;
		private String AssertionConsumerServiceURL = null;
		private String Destination = null;
		
		private String IssueInstantLogout= null;
		private String IssuerLogout = null;
		private String DestinationLogout = null;
		
		

		@Override
		public String toString()
		{
			// TODO Auto-generated method stub
			return "IssueInstant=" + IssueInstant
				+ ", Issuer=" + Issuer
				+ ", AuthnContextClassRefURI=" + AuthnContextClassRefURI
				+ ", AuthnContextComparisonTypeEnumeration=" + AuthnContextComparisonTypeEnumeration
				+ ", ForceAuthn=" + ForceAuthn
				+ ", ProviderName=" + ProviderName
				+ ", AssertionConsumerServiceIndex=" + AssertionConsumerServiceIndex
				+ ", AssertionConsumerServiceURL=" + AssertionConsumerServiceURL
				+ ", Destination=" + Destination
				+ ", IssueInstantLogout=" + IssueInstantLogout
				+ ", IssuerLogout=" + IssuerLogout
				+ ", DestinationLogout=" + DestinationLogout
			;
			
		}
		
		
		/**
		 * @return the issueInstant
		 */
		public synchronized String getIssueInstant()
		{
			return IssueInstant;
		}
		/**
		 * @param issueInstant the issueInstant to set
		 */
		public synchronized void setIssueInstant(String issueInstant)
		{
			IssueInstant = issueInstant;
		}
		/**
		 * @return the issuer
		 */
		public synchronized String getIssuer()
		{
			return Issuer;
		}
		/**
		 * @param issuer the issuer to set
		 */
		public synchronized void setIssuer(String issuer)
		{
			Issuer = issuer;
		}
		/**
		 * @return the authnContextClassRefURI
		 */
		public synchronized String getAuthnContextClassRefURI()
		{
			return AuthnContextClassRefURI;
		}
		/**
		 * @param authnContextClassRefURI the authnContextClassRefURI to set
		 */
		public synchronized void setAuthnContextClassRefURI(String authnContextClassRefURI)
		{
			AuthnContextClassRefURI = authnContextClassRefURI;
		}
		/**
		 * @return the authnContextComparisonTypeEnumeration
		 */
		public synchronized String getAuthnContextComparisonTypeEnumeration()
		{
			return AuthnContextComparisonTypeEnumeration;
		}
		/**
		 * @param authnContextComparisonTypeEnumeration the authnContextComparisonTypeEnumeration to set
		 */
		public synchronized void setAuthnContextComparisonTypeEnumeration(String authnContextComparisonTypeEnumeration)
		{
			AuthnContextComparisonTypeEnumeration = authnContextComparisonTypeEnumeration;
		}
		/**
		 * @return the forceAuthn
		 */
		public synchronized String getForceAuthn()
		{
			return ForceAuthn;
		}
		/**
		 * @param forceAuthn the forceAuthn to set
		 */
		public synchronized void setForceAuthn(String forceAuthn)
		{
			ForceAuthn = forceAuthn;
		}
		/**
		 * @return the providerName
		 */
		public synchronized String getProviderName()
		{
			return ProviderName;
		}
		/**
		 * @param providerName the providerName to set
		 */
		public synchronized void setProviderName(String providerName)
		{
			ProviderName = providerName;
		}
		/**
		 * @return the assertionConsumerServiceIndex
		 */
		public synchronized String getAssertionConsumerServiceIndex()
		{
			return AssertionConsumerServiceIndex;
		}
		/**
		 * @param assertionConsumerServiceIndex the assertionConsumerServiceIndex to set
		 */
		public synchronized void setAssertionConsumerServiceIndex(String assertionConsumerServiceIndex)
		{
			AssertionConsumerServiceIndex = assertionConsumerServiceIndex;
		}
		/**
		 * @return the assertionConsumerServiceURL
		 */
		public synchronized String getAssertionConsumerServiceURL()
		{
			return AssertionConsumerServiceURL;
		}
		/**
		 * @param assertionConsumerServiceURL the assertionConsumerServiceURL to set
		 */
		public synchronized void setAssertionConsumerServiceURL(String assertionConsumerServiceURL)
		{
			AssertionConsumerServiceURL = assertionConsumerServiceURL;
		}
		/**
		 * @return the destination
		 */
		public synchronized String getDestination()
		{
			return Destination;
		}
		/**
		 * @param destination the destination to set
		 */
		public synchronized void setDestination(String destination)
		{
			Destination = destination;
		}


		/**
		 * @return the issueInstantLogout
		 */
		public String getIssueInstantLogout()
		{
			return IssueInstantLogout;
		}


		/**
		 * @param issueInstantLogout the issueInstantLogout to set
		 */
		public void setIssueInstantLogout(String issueInstantLogout)
		{
			IssueInstantLogout = issueInstantLogout;
		}


		/**
		 * @return the issuerLogout
		 */
		public String getIssuerLogout()
		{
			return IssuerLogout;
		}


		/**
		 * @param issuerLogout the issuerLogout to set
		 */
		public void setIssuerLogout(String issuerLogout)
		{
			IssuerLogout = issuerLogout;
		}


		/**
		 * @return the destinationLogout
		 */
		public String getDestinationLogout()
		{
			return DestinationLogout;
		}


		/**
		 * @param destinationLogout the destinationLogout to set
		 */
		public void setDestinationLogout(String destinationLogout)
		{
			DestinationLogout = destinationLogout;
		}

	}
	// End SImple wrapper class for test data 

	
	
	/**
	 * @return the metadata4partner
	 */
	public synchronized Testdata4Partner getTestdata4partner()
	{
		if (testdata4partner == null) {
			testdata4partner = new Testdata4Partner();
		}
		return testdata4partner;
	}

	
}
