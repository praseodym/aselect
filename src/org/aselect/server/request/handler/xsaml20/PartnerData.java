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
	private String localIssuer = null;
	private String destination = null;
	private String assertionconsumerserviceindex = null;
	private String attributeconsumerserviceindex = null;
	private String addkeyname = null;
	private String addcertificate = null;
	
	private String federationurl = null;
	
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
}
