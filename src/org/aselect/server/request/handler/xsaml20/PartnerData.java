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
	
	public PartnerData(String sId)
	{
		partnerID = sId;
	}
	
	public String toString()
	{
		return "IdPData["+partnerID+"] meta="+metadataUrl+" sync="+sessionSyncUrl+" sec="+specialSettings;
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
}
