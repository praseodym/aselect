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
 *
 * @author Bauke Hiemstra - www.anoigo.nl
 * 
 * Version 1.0 - 14-11-2007
 */
package org.aselect.server.request.handler.idff12;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import org.aselect.server.request.handler.SamlAssertionConsumer;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.opensaml.artifact.ArtifactParseException;
import org.opensaml.artifact.SAMLArtifactType0003;
import org.opensaml.artifact.Util;


//
//
public class Idff12_AssertConsumer extends SamlAssertionConsumer
{
	protected final static String MODULE = "Idff12_AssertConsumer";

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#getSessionIdPrefix()
	 */
	@Override
	protected String getSessionIdPrefix()
	{
		return "";
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#useConfigToCreateSamlBuilder()
	 */
	@Override
	protected boolean useConfigToCreateSamlBuilder()
	{
		return false;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.SamlAssertionConsumer#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";
		super.init(oServletConfig, oConfig);

		// <identity_providers>
		// <idp id="idff_idp" url='http://192.168.1.211:8080/aselectserver/server/idff_resolve'/>
		// </identity_providers>
		Object oIdentityProviders = null;
		try {
			oIdentityProviders = _configManager.getSection(oConfig, "identity_providers");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'identity_providers' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		Object oIdP = null;
		try {
			oIdP = _configManager.getSection(oIdentityProviders, "idp");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Not even one config section 'idp' found in the 'identity_providers' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		_htIdPs = new HashMap();
		while (oIdP != null) {
			String sIdP_ID = null;
			try {
				sIdP_ID = _configManager.getParam(oIdP, "id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Not even one config item 'id' found in 'idp' section", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			String sIdP_URL = null;
			try {
				sIdP_URL = _configManager.getParam(oIdP, "url");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Not even one config item 'url' found in 'idp' section", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			if (_htIdPs.containsKey(sIdP_ID)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Identity Provider ID isn't unique: " + sIdP_ID);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			if (_htIdPs.containsValue(sIdP_URL)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Identity Provider URL isn't unique: " + sIdP_URL);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
			byte[] bSourceId;
			try {
				bSourceId = Util.generateSourceId(sIdP_ID);
			}
			catch (NoSuchAlgorithmException e) {
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "IdP id=" + sIdP_ID + " url=" + sIdP_URL + " srcid="
					+ Utils.byteArrayToHexString(bSourceId) + ", " + bSourceId.toString());

			_htIdPs.put(Utils.byteArrayToHexString(bSourceId), sIdP_URL);

			oIdP = _configManager.getNextSection(oIdP);
		}
	}

	// Overrides the default implementation
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.SamlAssertionConsumer#findArtifactUrl(java.lang.String)
	 */
	@Override
	public String findArtifactUrl(String sArtifact)
	throws ASelectException
	{
		String sMethod = "findArtifactUrl";
		String sSamlSite = "";
		try {
			// String sDecoded = Base64.decode(sArtifact);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Parse Artifact " + sArtifact + " storage=" + _htIdPs);
			SAMLArtifactType0003.Parser parser = new SAMLArtifactType0003.Parser();
			SAMLArtifactType0003 oArtifact = (SAMLArtifactType0003) parser.parse(sArtifact);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Artifact=" + oArtifact + ", SourceID="
					+ Utils.byteArrayToHexString(oArtifact.getSourceId()).toLowerCase() + ", AssertHandle="
					+ Utils.byteArrayToHexString(oArtifact.getAssertionHandle()).toLowerCase());
			// Find URL for the Artifact resolver
			Object obj = _htIdPs.get(Utils.byteArrayToHexString(oArtifact.getSourceId()));
			_systemLogger.log(Level.INFO, MODULE, sMethod, "obj=" + obj);
			if (obj == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unknown Identity Provider");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			sSamlSite = obj.toString();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "IdP url=" + sSamlSite);
		}
		catch (ArtifactParseException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not parse SAML Artifact", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return sSamlSite;
	}

	// Overrides the default implementation
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.SamlAssertionConsumer#getRedirectUrl(javax.servlet.http.HttpServletRequest)
	 */
	@Override
	public String getRedirectUrl(HttpServletRequest request)
	{
		_systemLogger.log(Level.INFO, MODULE, "getRedirectUrl", "RelayState=" + request.getParameter("RelayState"));
		return request.getParameter("RelayState");
	}
}
