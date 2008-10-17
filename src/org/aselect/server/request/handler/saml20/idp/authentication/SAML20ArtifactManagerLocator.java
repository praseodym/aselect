package org.aselect.server.request.handler.saml20.idp.authentication;

import org.aselect.system.exception.ASelectException;

public class SAML20ArtifactManagerLocator
{

	private static SAML20ArtifactManager artifactManager;

	public static SAML20ArtifactManager getArtifactManager()
		throws ASelectException
	{
		if (artifactManager == null) {
			artifactManager = new SAML20ArtifactManager();
			artifactManager.init();
		}
		return artifactManager;
	}

}
