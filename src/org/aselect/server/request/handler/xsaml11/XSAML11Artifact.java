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
package org.aselect.server.request.handler.xsaml11;

import org.aselect.server.request.handler.*;

//
// The SAML Artifact Resolver - Source Site
// (Also referred to as SAML Responder)
//
public class XSAML11Artifact extends SamlArtifactResolver
{
    private final static String MODULE = "XSAML11Artifact";
	protected String getSessionIdPrefix() { return ""; }
    protected boolean useConfigToCreateSamlBuilder() { return false; }
}
