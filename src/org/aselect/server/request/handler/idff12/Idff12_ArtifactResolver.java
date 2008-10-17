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

import javax.servlet.ServletConfig;

import org.aselect.server.request.handler.*;
import org.aselect.system.exception.ASelectException;

//
//
public class Idff12_ArtifactResolver extends SamlArtifactResolver
{
    protected final static String MODULE = "Idff12_ArtResolver";
	public final static String SESSION_ID_PREFIX = "idff12_";

	protected String getSessionIdPrefix() { return SESSION_ID_PREFIX; }

    public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
	    super.init(oServletConfig, oConfig);
	}
}
