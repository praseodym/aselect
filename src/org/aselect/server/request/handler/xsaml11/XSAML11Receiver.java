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

import java.util.logging.Level;

import javax.servlet.ServletConfig;

import org.aselect.server.request.handler.*;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

//
// SAML 1.1 Browser Artifact profile
// The Artifact Receiver (or Assertion Consumer) - Destination Site
//
public class XSAML11Receiver extends SamlAssertionConsumer
{
    private final static String MODULE = "XSAML11Receiver";

    protected String getSessionIdPrefix() { return ""; }

    //
    public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
	    String sMethod = "init()";
	    super.init(oServletConfig, oConfig);
        
        _sArtifactUrl = null;
        try {
            _sArtifactUrl = _configManager.getParam(oConfig, "sourcelocation");
        }
        catch (ASelectConfigException e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'source location' found", e);
            throw new ASelectException (Errors.ERROR_ASELECT_INIT_ERROR, e);
        }
    }   
}
