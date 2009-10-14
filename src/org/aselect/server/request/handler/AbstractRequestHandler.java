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
 */

/* 
 * $Id: AbstractRequestHandler.java,v 1.3 2006/04/26 12:18:32 tom Exp $ 
 */

package org.aselect.server.request.handler;

import java.util.logging.Level;
import java.util.regex.Pattern;

import javax.servlet.ServletConfig;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

/**
 * Abstract class implementing the basic functionality of a Request handler.
 * <br><br>
 * <b>Description:</b><br>
 * Reads default configuration and contains functionality for request handling.
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * -
 * <br>
 * @author Alfa & Ariss
 * 
 */
public abstract class AbstractRequestHandler extends BasicRequestHandler implements IRequestHandler
{
	protected SessionManager _oSessionManager;
	protected ServletConfig _oServletConfig;

	private final static String MODULE = "AbstractRequestHandler";
	private String _sID;
	private Pattern _pTarget;

	/**
	 * Initializes the default functionality for a RequestHandler.
	 * <br/><br/>
	 * <b>Description:</b><br>
	 * <li>Reads the configuration</li>
	 * <li>Verifies if the configured 'target' is a regular expression</li>
	 * <br><br>
	 * <b>Concurrency issues:</b>
	 * <br>
	 * -
	 * <br><br>
	 * <b>Preconditions:</b>
	 * <br><br>
	 * Reads the following configuration:<br/><br/>
	 * &lt;handler id='[id]' class='[class]' target='[target]'&gt;<br/>
	 * ...<br>
	 * &lt;/handler
	 * <br><br>
	 * <li><b>id</b> - Unique ID of the handler</li>
	 * <li><b>class</b> - Class name of the handler, must implement the 
	 * <code>IAuthnRequestHandler</code> interface</li>
	 * <li><b>target</b> - The regular expression of URLs that will be handled 
	 * by this request handler</li>
	 * <br><br>
	 * @see org.aselect.server.request.handler.IRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init()";
		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			_configManager = ASelectConfigManager.getHandle();
			_oSessionManager = SessionManager.getHandle();
			_oServletConfig = oServletConfig;

			try {
				_sID = _configManager.getParam(oConfig, "id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'id' in 'handler' section found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "id="+_sID);

			String sTarget = null;
			try {
				sTarget = _configManager.getParam(oConfig, "target");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'target' in 'handler' section found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "target="+sTarget);

			try {
				_pTarget = Pattern.compile(sTarget);
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Not a valid pattern: " + sTarget, e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Returns the handler ID as <code>String</code>.
	 * <br><br>
	 * @see org.aselect.server.request.handler.IRequestHandler#getID()
	 */
	public String getID()
	{
		return _sID;
	}

	/**
	 * Returns the configured target as <code>Pattern</code> object.
	 * <br><br>
	 * @see org.aselect.server.request.handler.IRequestHandler#getPattern()
	 */
	public Pattern getPattern()
	{
		return _pTarget;
	}

}
