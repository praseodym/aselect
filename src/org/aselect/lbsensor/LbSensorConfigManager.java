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
package org.aselect.lbsensor;

import java.io.File;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

// TODO: Auto-generated Javadoc
public class LbSensorConfigManager extends ConfigManager
{
	private final String MODULE = "LbSensorConfigManager";

	// The singleton instance
	private static LbSensorConfigManager _oLbSensorConfigManager;

	// The system logger
	private LbSensorSystemLogger _systemLogger;

	// The working directory
	private String _sWorkingDir = null;

	// The private constructor forces a singleton
	/**
	 * Instantiates a new lb sensor config manager.
	 */
	private LbSensorConfigManager() {
	}

	// Return the singleton class
	/**
	 * Gets the handle.
	 * 
	 * @return the handle
	 */
	public static LbSensorConfigManager getHandle()
	{
		if (_oLbSensorConfigManager == null)
			_oLbSensorConfigManager = new LbSensorConfigManager();

		return _oLbSensorConfigManager;
	}

	/**
	 * Initialize the configuration.
	 * 
	 * @param sWorkingDir
	 *            The working directory.
	 * @throws ASelectConfigException
	 *             the a select config exception
	 * @throws ASelectException
	 *             the a select exception
	 */
	public void init(String sWorkingDir)
		throws ASelectConfigException, ASelectException
	{
		final String sMethod = "init";

		_sWorkingDir = sWorkingDir;
		_systemLogger = LbSensorSystemLogger.getHandle();

		StringBuffer sb = new StringBuffer(_sWorkingDir).append(File.separator).append("lbsensor.xml");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "xml=" + sb);
		super.init(sb.toString(), _systemLogger);
	}

	// Convenience function
	/**
	 * Gets the param from section.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sSection
	 *            the s section
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the param from section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public String getParamFromSection(Object oConfig, String sSection, String sParam, boolean bMandatory)
		throws ASelectConfigException
	{
		return Utils.getParamFromSection(getHandle(), LbSensorSystemLogger.getHandle(), oConfig, sSection, sParam,
				bMandatory);
	}

	// Convenience function
	/**
	 * Gets the simple section.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the simple section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public Object getSimpleSection(Object oConfig, String sParam, boolean bMandatory)
		throws ASelectConfigException
	{
		return Utils.getSimpleSection(getHandle(), LbSensorSystemLogger.getHandle(), oConfig, sParam, bMandatory);
	}

	// Convenience function
	/**
	 * Gets the simple param.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the simple param
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String getSimpleParam(Object oConfig, String sParam, boolean bMandatory)
		throws ASelectException
	{
		return Utils.getSimpleParam(getHandle(), LbSensorSystemLogger.getHandle(), oConfig, sParam, bMandatory);
	}

	// Convenience function
	/**
	 * Gets the simple int param.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the simple int param
	 * @throws ASelectException
	 *             the a select exception
	 */
	public int getSimpleIntParam(Object oConfig, String sParam, boolean bMandatory)
		throws ASelectException
	{
		return Utils.getSimpleIntParam(getHandle(), LbSensorSystemLogger.getHandle(), oConfig, sParam, bMandatory);
	}

	// Convenience function
	/**
	 * Gets the section from section.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param sValue
	 *            the s value
	 * @param bMandatory
	 *            the b mandatory
	 * @return the section from section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public Object getSectionFromSection(Object oConfig, String sParam, String sValue, boolean bMandatory)
		throws ASelectConfigException
	{
		return Utils.getSectionFromSection(getHandle(), LbSensorSystemLogger.getHandle(), oConfig, sParam, sValue,
				bMandatory);
	}

}
