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
package org.aselect.server.request.handler.xsaml20.idp;

import java.util.Timer;
import java.util.logging.Level;
import org.aselect.server.log.ASelectSystemLogger;


public class SLOTimer extends Timer
{
	private static SLOTimer sloTimer;

	private static ASelectSystemLogger _systemLogger;

	private static String MODULE = "SLOTimer";

	/**
	 * Gets the handle.
	 * 
	 * @param logger
	 *            the logger
	 * @return the handle
	 */
	public static SLOTimer getHandle(ASelectSystemLogger logger)
	{
		String sMethod = "getHandle";
		if (sloTimer == null) {
			sloTimer = new SLOTimer();
		}
		_systemLogger = logger;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "SLOTimer");
		return sloTimer;
	}

	/*
	 * TEST: SLOTimer timer = SLOTimer.getHandle(_systemLogger); SLOTimerTask task = new SLOTimerTask("950000516",
	 * "1234567890", "79714", _sASelectServerUrl); long now = new Date().getTime(); _systemLogger.log(Level.INFO,
	 * MODULE, sMethod, "Schedule timer +" + _iRedirectLogoutTimeout * 500); timer.schedule(task, new Date(now +
	 * _iRedirectLogoutTimeout * 1000)); //timer.cancel();
	 */

	/**
	 * Instantiates a new sLO timer.
	 */
	private SLOTimer() {
		super();
	}

	/* (non-Javadoc)
	 * @see java.util.Timer#cancel()
	 */
	@Override
	public void cancel()
	{
		String sMethod = "cancel";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "cancel");
		super.cancel();
	}
}
