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
package org.aselect.system.storagemanager;

import java.util.TimerTask;
import java.util.logging.Level;

import org.aselect.system.logging.SystemLogger;

public class SendQueueSender extends TimerTask
{
	public final static String MODULE = "SendQueueSender";

	protected SystemLogger _oLogger = null;

	public SendQueueSender(SystemLogger oLog)
	{	
		String sMethod = "SendQueueSender";
		_oLogger = oLog;
		_oLogger.log(Level.INFO, MODULE, sMethod, "Task created");
	}
	
	@Override
	public void run()
	{
		String sMethod = "run";
		
		SendQueue hQueue = SendQueue.getHandle();
		if (hQueue == null) {
			_oLogger.log(Level.WARNING, MODULE, sMethod, "Cannot get SendQueue");
			return;
		}
		hQueue.sendEntries();
	}
}
