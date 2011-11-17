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

import java.util.TimerTask;
import java.util.logging.Level;

import org.aselect.lbsensor.handler.DataCollectStore;

public class DataCollectExporter extends TimerTask
{
	public final static String MODULE = "DataCollectExporter";

	protected LbSensorSystemLogger _oLbSensorLogger = LbSensorSystemLogger.getHandle();

	public DataCollectExporter()
	{	
		String sMethod = "DataCollectExporter";
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Task STARTED");
	}
	
	@Override
	public void run()
	{
		String sMethod = "run";
		
		DataCollectStore hStore = DataCollectStore.getHandle();
		if (hStore == null) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot get DataCollectStore");
			return;
		}
		hStore.exportEntries();
	}
}
