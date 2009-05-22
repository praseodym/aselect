package org.aselect.lbsensor;

import org.aselect.lbsensor.handler.SensorStore;
import org.aselect.system.exception.ASelectException;

public interface ISensorHandler extends Runnable
{
	void initialize(Object oConfigHandler, String sId)
	throws ASelectException;

	abstract SensorStore getMyStore();
}
