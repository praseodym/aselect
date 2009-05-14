package org.aselect.lbsensor;

import org.aselect.system.exception.ASelectException;

public interface ISensorHandler extends Runnable
{
	void initialize(Object oConfigHandler)
	throws ASelectException;
}
