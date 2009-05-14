package org.aselect.lbsense;

import org.aselect.system.exception.ASelectException;

public interface ISenseHandler extends Runnable
{
	void initialize(Object oConfigHandler)
	throws ASelectException;
}
