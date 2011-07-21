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

import org.aselect.lbsensor.handler.SensorStore;
import org.aselect.system.exception.ASelectException;

public interface ISensorHandler extends Runnable
{
	
	/**
	 * Initialize.
	 * 
	 * @param oConfigHandler
	 *            the o config handler
	 * @param sId
	 *            the s id
	 * @throws ASelectException
	 *             the a select exception
	 */
	void initialize(Object oConfigHandler, String sId)
		throws ASelectException;

	/**
	 * Gets the my store.
	 * 
	 * @return the my store
	 */
	abstract SensorStore getMyStore();
}
