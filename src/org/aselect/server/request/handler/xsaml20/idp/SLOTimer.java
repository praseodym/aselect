package org.aselect.server.request.handler.xsaml20.idp;

import java.util.Timer;
import java.util.logging.Level;
import org.aselect.server.log.ASelectSystemLogger;

public class SLOTimer extends Timer
{
	private static SLOTimer sloTimer;

	private static ASelectSystemLogger _systemLogger;

	private static String MODULE = "SLOTimer";

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

/*TEST:		SLOTimer timer = SLOTimer.getHandle(_systemLogger);
			SLOTimerTask task = new SLOTimerTask("950000516", "1234567890", "79714", _sASelectServerUrl);
			long now = new Date().getTime();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Schedule timer +" + _iRedirectLogoutTimeout * 500);
			timer.schedule(task, new Date(now + _iRedirectLogoutTimeout * 1000));
			//timer.cancel();
*/

	private SLOTimer()
	{
		super();
	}
	
	public void cancel()
	{
		String sMethod = "cancel";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "cancel");
		super.cancel();
	}
}
