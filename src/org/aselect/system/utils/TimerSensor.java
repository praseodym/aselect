package org.aselect.system.utils;

import java.util.logging.Level;

import org.aselect.system.logging.SystemLogger;

public class TimerSensor
{		
	private String MODULE = "TimerSensor";
	private SystemLogger _oSystemLogger;

	// Internal class
	public class TimeVal
	{
		static final int OVERFLOW = 1000;
		long tv_sec = 0;
		long tv_usec = 0;

		// We're working with milliseconds
		public String toString()
		{
		    return String.format("%d.%03d", tv_sec, tv_usec);
		}

		// 123.456 or 123.004567 or 123.456789 or 123.000012
		private void fromString(String sUnpacked)
		{
			String[] aElem = sUnpacked.split("\\.");
			int len = aElem[1].length();
			tv_sec = Integer.parseInt(aElem[0]);
			tv_usec = Integer.parseInt(aElem[1]);
			if (len > 3) {  // round value
				tv_usec += (OVERFLOW / 2);
				tv_usec /= OVERFLOW;
				if (tv_usec >= OVERFLOW) {
					tv_usec -= OVERFLOW;
					tv_sec++;
				}
			}
		}

		public void timeValZero()
		{
		    tv_sec = 0;
		    tv_usec = 0;
		}

		public void timeValNow()
		{
		    long now = System.currentTimeMillis();
		    timeValThen(now);
		}
		
		public void timeValThen(long timeThen)
		{
		    tv_sec = timeThen / 1000;
		    tv_usec = timeThen - 1000 * tv_sec;
		}

		public void timeValPlus(TimeVal p2)
		{

		    tv_sec += p2.tv_sec;
		    tv_usec += p2.tv_usec;

		    if (tv_usec > OVERFLOW) {
		        tv_usec -= OVERFLOW;
		        tv_sec++;
		    }
		}

		public void timeValMinus(TimeVal p2)
		{
		    tv_sec -= p2.tv_sec;
		    tv_usec -= p2.tv_usec;
		   if (tv_usec < 0) {
		        tv_sec--;
		        tv_usec += OVERFLOW;
		    }
		}

		public void timeValCopy(TimeVal p2)
		{
		    tv_sec = p2.tv_sec;
		    tv_usec = p2.tv_usec;
		}

		// return: 1 this is bigger, 0 equal, -1 p2 is bigger
		public int timeValCompare(TimeVal p2)
		{
			if (tv_sec > p2.tv_sec)
				return 1;
			if (tv_sec < p2.tv_sec)
				return -1;
			// seconds equal
			if (tv_usec > p2.tv_usec)
				return 1;
			if (tv_usec < p2.tv_usec)
				return -1;
		    return 0;
		}
		
		public long getSeconds() { return tv_sec; }
		public void setSeconds(long tvSec) { tv_sec = tvSec; }

		public long getMicro() { return tv_usec; }
		public void setMicro(long tvUsec) { tv_usec = tvUsec; }
	}
	
    private String timerSensorSender = "";  // the sending process
	private String timerSensorId = "";  // unique sensor id
	private String timerSensorAppId = ""; // application requested (app1, ...)
	private int timerSensorLevel = -1;  // -1=unused, 0=???, 1=flow complete, 2=detail flow, 3=even more detail
    private int timerSensorType = -1;   // -1=unused, 0=???, 1=filter, 2=filter+agent, 3=...server, 4=...authsp 
    private long timerSensorThread = -1;
	public TimeVal td_start = new TimeVal();  // timestamp start
    public TimeVal td_finish = new TimeVal(); // timestamp finish
    public TimeVal td_spent = new TimeVal();  // time spent in milliseconds
    private boolean timerSensorSuccess = false; 
    private String timerSensorRid = "";  // session id
	private String timerSensorTgt = ""; // ticket
    
    /**
	 * Convert milliseconds to TimeVal format
	 * 
	 * @param mSec - the milliseconds
	 * @return the TimeVal string
	 */
    public static String timerSensorMilli2Time(long mSec)
    {
       long sec = mSec / 1000;
	    long usec = mSec - 1000 * sec;
    	return String.format("%d.%03d", sec, usec);
    }

    /**
	 * Instantiates a new time sensor.
	 * 
	 * @param systemLogger
	 *            the system logger
	 */
    public TimerSensor(SystemLogger systemLogger, String sSenderId)
    {
		_oSystemLogger = systemLogger;
		timerSensorSender = sSenderId;
    }
    
    public TimerSensor(TimerSensor ts)
    {
    	timerSensorUnPack(ts.timerSensorPack());
    }
    
    /**
	 * Timer sensor pack method.
	 * 
	 * @return the packed string that represents the TimerSensor object
	 *
     * Output example: agt_vtk,1378644913.063682,,1,2,1102,1378644913.068,1378644913.068,0.000,false,,
	 */
    public String timerSensorPack()
    {
	    return String.format("%s,%s,%s,%d,%d,%d,%s,%s,%s,%s,%s,%s", timerSensorSender, timerSensorId,
	    			timerSensorAppId, timerSensorLevel, timerSensorType, timerSensorThread,
	    			td_start.toString(), td_finish.toString(), td_spent.toString(),
	    			isTimerSensorSuccess(), timerSensorRid, timerSensorTgt);
    }
    
    /**
	 * Timer sensor unpack method.
	 * 
	 * @param sPack
	 *            the packed string
	 * @return the time sensor object
	 */
    public void timerSensorUnPack(String sPack)
    {
		String sMethod = "timerSensorUnPack";
    	String[] sUnpacked = sPack.split(",", -1/*also empty fields*/);

    	//_oSystemLogger.log(Level.INFO, MODULE, sMethod, "flds="+sUnpacked.length);
    	int i = 0;
    	try {
	    	timerSensorSender = sUnpacked[i++];
	    	timerSensorId = sUnpacked[i++];
	    	timerSensorAppId = sUnpacked[i++];
	    	timerSensorLevel = Integer.parseInt(sUnpacked[i++]);
	    	timerSensorType = Integer.parseInt(sUnpacked[i++]);
	    	timerSensorThread = Integer.parseInt(sUnpacked[i++]);
	    	
	    	td_start.fromString(sUnpacked[i++]);
	    	td_finish.fromString(sUnpacked[i++]);
	    	td_spent.fromString(sUnpacked[i++]);
	    	timerSensorSuccess = Boolean.parseBoolean(sUnpacked[i++]);
	    	timerSensorRid = sUnpacked[i++];
	    	timerSensorTgt = sUnpacked[i++];
    	}
    	catch (Exception e) {
			_oSystemLogger.log(Level.FINEST, MODULE, sMethod, "Exception:"+e.getClass()+" "+e.getMessage()+" i="+i);
    	}
    }

    public void timerSensorSpentPlus(TimerSensor tsOther)
    {
    	td_spent.timeValPlus(tsOther.td_spent);
    }

	/**
	 * Timer sensor start.
	 * 
	 * @param level
	 *            the level of detail
	 */
	public void timerSensorStart(int level, int type, long threadId)
	{
	    long now = System.currentTimeMillis();
	    timerSensorStart(now, level, type, threadId);
	}

	public void timerSensorStart(long lStartTime, int level, int type, long threadId)
	{
		String sMethod = "timerSensorStart";

		timerSensorType = type;
 	    timerSensorLevel = level;
 	    timerSensorThread = threadId;
	    td_start.timeValThen(lStartTime);
	    td_spent.timeValZero();
	    td_finish.timeValZero();
		_oSystemLogger.log(Level.FINEST, MODULE, sMethod, "TS_"+timerSensorThread+" start: st="+td_start.toString());
	}

	/**
	 * Timer sensor pause.
	 */
	public void timerSensorPause()
	{
		String sMethod = "timerSensorPause";
		td_finish.timeValNow();
		_oSystemLogger.log(Level.FINEST, MODULE, sMethod, "TS_"+timerSensorThread+" pause: fi="+td_finish.toString());
	}

	/**
	 * Timer sensor resume. Must be called after timer_pause()
	 */
	public void timerSensorResume()
	{
		String sMethod = "timerSensorResume";
	    TimeVal tvNow = new TimeVal();
	    tvNow.timeValNow();
	    String sNow = tvNow.toString();
	    
	    // spent += now - finish;
	    tvNow.timeValMinus(td_finish);
	    String sDiff = tvNow.toString();
	    td_spent.timeValPlus(tvNow);
	    td_finish.timeValZero();
	    _oSystemLogger.log(Level.FINEST, MODULE, sMethod, "TS_"+timerSensorThread+
	    				" resume: nw="+sNow+" df="+sDiff+" sp="+td_spent.toString());
	}

	/**
	 * Timer sensor finish.
	 */
	public void timerSensorFinish(boolean bSuccess)
	{
	    long now = System.currentTimeMillis();
	    timerSensorFinish(now, bSuccess);
	}
	
	public void timerSensorFinish(long timeFinish, boolean bSuccess)
	{
		String sMethod = "timerSensorFinish";
	    TimeVal tvNow = new TimeVal();

	    // TotalSpent = (now - start) - spent;
	    tvNow.timeValThen(timeFinish);
	    td_finish.timeValCopy(tvNow);
	    tvNow.timeValMinus(td_start);
	    tvNow.timeValMinus(td_spent);
	    td_spent.timeValCopy(tvNow);
	    timerSensorSuccess = bSuccess;
	    _oSystemLogger.log(Level.FINEST, MODULE, sMethod, "TS_"+timerSensorThread+" finish: "+
	    			td_start.toString()+" "+td_spent.toString()+" "+td_finish.toString()+
	    			" id="+timerSensorId+" level="+timerSensorLevel+" type="+timerSensorType+" ok="+timerSensorSuccess);
	}

	public int getTimerSensorType() { return timerSensorType; }
	public void setTimerSensorType(int tdType) { timerSensorType = tdType; }
	
	public int getTimerSensorLevel() { return timerSensorLevel; }
	public void setTimerSensorLevel(int tdLevel) { timerSensorLevel = tdLevel; }
	
	public String getTimerSensorId() { return timerSensorId; }
	public void setTimerSensorId(String tdId) { 
		timerSensorId = tdId;
	    _oSystemLogger.log(Level.INFO, MODULE, "setTimerSensorId", "TS_"+timerSensorThread+" id="+timerSensorId);
	}
	
    public String getTimerSensorRid() { return timerSensorRid; }
	public void setTimerSensorRid(String timerSensorRid) { this.timerSensorRid = timerSensorRid; }

	public String getTimerSensorTgt() { return timerSensorTgt; }
	public void setTimerSensorTgt(String timerSensorTgt) { this.timerSensorTgt = timerSensorTgt.substring(0, 41); }

	public String getTimerSensorSender() { return timerSensorSender; }
	public void setTimerSensorSender(String timerSender) { this.timerSensorSender = timerSender; }

	public boolean isTimerSensorSuccess() { return timerSensorSuccess; }
	public void setTimerSensorSuccess(boolean timerSensorSuccess) { this.timerSensorSuccess = timerSensorSuccess; }

    public String getTimerSensorAppId() { return timerSensorAppId; }
	public void setTimerSensorAppId(String timerSensorAppId) { this.timerSensorAppId = timerSensorAppId; }
}
