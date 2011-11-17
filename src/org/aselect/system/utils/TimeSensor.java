package org.aselect.system.utils;

import java.util.logging.Level;

import org.aselect.system.logging.SystemLogger;

public class TimeSensor
{		
	private String MODULE = "TimeSensor";
	private SystemLogger _oSystemLogger;

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
		    tv_sec = now / 1000;
		    tv_usec = now - 1000 * tv_sec;
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
	
    private String timeSender = "";  // the sending process
	private String timeSensorId = "";  // unique sensor id
    private String timeSensorRid = "";  // session id
	private String timeSensorTgt = ""; // ticket
	private String timeSensorAppId = ""; // application requested (app1, ...)
	private int timeSensorLevel = -1;  // -1=unused, 0=???, 1=flow complete, 2=detail flow, 3=even more detail
    private int timeSensorType = -1;   // -1=unused, 0=???, 1=filter, 2=filter+agent, 3=...server, 4=...authsp 
    private long timeSensorThread = -1; 
    private boolean timeSensorSuccess = false; 

	public TimeVal td_start = new TimeVal();  // timestamp start
    public TimeVal td_finish = new TimeVal(); // timestamp finish
    public TimeVal td_spent = new TimeVal();  // time spent in milliseconds
    
    /**
	 * Convert milliseconds to TimeVal format
	 * 
	 * @param mSec - the milliseconds
	 * @return the TimeVal string
	 */
    public static String timeSensorMilli2Time(long mSec)
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
    public TimeSensor(SystemLogger systemLogger, String sSenderId)
    {
		_oSystemLogger = systemLogger;
		timeSender = sSenderId;
    }
    
    /**
	 * Timer sensor pack method.
	 * 
	 * @return the packed string that represents the TimeSensor object
	 *
     * Output example: 1320673143.256681,1,1,1320673143.281,1320673143.739,0.458
	 */
    public String timeSensorPack()
    {
	    return String.format("%s,%s,%s,%d,%d,%d,%s,%s,%s,%s,%s,%s", timeSender, timeSensorId,
	    			timeSensorAppId, timeSensorLevel, timeSensorType, timeSensorThread,
	    			td_start.toString(), td_finish.toString(), td_spent.toString(),
	    			isTimeSensorSuccess(), timeSensorRid, timeSensorTgt);
    }
    
    /**
	 * Timer sensor unpack method.
	 * 
	 * @param sPack
	 *            the packed string
	 * @return the time sensor object
	 */
    public void timeSensorUnPack(String sPack)
    {
		String sMethod = "timeSensorUnPack";
    	String[] sUnpacked = sPack.split(",", -1/*also empty fields*/);

    	//_oSystemLogger.log(Level.INFO, MODULE, sMethod, "flds="+sUnpacked.length);
    	int i = 0;
    	try {
	    	timeSender = sUnpacked[i++];
	    	timeSensorId = sUnpacked[i++];
	    	timeSensorAppId = sUnpacked[i++];
	    	timeSensorLevel = Integer.parseInt(sUnpacked[i++]);
	    	timeSensorType = Integer.parseInt(sUnpacked[i++]);
	    	timeSensorThread = Integer.parseInt(sUnpacked[i++]);
	    	
	    	td_start.fromString(sUnpacked[i++]);
	    	td_finish.fromString(sUnpacked[i++]);
	    	td_spent.fromString(sUnpacked[i++]);
	    	timeSensorSuccess = Boolean.parseBoolean(sUnpacked[i++]);
	    	timeSensorRid = sUnpacked[i++];
	    	timeSensorTgt = sUnpacked[i++];
    	}
    	catch (Exception e) {
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Exception:"+e.getClass()+" "+e.getMessage()+" i="+i);
    	}
    }
    
    public void timeSensorSpentPlus(TimeSensor tsOther)
    {
    	td_spent.timeValPlus(tsOther.td_spent);
    }
    
	/**
	 * Timer sensor start.
	 * 
	 * @param level
	 *            the level of detail
	 */
	public void timeSensorStart(int level, int type, long threadId)
	{
		String sMethod = "timeSensorStart";
		
 	    timeSensorType = type;
 	    timeSensorLevel = level;
 	    timeSensorThread = threadId;
	    td_start.timeValNow();
	    td_spent.timeValZero();
	    td_finish.timeValZero();
		_oSystemLogger.log(Level.INFO, MODULE, sMethod, "TS_"+timeSensorThread+" start: st="+td_start.toString());
	}

	/**
	 * Timer sensor pause.
	 */
	public void timeSensorPause()
	{
		String sMethod = "timeSensorPause";
		td_finish.timeValNow();
		_oSystemLogger.log(Level.INFO, MODULE, sMethod, "TS_"+timeSensorThread+" pause: fi="+td_finish.toString());
	}

	/**
	 * Timer sensor resume. Must be called after timer_pause()
	 */
	public void timeSensorResume()
	{
		String sMethod = "timeSensorResume";
	    TimeVal tvNow = new TimeVal();
	    tvNow.timeValNow();
	    String sNow = tvNow.toString();
	    
	    // spent += now - finish;
	    tvNow.timeValMinus(td_finish);
	    String sDiff = tvNow.toString();
	    td_spent.timeValPlus(tvNow);
	    td_finish.timeValZero();
	    _oSystemLogger.log(Level.INFO, MODULE, sMethod, "TS_"+timeSensorThread+
	    					" resume: nw="+sNow+" df="+sDiff+" sp="+td_spent.toString());
	}

	/**
	 * Timer sensor finish.
	 */
	public void timeSensorFinish(boolean bSuccess)
	{
		String sMethod = "timeSensorFinish";
	    TimeVal tvNow = new TimeVal();

	    // TotalSpent = (now - start) - spent;
	    tvNow.timeValNow();
	    td_finish.timeValCopy(tvNow);
	    tvNow.timeValMinus(td_start);
	    tvNow.timeValMinus(td_spent);
	    td_spent.timeValCopy(tvNow);
	    timeSensorSuccess = bSuccess;
	    _oSystemLogger.log(Level.INFO, MODULE, sMethod, "TS_"+timeSensorThread+" finish: "+
	    			td_start.toString()+" "+td_spent.toString()+" "+td_finish.toString()+
	    			" id="+timeSensorId+" level="+timeSensorLevel+" type="+timeSensorType+" ok="+timeSensorSuccess);
	}

	public int getTimeSensorType() { return timeSensorType; }
	public void setTimeSensorType(int tdType) { timeSensorType = tdType; }
	
	public int getTimeSensorLevel() { return timeSensorLevel; }
	public void setTimeSensorLevel(int tdLevel) { timeSensorLevel = tdLevel; }
	
	public String getTimeSensorId() { return timeSensorId; }
	public void setTimeSensorId(String tdId) { timeSensorId = tdId; }
	
    public String getTimeSensorRid() { return timeSensorRid; }
	public void setTimeSensorRid(String timeSensorRid) { this.timeSensorRid = timeSensorRid; }

	public String getTimeSensorTgt() { return timeSensorTgt; }
	public void setTimeSensorTgt(String timeSensorTgt) { this.timeSensorTgt = timeSensorTgt.substring(0, 41); }

	public String getTimeSender() { return timeSender; }
	public void setTimeSender(String timeSender) { this.timeSender = timeSender; }

	public boolean isTimeSensorSuccess() { return timeSensorSuccess; }
	public void setTimeSensorSuccess(boolean timeSensorSuccess) { this.timeSensorSuccess = timeSensorSuccess; }

    public String getTimeSensorAppId() { return timeSensorAppId; }
	public void setTimeSensorAppId(String timeSensorAppId) { this.timeSensorAppId = timeSensorAppId; }
}
