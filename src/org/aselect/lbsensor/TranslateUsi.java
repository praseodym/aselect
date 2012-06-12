package org.aselect.lbsensor;

public class TranslateUsi
{
	String sTransMain;
	long lTransTimeStamp;
	
	public TranslateUsi(String sUsi)
	{
		sTransMain = sUsi;
		lTransTimeStamp = System.currentTimeMillis();
	}
	
	public void refreshTimeStamp()
	{
		lTransTimeStamp = System.currentTimeMillis();
	}
	
	public String getTransMain() { return sTransMain; }
	public long getTransTimeStamp() { return lTransTimeStamp; }
}
