package org.aselect.system.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Hashtable;
import java.util.logging.Level;

import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;

public class FileCache
{
	private static final String MODULE = "Utils";

	String sFileName;
	String sFileContent;
	long lTimeRefreshed;
	boolean bFileExists;
	
	static long lFileCacheKeep = 900; // seconds
	
	public static long getFileCacheKeep() { return lFileCacheKeep; }
	public static void setFileCacheKeep(long lKeepCache) { FileCache.lFileCacheKeep = lKeepCache; }

	static Hashtable<String, FileCache> theFileCache = new Hashtable<String, FileCache>();
	
	/**
	 * Adds the file to the cache.
	 * 
	 * @param sName
	 *            the file name
	 * @param sContent
	 *            the file content
	 * @param lRefreshed
	 *            the time when the file was last refreshed in the cache
	 */
	static void addFile(String sName, String sContent, long lRefreshed, SystemLogger oSysLog)
	{
		String sMethod = "addFile";
		//oSysLog.log(Level.INFO, MODULE, sMethod, "HTML add "+sName+" refresh="+lRefreshed/1000+
		//										(Utils.hasValue(sContent)?" present": " absent"));
		FileCache fc = new FileCache();
		fc.sFileName = sName;
		fc.lTimeRefreshed = lRefreshed;
		fc.sFileContent = sContent;
		theFileCache.put(sName, fc);
	}
	
	/**
	 * Gets the file.
	 * 
	 * @param sFileName
	 *          the file name
	 * @param oSysLog
	 *          the system log
	 * @return the file content,
	 * 			can be "" if the file is not present
	 * @throws ASelectException
	 *			if reading the file failed
	 */
	static String getFile(String sFileName, SystemLogger oSysLog)
	throws ASelectException
	{
		String sMethod = "getFile";
	    long now = System.currentTimeMillis();

		FileCache fCache = theFileCache.get(sFileName);
		//if (fCache != null)
		//	oSysLog.log(Level.INFO, MODULE, sMethod, "HTML "+sFileName+" CACHED="+(fCache.lTimeRefreshed/1000)+" now="+now/1000);
		//else
		//	oSysLog.log(Level.INFO, MODULE, sMethod, "HTML "+sFileName+" NOT CACHED"+" now="+now/1000);

		if (fCache != null && now - fCache.lTimeRefreshed < 1000*lFileCacheKeep) {
			oSysLog.log(Level.INFO, MODULE, sMethod, "HTML "+sFileName+" CACHED"+
					(Utils.hasValue(fCache.sFileContent)?" present": " absent")+", cache age="+(now - fCache.lTimeRefreshed)/1000);
			return fCache.sFileContent;  // present in the cache and reasonably up-to-date
		}
		
		// We don't have the file yet, or it was checked too long ago
		// Access the file system
		File fFile = new File(sFileName);
		if (!fFile.exists()) {
			oSysLog.log(Level.INFO, MODULE, sMethod, "HTML "+sFileName+" file absent"+(fCache!=null?", re-checked": ""));
			addFile(sFileName, "", now, oSysLog);  // register absence
			return null;
		}
		//oSysLog.log(Level.INFO, MODULE, sMethod, "HTML "+sFileName+" mod="+fFile.lastModified()/1000);
		
		// The file is present on the file system
		if (fCache != null && fFile.lastModified() < fCache.lTimeRefreshed) {
			// We have the file and it was not changed since entry
			oSysLog.log(Level.INFO, MODULE, sMethod, "HTML "+sFileName+" not modified, re-checked"+
					", file age="+(now-fFile.lastModified())/1000);
			fCache.lTimeRefreshed = now;  // register refresh
			return fCache.sFileContent;  // File was not modified
		}

		// Read the file
		oSysLog.log(Level.INFO, MODULE, sMethod, "HTML "+sFileName+(fCache!=null?" re-read file": " read file")+
				", file age="+(now-fFile.lastModified())/1000);
		BufferedReader brInput = null;
		String sResult = "", sLine;
		try {
			brInput = new BufferedReader(new InputStreamReader(new FileInputStream(fFile)));
			while ((sLine = brInput.readLine()) != null) {
				sResult += sLine + "\n";
			}
			addFile(sFileName, sResult, now, oSysLog);
			return sResult;
		}
		catch (IOException e) {
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}
		finally {
			if (brInput != null)
				try {
					brInput.close();
				}
				catch (IOException e) {
					throw new ASelectException(Errors.ERROR_ASELECT_IO);
				}
		}
	}
}
