package org.aselect.server.request.handler.saml20.sp.authentication;

import java.util.HashMap;

/**
 * utility class to easily find a tgt by user id
 * 
 */
public class UserToTgtMapper
{

	private static HashMap<String, String> _htMapper = new HashMap<String, String>();

	public static void put(String userName, String tgtId)
	{
		_htMapper.put(userName, tgtId);
	}

	public static String getTgtId(String userName)
	{
		return _htMapper.get(userName);
	}

}
