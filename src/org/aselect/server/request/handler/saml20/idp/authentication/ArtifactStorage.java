/*
 * Created on 16-aug-2007
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package org.aselect.server.request.handler.saml20.idp.authentication;

import java.util.Hashtable;

public class ArtifactStorage
{
	private static Hashtable _htStorage;

	private static void init()
	{
		_htStorage = new Hashtable();
	}

	public static void put(Object key, Object value)
	{
		if (_htStorage == null) {
			init();
		}
		_htStorage.put(key, value);
	}

	public static Object get(Object key)
	{
		return _htStorage.get(key);
	}
}
