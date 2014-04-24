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

package org.aselect.server.utils;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringEscapeUtils;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.BASE64Encoder;

/**
 * @author RH
 * 
 * 
 * Utility class containing various methods specific for server
 * Avoids cyclic dependency system<->server
 *
 * Methods in this class must be static
 * 
 */
public class Utils
{
	private static final String MODULE = "Utils";

	/**
	 * Present organization choice to the user.
	 * 
	 * @param configManager
	 *            the config manager
	 * @param htSessionContext
	 *            the session context
	 * @param sRid
	 *            the rid
	 * @param sLanguage
	 *            the language
	 * @param hUserOrganizations
	 *            the list of user organizations
	 * @return the string
	 * @throws ASelectConfigException
	 * @throws ASelectException
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String presentOrganizationChoice(HttpServletRequest servletRequest, ASelectConfigManager configManager, HashMap htSessionContext,
			String sRid, String sLanguage, HashMap<String, String> hUserOrganizations)
	throws ASelectConfigException, ASelectException, IOException
	{
		String sUserId = (String)htSessionContext.get("user_id");
		String sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);
		String sServerId = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);
		String sSelectForm = configManager.loadHTMLTemplate(null, "orgselect", sLanguage, sLanguage);
		
		sSelectForm = org.aselect.system.utils.Utils.replaceString(sSelectForm, "[request]", "org_choice");
		if (sUserId != null) sSelectForm = org.aselect.system.utils.Utils.replaceString(sSelectForm, "[user_id]", sUserId);
		sSelectForm = org.aselect.system.utils.Utils.replaceString(sSelectForm, "[rid]", sRid);
		sSelectForm = org.aselect.system.utils.Utils.replaceString(sSelectForm, "[a-select-server]", sServerId);
		sSelectForm = org.aselect.system.utils.Utils.replaceString(sSelectForm, "[aselect_url]", sServerUrl + "/org_choice");
		
		StringBuffer sb = new StringBuffer();
		Set<String> keySet = hUserOrganizations.keySet();
		Iterator<String> it = keySet.iterator();
		while(it.hasNext()) {
			String sOrgId = it.next();
			String sOrgName = hUserOrganizations.get(sOrgId);
//			sb.append("<option value=").append(sOrgId).append(">").append(sOrgName);
			sb.append("<option value=").append(sOrgId).append(">").append(StringEscapeUtils.escapeHtml(sOrgName));
			sb.append("</option>");
		}
		sSelectForm = org.aselect.system.utils.Utils.replaceString(sSelectForm, "[user_organizations]", sb.toString());
		sSelectForm = configManager.updateTemplate(sSelectForm, htSessionContext, servletRequest);
		return sSelectForm;
	}

	/**
	 * Decode the credentials passed.
	 * 
	 * @param credentials
	 *            the user's credentials
	 * @param oSysLog
	 * @return the decoded credentials
	 * @throws ASelectException
	 */
	public static String decodeCredentials(String credentials, SystemLogger oSysLog)
	throws ASelectException
	{
		String _sMethod = "decodeCredentials";
		String decodedCredentials = null;
		try {
			oSysLog.log(Level.INFO, MODULE, _sMethod, "Credentials are " + credentials);
			byte[] TgtBlobBytes = CryptoEngine.getHandle().decryptTGT(credentials);
			decodedCredentials = org.aselect.system.utils.Utils.byteArrayToHexString(TgtBlobBytes);
		}
		catch (ASelectException as) {
			oSysLog.log(Level.WARNING, MODULE, _sMethod, "failed to decrypt credentials", as);
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
		}
		return decodedCredentials;
	}

	/**
	 * Serialize attributes contained in a HashMap. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method serializes attributes contained in a HashMap:
	 * <ul>
	 * <li>They are formatted as attr1=value1&attr2=value2;...
	 * <li>If a "&amp;" or a "=" appears in either the attribute name or value, they are transformed to %26 or %3d
	 * respectively.
	 * <li>The end result is base64 encoded.
	 * </ul>
	 * <br>
	 * 
	 * @param htAttributes - HashMap containing all attributes
	 * @return Serialized representation of the attributes
	 * @throws ASelectException - If serialization fails.
	 */
	public static String serializeAttributes(HashMap htAttributes)
	throws ASelectException
	{
		final String sMethod = "serializeAttributes";
		try {
			if (htAttributes == null || htAttributes.isEmpty())
				return null;
			StringBuffer sb = new StringBuffer();
	
			Set keys = htAttributes.keySet();
			for (Object s : keys) {
				String sKey = (String) s;
				// for (Enumeration e = htAttributes.keys(); e.hasMoreElements(); ) {
				// String sKey = (String)e.nextElement();
				Object oValue = htAttributes.get(sKey);
	
				if (oValue instanceof Vector) {// it's a multivalue attribute
					Vector vValue = (Vector) oValue;
	
					sKey = URLEncoder.encode(sKey + "[]", "UTF-8");
					Enumeration eEnum = vValue.elements();
					while (eEnum.hasMoreElements()) {
						String sValue = (String) eEnum.nextElement();
	
						// add: key[]=value
						sb.append(sKey).append("=").append(URLEncoder.encode(sValue, "UTF-8"));
						if (eEnum.hasMoreElements())
							sb.append("&");
					}
				}
				else if (oValue instanceof String) {// it's a single value attribute
					String sValue = (String) oValue;
					sb.append(URLEncoder.encode(sKey, "UTF-8")).append("=").append(URLEncoder.encode(sValue, "UTF-8"));
				}
	
				// if (e.hasMoreElements())
				sb.append("&");
			}
			int len = sb.length();
			String result = sb.substring(0, len - 1);
			BASE64Encoder b64enc = new BASE64Encoder();
			return b64enc.encode(result.getBytes("UTF-8"));
		}
		catch (Exception e) {
			ASelectSystemLogger logger = ASelectSystemLogger.getHandle();
			logger.log(Level.WARNING, MODULE, sMethod, "Could not serialize attributes", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Deserialize attributes and convertion to a <code>HashMap</code>. <br/>
	 * Conatins support for multivalue attributes, with name of type <code>
	 * String</code> and value of type <code>Vector</code>.
	 * 
	 * @param sSerializedAttributes
	 *            the serialized attributes.
	 * @return The deserialized attributes (key,value in <code>HashMap</code>)
	 * @throws ASelectException
	 *             If URLDecode fails
	 */
	public static HashMap deserializeAttributes(String sSerializedAttributes)
	throws ASelectException
	{
		String sMethod = "deSerializeAttributes";
		HashMap htAttributes = new HashMap();
		if (sSerializedAttributes != null) {  // Attributes available
			try {  // base64 decode
				BASE64Decoder base64Decoder = new BASE64Decoder();
				String sDecodedUserAttrs = new String(base64Decoder.decodeBuffer(sSerializedAttributes));
	
				// decode & and = chars
				String[] saAttrs = sDecodedUserAttrs.split("&");
				for (int i = 0; i < saAttrs.length; i++) {
					int iEqualChar = saAttrs[i].indexOf("=");
					String sKey = "";
					String sValue = "";
					Vector vVector = null;
	
					if (iEqualChar > 0) {
						sKey = URLDecoder.decode(saAttrs[i].substring(0, iEqualChar), "UTF-8");
						sValue = URLDecoder.decode(saAttrs[i].substring(iEqualChar + 1), "UTF-8");
	
						if (sKey.endsWith("[]")) { // it's a multi-valued attribute
							// Strip [] from sKey
							sKey = sKey.substring(0, sKey.length() - 2);
							if ((vVector = (Vector) htAttributes.get(sKey)) == null)
								vVector = new Vector();
							vVector.add(sValue);
						}
					}
					else
						sKey = URLDecoder.decode(saAttrs[i], "UTF-8");
	
					if (vVector != null)  // store multivalue attribute
						htAttributes.put(sKey, vVector);
					else  // store singlevalue attribute
						htAttributes.put(sKey, sValue);
				}
			}
			catch (Exception e) {
				ASelectSystemLogger logger = ASelectSystemLogger.getHandle();
				logger.log(Level.WARNING, Utils.MODULE, sMethod, "Error during deserialization of attributes", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
		}
		return htAttributes;
	}
}
