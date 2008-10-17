package org.aselect.server.request.handler.saml20.common;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;

import org.aselect.server.log.ASelectSystemLogger;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLConstants;

public class SignatureUtil
{

	private static final String MODULE = "SignatureUtil";

	/**
	 * Helper method to detect if the HttpServletRequest is signed The
	 * HttpServletRequest is signed if:
	 * <ul>
	 * <li> There is a parameter 'SigAlg' witch contains the value
	 * 'http://www.w3.org/2000/09/xmldsig#'</li>
	 * <li> <b>And</b> there is a parameter 'Signature'</li>
	 * </ul>
	 * 
	 * @param httpRequest
	 * @return boolean
	 */
	@SuppressWarnings("unchecked")
	public static boolean isSigned(HttpServletRequest httpRequest)
	{
		Enumeration<String> enumParameterNames = httpRequest.getParameterNames();

		boolean bSigAlg = false;
		boolean bSignature = false;

		while (enumParameterNames.hasMoreElements() && (!bSigAlg || !bSignature)) {
			String sParameterName = enumParameterNames.nextElement();
			if (!bSigAlg)
				bSigAlg = httpRequest.getParameter(sParameterName).contains(XMLConstants.XMLSIG_NS);
			if (!bSignature)
				bSignature = sParameterName.equals(Signature.DEFAULT_ELEMENT_LOCAL_NAME);
		}
		return bSigAlg && bSignature;
	}

	/**
	 * Helper method to verify the Signature of the httpRequest
	 * 
	 * @param key PublicKey
	 * @param httpRequest HttpServletRequest
	 * @return boolean
	 */
	@SuppressWarnings("unchecked")
	public static boolean verifySignature(PublicKey key, HttpServletRequest httpRequest)
		throws MessageDecodingException
	{
		String sMethod = "verifySignature()";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		systemLogger.log(Level.INFO, MODULE, sMethod, "==== VS "+key);

		java.security.Signature signature;

		String signingAlgo;
		if (key instanceof RSAPublicKey) {
			signingAlgo = "SHA1withRSA";
		}
		else {
			signingAlgo = "SHA1withDSA";
		}

		try {
			// De te verifieren data is de gehele query string minus het
			// 'Signature' deel.

			String sQuery = httpRequest.getQueryString();
			StringTokenizer tokenizer = new StringTokenizer(sQuery, "&");
			String sData = "";
			while (tokenizer.hasMoreTokens()) {
				String s = tokenizer.nextToken();
				if (!s.startsWith("Signature=")) {
					sData += s + "&";
				}
			}
			sData = sData.substring(0, sData.length() - 1); // Delete the
			// last '&'

			signature = java.security.Signature.getInstance(signingAlgo);
			signature.initVerify(key);
			byte[] bData = sData.getBytes();
			signature.update(bData);

			String sSig = httpRequest.getParameter("Signature");
			byte[] bSig = Base64.decode(sSig);
			return signature.verify(bSig);
		}
		catch (Exception e) {
			throw new MessageDecodingException("Unable to verify URL query string", e);
		}
	}

}
