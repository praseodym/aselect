/*
 * Created on 28-aug-2007
 */
package org.aselect.server.request.handler.xsaml20;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import java.util.Map.Entry;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.RequestedAuthnContext;

public class SecurityLevel
{
	final static String MODULE = "SecurityLevel";

	// Saml text
	final private static String UNSPECIFIED_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
	final private static String PASSWORD_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
	
	final private static String PASSWORDPROTECTEDTRANSPORT_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
	final private static String MOBILETWOFACTORUNREGISTERED_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered";
	//final private static String MOBILETWOFACTORCONTRACT_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken";  // Novell
	final private static String MOBILETWOFACTORCONTRACT_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";
	final private static String SMARTCARDPKI_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI";

	final private static int LEVEL_NOT_FOUND = -1;
	final private static int LEVEL_MIN = 0;  // used for searching
	final private static int LEVEL_NULL = 5;
	final private static int LEVEL_POOR = 7;	// RH, 20120124, n
	final private static int LEVEL_LOW = 10;
	final private static int LEVEL_BETTER = 15;  // 20100714 was 5?!?
	final private static int LEVEL_MEDIUM = 20;
	final private static int LEVEL_HIGH = 30;
	final private static int LEVEL_MAX = 999; // used for searching
	
	// 20090109: Bauke changed levels
	//final private static int LEVEL_NULL = 5; // 1;
	//final private static int LEVEL_LOW = 10; // 2;
	//final private static int LEVEL_MEDIUM = 20; // 3;
	//final private static int LEVEL_HIGH = 30; // 4;

	// public final static String BN_EMPTY = "empty"; // no longer 20090501
	final private static String BN_NUL = "5";
	final private static String BN_POVER = "7";	// RH, 20120124, n
	final private static String BN_LAAG = "10";
	final private static String BN_BETTER = "15";
	final private static String BN_MEDIUM = "20";
	final private static String BN_HOOG = "30";
	
	final public static String BN_NOT_FOUND = "not_found";
//	private static String[] aAlllowedLevels = {BN_NUL, BN_LAAG, BN_BETTER, BN_MEDIUM,  BN_HOOG} ;	// RH, 20120124, o
	private static String[] aAlllowedLevels = {BN_NUL, BN_POVER, BN_LAAG, BN_BETTER, BN_MEDIUM,  BN_HOOG} ;	// RH, 20120124, n
	public static Set<String> ALLOWEDLEVELS = new HashSet( Arrays.asList(aAlllowedLevels) );

	/**
	 * Convert level to authn context class ref uri.
	 * 
	 * @param sLevel
	 *            the level
	 * @param systemLogger
	 *            the system logger
	 * @param sModule
	 *            the module
	 * @return the string
	 * @throws ASelectException
	 */
	public static String convertLevelToAuthnContextClassRefURI(String sLevel, ASelectSystemLogger systemLogger)
	throws ASelectException
	{
		String sMethod = "convertLevelToAuthnContextClassRefURI";

		int iLevel;
		try {
			iLevel = Integer.parseInt(sLevel);
		}
		catch (Exception e) {
			if (systemLogger != null)
				systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unable to parse level value: " + sLevel, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		switch (iLevel) {
		case LEVEL_NULL:
			return UNSPECIFIED_URI;
		case LEVEL_POOR:	// RH, 20120124, sn
			return PASSWORD_URI;	// RH, 20120124, en
		case LEVEL_LOW:
			return PASSWORDPROTECTEDTRANSPORT_URI;
		case LEVEL_BETTER:
			return MOBILETWOFACTORUNREGISTERED_URI;
		case LEVEL_MEDIUM:
			return MOBILETWOFACTORCONTRACT_URI;
		case LEVEL_HIGH:
			return SMARTCARDPKI_URI;
		}
		if (systemLogger != null)
			systemLogger.log(Level.SEVERE, MODULE, sMethod, "Level value: " + sLevel + " is not valid.");
		throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
	}

	/**
	 * Convert authn context class ref uri to level.
	 * 
	 * @param sAuthnContextClassRefURI
	 *            the s authn context class ref uri
	 * @param systemLogger
	 *            the system logger
	 * @param sModule
	 *            the s module
	 * @return the string
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static String convertAuthnContextClassRefURIToLevel(String sAuthnContextClassRefURI,
			ASelectSystemLogger systemLogger)
	throws ASelectException
	{
		String sMethod = "convertAuthnContextClassRefURIToLevel";

		try {
			if (sAuthnContextClassRefURI.equals(UNSPECIFIED_URI))
				return String.valueOf(LEVEL_NULL);
			else if (sAuthnContextClassRefURI.equals(PASSWORD_URI))		// RH, 20120124, sn
				return String.valueOf(LEVEL_POOR);	// RH, 20120124, en
			else if (sAuthnContextClassRefURI.equals(PASSWORDPROTECTEDTRANSPORT_URI))
				return String.valueOf(LEVEL_LOW);
			else if (sAuthnContextClassRefURI.equals(MOBILETWOFACTORUNREGISTERED_URI))
				return String.valueOf(LEVEL_BETTER);
			else if (sAuthnContextClassRefURI.equals(MOBILETWOFACTORCONTRACT_URI))
				return String.valueOf(LEVEL_MEDIUM);
			else if (sAuthnContextClassRefURI.equals(SMARTCARDPKI_URI))
				return String.valueOf(LEVEL_HIGH);

			if (systemLogger != null)
				systemLogger.log(Level.SEVERE, MODULE, sMethod, "AuthnContextClassRefURI value: "
						+ sAuthnContextClassRefURI + " is not valid.");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		catch (Exception e) {
			if (systemLogger != null)
				systemLogger.log(Level.SEVERE, MODULE, sMethod, "", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);

		}
	}

	
	/**
	 * Gets the Security Level.
	 * 
	 * @param requestedAuthnContext
	 *            the requested authn context
	 * @param systemLogger
	 *            the system logger
	 * @return the Security Level
	 */
	public static String getSecurityLevel(RequestedAuthnContext requestedAuthnContext, ASelectSystemLogger systemLogger)
	{
		return getSecurityLevel(requestedAuthnContext, systemLogger, null);
	}
	
	/**
	 * Gets the Security Level.
	 * 
	 * @param requestedAuthnContext
	 *            the requested authn context
	 * @param systemLogger
	 *            the system logger
	 * @param secLevels
	 *            HashMap with mapping from key=level to value=AuthnContextClassRef
	 * @return the Security Level
	 */
//	public static String getSecurityLevel(RequestedAuthnContext requestedAuthnContext, ASelectSystemLogger systemLogger)
	public static String getSecurityLevel(RequestedAuthnContext requestedAuthnContext, ASelectSystemLogger systemLogger, HashMap<String, String> secLevels )
	{
		String sMethod = "getSecurityLevel";
		final int EXACT = 0;
		final int MINIMUM = 1;
		final int MAXIMUM = 2;
		final int BETTER = 3;

		if (requestedAuthnContext != null) {
			int iComparison = EXACT;
			AuthnContextComparisonTypeEnumeration authnContextComparisonTypeEnumeration =
								requestedAuthnContext.getComparison();
			if (authnContextComparisonTypeEnumeration != null) {
				if (authnContextComparisonTypeEnumeration.equals(AuthnContextComparisonTypeEnumeration.MINIMUM)) {
					iComparison = MINIMUM;
				}
				else if (authnContextComparisonTypeEnumeration.equals(AuthnContextComparisonTypeEnumeration.MAXIMUM)) {
					iComparison = MAXIMUM;
				}
				else if (authnContextComparisonTypeEnumeration.equals(AuthnContextComparisonTypeEnumeration.BETTER)) {
					iComparison = BETTER;
				}
			}

			List<AuthnContextClassRef> authnContextClassRefs = requestedAuthnContext.getAuthnContextClassRefs();
			ListIterator<AuthnContextClassRef> itr = authnContextClassRefs.listIterator();

			String sCurrentAuthnContextClassRef = null;
			String sMatchedBetrouwheidsNiveau = BN_NOT_FOUND;
			int iCurrentBetrouwheidsNiveau = LEVEL_NOT_FOUND;

			switch (iComparison) {
			case EXACT:
				while (itr.hasNext() && sMatchedBetrouwheidsNiveau == BN_NOT_FOUND) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
//					sMatchedBetrouwheidsNiveau = getSecurityLevelFromContext(sCurrentAuthnContextClassRef);
					sMatchedBetrouwheidsNiveau = getSecurityLevelFromContext(sCurrentAuthnContextClassRef, secLevels);
					
				}
				break;

			case MINIMUM:
				int iCurrentMinBetrouwheidsNiveau = LEVEL_MAX;
				while (itr.hasNext()) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
//					iCurrentBetrouwheidsNiveau = getIntSecurityLevel(sCurrentAuthnContextClassRef);
					iCurrentBetrouwheidsNiveau = getIntSecurityLevel(sCurrentAuthnContextClassRef, secLevels);
					if (iCurrentBetrouwheidsNiveau != LEVEL_NOT_FOUND
							&& iCurrentBetrouwheidsNiveau < iCurrentMinBetrouwheidsNiveau)
						iCurrentMinBetrouwheidsNiveau = iCurrentBetrouwheidsNiveau;
				}
				sMatchedBetrouwheidsNiveau = getStringSecurityLevel(iCurrentMinBetrouwheidsNiveau);
				break;

			case BETTER:
				int iCurrentBestBetrouwheidsNiveau = LEVEL_MIN;
				while (itr.hasNext()) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
//					iCurrentBetrouwheidsNiveau = getIntSecurityLevel(sCurrentAuthnContextClassRef);
					iCurrentBetrouwheidsNiveau = getIntSecurityLevel(sCurrentAuthnContextClassRef, secLevels);
					if (iCurrentBetrouwheidsNiveau != LEVEL_NOT_FOUND
							&& iCurrentBetrouwheidsNiveau > iCurrentBestBetrouwheidsNiveau)
						iCurrentBestBetrouwheidsNiveau = iCurrentBetrouwheidsNiveau;
				}
				if (iCurrentBestBetrouwheidsNiveau == LEVEL_NULL)
					iCurrentBestBetrouwheidsNiveau = LEVEL_LOW;
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_POOR)			// RH, 20120124, sn
					iCurrentBestBetrouwheidsNiveau = LEVEL_LOW;			// RH, 20120124, en
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_LOW)
					iCurrentBestBetrouwheidsNiveau = LEVEL_BETTER;
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_BETTER)
					iCurrentBestBetrouwheidsNiveau = LEVEL_MEDIUM;
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_MEDIUM)
					iCurrentBestBetrouwheidsNiveau = LEVEL_HIGH;
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_HIGH)
					iCurrentBestBetrouwheidsNiveau = LEVEL_MAX;

				sMatchedBetrouwheidsNiveau = getStringSecurityLevel(iCurrentBestBetrouwheidsNiveau);
				break;

			case MAXIMUM:
				int iCurrentMaxBetrouwheidsNiveau = LEVEL_MIN;
				while (itr.hasNext()) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
//					iCurrentBetrouwheidsNiveau = getIntSecurityLevel(sCurrentAuthnContextClassRef);
					iCurrentBetrouwheidsNiveau = getIntSecurityLevel(sCurrentAuthnContextClassRef, secLevels);
					if (iCurrentBetrouwheidsNiveau != LEVEL_NOT_FOUND
							&& iCurrentBetrouwheidsNiveau > iCurrentMaxBetrouwheidsNiveau)
						iCurrentMaxBetrouwheidsNiveau = iCurrentBetrouwheidsNiveau;
				}
				sMatchedBetrouwheidsNiveau = getStringSecurityLevel(iCurrentMaxBetrouwheidsNiveau);
			}
			systemLogger.log(Level.INFO, MODULE, sMethod, "Level=" + sMatchedBetrouwheidsNiveau);
			return sMatchedBetrouwheidsNiveau;  // can be BN_NOTFOUND

		}
		// 20090501, Bauke: Since the <RequestedAuthnContext> element is optional,
		// we return the lowest known level here. (no restriction on the level is required)
		return BN_NUL; // BN_EMPTY;
	}
	
	/**
	 * Gets the Security Level as a String
	 * 
	 * @param sCurrentAuthnContextClassRef
	 *            AuthnContext class ref
	 * @return the Security Level
	 */
	private static String getSecurityLevelFromContext(String sAuthnContextClassRef)
	{
		if (sAuthnContextClassRef.equals(UNSPECIFIED_URI))
			return BN_NUL;
		else if (sAuthnContextClassRef.equals(PASSWORD_URI))				// RH, 20120124, sn
			return BN_POVER;						// RH, 20120124, en
		else if (sAuthnContextClassRef.equals(PASSWORDPROTECTEDTRANSPORT_URI))
			return BN_LAAG;
		else if (sAuthnContextClassRef.equals(MOBILETWOFACTORUNREGISTERED_URI))
			return BN_BETTER;
		else if (sAuthnContextClassRef.equals(MOBILETWOFACTORCONTRACT_URI))
			return BN_MEDIUM;
		else if (sAuthnContextClassRef.equals(SMARTCARDPKI_URI))
			return BN_HOOG;

		return BN_NOT_FOUND;
	}

	/**
	 * Convert contextRef to Level (as String) from supplied HashMap with key=level, value=ContextRef
	 * 
	 * @param sAuthnContextClassRef
	 *           the reference to look for
	 * @param secLevels
	 *            HashMap with mapping from key=level to value=AuthnContextClassRef
	 * @return the Security Level or BN_NUL if not found
	 */
	private static String getSecurityLevelFromContext(String sAuthnContextClassRef, HashMap<String, String> secLevels ) {
		if (secLevels == null) {	// backward compatibility
			return  getSecurityLevelFromContext(sAuthnContextClassRef);
		} else {
			String level = BN_NOT_FOUND;
			Iterator<?> secIter = secLevels.entrySet().iterator();
			while (secIter.hasNext()) {
				Entry<?, ?> secEntry =  (Entry<?, ?>)secIter.next();
				if (  sAuthnContextClassRef.equals(secEntry.getValue()) ) {
					level = (String)secEntry.getKey();
					break;
				}
			}
			return level;
		}
	}

	
	
	/**
	 * Translate the Security Level from int to String.
	 * 
	 * @param sCurrentAuthnContextClassRef
	 *            AuthnContext class ref
	 * @return the Security Level
	 */
	private static String getStringSecurityLevel(int iSecurityLevel)
	{
		if (iSecurityLevel == LEVEL_NULL)
			return BN_NUL;
		else if (iSecurityLevel == LEVEL_POOR)				// RH, 20120124, sn
			return BN_POVER;							// RH, 20120124, en
		else if (iSecurityLevel == LEVEL_LOW)
			return BN_LAAG;
		else if (iSecurityLevel == LEVEL_BETTER)
			return BN_BETTER;
		else if (iSecurityLevel == LEVEL_MEDIUM)
			return BN_MEDIUM;
		else if (iSecurityLevel == LEVEL_HIGH)
			return BN_HOOG;

		return BN_NOT_FOUND;
	}

	/**
	 * Convert URI Security Level to an integer.
	 * 
	 * @param sCurrentAuthnContextClassRef
	 *            AuthnContext class ref
	 * @return the Security Level
	 */
	private static int getIntSecurityLevel(String sCurrentAuthnContextClassRef)
	{
		if (sCurrentAuthnContextClassRef.equals(UNSPECIFIED_URI))
			return LEVEL_NULL;
		else if (sCurrentAuthnContextClassRef.equals(PASSWORD_URI))						// RH, 20120124, sn
			return LEVEL_POOR;									// RH, 20120124, en
		else if (sCurrentAuthnContextClassRef.equals(PASSWORDPROTECTEDTRANSPORT_URI))
			return LEVEL_LOW;
		else if (sCurrentAuthnContextClassRef.equals(MOBILETWOFACTORUNREGISTERED_URI))
			return LEVEL_BETTER;
		else if (sCurrentAuthnContextClassRef.equals(MOBILETWOFACTORCONTRACT_URI))
			return LEVEL_MEDIUM;
		else if (sCurrentAuthnContextClassRef.equals(SMARTCARDPKI_URI))
			return LEVEL_HIGH;

		return LEVEL_NOT_FOUND;
	}

	/**
	 * Convert URI Security Level to an integer.
	 * 
	 * @param sCurrentAuthnContextClassRef
	 *            AuthnContext class ref
	 * @param secLevels
	 *            HashMap with mapping from key=level to value=AuthnContextClassRef
	 * @return the Security Level
	 */
	private static int getIntSecurityLevel(String sCurrentAuthnContextClassRef, HashMap<String, String> secLevels )
	{
		if (secLevels == null) {	// backward compatibility
			return  getIntSecurityLevel(sCurrentAuthnContextClassRef);
		}  else 
		{
			String sLevel = getSecurityLevelFromContext(sCurrentAuthnContextClassRef, secLevels );
			if (sLevel.equals(BN_NOT_FOUND)) {
				return LEVEL_NOT_FOUND;
			} else {
				return  Integer.parseInt(sLevel);	// levels (=keys) from secLevels should be checked for integer at startup
			}
		}
			
		
	}
}
