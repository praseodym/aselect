/*
 * Created on 28-aug-2007
 */
package org.aselect.server.request.handler.xsaml20;

import java.util.List;
import java.util.ListIterator;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.RequestedAuthnContext;

public class SecurityLevel
{
	final static String MODULE = "Utils";
	final static String UNSPECIFIED_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
	final static String PASSWORDPROTECTEDTRANSPORT_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
	final static String MOBILETWOFACTORCONTRACT_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";
	final static String SMARTCARDPKI_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI";

	final static int LEVEL_NUL = 5;
	final static int LEVEL_LAAG = 10;
	final static int LEVEL_MIDDEN = 20;
	final static int LEVEL_HOOG = 30;

	final private static int NOT_FOUND = -1;

	final private static int MIN = 0;
	final private static int NUL = 1;
	final private static int LAAG = 2;
	final private static int MIDDEN = 3;
	final private static int HOOG = 4;
	final private static int MAX = 5;

	public final static String BN_EMPTY = "empty";
	public final static String BN_NUL = "5";
	public final static String BN_LAAG = "10";
	public final static String BN_MIDDEN = "20";
	public final static String BN_HOOG = "30";
	public final static String BN_NOT_FOUND = "not_found";

	public static String convertLevelToAuthnContextClassRefURI(String sLevel, ASelectSystemLogger systemLogger,
			String sModule)
		throws ASelectException
	{
		String sMethod = "convertLevelToAuthnContextClassRefURI()";

		int iLevel;
		try {
			iLevel = Integer.parseInt(sLevel);
		}
		catch (Exception e) {
			if (systemLogger != null)
				systemLogger.log(Level.SEVERE, sModule, sMethod, "Unable to parse level value: " + sLevel, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		switch (iLevel) {
		case LEVEL_NUL:
			return UNSPECIFIED_URI;
		case LEVEL_LAAG:
			return PASSWORDPROTECTEDTRANSPORT_URI;
		case LEVEL_MIDDEN:
			return MOBILETWOFACTORCONTRACT_URI;
		case LEVEL_HOOG:
			return SMARTCARDPKI_URI;
		}
		if (systemLogger != null)
			systemLogger.log(Level.SEVERE, sModule, sMethod, "Level value: " + sLevel + " is not valid.");
		throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
	}

	public static String convertAuthnContextClassRefURIToLevel(String sAuthnContextClassRefURI,
			ASelectSystemLogger systemLogger, String sModule)
		throws ASelectException
	{
		String sMethod = "convertLevelToAuthnContextClassRefURI()";

		try {
			if (sAuthnContextClassRefURI.equals(UNSPECIFIED_URI))
				return String.valueOf(LEVEL_NUL);
			else if (sAuthnContextClassRefURI.equals(PASSWORDPROTECTEDTRANSPORT_URI))
				return String.valueOf(LEVEL_LAAG);
			else if (sAuthnContextClassRefURI.equals(MOBILETWOFACTORCONTRACT_URI))
				return String.valueOf(LEVEL_MIDDEN);
			else if (sAuthnContextClassRefURI.equals(SMARTCARDPKI_URI))
				return String.valueOf(LEVEL_HOOG);

			if (systemLogger != null)
				systemLogger.log(Level.SEVERE, sModule, sMethod, "AuthnContextClassRefURI value: "
						+ sAuthnContextClassRefURI + " is not valid.");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		catch (Exception e) {
			if (systemLogger != null)
				systemLogger.log(Level.SEVERE, sModule, sMethod, "", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);

		}
	}

	public static String getBetrouwbaarheidsNiveau(RequestedAuthnContext requestedAuthnContext)
	{
		final int EXACT = 0;
		final int MINIMUM = 1;
		final int MAXIMUM = 2;
		final int BETTER = 3;

		if (requestedAuthnContext != null) {
			int iComparison = EXACT;
			AuthnContextComparisonTypeEnumeration authnContextComparisonTypeEnumeration = requestedAuthnContext
					.getComparison();
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
			int iCurrentBetrouwheidsNiveau = NOT_FOUND;

			switch (iComparison) {
			case EXACT:
				// Doorloop de lijst totdat de URI er tussen zit
				while (itr.hasNext() && sMatchedBetrouwheidsNiveau == BN_NOT_FOUND) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
					sMatchedBetrouwheidsNiveau = getBetrouwbaarheidsNiveau(sCurrentAuthnContextClassRef);
				}
				break;

			case MINIMUM:
				// Doorloop de lijst en pik het minimum eruit
				int iCurrentMinBetrouwheidsNiveau = MAX;
				while (itr.hasNext()) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
					iCurrentBetrouwheidsNiveau = getIntBetrouwbaarheidsNiveau(sCurrentAuthnContextClassRef);
					if (iCurrentBetrouwheidsNiveau != NOT_FOUND
							&& iCurrentBetrouwheidsNiveau < iCurrentMinBetrouwheidsNiveau)
						iCurrentMinBetrouwheidsNiveau = iCurrentBetrouwheidsNiveau;
				}
				sMatchedBetrouwheidsNiveau = getBetrouwbaarheidsNiveau(iCurrentMinBetrouwheidsNiveau);
				break;

			case BETTER:
				// Doorloop de lijst en pik 1 beter dan het maximum eruit
				int iCurrentBestBetrouwheidsNiveau = MIN;
				while (itr.hasNext()) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
					iCurrentBetrouwheidsNiveau = getIntBetrouwbaarheidsNiveau(sCurrentAuthnContextClassRef);
					if (iCurrentBetrouwheidsNiveau != NOT_FOUND
							&& iCurrentBetrouwheidsNiveau > iCurrentBestBetrouwheidsNiveau)
						iCurrentBestBetrouwheidsNiveau = iCurrentBetrouwheidsNiveau;
				}
				if (iCurrentBestBetrouwheidsNiveau == NUL)
					iCurrentBestBetrouwheidsNiveau = LAAG;
				else if (iCurrentBestBetrouwheidsNiveau == LAAG)
					iCurrentBestBetrouwheidsNiveau = MIDDEN;
				else if (iCurrentBestBetrouwheidsNiveau == MIDDEN)
					iCurrentBestBetrouwheidsNiveau = HOOG;
				else if (iCurrentBestBetrouwheidsNiveau == HOOG)
					iCurrentBestBetrouwheidsNiveau = MAX;

				sMatchedBetrouwheidsNiveau = getBetrouwbaarheidsNiveau(iCurrentBestBetrouwheidsNiveau);
				break;

			case MAXIMUM:
				// Doorloop de lijst en pik het maximum eruit
				int iCurrentMaxBetrouwheidsNiveau = MIN;
				while (itr.hasNext()) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
					iCurrentBetrouwheidsNiveau = getIntBetrouwbaarheidsNiveau(sCurrentAuthnContextClassRef);
					if (iCurrentBetrouwheidsNiveau != NOT_FOUND
							&& iCurrentBetrouwheidsNiveau > iCurrentMaxBetrouwheidsNiveau)
						iCurrentMaxBetrouwheidsNiveau = iCurrentBetrouwheidsNiveau;
				}
				sMatchedBetrouwheidsNiveau = getBetrouwbaarheidsNiveau(iCurrentMaxBetrouwheidsNiveau);
			}

			return sMatchedBetrouwheidsNiveau;

		}
		return BN_EMPTY;
	}

	private static String getBetrouwbaarheidsNiveau(String sAuthnContextClassRef)
	{
		if (sAuthnContextClassRef.equals(UNSPECIFIED_URI))
			return BN_NUL;
		else if (sAuthnContextClassRef.equals(PASSWORDPROTECTEDTRANSPORT_URI))
			return BN_LAAG;
		else if (sAuthnContextClassRef.equals(MOBILETWOFACTORCONTRACT_URI))
			return BN_MIDDEN;
		else if (sAuthnContextClassRef.equals(SMARTCARDPKI_URI))
			return BN_HOOG;

		return BN_NOT_FOUND;
	}

	private static String getBetrouwbaarheidsNiveau(int iBetrouwbaarheidsNiveau)
	{
		if (iBetrouwbaarheidsNiveau == NUL)
			return BN_NUL;
		else if (iBetrouwbaarheidsNiveau == LAAG)
			return BN_LAAG;
		else if (iBetrouwbaarheidsNiveau == MIDDEN)
			return BN_MIDDEN;
		else if (iBetrouwbaarheidsNiveau == HOOG)
			return BN_HOOG;

		return BN_NOT_FOUND;
	}

	public static int getIntBetrouwbaarheidsNiveauFromBN(String sBetrouwbaarheidsNiveau)
	{
		if (BN_NUL.equals(sBetrouwbaarheidsNiveau))
			return LEVEL_NUL;
		else if (BN_LAAG.equals(sBetrouwbaarheidsNiveau))
			return LEVEL_LAAG;
		else if (BN_MIDDEN.equals(sBetrouwbaarheidsNiveau))
			return LEVEL_MIDDEN;
		else if (BN_HOOG.equals(sBetrouwbaarheidsNiveau))
			return LEVEL_HOOG;
		else if (BN_EMPTY.equals(sBetrouwbaarheidsNiveau))
			return LEVEL_NUL;
		// if it is empty the requestor apparently does not care

		return Integer.MAX_VALUE;
	}

	private static int getIntBetrouwbaarheidsNiveau(String sCurrentAuthnContextClassRef)
	{
		if (sCurrentAuthnContextClassRef.equals(UNSPECIFIED_URI))
			return NUL;
		else if (sCurrentAuthnContextClassRef.equals(PASSWORDPROTECTEDTRANSPORT_URI))
			return LAAG;
		else if (sCurrentAuthnContextClassRef.equals(MOBILETWOFACTORCONTRACT_URI))
			return MIDDEN;
		else if (sCurrentAuthnContextClassRef.equals(SMARTCARDPKI_URI))
			return HOOG;

		return NOT_FOUND;
	}
}
