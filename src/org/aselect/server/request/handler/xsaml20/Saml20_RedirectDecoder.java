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
package org.aselect.server.request.handler.xsaml20;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.ws.message.decoder.MessageDecodingException;

public class Saml20_RedirectDecoder extends HTTPRedirectDeflateDecoder
{
	protected ASelectSystemLogger _systemLogger;
	private final static String MODULE = "Saml20_RedirectDecoder";

	/**
	 * Compare the message endpoint URI's specified.
	 * Overrides the default implementation to ignore https / http differences
	 * 
	 * @param messageDestination
	 *            the intended message destination endpoint URI
	 * @param receiverEndpoint
	 *            the endpoint URI at which the message was received
	 * @return true if the endpoints are equivalent, false otherwise
	 * @throws MessageDecodingException
	 *             thrown if the endpoints specified are not equivalent
	 */
	@Override
	protected boolean compareEndpointURIs(String messageDestination, String receiverEndpoint)
	throws MessageDecodingException
	{
		_systemLogger = ASelectSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, MODULE, "compareEndpointURIs", "Dest=" + messageDestination + " Recv="
				+ receiverEndpoint);
		;
		try {
			new URL(messageDestination);
		}
		catch (MalformedURLException e) {
			_systemLogger.log(Level.INFO, "Message destination URL was malformed in destination check: "
					+ e.getMessage());
			throw new MessageDecodingException("Message destination URL was malformed in destination check");
		}

		try {
			new URL(receiverEndpoint);
		}
		catch (MalformedURLException e) {
			_systemLogger.log(Level.INFO, "Recipient endpoint URL was malformed in destination check: "
					+ e.getMessage());
			throw new MessageDecodingException("Recipient endpoint URL was malformed in destination check");
		}
		// URL's are decent

		// We want to ignore the secure / not secure protocol differences
		String sDest = messageDestination.replaceFirst("s://", "://");
		String sRecv = receiverEndpoint.replaceFirst("s://", "://");
		return sDest.equals(sRecv);
	}
}
