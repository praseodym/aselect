/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 */

/* 
 * $Id: SAML11ArtifactRequestHandler.java,v 1.8 2006/05/03 10:11:08 tom Exp $ 
 */

package org.aselect.server.request.handler.saml11;

import java.util.Iterator;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xml.security.signature.XMLSignature;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.saml11.common.AssertionSessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLBindingFactory;
import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.artifact.SAMLArtifact;


/**
 * SAML 1.1 Artifact request handler. <br>
 * <br>
 * <b>Description:</b><br>
 * Request handler for SAML 1.1 Artifact Requests. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class SAML11ArtifactRequestHandler extends AbstractRequestHandler
{
	private final static String MODULE = "SAML11ArtifactRequestHandler";
	private SAMLBinding _oSAMLBinding;
	private AssertionSessionManager _oAssertionSessionManager;

	/**
	 * Initializes the SAML 1.1 Artifact request handler. <br>
	 * <br>
	 * 
	 * @param oServletConfig
	 *            the o servlet config
	 * @param oConfig
	 *            the o config
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init()";
		try {
			super.init(oServletConfig, oConfig);

			_oAssertionSessionManager = AssertionSessionManager.getHandle();
			_oSAMLBinding = SAMLBindingFactory.getInstance(SAMLBinding.SOAP);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Processes a SAML message inside a SOAP message containing an Artifact request. <br/>
	 * <br/>
	 * <li>parses the incoming request as SOAP/SAML message</li> <li>searches for an Assertion in the
	 * AssertionSessionManager</li> <li>verifies if the Assertion is still valid (checks expire times)</li> <li>signes
	 * the SAML response</li> <br>
	 * <br>
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @return the request state
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#process(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process()";
		SAMLRequest oSAMLRequest = null;
		SAMLResponse oSAMLResponse = null;
		SAMLArtifact oSAMLArtifact = null;
		SAMLAssertion oSAMLAssertion = null;

		try {
			response.setContentType("text/xml");

			String sShire = request.getRequestURL().toString();

			try {
				oSAMLRequest = _oSAMLBinding.receive(request, 1);
			}
			catch (SAMLException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not parse SAML request with SOAP binding", e);
				throw e;
			}

			StringBuffer sbFiner = new StringBuffer("Retrieving SAML Artifact Request message:\r\n");
			sbFiner.append(oSAMLRequest.toString());
			_systemLogger.log(Level.FINER, MODULE, sMethod, sbFiner.toString());

			// if (!oSAMLRequest.isSigned())
			// {
			// _systemLogger.log(Level.WARNING, MODULE, sMethod, "Request isn't signed");
			// throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			// }

			Vector vSAMLAssertions = new Vector();

			Iterator iterArtifacts = oSAMLRequest.getArtifacts();
			while (iterArtifacts.hasNext()) {
				oSAMLArtifact = (SAMLArtifact) iterArtifacts.next();

				oSAMLAssertion = _oAssertionSessionManager.getAssertion(oSAMLArtifact);
				if (oSAMLAssertion == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"No SAML Assertion available for the supplied artifact");
					throw new SAMLException(SAMLException.REQUESTER,
							"No SAML Assertion available for the supplied artifact");
				}

				long lNotBefore = oSAMLAssertion.getNotBefore().getTime();
				long lNotOnOrAfter = oSAMLAssertion.getNotOnOrAfter().getTime();
				long lCurrent = System.currentTimeMillis();
				if ((lCurrent > lNotBefore) && (lCurrent <= lNotOnOrAfter)) {
					vSAMLAssertions.add(oSAMLAssertion);

					// a SAMLAssertion may only be requested once
					_oAssertionSessionManager.remove(oSAMLArtifact);
				}
				else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAML Assertion expired");
					throw new SAMLException(SAMLException.REQUESTER, "SAML Assertion expired");
				}
			}

			oSAMLResponse = new SAMLResponse(oSAMLRequest.getId(), sShire, vSAMLAssertions, null);

			Vector vCertificatesToInclude = new Vector();
			vCertificatesToInclude.add(_configManager.getDefaultCertificate());

			oSAMLResponse.sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, _configManager.getDefaultPrivateKey(),
					vCertificatesToInclude);

			String sSAMLResponse = oSAMLResponse.toString();

			sbFiner = new StringBuffer("Sending SAML Artifact Response message:\r\n");
			sbFiner.append(sSAMLResponse);
			_systemLogger.log(Level.FINER, MODULE, sMethod, sbFiner.toString());

			_oSAMLBinding.respond(response, oSAMLResponse, null);

		}
		catch (SAMLException e) {
			respondError(response, oSAMLRequest, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return new RequestState(null);
	}

	/**
	 * Removes class variables from memory <br>
	 * <br>
	 * .
	 * 
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#destroy()
	 */
	public void destroy()
	{
		// does nothing
	}

	/**
	 * Sends an error in a SAML message.
	 * 
	 * @param response
	 *            HttpServletResponse were to the response will be sent
	 * @param oSAMLRequest
	 *            SAMLRequest object, can be <code>null</code>
	 * @param oSAMLException
	 *            A SAML Exception object containing the error
	 * @throws ASelectException
	 *             if no SAML response could be sent
	 */
	private void respondError(HttpServletResponse response, SAMLRequest oSAMLRequest, SAMLException oSAMLException)
	throws ASelectException
	{
		String sMethod = "respondError()";
		String sResponseId = null;
		try {
			if (oSAMLRequest != null)
				sResponseId = oSAMLRequest.getId();

			SAMLResponse oSAMLResponse = new SAMLResponse(sResponseId, null, null, oSAMLException);

			_oSAMLBinding.respond(response, oSAMLResponse, null);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not send failure over SAML binding", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);

		}
	}

}
