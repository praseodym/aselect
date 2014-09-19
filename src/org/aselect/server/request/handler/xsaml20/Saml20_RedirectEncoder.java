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

import java.util.List;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.util.URLBuilder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.Pair;

public class Saml20_RedirectEncoder extends HTTPRedirectDeflateEncoder
{
	protected ASelectSystemLogger _systemLogger;
	private final static String MODULE = "Saml20_RedirectEncoder";

	/**
	 * Overrides the default implementation
	 * This method was not changed, only logging was added
	 * 
	 * @param messageContext
	 *            the message context
	 * @throws MessageEncodingException
	 *            on encoding errors
	 */
	@Override
    protected void doEncode(MessageContext messageContext)
	throws MessageEncodingException
    {
		String sMethod = "doEncode";
		
    	_systemLogger = ASelectSystemLogger.getHandle();
        if (!(messageContext instanceof SAMLMessageContext)) {
    		_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid message context type, this encoder only support SAMLMessageContext");
            throw new MessageEncodingException(
                    "Invalid message context type, this encoder only support SAMLMessageContext");
        }

        if (!(messageContext.getOutboundMessageTransport() instanceof HTTPOutTransport)) {
        	_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid outbound message transport type, this encoder only support HTTPOutTransport");
            throw new MessageEncodingException(
                    "Invalid outbound message transport type, this encoder only support HTTPOutTransport");
        }

        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) messageContext;

        String endpointURL = getEndpointURL(samlMsgCtx);
        _systemLogger.log(Level.INFO, MODULE, sMethod, "endpointURL="+endpointURL);

        // Because of incompatibility between opensaml <= v. 2.3.0 and > v. 2.3.0 in getEndpointURL(samlMsgCtx) we must
//        String endpointURL = getEndpointURL(samlMsgCtx).buildURL();	// RH, 20140710, n, fix for opensaml 2.6.1
//        _systemLogger.log(Level.INFO, MODULE, sMethod, "endpointURL="+endpointURL);


        setResponseDestination(samlMsgCtx.getOutboundSAMLMessage(), endpointURL);

        removeSignature(samlMsgCtx);

        String encodedMessage = deflateAndBase64Encode(samlMsgCtx.getOutboundSAMLMessage());
        _systemLogger.log(Level.INFO, MODULE, sMethod, "encodedMessage="+encodedMessage);

        String redirectURL = buildRedirectURL(samlMsgCtx, endpointURL, encodedMessage);
        _systemLogger.log(Level.INFO, MODULE, sMethod, "redirectURL="+redirectURL);

        HTTPOutTransport out = (HTTPOutTransport) messageContext.getOutboundMessageTransport();
        HTTPTransportUtils.addNoCacheHeaders(out);
        HTTPTransportUtils.setUTF8Encoding(out);

        out.sendRedirect(redirectURL);
    }

	/**
     * Builds the URL to redirect the client to.
     * Overrides the default implementation by using sha-256 signing
     * 
     * @param messagesContext current message context
     * @param endpointURL endpoint URL to send encoded message to
     * @param message Deflated and Base64 encoded message
     * 
     * @return URL to redirect client to
     * 
     * @throws MessageEncodingException thrown if the SAML message is neither a RequestAbstractType or Response
     */
    protected String buildRedirectURL(SAMLMessageContext messagesContext, String endpointURL, String message)
    throws MessageEncodingException
    {
    	String sMethod = "buildRedirectURL";
    	_systemLogger.log(Level.INFO, MODULE, sMethod, "Building redirect URL using:"+endpointURL);
        
    	URLBuilder urlBuilder = new URLBuilder(endpointURL);

        List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();
        queryParams.clear();

        if (messagesContext.getOutboundSAMLMessage() instanceof RequestAbstractType) {
            queryParams.add(new Pair<String, String>("SAMLRequest", message));
        }
        else if (messagesContext.getOutboundSAMLMessage() instanceof StatusResponseType) {
            queryParams.add(new Pair<String, String>("SAMLResponse", message));
        }
        else {
            throw new MessageEncodingException(
                    "SAML message is neither a SAML RequestAbstractType or StatusResponseType");
        }

        String relayState = messagesContext.getRelayState();
        if (checkRelayState(relayState)) {
            queryParams.add(new Pair<String, String>("RelayState", relayState));
        }

        Credential signingCredential = messagesContext.getOuboundSAMLMessageSigningCredential();
    	if (signingCredential != null) {
            // OpenSaml2 comment: pull SecurityConfiguration from SAMLMessageContext? needs to be added
//            String sigAlgURI = getSignatureAlgorithmURI(signingCredential, null);
//            _systemLogger.log(Level.INFO, MODULE, sMethod, "sigAlgURI="+sigAlgURI);
/*           	byte[] bytesToBeSigned = urlBuilder.buildQueryString().getBytes();
            try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				_systemLogger.log(Level.INFO, MODULE, sMethod, md.getProvider().getInfo() );
		        // Calculate the digest and print it out
		        md.update(bytesToBeSigned);
		        _systemLogger.log(Level.INFO, MODULE, sMethod, "Digest="+new String(md.digest(), "UTF8"));
            }
            catch (Exception e) {
				 _systemLogger.log(Level.INFO, MODULE, sMethod, "Bad digest "+e);
			}
*/          
/*            byte[] sig = null;
            try {
            	Signature dsa = Signature.getInstance("SHA256withRSA");
            	PrivateKey priv = signingCredential.getPrivateKey();  //pair.getPrivate();
            	_systemLogger.log(Level.INFO, MODULE, sMethod, "Do initSign priv algo="+priv.getAlgorithm());
            	dsa.initSign(priv);
            	_systemLogger.log(Level.INFO, MODULE, sMethod, "Do update");
            	// Update and sign the data
            	dsa.update(bytesToBeSigned);
            	_systemLogger.log(Level.INFO, MODULE, sMethod, "Do sign alg="+dsa.getAlgorithm());
            	sig = dsa.sign();
            	_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed="+sig);
            	
	            XMLSignatureFactory fac = XMLSignatureFactory.getInstance();  // since 1.4.2
	            SignatureMethodParameterSpec smps = null;
	            SignatureMethod sm = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", smps);
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "Algo="+sm.getAlgorithm());
		    }
            catch (Exception e) {
				 _systemLogger.log(Level.INFO, MODULE, sMethod, "Bad xml sig alg "+e);
			}
*/          
/*            try {
            	_systemLogger.log(Level.INFO, MODULE, sMethod, "signingCredential="+signingCredential.toString());

	            RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "signer="+signer);
	            byte[] keyBytes = signingCredential.getPrivateKey().getEncoded();
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "keyBytes="+keyBytes);
	            
	            CipherParameters cp = new RSAKeyParameters(true, new BigInteger("125".getBytes()), new BigInteger("15".getBytes())); // KeyParameter(keyBytes);
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "cp="+cp);
	            signer.init(true, cp);
	            signer.update(bytesToBeSigned, 0, bytesToBeSigned.length);
	            byte[] result = signer.generateSignature();
	            _systemLogger.log(Level.INFO, MODULE, sMethod, "Result="+result.toString());
		    }
            catch (Exception e) {
				 _systemLogger.log(Level.INFO, MODULE, sMethod, "Bad bouncy "+e);
			}
*/
            // sigAlgURI = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";  // sha1 default
            // sigAlgURI = "http://www.w3.org/2001/04/xmlenc#sha256";  // RECOMMENDED http://www.w3.org/TR/xmlenc-core/
            String sigAlgURI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";  // required by eHerkenning
            Pair<String, String> sigAlg = new Pair<String, String>("SigAlg", sigAlgURI);
            queryParams.add(sigAlg);
            String sigMaterial = urlBuilder.buildQueryString();

            _systemLogger.log(Level.INFO, MODULE, sMethod, "sigAlgURI="+sigAlgURI+" sigMaterial="+sigMaterial);
            queryParams.add(new Pair<String, String>("Signature", generateSignature(signingCredential, sigAlgURI, sigMaterial)));
        }
        return urlBuilder.buildURL();
    }
    
    /**
     * Generates the signature over the query string.
     * 
     * @param signingCredential credential that will be used to sign query string
     * @param algorithmURI algorithm URI of the signing credential
     * @param queryString query string to be signed
     * 
     * @return base64 encoded signature of query string
     * 
     * @throws MessageEncodingException there is an error computing the signature
     */
/*	protected String generateSignature(Credential signingCredential, String algorithmURI, String queryString)
	throws MessageEncodingException
	{
		String sMethod = "generateSignature";
		_systemLogger.log(Level.INFO, MODULE, sMethod,
				String.format("Generating signature with key type '%s', algorithm URI '%s' over query string '%s'",
						SecurityHelper.extractSigningKey(signingCredential).getAlgorithm(), algorithmURI,queryString));

		String b64Signature = null;
		try {
			Signature dsa = Signature.getInstance("SHA256withRSA");
			PrivateKey priv = signingCredential.getPrivateKey(); // pair.getPrivate();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do initSign priv algo=" + priv.getAlgorithm());
			dsa.initSign(priv);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do update");

			// Update and sign the data
			dsa.update(queryString.getBytes());
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do sign alg=" + dsa.getAlgorithm());
			byte[] rawSignature = dsa.sign();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed=" + rawSignature);
			b64Signature = Base64.encodeBytes(rawSignature, Base64.DONT_BREAK_LINES);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Generated digital signature value (base64-encoded)="+b64Signature);

		} catch (Exception e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Bad xml sig alg " + e);
		}
		return b64Signature;
	}*/
}
