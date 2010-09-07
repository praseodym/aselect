package org.aselect.server.request.handler.openid.op;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.AbstractRequestHandler;
import org.aselect.server.request.handler.openid.Utils;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Encoder;
import org.openid4java.association.AssociationException;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.DirectError;
import org.openid4java.message.Message;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.server.InMemoryServerAssociationStore;
import org.openid4java.server.ServerException;
import org.openid4java.server.ServerManager;
//import sun.misc.Regexp;

public class OpenID_RequestHandler extends AbstractRequestHandler
{

	private final static String MODULE = "OpenID_RequestHandler";
	private ServerManager serverManager;	// Singleton per OpenID_RequestHandler
	private String opEndpointUrl =  null;
	private String _sMyServerID = null;
	private String _sMyOrg = null;
	private String appID = null;
	private String sharedSecret = null;
	private String verifySignature = null;
	private String defaultUID = null;
	private String aselectServerURL = null;
	

	/* @param oServletConfig
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
			Object oASelect = null;
			try {
				oASelect = _configManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not find 'aselect' config section in config file", e);
				throw e;
			}

			try {
				_sMyServerID = _configManager.getParam(oASelect, "server_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'server_id' config parameter in 'aselect' config section", e);
				throw e;
			}
			try {
				aselectServerURL = _configManager.getParam(oASelect, "redirect_url");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'server_id' config parameter in 'redirect_url' config section", e);
				throw e;
			}

			try {
				_sMyOrg = _configManager.getParam(oASelect, "organization");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'organization' config parameter in 'aselect' config section", e);
				throw e;
			}

			try {
				// TODO maybe get this info dynamically from servletconfi and "target" parameter?
				opEndpointUrl = _configManager.getParam(oConfig, "opendpointurl");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'opendpointurl' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				appID = _configManager.getParam(oConfig, "application");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'application' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
						
			try {
				sharedSecret = _configManager.getParam(oConfig, "shared_secret");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'shared_secret' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

//			try {
//				verifySignature = _configManager.getParam(oConfig, "verify_signature");
//			}
//			catch (ASelectConfigException e) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'verify_signature' found", e);
//				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
//			}

			try {
				defaultUID = _configManager.getParam(oConfig, "uid");
			}
			catch (ASelectConfigException e) {
				defaultUID = "siam_user";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'uid' found, using default (used for testing only):" + defaultUID , e);
//				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			// Initialize ServerManager
		    if (serverManager == null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Initializing ServerManager");
			      serverManager = new ServerManager();
//			      setOpEndpointUrl(_configManager.getParam(oSection, sConfigItem));
//			      setOpEndpointUrl("https://siam14.theopenfactory.local/aselectserver/server/openidop_request");
			      setOpEndpointUrl(opEndpointUrl);
			      serverManager.setOPEndpointUrl(getOpEndpointUrl());
			      serverManager.setPrivateAssociations(new InMemoryServerAssociationStore());
			      serverManager.setSharedAssociations(new InMemoryServerAssociationStore());
			    }
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}


	}

	
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{		
			String sMethod = "process()";
			//// maybe use "on the fly" endPointURL ?
//			String handlerTarget = "/openidop_request";	// TODO Don't forget to fill in the target
//			String epu = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + handlerTarget;
//			setOpEndpointUrl(epu);
//			serverManager.setOPEndpointUrl(getOpEndpointUrl());
			/////
			
		    ParameterList requestp = null;			
		    Message opResponse = null;
		    String mode = null;
		    
		    Map reqParms = request.getParameterMap();
		    if (reqParms.isEmpty() ) {
		    	// assume discovery request...
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Parameterlist is empty, assuming discovery request");

		    	try {
					String localID = request.getRequestURL().toString();
		    		localID = StringUtils.substringAfter(localID, getOpEndpointUrl());
		    		localID = localID.replaceFirst("^/", ""); // strip starting slash
					
					_systemLogger.log(Level.INFO, MODULE, sMethod, "localID:" + localID);

					Utils.sendDiscoveryResponse(response, createXrdsResponse(localID), _systemLogger);
				}
				catch (IOException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem sending XRDS response");
					throw new ASelectCommunicationException("Problem sending XRDS response", e);
				}
		    	
		    	
		    } else {
		    	requestp = new ParameterList(request.getParameterMap());
		    	mode = reqParms.containsKey("openid.mode") ?
		    			requestp.getParameterValue("openid.mode") : null;
		    }

		    if ("associate".equals(mode))
		    {
		        // --- process an association request ---
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Process an association request");
		    	opResponse = serverManager.associationResponse(requestp);
		    	Utils.logRequestParameters(requestp, _systemLogger);
		    	Utils.sendPlainTextResponse(response, opResponse, _systemLogger);
		        
		    } else if ("checkid_setup".equals(mode)
		            || "checkid_immediate".equals(mode)) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Process a checkid_setup or checkid_immediate request");
		    	Utils.logRequestParameters(requestp, _systemLogger);
		    	
		    	// TODO ask the user to trust the realm in the openid.realm parameter
		    	// TODO, save get a better sessionid for requestp in user session somehow  in _oSessionManager
		    	
			    	// authenticate to the aselect server
		    		String ridReqURL = aselectServerURL;
		    		String ridSharedSecret = sharedSecret;
		    		String ridAselectServer = _sMyServerID;
		    		String ridrequest= "authenticate";
		    		String ridAppURL = opEndpointUrl;
		    		
//		    		String ridCheckSignature = verifySignature; 
					// maybe also forced_userid ?
		    		
		    		String claimedUID = requestp.getParameterValue("openid.claimed_id");
		    		String identity = requestp.getParameterValue("openid.identity");
		    		if (claimedUID == null && identity == null) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "return error, extensions not supported (yet) ");
				    	Utils.logRequestParameters(requestp, _systemLogger);
				    	opResponse = DirectError.createDirectError("Extensions not supported (yet)");
				    	Utils.sendPlainTextResponse(response, opResponse, _systemLogger);
		    		}
		    		String uid = null;
		    		if ("http://specs.openid.net/auth/2.0/identifier_select".equals(identity)) {	// TODO get this constant somewhere from the openid4java library (probably some static somewhere
		    			// TODO
		    			// This should trigger a username input in  aselect
		    			// Either by presenting a choice or an input box
		    			// We let aselectserver handle this
		    			uid = defaultUID;
		    		} else {
						String localID = (identity == null) ? "" : identity;
			    		localID = StringUtils.substringAfter(localID, getOpEndpointUrl());
			    		localID = localID.replaceFirst("^/", ""); // strip starting slash
		    			uid = localID;
		    		}
		    		
		    		String ridResponse = "";
		    		// Send data 
		    		BufferedReader in = null;
		    		try { 
			    		//Construct request data 
			    		String ridURL = ridReqURL + "?" + "shared_secret=" + URLEncoder.encode(ridSharedSecret, "UTF-8") +
			    				"&a-select-server=" + URLEncoder.encode(ridAselectServer, "UTF-8") +
			    				"&request=" + URLEncoder.encode(ridrequest, "UTF-8") +
			    				"&uid=" + URLEncoder.encode(uid, "UTF-8") +
			    				"&app_url=" + URLEncoder.encode(ridAppURL /* TODO + serialized version of requestp */ , "UTF-8") +
//			    				"&check-signature=" + URLEncoder.encode(ridCheckSignature, "UTF-8") +
			    				"&app_id=" + URLEncoder.encode(appID, "UTF-8");
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Requesting rid through: " + ridURL);

		    			URL url = new URL(ridURL); 
		    			
		    			in = new BufferedReader(
		    					new InputStreamReader(
		    							url.openStream()));

		    			String inputLine = null;
		    			while ((inputLine = in.readLine()) != null) {
		    				ridResponse += inputLine;
		    			}
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Requesting rid response: " + ridResponse);


		    		} catch (Exception e) { 	
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could retrieve rid from aselectserver: " + ridAselectServer);
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
		    		} finally {
		    			if (in != null)
							try {
								in.close();
							}
							catch (IOException e) {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close stream to aselectserver : " + ridAselectServer);
							}
		    		}



		    		//out.println("<br/>ridResponse=" + ridResponse); 

		    		String extractedRid = ridResponse.replaceFirst(".*rid=([^&]*).*$", "$1");
					_systemLogger.log(Level.INFO, MODULE, sMethod, "rid retrieved: " + extractedRid);

					String sessionID =  extractedRid+ "54321";
//					String sessionID =  "98765";
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Storing requestparameters with id: " + sessionID);
			    	Utils.logRequestParameters(requestp, _systemLogger);

					HashMap<String, Object> htSessionContext = new HashMap<String, Object>();
					htSessionContext.put("openid_requestp", requestp);
//					_oSessionManager.writeSession(extractedRid, htSessionContext);
					_oSessionManager.writeSession(sessionID, htSessionContext);
					
		    		String loginrequest= "login1";

		    		//Construct request data 
		    		String redirectURL = null;
					try {
						redirectURL = ridReqURL + "?" + 
								"request=" + URLEncoder.encode(loginrequest, "UTF-8") +
								"&a-select-server=" + URLEncoder.encode(ridAselectServer, "UTF-8") +
								"&rid=" + extractedRid;
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Requesting login through redirect with redirectURL: " + redirectURL);
						
			    		response.sendRedirect(redirectURL);
					}
					catch (UnsupportedEncodingException e1) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e1);
					}
					catch (IOException e) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not redirect to: " + redirectURL);
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
					}


		    } else if ("check_authentication".equals(mode)) {
		        // --- processing a verification request ---
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Process a check_authentication request");
		    	Utils.logRequestParameters(requestp, _systemLogger);
		        opResponse = serverManager.verify(requestp);
		    	Utils.sendPlainTextResponse(response, opResponse, _systemLogger);
		    } else {
		    	// This should be the aselectserver response
		    	if (request.getParameter("aselect_credentials") != null) {
		    		// TODO retrieve requestp from session
			    	// handle the aselectserver response
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Handle the aselectserver response");

					// TODO this can be done by getting request parametermap
		    		String queryData = request.getQueryString();
		    		String extractedAselect_credentials = queryData.replaceFirst(".*aselect_credentials=([^&]*).*$", "$1");
		    		String extractedRid = queryData.replaceFirst(".*rid=([^&]*).*$", "$1");
		    		String finalReqURL = aselectServerURL;
		    		String finalReqSharedSecret = sharedSecret;
		    		String finalReqAselectServer = _sMyServerID;
		    		String finalReqrequest= "verify_credentials";
//		    		String ridCheckSignature = verifySignature; // this does not help for verify_credentials if <applications>
		    											// in aselect.xml has require_signing="true"


		    		//Construct request data
		    		// TODO implement signing
		    		String finalRequestURL = null;
					try {
						finalRequestURL = finalReqURL + "?" + "shared_secret=" + URLEncoder.encode(finalReqSharedSecret, "UTF-8") +
								"&a-select-server=" + URLEncoder.encode(finalReqAselectServer, "UTF-8") +
								"&request=" + URLEncoder.encode(finalReqrequest, "UTF-8") +
								"&aselect_credentials=" + extractedAselect_credentials +
//								"&check-signature=" + URLEncoder.encode(ridCheckSignature, "UTF-8") +
								"&rid=" + extractedRid;

					}
					catch (UnsupportedEncodingException e3) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e3);
						}
		    		String finalResult = "";

		    		//Send data
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieving attributes through: " + finalRequestURL);

		    		BufferedReader in = null;
		    		try { 
		    			URL url = new URL(finalRequestURL); 
		    			
		    			in = new BufferedReader(
		    					new InputStreamReader(
		    							url.openStream()));

		    			String inputLine = null;
		    			while ((inputLine = in.readLine()) != null) {
		    				finalResult += inputLine;
		    			}
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieved attributes in: " + finalResult);

		    		} catch (Exception e) { 	
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not retrieve attributes from aselectserver: " + finalReqAselectServer);
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
		    		} finally {
		    			if (in != null)
							try {
								in.close();
							}
							catch (IOException e) {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close stream to aselectserver : " + finalReqAselectServer);
							}
		    		}

		    		
		    		String extractedAttributes = finalResult.replaceFirst(".*attributes=([^&]*).*$", "$1");
		    		String extractedResultCode = finalResult.replaceFirst(".*result_code=([^&]*).*$", "$1");

		    		String urlDecodedAttributes = null;;
		    		String decodedAttributes = null;
					try {
						urlDecodedAttributes = URLDecoder.decode(extractedAttributes, "UTF-8");
			    		decodedAttributes = URLDecoder.decode(new String(org.apache.commons.codec.binary.Base64.decodeBase64(urlDecodedAttributes.getBytes())), "UTF-8");
			    		String attribs[] = decodedAttributes.split("&");
			    		for (int i=0;i<attribs.length;i++) {
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieved attribute from aselectserver: " + attribs[i]);
			    		}

					}
					catch (UnsupportedEncodingException e2) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLDecode from UTF-8, this should not happen!");
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e2);
					} 


					String sessionID =  extractedRid + "54321";

					_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieving requestparameters with sessionID: " + sessionID);

			    	HashMap<String, Object> htSessionContext = (HashMap<String, Object>) _oSessionManager.get(sessionID);
			    	requestp = (ParameterList) htSessionContext.get("openid_requestp");
			    	
			    	Utils.logRequestParameters(requestp, _systemLogger);
			    	// TODO we should be able to kill the session
//			       _oSessionManager.killSession(sessionID);

			        String userSelectedId = null;
			        String userSelectedClaimedId =  null;
			        userSelectedId = getOpEndpointUrl() + "/" + finalResult.replaceFirst(".*uid=([^&]*).*$", "$1");
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieved uid from aselect query string (userSelectedId): " + userSelectedId);
			        userSelectedClaimedId =  getOpEndpointUrl() + "/" +decodedAttributes.replaceFirst(".*uid=([^&]*).*$", "$1");
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieved uid from aselect attributes  (userSelectedClaimedId): " + userSelectedClaimedId);
			        
			        Boolean authenticatedAndApproved = false;
			        try {
			        	authenticatedAndApproved = Boolean.valueOf(Integer.parseInt(extractedResultCode) == 0);
			        } catch (NumberFormatException nfe ) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Resultcode from aselectserver was non-numeric: " + extractedResultCode);
			        }
			        
			        // --- process an authentication request ---
			        // ? does authResponse verify the requestp signature ?
			        opResponse = serverManager.authResponse(requestp,
			                userSelectedId,
			                userSelectedClaimedId,
			                authenticatedAndApproved.booleanValue());
			        if (authenticatedAndApproved.booleanValue()) {
				        try {
							serverManager.sign((AuthSuccess)opResponse);
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Response signed");
						}
						catch (ServerException e1) {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to sign response, corresponding association cannot be found in store");
						}
						catch (AssociationException e1) {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to sign response, signature cannot be computed");
						}
			        }
	
			        // caller will need to decide which of the following to use:
			        // - GET HTTP-redirect to the return_to URL
			        // - HTML FORM Redirection
			        
			        String sRedirectUrl = opResponse.getDestinationUrl(true); 
			        // FOR GET-redirect
					_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIR " + sRedirectUrl);
					try {
						response.sendRedirect(sRedirectUrl);
					}
					catch (IOException e) {
						StringBuffer sbWarning = new StringBuffer("Failed to redirect user to: ");
						sbWarning.append(sRedirectUrl);
						_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
					}
	
			        // FOR FORM POST, set up form and...
					//		responseText = opResponse.wwwFormEncoding();
			        //		String sRedirectUrl = opResponse.getDestinationUrl(false); 
			        //		redirect(opResponse.getDestinationUrl(false));

		    		
		    	} else {
		    		// oops, it was not an aselectserver response
			        // --- error response ---
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unknown request: " + mode);
			    	Utils.logRequestParameters(requestp, _systemLogger);
			    	opResponse = DirectError.createDirectError("Unknown request");
			    	Utils.sendPlainTextResponse(response, opResponse, _systemLogger);
		    	}
		    }

			
		return null;
	}

	public void destroy()
	{
		
	}


	
	 public synchronized String getOpEndpointUrl()
		{
			return opEndpointUrl;
		}


		public synchronized void setOpEndpointUrl(String opEndpointUrl)
		{
			this.opEndpointUrl = opEndpointUrl;
		}
		
		  /**
		   * TODO: document this
		   * @return
		   */
		  public String createXrdsResponse() {
			  return createXrdsResponse(null);
		  }
		  

		
			/**
		   * TODO: document this
		   * @param the (optional) localID to return in the XRDS
		   * @return
		   */
		  public String createXrdsResponse(String localID) {
				String sMethod = "createXrdsResponse()";
			  
				_systemLogger.log(Level.INFO, MODULE, sMethod, "BEGIN");
			  
		    org.aselect.server.request.handler.openid.XrdsDocumentBuilder documentBuilder = new org.aselect.server.request.handler.openid.XrdsDocumentBuilder();
		    if (localID == null || "".equals(localID)) {
			    documentBuilder.addServiceElement("http://specs.openid.net/auth/2.0/server", serverManager.getOPEndpointUrl(), "0");
			    documentBuilder.addServiceElement("http://specs.openid.net/auth/2.0/signon", serverManager.getOPEndpointUrl(), "10");
		    } else {
			    documentBuilder.addServiceElement("http://specs.openid.net/auth/2.0/signon", serverManager.getOPEndpointUrl(), "10", localID);
		    }

		    // next lines needed when we implement extensions
//		    documentBuilder.addServiceElement(AxMessage.OPENID_NS_AX, serverManager.getOPEndpointUrl(), "30");
//		    documentBuilder.addServiceElement(SRegMessage.OPENID_NS_SREG, serverManager.getOPEndpointUrl(), "40");
		    String xmlString = documentBuilder.toXmlString();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "created XrdsResponse: " + xmlString);
		    return xmlString;
		  }

}
