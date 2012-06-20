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
 * 
 * Created on 20090615
 *  This class provides a "wrapper" for the  HTTPMetadataProvider class
 *  to support a forward proxy server
 *  
 *  Unfortunately all properties in opensaml HTTPMetadataProvider are private
 *  and for most of them there are no getters/setters
 *  Life would have been much easier if there had been :P
 *  
 *  This class should be removed as soon as opensaml supports forward proxies
 */
package org.aselect.server.request.handler.xsaml20;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.logging.SystemLogger;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

/**
 * @author Remy Hanswijk
 */
public class ProxyHTTPMetadataProvider extends HTTPMetadataProvider
{

	/** HTTP Client used to pull the metadata. */
	protected HttpClient proxyhttpClient;
	/** URL scope that requires authentication. */
	private AuthScope proxyauthScope;

	protected SystemLogger _systemLogger;

	/**
	 * The Constructor.
	 * 
	 * @param metadataURL
	 *            the metadata url
	 * @param requestTimeout
	 *            the request timeout
	 * @param proxyHost
	 *            the proxy host
	 * @param proxyPort
	 *            the proxy port
	 * @throws MetadataProviderException
	 *             the metadata provider exception
	 */
	public ProxyHTTPMetadataProvider(String metadataURL, int requestTimeout, String proxyHost, int proxyPort)
	throws MetadataProviderException {

		super(metadataURL, requestTimeout);

		_systemLogger = ASelectSystemLogger.getHandle();
		HttpClientParams clientParams = new HttpClientParams();
		clientParams.setSoTimeout(requestTimeout);
		proxyhttpClient = new HttpClient(clientParams);
		proxyhttpClient.getHostConfiguration().setProxy(proxyHost, proxyPort);
		URI l_metadataURI;
		try {
			l_metadataURI = new URI(getMetadataURI());
		}
		catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			throw new MetadataProviderException("Illegal URL syntax", e);

		}

		proxyauthScope = new AuthScope(l_metadataURI.getHost(), l_metadataURI.getPort());

		// commons-http-client >= 4.0 might use:
		// ProxySelectorRoutePlanner routePlanner = new ProxySelectorRoutePlanner(
		// httpclient.getConnectionManager().getSchemeRegistry(),
		// ProxySelector.getDefault());
		// httpclient.setRoutePlanner(routePlanner);

		// or:
		// HttpHost proxy = new HttpHost(proxyHost, proxyPort);
		// getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);

	}

	/**
	 * Sets the username and password used to access the metadata URL. To disable BASIC authentication set the username
	 * and password to null;
	 * 
	 * @param username
	 *            the username
	 * @param password
	 *            the password
	 */
	@Override
	public void setBasicCredentials(String username, String password)
	{
		if (username == null && password == null) {
			proxyhttpClient.getState().setCredentials(null, null);
		}
		else {
			UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(username, password);
			proxyhttpClient.getState().setCredentials(proxyauthScope, credentials);
		}
	}

	/**
	 * Gets the length of time in milliseconds to wait for the server to respond.
	 * 
	 * @return length of time in milliseconds to wait for the server to respond
	 */
	@Override
	public int getRequestTimeout()
	{
		return proxyhttpClient.getParams().getSoTimeout();
	}

	/**
	 * Sets the socket factory used to create sockets to the HTTP server.
	 * 
	 * @param newSocketFactory
	 *            the socket factory used to produce sockets used to connect to the server
	 * @see <a href="http://jakarta.apache.org/commons/httpclient/sslguide.html">HTTPClient SSL guide</a>
	 */
	@Override
	public void setSocketFactory(ProtocolSocketFactory newSocketFactory)
	{
		Protocol protocol;
		try {
			protocol = new Protocol(new URI(getMetadataURI()).getScheme(), newSocketFactory, new URI(getMetadataURI())
					.getPort());
			proxyhttpClient.getHostConfiguration().setHost(new URI(getMetadataURI()).getHost(),
					new URI(getMetadataURI()).getPort(), protocol);
		}
		catch (URISyntaxException e) {
			_systemLogger.log(Level.FINEST, "This should not happen, same URI has been instantiated before");
		}
	}

	/**
	 * Fetches the metadata from the remote server and unmarshalls it.
	 * 
	 * @return the unmarshalled metadata
	 * @throws IOException
	 *             thrown if the metadata can not be fetched from the remote server
	 * @throws UnmarshallingException
	 *             thrown if the metadata can not be unmarshalled
	 */
	@Override
	protected XMLObject fetchMetadata()
	throws IOException, UnmarshallingException
	{
		_systemLogger.log(Level.FINEST, "Fetching metadata document from remote server");

		GetMethod getMethod = new GetMethod(getMetadataURI());
		if (proxyhttpClient.getState().getCredentials(proxyauthScope) != null) {
			_systemLogger.log(Level.FINEST, "Using BASIC authentication when retrieving metadata");
			getMethod.setDoAuthentication(true);
		}
		proxyhttpClient.executeMethod(getMethod);

		_systemLogger.log(Level.INFO, "Retrieved the following metadata document\n{}"
				+ getMethod.getResponseBodyAsString());
		XMLObject metadata = unmarshallMetadata(getMethod.getResponseBodyAsStream());

		_systemLogger.log(Level.FINEST, "Unmarshalled metadata from remote server");
		return metadata;

	}

}
