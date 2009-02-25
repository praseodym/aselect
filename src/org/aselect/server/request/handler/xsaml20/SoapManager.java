package org.aselect.server.request.handler.xsaml20;

import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.utils.Tools;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObjectBuilderFactory;

public class SoapManager
{
	private static final String MODULE = "SoapManager";
	private static final String CONTENT_TYPE = "text/xml; charset=utf-8";

	protected ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();

	/**
	 * Build a SOAP Message. <br>
	 * 
	 * @param samlMessage
	 *            SAMLObject.
	 * @return Envelope soap envelope
	 */
	@SuppressWarnings("unchecked")
	public Envelope buildSOAPMessage(SAMLObject samlMessage)
	{
		String sMethod = "buildSOAPMessage()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "#=============#");

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		SOAPObjectBuilder<Envelope> envBuilder = (SOAPObjectBuilder<Envelope>) builderFactory
				.getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
		Envelope envelope = envBuilder.buildObject();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Adding SAML message to the SOAP message's body");

		SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory
				.getBuilder(Body.DEFAULT_ELEMENT_NAME);
		Body body = bodyBuilder.buildObject();
		body.getUnknownXMLObjects().add(samlMessage);
		envelope.setBody(body);

		return envelope;
	}

	/**
	 * Send SOAP message. <br>
	 * 
	 * @param sMessage
	 *            String with message that needs to be send.
	 * @param sUrl
	 *            String with url to send message to.
	 * @throws MalformedURLException
	 *             If url is not correct
	 * @throws ASelectCommunicationException
	 *             If sending fails.
	 */
	public String sendSOAP(String sMessage, String sUrl)
		throws java.net.MalformedURLException, ASelectCommunicationException
	{
		StringBuffer sb = new StringBuffer();
		String sMethod = "sendSOAP";
		URL url = null;
		HttpURLConnection connection = null;

		// http://[target address]/[schema target]
		url = new URL(sUrl);

		try {
			// open HTTP connection to URL
			connection = (HttpURLConnection) url.openConnection();
			// enable sending to connection
			connection.setDoOutput(true);

			// set mime headers
			connection.setRequestProperty("Content-Type", CONTENT_TYPE);
			connection.setRequestProperty("Accept", CONTENT_TYPE);

			StringBuffer sbSOAPAction = new StringBuffer("\"");
			sbSOAPAction.append(sUrl).append("\"");
			connection.setRequestProperty("SOAPAction", sbSOAPAction.toString());
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Send: ContentType: "+CONTENT_TYPE+
					" Action: "+sbSOAPAction);
			// RH, 20081113, set appropriate headers
			connection.setRequestProperty("Pragma", "no-cache");
			connection.setRequestProperty("Cache-Control", "no-cache, no-store");
			// write message to output
			PrintStream osOutput = new PrintStream(connection.getOutputStream());
			osOutput.println(sMessage);
			osOutput.println("\r\n\r\n");
			osOutput.close();

			/*
			int xRead = 0;
			byte[] ba = new byte[512];
			DataInputStream isInput = null;
			 */
			
			int iRetCode = connection.getResponseCode();
			switch (iRetCode) { // switch on HTTP response code
			case 200: // ok
			{
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Recv: ContentType: "+connection.getContentType());
				
				/*
				isInput = new DataInputStream(connection.getInputStream());
				ByteArrayOutputStream bos = new ByteArrayOutputStream();  // RH, 20080714, n
				// Retrieve message as bytes and put them in a string
				while ((xRead = isInput.read(ba)) != -1) {
					// append to stringbuffer
					//sb.append(new String(ba, 0, xRead)); // RH, 20080714, o
					bos.write(ba, 0, xRead); // RH, 20080714, n
					// clear the buffer
					Arrays.fill(ba, (byte) 0);
					
				} 
				*/
				// TODO, we might want to parse the charset from the connection
				// 		then we should use stream2string(connection.getInputStream, <charset>);
				// For now we assume utf-8 (default)
				sb = new StringBuffer(Tools.stream2string(connection.getInputStream()));  // RH, 20080715, n
//				// close the stream
//				isInput.close();
				break;
			}
			case 500: // Internal server error
			{
				StringBuffer sbBuffer = new StringBuffer("Internal server error at target host. errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				break;
			}
			default: // unknown error
			{
				StringBuffer sbBuffer = new StringBuffer("Invalid response from target host: \"");
				sbBuffer.append(connection.getHeaderField(0));
				sbBuffer.append(" \". errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				break;
			}
			}
		}
		catch (java.net.UnknownHostException eUH)// target host unknown
		{
			StringBuffer sbBuffer = new StringBuffer("Target host unknown: \"");
			sbBuffer.append(sUrl);
			sbBuffer.append("\" errorcode: ");
			sbBuffer.append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eUH);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, eUH);
		}
		catch (java.io.IOException eIO)
		// error while connecting,writing or reading
		{
			StringBuffer sbBuffer = new StringBuffer("Could not open connection with host: \"");
			sbBuffer.append(sUrl);
			sbBuffer.append("\" errorcode: ");
			sbBuffer.append(Errors.ERROR_ASELECT_IO);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eIO);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, eIO);
		}
		return sb.toString();
	}
	

}
