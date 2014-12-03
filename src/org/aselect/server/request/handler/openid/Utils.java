package org.aselect.server.request.handler.openid;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.http.HttpServletResponse;

import org.aselect.server.log.ASelectSystemLogger;
import org.openid4java.message.Message;
import org.openid4java.message.Parameter;
import org.openid4java.message.ParameterList;

public abstract class Utils
{
	private final static String MODULE = "Utils";

	public static void sendPlainTextResponse(HttpServletResponse response, Message message, ASelectSystemLogger _systemLogger)
	{
		String sMethod = "sendPlainTextResponse";

		response.setContentType("text/plain");
		OutputStream os = null;
		try {
			os = response.getOutputStream();
			os.write(message.keyValueFormEncoding().getBytes());
		} catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not send response message", e);
		} finally {
			try {
				if (os != null)
					os.close();
			} catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not close outputstream", e);
			}
		}
	}

	public static void sendDiscoveryResponse(HttpServletResponse response, String message, ASelectSystemLogger _systemLogger)
	throws IOException
	{
		String sMethod = "sendDiscoveryResponse";
		_systemLogger.log(Level.INFO, MODULE, sMethod,
				"sending XRDS Response: " + message);

		response.setContentType("application/xrds+xml");
		OutputStream outputStream = response.getOutputStream();
		outputStream.write(message.getBytes());
		outputStream.close();
	}
	
	/**
	 * This is a helpful method to enable if you want to see what is being sent
	 * across. Disable this in production.
	 * 
	 * @param request
	 */
	@SuppressWarnings("unchecked")
	public static void logRequestParameters(ParameterList request, ASelectSystemLogger _systemLogger)
	{
		String sMethod = "logRequestParameters";
		_systemLogger.log(Level.INFO, MODULE, sMethod,
				"Dumping request parameters:");
		if (request != null) {
			List<Parameter> paramList = request.getParameters();
			for (Parameter parameter : paramList) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Parameter:"
						+ parameter.getKey() + ":" + parameter.getValue());
			}
		} else {
			_systemLogger.log(Level.INFO, MODULE, sMethod,
					"Parameterlist empty");
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod,
				"End dumping request parameters");
	}
}
