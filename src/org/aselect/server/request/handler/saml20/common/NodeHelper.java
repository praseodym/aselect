package org.aselect.server.request.handler.saml20.common;

import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.opensaml.Configuration;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class NodeHelper
{
	private static final String MODULE = "NodeHelper";

	public Node getNode(Node node, String sSearch)
	{
		Node nResult = null;
		NodeList nodeList = node.getChildNodes();
		for (int i = 0; i < nodeList.getLength() && nResult == null; i++) {
			if (sSearch.equals(nodeList.item(i).getLocalName()))
				nResult = nodeList.item(i);
			else
				nResult = getNode(nodeList.item(i), sSearch);
		}
		return nResult;
	}

	/**
	 * Helper method that marshalls the given message.
	 * 
	 * @param message
	 *            message the marshall and serialize
	 * @return marshalled message
	 * @throws MessageEncodingException
	 *             thrown if the give message can not be marshalled into its DOM
	 *             representation
	 */
	public Element marshallMessage(XMLObject message)
	throws MessageEncodingException
	{
		String sMethod = "marshallMessage()";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();

		try {
			Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(message);
			if (marshaller == null) {
				systemLogger.log(Level.INFO, MODULE, sMethod,
						"Unable to marshall message, no marshaller registered for message object: "
								+ message.getElementQName());
			}
			Element messageElem = marshaller.marshall(message);
			systemLogger.log(Level.INFO, MODULE, sMethod, "Marshalled message into DOM:\n"
					+ XMLHelper.nodeToString(messageElem));

			return messageElem;
		}
		catch (MarshallingException e) {
			throw new MessageEncodingException("Encountered error marshalling message into its DOM representation", e);
		}
	}

	public XMLObject unmarshallElement(Element element)
	throws MessageEncodingException
	{
		String sMethod = "unmarshallMessage()";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();

		try {
			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(element);
			if (unmarshaller == null) {
				systemLogger.log(Level.INFO, MODULE, sMethod,
						"Unable to unmarshall element, no unmarshaller registered for element object: " + element);
			}
			XMLObject xmlObject = unmarshaller.unmarshall(element);
			systemLogger.log(Level.INFO, MODULE, sMethod, "Unmarshalled element to: " + xmlObject.getClass());

			return xmlObject;
		}
		catch (UnmarshallingException e) {
			throw new MessageEncodingException(
					"Encountered error unmarshalling element into its object representation", e);
		}
	}
}
