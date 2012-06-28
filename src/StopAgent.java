import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

/**
 * The Class StopAgent.
 */
public class StopAgent {

	/**
	 * The main method.
	 * 
	 * @param args
	 *            the arguments: <port> <timeOutMs> <request=...>
	 */
	public static void main(String[] args)
	{
		int port = 1946;
		int timeoutMs = 5000;
		String req = "request=stop";
		try {
			// NOTE: do not use Utils.<...> this makes the class dependant on org.aselect.system.jar
			if (args.length > 0 && args[0] != null)
				port = Integer.parseInt(args[0]);
			if (args.length > 1 && args[1] != null)
				timeoutMs = Integer.parseInt(args[1]);
			if (args.length > 2)
				req = args[2];
			if (args.length > 3)
				req += "&"+args[3];
			InetAddress addr = InetAddress.getByName("localhost");
			SocketAddress sockaddr = new InetSocketAddress(addr, port);
			Socket sock = new Socket();
			sock.connect(sockaddr, timeoutMs);
			OutputStreamWriter out = new OutputStreamWriter(sock.getOutputStream());
			out.write(req);
			out.write("\r\n");
			out.close();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
