import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

public class StopAgent {

	public static void main(String[] args) {
		try {
			int port = 1946;
			if (args.length > 0) port = Integer.parseInt(args[0]);
			int timeoutMs = 5000;
			if (args.length > 1) timeoutMs = Integer.parseInt(args[1]);
			String msg = "request=stop";
			if (args.length > 2) msg = args[2];
			InetAddress addr = InetAddress.getByName("localhost");
			SocketAddress sockaddr = new InetSocketAddress(addr, port);
			Socket sock = new Socket();
			sock.connect(sockaddr, timeoutMs);
			OutputStreamWriter out = new OutputStreamWriter(sock.getOutputStream());
			out.write(msg);
			out.write("\r\n");
			out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
