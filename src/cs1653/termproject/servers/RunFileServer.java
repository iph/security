package cs1653.termproject.servers;

/**
 * Driver program for running the File Server.
 * @author Sean and Matt
 *
 */
public class RunFileServer {
	public static void main(String[] args) {
		if (args.length > 0) {
			try {
				FileServer server = new FileServer(Integer.parseInt(args[0]));
				server.start();
			}
			catch (NumberFormatException e) {
				System.out.printf("Enter a valid port number or pass no arguments to use the default port (%d)\n", FileServer.SERVER_PORT);
			}
		}
		else {
			FileServer server = new FileServer();
			server.start();
		}
	}
}
