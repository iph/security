import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected String myServer;
	protected int myPort;
	protected ClientController my_cc;

	public boolean connect(final String server, final int port) {
		System.out.println("attempting to connect");

		try{
		    // Connect to the specified server
		    sock = new Socket(server, port);
		    
		    // Set up I/O streams with the server
		    output = new ObjectOutputStream(sock.getOutputStream());
		    input = new ObjectInputStream(sock.getInputStream());
		    return true;
		}
		catch(Exception e){
		    System.err.println("Error: " + e.getMessage());
		    e.printStackTrace(System.err);
		    return false;
		}
	}
	
	public boolean connect() {
		return connect(myServer, myPort);
	}
	
	public Client (String inputServer, int inputPort, ClientController _cc) {
		myServer = inputServer;
		myPort = inputPort;
		my_cc = _cc;
	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect() {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
	
	public void secureDisconnect() {
		if (isConnected()) {
			try
			{
				SecureEnvelope secureMessage = new SecureEnvelope("DISCONNECT");
				output.writeObject(secureMessage);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
