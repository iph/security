package cs1653.termproject.servers;

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Hex;

/**
 * Group server. Server loads the users from UserList.bin and groups from GroupList.bin.
 * If user list does not exists, it creates a new list and prompts the user to create a server administrator.
 * On exit, and periodically, the server saves the user and group lists to file. 
 * @author Sean and Matt
 *
 */
public class GroupServer extends Server {
	public static final int SERVER_PORT = 8765; // Default port if none specified
	public final String USER_FILE = "UserList.bin"; // User file name
	public final String GROUP_FILE = "GroupList.bin"; // Group file name
	public final String MASTER_KEY_FILE = "MasterKeyList.bin"; // Master File Key file name
	public UserList userList; // User list
	public GroupList groupList; // Group list
	public PrivateKey privateKey; // Group Server private key
	public PublicKey publicKey; // Group Server public key
	protected ArrayList<byte[]> masterKeyList; // Master File Key list
	private Scanner console; // Input console

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		console = new Scanner(System.in);

		// This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		// Add BouncyCastle as a provider
		Security.addProvider(new BouncyCastleProvider());

		// Import the private key
		if (!importPrivateKey()) {
			console.close();
			return; // End server execution if there was no key imported
		}

		// Import the public key
		if (!importPublicKey()) {
			console.close();
			return; // End server execution if there was no key imported
		}

		// Load the master file keys
		if(!loadKeys()) {
			// Just in case, if there is no key file, use the MasterKeyManger's public method to create one!
			MasterKeyManager.addKeyExternal();
			// Now try loading the keys again.
			loadKeys();
		}

		// Import the user and group lists
		if (!importLists()) {
			console.close();
			return; // End server execution if the lists were not import successfully
		}

		// No more input needed if everything completed successfully
		console.close();

		// Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		// This block listens for connections and creates threads on new connections
		try {
			System.out.println("Good to go! Listening for new connections...");
			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;

			while(true) {
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	private boolean importPrivateKey() {
		boolean importSuccess = false;
		PEMReader reader = null;
		privateKey = null;
		Object pemObject = null;

		try {
			reader = new PEMReader(new FileReader("private-key.pem")); // Read the pem file containing the private KeyPair
			pemObject = reader.readObject(); // Read the KeyPair as a pemObject
			reader.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		KeyPair pair = (KeyPair)pemObject; // Cast the pemObject to a KeyPair
		privateKey = pair.getPrivate(); // Get the private key from the KeyPair

		if(privateKey == null) { // If there was no private key
			System.out.println("Problem setting up the private key.");
		}
		else { // Successful import
			System.out.println("Imported the private key: " + new String(Hex.encode(privateKey.getEncoded())));
			importSuccess = true;
		}

		return importSuccess;
	}

	private boolean importPublicKey() {
		boolean importSuccess = false;
		PEMReader publicReader = null;
		Object publicPEMObject = null;

		try {
			publicReader = new PEMReader(new FileReader("public-cert.pem")); // Read the pem file containing the certificate of the public key
			publicPEMObject = publicReader.readObject(); // Read the certificate as a pemObject
			publicReader.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		if (publicPEMObject instanceof X509Certificate) {
			X509Certificate cert = (X509Certificate)publicPEMObject; // Cast the pemObject as an X509 certificate
			try {
				cert.checkValidity(); // Check validity of the certificate (2 years from issuance)
				publicKey = cert.getPublicKey(); // Set the public key to the key in the certificate
			} catch (Exception e) {
				e.printStackTrace();
			} 
		}

		if(publicKey == null) { // If there was no public key
			System.out.println("Problem setting up the public key.");
		}
		else { // Successful import
			System.out.println("Imported the public key: " + new String(Hex.encode(publicKey.getEncoded())));
			importSuccess = true;
		}

		return importSuccess;
	}

	private boolean importLists() {
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		boolean importSuccess = false;
		FileInputStream user_fis = null;
		FileInputStream group_fis = null;

		try { // Try importing both lists. If one fails, redo everything to maintain stability
			// Import the userList
			user_fis = new FileInputStream(USER_FILE);
			userStream = new ObjectInputStream(user_fis);
			userList = (UserList)userStream.readObject();
			userStream.close();
			// Import the groupList
			group_fis = new FileInputStream(GROUP_FILE);
			groupStream = new ObjectInputStream(group_fis);
			groupList = (GroupList)groupStream.readObject();
			groupStream.close();
			// Imports where successful
			importSuccess = true;
		}
		catch(FileNotFoundException e) // Expected behavior, just create both lists from scratch
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.nextLine();
			System.out.print("Enter your password: ");
			String password = console.nextLine();

			// Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username, password);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			// Create a new groupList with the group ADMIN and the new admin as owner and member
			groupList = new GroupList();
			groupList.addGroup("ADMIN");
			groupList.addOwner("ADMIN", username);
			groupList.addMember("ADMIN", username);

			ObjectOutputStream outStream;
			try {
				// Write the user file
				outStream = new ObjectOutputStream(new FileOutputStream(USER_FILE));
				outStream.writeObject(userList);
				outStream.close();
				// Write the group file
				outStream = new ObjectOutputStream(new FileOutputStream(GROUP_FILE));
				outStream.writeObject(groupList);
				outStream.close();
				importSuccess = true;
			} catch(Exception e2) { // Something wrong trying to write the files
				e2.printStackTrace();
			}
		} catch (Exception e) { // Some other exception, not good!
			e.printStackTrace();
		}

		return importSuccess;
	}

	private boolean loadKeys() {
		boolean returnValue = false;
		FileInputStream fis = null;

		try {
			fis = new FileInputStream(MASTER_KEY_FILE);
			ObjectInputStream keyStream = new ObjectInputStream(fis);
			masterKeyList = (ArrayList<byte[]>)keyStream.readObject();
			fis.close();
			returnValue = true;
		} catch (FileNotFoundException e) {
			System.out.println("There is no key file yet!");
		} catch (Exception e) {
			System.out.println("keyFile issue!");
			e.printStackTrace();
		}

		return returnValue;
	}
}

// This thread saves the user list
class ShutDownListener extends Thread {
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run() {
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try {
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			outStream.close();
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.groupList);
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread {
	private GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run() {
		do {
			try {
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream(my_gs.USER_FILE));
					outStream.writeObject(my_gs.userList);
					outStream.close();
					outStream = new ObjectOutputStream(new FileOutputStream(my_gs.GROUP_FILE));
					outStream.writeObject(my_gs.groupList);
				} catch(Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e) {
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
