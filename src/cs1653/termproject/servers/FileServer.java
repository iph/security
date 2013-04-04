package cs1653.termproject.servers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Hex;

/**
 * File Server loads files from FileList.bin.  Stores files in shared_files directory.
 * @author Sean and Matt
 *
 */
public class FileServer extends Server {
	public static final int SERVER_PORT = 4321; // Default port if none specified
	public FileList fileList; // File list
	public final String FILE_FILE = "FileList.bin"; // File list file name
	public PrivateKey privateKey; // File Server private key
	public PublicKey publicKey; // File Server public key
	public PublicKey publicKeyGS; // Group Server public key

	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FileServerBeta");
	}

	public void start() {
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS(this));
		runtime.addShutdownHook(catchExit);

		// Add BouncyCastle as a provider
		Security.addProvider(new BouncyCastleProvider());

		// Import the keys
		if (!importKeys()) {
			return; // End server execution if there was no key imported in any case
		}

		// Import/Create file list
		if (!importFileList()) {
			return; // End server execution if there was no list imported or created
		}

		// Create/Verify shared_files directory
		File file = new File("shared_files");
		if (file.mkdir()) { // If the directory was newly created
			System.out.println("Created new shared_files directory");
		}
		else if (file.exists()) { // If the directory already exists
			System.out.println("Found shared_files directory");
		}
		else { // Directory could not be created or verified
			System.out.println("Error creating shared_files directory");
			return;
		}

		// Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS(this);
		aSave.setDaemon(true);
		aSave.start();

		boolean running = true;

		try {			
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());

			Socket sock = null;
			Thread thread = null;

			while(running) {
				sock = serverSock.accept();
				thread = new FileThread(sock, this);
				thread.start();
			}

			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}

	private boolean importFileList() {
		ObjectInputStream fileStream = null;
		boolean importSuccess = false;

		// Open fileList file
		try {
			FileInputStream fis = new FileInputStream(FILE_FILE);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
			fileStream.close();
			importSuccess = true;
		}
		catch(FileNotFoundException e) { // Expected behavior, just create a new fileList
			System.out.println("FileList Does Not Exist. Creating FileList...");
			fileList = new FileList();
			importSuccess = true;
		} catch(Exception e) {
			e.printStackTrace();
		}

		return importSuccess;
	}

	private boolean importFSPrivateKey() {
		boolean importSuccess = false;
		PEMReader reader = null;
		privateKey = null;
		Object pemObject = null;

		try {
			reader = new PEMReader(new FileReader("private-keyFS.pem")); // Read the pem file containing the private KeyPair
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

	private boolean importFSPublicKey() {
		boolean importSuccess = false;
		PEMReader publicReader = null;
		Object publicPEMObject = null;

		try {
			publicReader = new PEMReader(new FileReader("public-certFS.pem")); // Read the pem file containing the certificate of the public key
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

	private boolean importGSPublicKey() {
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
				publicKeyGS = cert.getPublicKey(); // Set the public key to the key in the certificate
			} catch (Exception e) {
				e.printStackTrace();
			} 
		}

		if(publicKeyGS == null) { // If there was no public key
			System.out.println("Problem setting up the Group Server public key.");
		}
		else { // Successful import
			System.out.println("Imported the Group Server public key: " + new String(Hex.encode(publicKey.getEncoded())));
			importSuccess = true;
		}

		return importSuccess;
	}

	private boolean importKeys() {
		boolean importSuccess = false;

		// If all keys were imported successfully
		if ((importFSPrivateKey()) && (importFSPublicKey()) && (importGSPublicKey())) {
			importSuccess = true;
		}

		return importSuccess;
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable {
	private FileServer my_fs;

	public ShutDownListenerFS (FileServer _fs) {
		my_fs = _fs;
	}

	public void run() {
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try {
			outStream = new ObjectOutputStream(new FileOutputStream(my_fs.FILE_FILE));
			outStream.writeObject(my_fs.fileList);
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread {
	private FileServer my_fs;

	public AutoSaveFS (FileServer _fs) {
		my_fs = _fs;
	}

	public void run() {
		do {
			try {
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream(my_fs.FILE_FILE));
					outStream.writeObject(my_fs.fileList);
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
