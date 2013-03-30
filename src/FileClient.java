/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;

import javax.crypto.KeyGenerator;

import org.bouncycastle.util.encoders.Base64;

public class FileClient extends Client implements FileClientInterface {

	private String fingerprint; // Printable version of FS's public key :)
	protected FileClientThread fcThread;
	protected ArrayBlockingQueue<Object> inputQueue;
	protected Ticket myTicket;
	
	public FileClient(String inputServer, int inputPort, ClientController _cc) {
		super(inputServer, inputPort, _cc);
		inputQueue = new ArrayBlockingQueue<Object>(1);
	}
	
	public boolean connect() {
		if (!super.connect())
			return false;
		
		return getPublicKey();
	}
	
	public String getFingerprint() {
		return fingerprint;
	}


	private int beginSession(ArrayList<Object> list) {
		try
		{
			//Envelope message = null, response = null;
			SecureEnvelope secureMessage = null;
			SecureEnvelope secureResponse = null;
			
			// Create the secure message
			secureMessage = new SecureEnvelope("SESSIONINIT");
			
			// Set the payload using the encrypted ArrayList
			secureMessage.setPayload(encryptPayload(listToByteArray(list), false, null));
			
			// Write the envelope to the socket
			output.writeObject(secureMessage);
		
			// Get the response from the server
			secureResponse = (SecureEnvelope)input.readObject();
			
			// If the message is empty or does not equal FAIL, then it is a SecureEnvelope with a nonce-1 and sequenceNumber
			if ((secureResponse.getMessage() == null) || (!secureResponse.getMessage().equals("FAIL"))) {
				ArrayList<Object> tempList = getDecryptedPayload(secureResponse);
				// Successful response
				if (((String)(tempList.get(0))).equals("OK")) {
					// If there is a return nonce in the Envelope, return it
					if (tempList.size() == 4) {
						int returnNonce = (Integer) tempList.get(2);
						// Grab the sequenceNumber from the message as well
						sequenceNumber = (Integer)tempList.get(1);
						// Get the Ticket from the message
						myTicket = (Ticket)tempList.get(3);
						return returnNonce;
					}
				}
			}
			
			return -1;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return -1;
		}
	}
	
	private boolean getPublicKey() {
		Envelope message = null;
		try {
			message = (Envelope)input.readObject();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if ((message != null) && message.getMessage().equals("KEYANNOUNCE")) {
			publicKey = (PublicKey)message.getObjContents().get(0);
			if(publicKey == null) {
				System.out.println("Problem getting the public key.");
			}
			else {
				fingerprint = new String(Base64.encode(publicKey.getEncoded()));
				System.out.println("Got the public key: " + fingerprint);
				
			}
			return true;
		}
		else {
			return false;
		}
	}
	
	public boolean setupChannel() {
		
		// Create a secure random number generator
		SecureRandom rand = new SecureRandom();
		
		// Get random integer nonce
		int nonce = rand.nextInt();
		
		// Generate an AES128 key
		System.out.println("Generating an AES 128 key...");
		
		KeyGenerator AESkeygen = null;
		Key AES128key = null;
		
		try {
			AESkeygen = KeyGenerator.getInstance("AES", "BC");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Initialize with a key size of 128
		AESkeygen.init(128);
		
		// Actual key generation
		AES128key = AESkeygen.generateKey();
		sessionKey = AES128key;
		
		// Create the payload ArrayList with the key and the nonce
		ArrayList<Object> payloadList = new ArrayList<Object>();
		payloadList.add(AES128key);
		payloadList.add(nonce);
		
		// Initialize the secure session
		int nonceReturn = beginSession(payloadList);
		
		// If the group server returns the nonce - 1, then we know it is actually the group server.
		// We also know to begin using the session key
		if (nonceReturn == (nonce - 1)) {
			System.out.println("Successfully created a secure session!");
			// Create the listening thread
			fcThread = new FileClientThread(output, input, this);
			// Run the thread
			fcThread.start();
			return true;
		}
		else {
			sessionKey = null;
			
			//
			// TODO: Might have to modify this later to have an encrypted disconnect
			secureDisconnect();
			//
			
			return false;
		}
		
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		SecureEnvelope secureMessage = null;
		
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		ArrayList<Object> list = new ArrayList<Object>();
		list.add(remotePath);
		list.add(token);
		list.add(myTicket);
		secureMessage = makeSecureEnvelope("DELETEF", list);
	    
	    try {
			output.writeObject(secureMessage);
			
			//secureResponse = (SecureEnvelope)input.readObject();
			
			ArrayList<Object> contents = (ArrayList<Object>)inputQueue.take();
			String msg = (String)contents.get(0);
		    
			if (msg.equals("OK")) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, msg);
				return false;
			}			
		} catch (Exception e) {
			e.printStackTrace();
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
		SecureEnvelope secureMessage = null;
		
		if (sourceFile.charAt(0) == '/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try {

			if (!file.exists()) {
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);

				ArrayList<Object> list = new ArrayList<Object>();
				list.add(sourceFile);
				list.add(token);
				list.add(myTicket);
				secureMessage = makeSecureEnvelope("DOWNLOADF", list);
				
				output.writeObject(secureMessage);

				ArrayList<Object> contents = (ArrayList<Object>)inputQueue.take();
				String msg = (String)contents.get(0);

				while (msg.equals("CHUNK")) {
					fos.write((byte[]) contents.get(2), 0, (Integer) contents.get(3));
					System.out.printf(".");
					secureMessage = makeSecureEnvelope("DOWNLOADF"); // Success
					output.writeObject(secureMessage);
					contents = (ArrayList<Object>)inputQueue.take();
					msg = (String)contents.get(0);
				}
				fos.close();

				if (msg.equals("EOF")) {
					fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					secureMessage = makeSecureEnvelope("OK"); // Success
					output.writeObject(secureMessage);
				} else {
					System.out.printf("Error reading file %s (%s)\n", sourceFile, msg);
					file.delete();
					return false;
				}
			}

			else {
				System.out.printf("Error couldn't create file %s\n", destFile);
				return false;
			}

		} catch (IOException e) {
			System.out.printf("Error couldn't create file %s\n", destFile);
			return false;
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		SecureEnvelope secureMessage = null;
		try {
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(token);
			list.add(myTicket);
			secureMessage = makeSecureEnvelope("LFILES", list);

			output.writeObject(secureMessage);

			ArrayList<Object> contents = (ArrayList<Object>) inputQueue.take();
			String msg = (String) contents.get(0);

			// If server indicates success, return the member list
			if (msg.equals("OK")) {
				// This cast creates compiler warnings, sorry.
				return (List<String>) contents.get(2);
			}

			return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public boolean upload(String sourceFile, String destFile, String group, UserToken token) {
		SecureEnvelope secureMessage = null;
		
		if (destFile.charAt(0) != '/') {
			destFile = "/" + destFile;
		}

		try {
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(destFile);
			list.add(group);
			list.add(token);
			list.add(myTicket);
			secureMessage = makeSecureEnvelope("UPLOADF", list);

			output.writeObject(secureMessage);

			FileInputStream fis = new FileInputStream(sourceFile);

			ArrayList<Object> contents = (ArrayList<Object>) inputQueue.take();
			String msg = (String) contents.get(0);

			// If server indicates success, return the member list
			if (msg.equals("READY")) {
				System.out.printf("Meta data upload successful\n");
			} else {
				System.out.printf("Upload failed: %s\n", msg);
				return false;
			}

			do {
				byte[] buf = new byte[4096];
				if (!msg.equals("READY")) {
					System.out.printf("Server error: %s\n", msg);
					return false;
				}

				int n = fis.read(buf); // Can throw an IOException
				if (n > 0) {
					System.out.printf(".");
				} else if (n < 0) {
					System.out.println("Read error");
					return false;
				}

				ArrayList<Object> tempList = new ArrayList<Object>();
				tempList.add(buf);
				tempList.add(new Integer(n));
				secureMessage = makeSecureEnvelope("CHUNK", tempList);

				output.writeObject(secureMessage);

				contents = (ArrayList<Object>) inputQueue.take();
				msg = (String) contents.get(0);

			} while (fis.available() > 0);

			// If server indicates success, return the member list
			if (msg.equals("READY")) {

				secureMessage = makeSecureEnvelope("EOF");
				output.writeObject(secureMessage);

				contents = (ArrayList<Object>) inputQueue.take();
				msg = (String) contents.get(0);

				if (msg.equals("OK")) {
					System.out.printf("\nFile data upload successful\n");
				} else {
					System.out.printf("\nUpload failed: %s\n", msg);
					return false;
				}
			} else {
				System.out.printf("Upload failed: %s\n", msg);
				return false;
			}

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}
}

