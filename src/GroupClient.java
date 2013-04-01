/* Implements the GroupClient Interface */

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Hex;

public class GroupClient extends Client implements GroupClientInterface {

	protected X509Certificate cert;
	protected GroupClientThread gcThread;
	protected ArrayBlockingQueue<Object> inputQueue;
	

	public GroupClient(String inputServer, int inputPort, ClientController _cc) {
		super(inputServer, inputPort, _cc);
		publicKey = null;
		cert = null;
		Object pemObject = null;
		inputQueue = new ArrayBlockingQueue<Object>(1);
		
		// Import the public key
		PEMReader reader = null;
		try {
			reader = new PEMReader(new FileReader("public-cert.pem"));
			pemObject = reader.readObject();
			
			if (pemObject instanceof X509Certificate) {
				X509Certificate cert = (X509Certificate) pemObject;
				cert.checkValidity(); // to check it's valid in time
				publicKey = cert.getPublicKey();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		if (publicKey == null) {
			System.out.println("Problem setting up the public key.");
		} else {
			System.out.println("Imported the public key: "
					+ new String(Hex.encode(publicKey.getEncoded())));
		}
	}

	public boolean connect() {
		if (!super.connect()) {
			return false;
		}

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

		// If the group server returns the nonce - 1, then we know it is
		// actually the group server.
		// We also know to begin using the session key
		if (nonceReturn == (nonce - 1)) {
			System.out.println("Successfully created a secure session!");
			// Create the listening thread
			gcThread = new GroupClientThread(output, input, this);
			// Run the thread
			gcThread.start();

			return true;
		} else {
			sessionKey = null;

			//
			// TODO: Might have to modify this later to have an encrypted
			// disconnect
			secureDisconnect();
			//

			return false;
		}
	}

	// This gets called by the internal thread to update the token in the
	// controller.
	public boolean updateToken(Token _token) {
		return controller.updateToken(_token);
	}

	private int beginSession(ArrayList<Object> list) {
		try {
			// Envelope message = null, response = null;
			SecureEnvelope secureMessage = null;
			SecureEnvelope secureResponse = null;

			// Create the secure message
			secureMessage = new SecureEnvelope("SESSIONINIT");

			// Set the payload using the encrypted ArrayList
			secureMessage.setPayload(encryptPayload(listToByteArray(list),
					false, null));

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
					if (tempList.size() == 3) {
						int returnNonce = (Integer) tempList.get(2);
						// Grab the sequenceNumber from the message as well
						sequenceNumber = (Integer)tempList.get(1);
						return returnNonce;
					}
				}
			}

			return -1;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return -1;
		}
	}

	public Token getToken(String username, String password) {
		try {
			Token token = null;
			// Envelope message = null, response = null;
			SecureEnvelope secureMessage = null;

			// Make a temporary ArrayList which which be converted to a byte
			// array
			ArrayList<Object> list = new ArrayList<Object>();

			// Add the username
			list.add(username);
			list.add(password);

			// Make a new SecureEnvelope using the appropriate method
			// Set the message type to GET to return a token
			secureMessage = makeSecureEnvelope("GET", list);
			
			output.writeObject(secureMessage);

			// Get the response from the server
			//secureResponse = (SecureEnvelope) input.readObject();
			//secureResponse = (SecureEnvelope)inputQueue.take();
			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();
			
			// Successful response
			//if (secureResponse.getMessage().equals("OK")) {
			if (((String)(tempList.get(0))).equals("OK")) {
				// If there is a token in the SecureEnvelope, return it
				if (tempList.size() == 3) {
					token = (Token)tempList.get(2);
					return token;
				}
			}

			return null;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean createUser(String username, String password, UserToken token) {
		try {
			SecureEnvelope secureMessage = null, secureResponse = null;
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(username);
			list.add(password);
			list.add(token);
			secureMessage = makeSecureEnvelope("CUSER", list);
			output.writeObject(secureMessage);

			//secureResponse = (SecureEnvelope) input.readObject();
			//secureResponse = (SecureEnvelope)inputQueue.take();
			
			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();

			// If server indicates success, return true
			if (((String)(tempList.get(0))).equals("OK")) {
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUser(String username, UserToken token) {
		try {
			SecureEnvelope secureMessage = null;
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(username);
			list.add(token);
			secureMessage = makeSecureEnvelope("DUSER", list);
			output.writeObject(secureMessage);

			//secureResponse = (SecureEnvelope) input.readObject();
			//secureResponse = (SecureEnvelope)inputQueue.take();
			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();

			// If server indicates success, return true
			if (((String)(tempList.get(0))).equals("OK")) {
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean createGroup(String groupname, UserToken token) {
		try {
			SecureEnvelope secureMessage = null;
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(groupname);
			list.add(token);
			secureMessage = makeSecureEnvelope("CGROUP", list);
			output.writeObject(secureMessage);

			//secureResponse = (SecureEnvelope) input.readObject();
			//secureResponse = (SecureEnvelope)inputQueue.take();
			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();

			// If server indicates success, return true
			if (((String)(tempList.get(0))).equals("OK")) {
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteGroup(String groupname, UserToken token) {
		try {
			SecureEnvelope secureMessage = null;
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(groupname);
			list.add(token);
			secureMessage = makeSecureEnvelope("DGROUP", list);
			output.writeObject(secureMessage);

			//secureResponse = (SecureEnvelope) input.readObject();
			//secureResponse = (SecureEnvelope)inputQueue.take();
			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();

			// If server indicates success, return true
			if (((String)(tempList.get(0))).equals("OK")) {
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}


	@SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token) {
		try {
			SecureEnvelope secureMessage = null;
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(group);
			list.add(token);
			secureMessage = makeSecureEnvelope("LMEMBERS", list);
			output.writeObject(secureMessage);

			//secureResponse = (SecureEnvelope) input.readObject();
			//secureResponse = (SecureEnvelope)inputQueue.take();
			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();

			// If server indicates success, return true
			if (((String)(tempList.get(0))).equals("OK")) {
				return (List<String>)tempList.get(2);
			}

			return null;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean addUserToGroup(String username, String groupname,
			UserToken token) {
		try {
			SecureEnvelope secureMessage = null;
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(username);
			list.add(groupname);
			list.add(token);
			secureMessage = makeSecureEnvelope("AUSERTOGROUP", list);
			output.writeObject(secureMessage);

			//secureResponse = (SecureEnvelope) input.readObject();
			//secureResponse = (SecureEnvelope)inputQueue.take();
			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();

			// If server indicates success, return true
			if (((String)(tempList.get(0))).equals("OK")) {
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean addOwnerToGroup(String username, String groupname,
			UserToken token) {
		try {
			SecureEnvelope secureMessage = null;
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(username);
			list.add(groupname);
			list.add(token);
			secureMessage = makeSecureEnvelope("AOWNERTOGROUP", list);
			output.writeObject(secureMessage);

			//secureResponse = (SecureEnvelope) input.readObject();
			//secureResponse = (SecureEnvelope)inputQueue.take();
			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();

			// If server indicates success, return true
			if (((String)(tempList.get(0))).equals("OK")) {
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUserFromGroup(String username, String groupname,
			UserToken token) {
		try {
			SecureEnvelope secureMessage = null;
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(username);
			list.add(groupname);
			list.add(token);
			secureMessage = makeSecureEnvelope("RUSERFROMGROUP", list);
			output.writeObject(secureMessage);

			//secureResponse = (SecureEnvelope) input.readObject();
			//secureResponse = (SecureEnvelope)inputQueue.take();
			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();

			// If server indicates success, return true
			if (((String)(tempList.get(0))).equals("OK")) {
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
	
	public ArrayList<Object> getNewFileKey(String groupname, UserToken token){
		try{
			SecureEnvelope secureMessage = null;
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(groupname);
			list.add(token);
			secureMessage = makeSecureEnvelope("NEWFILEKEY", list);
			output.writeObject(secureMessage);


			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();
			return tempList;		
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;		
		}
	}
	
	public SecretKeySpec getFileKey(byte[] seed, int keyId, String group, UserToken token) {
		SecureEnvelope secureMessage = null;
		ArrayList<Object> list = new ArrayList<Object>();
		list.add(group);
		list.add(seed);
		list.add(keyId);
		list.add(token);
		secureMessage = makeSecureEnvelope("RETRIEVEFILEKEY", list);
		try {
			output.writeObject(secureMessage);
			ArrayList<Object> tempList = (ArrayList<Object>)inputQueue.take();
			String msg = (String)tempList.get(0);
			if(msg.equals("OK")){
				return (SecretKeySpec) tempList.get(2);
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

	}
}
