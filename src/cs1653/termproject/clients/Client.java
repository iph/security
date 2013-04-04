package cs1653.termproject.clients;

import java.net.Socket;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import cs1653.termproject.shared.Envelope;
import cs1653.termproject.shared.SecureEnvelope;
import cs1653.termproject.shared.SecurityUtils;

/**
 * Client is the base class for GroupClient and FileClient. It holds the encryption/decryption/envelope methods.
 * @author Sean and Matt
 *
 */
public abstract class Client {
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected String myServer;
	protected int myPort;
	protected ClientController controller;
	protected Key sessionKey;
	protected Key integrityKey;
	protected PublicKey publicKey;
	protected int sequenceNumber;
	protected boolean tamperedConnection;

	/**
	 * Connect to a server.
	 * @param server Address of the server to connect to
	 * @param port Port of the server to connect to
	 * @return True if connected, successfully, otherwise false
	 */
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

	/**
	 * Connect to a server using previously initialized variables (due to constructor).
	 * @return True if connected, successfully, otherwise false
	 */
	public boolean connect() {
		return connect(myServer, myPort);
	}

	/**
	 * Constructor for the client instance.
	 * @param server Address of the server to connect to later
	 * @param port Port of the server to connect to later
	 * @param _controller ClientController that is maintaining this client
	 */
	public Client (String server, int port, ClientController _controller) {
		myServer = server;
		myPort = port;
		controller = _controller;
	}

	/**
	 * Check the state of the client socket.
	 * @return True if the socket it connected, false if not
	 */
	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	/**
	 * Perform an unsecure disconnection from the server.
	 */
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

	/**
	 * Perform a secure disconnection (encrypted messages) from the server.
	 */
	public void secureDisconnect() {
		if (isConnected()) {
			try {
				SecureEnvelope secureMessage = makeSecureEnvelope("DISCONNECT");
				output.writeObject(secureMessage);
			}
			catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}


	/* ******************************
	 * Crypto Related Methods
	 ****************************** */

	/**
	 * Creates a SecureEnvelope with just a message in it. Serves as a wrapper for the more detailed method.
	 * @param msg The msg for the SecureEnvelope
	 * @return SecureEnvelope ready to send
	 */
	protected SecureEnvelope makeSecureEnvelope(String msg) {
		ArrayList<Object> list = new ArrayList<Object>();
		return makeSecureEnvelope(msg, list);
	}

	/**
	 * Creates a SecureEnvelope based on a msg and a list of Objects. The msg and a sequence number are added to the payload implicitly.
	 * @param msg The msg of the SecureEnvelope
	 * @param list The list of Objects to be added to the SecureEnvelope
	 * @return SecureEnvelope ready to send
	 */
	protected SecureEnvelope makeSecureEnvelope(String msg, ArrayList<Object> list) {
		// Make a new envelope
		SecureEnvelope envelope = new SecureEnvelope();

		// Create new ivSpec
		IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);

		// Set the ivSpec in the envelope
		envelope.setIV(ivSpec.getIV());

		// Increment the sequenceNumber
		sequenceNumber++;

		// Add the msg and sequenceNumber to the list
		list.add(0, sequenceNumber);
		list.add(0, msg);

		// Get the byte[] conversion of the payload list
		byte[] payloadBytes = listToByteArray(list);
		// Generate an HMAC for the message
		byte[] hmac = SecurityUtils.createHMAC(payloadBytes, integrityKey);
		// Set the HMAC in the envelope
		envelope.setHMAC(hmac);
		// Set the payload to the encrypted byte[] of the list
		envelope.setPayload(encryptPayload(payloadBytes, true, ivSpec));

		return envelope;
	}

	/**
	 * Method to encrypt a payload of a SecureEnvelope.
	 * @param plainText Unencrypted byte[] plain text payload
	 * @param useSessionKey True to use the session key, false to use the PublicKey
	 * @param ivSpec The random IV to use for the session key option
	 * @return byte[] of encrypted payload data
	 */
	protected byte[] encryptPayload(byte[] plainText, boolean useSessionKey, IvParameterSpec ivSpec) {
		byte[] cipherText = null;
		Cipher inCipher;

		if (useSessionKey) {
			try {
				inCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				inCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
				cipherText = inCipher.doFinal(plainText);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		else { // Use public key RSA
			try {
				inCipher = Cipher.getInstance("RSA", "BC");
				inCipher.init(Cipher.ENCRYPT_MODE, publicKey, new SecureRandom());
				System.out.println("plainText length: " + plainText.length);
				cipherText = inCipher.doFinal(plainText);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return cipherText;
	}

	/**
	 * Decrypts the payload of the SecureEnvelope that was passed in and returns the plain text data.
	 * @param envelope SecureEnvelope whose payload to decrypt
	 * @return ArrayList<Object> containing the decrypted payload
	 */
	protected ArrayList<Object> getDecryptedPayload(SecureEnvelope envelope) {
		return byteArrayToList(decryptPayload(envelope.getPayload(), new IvParameterSpec(envelope.getIV())));
	}

	/**
	 * Decrypts a payload of encrypted data into a plain text byte[].
	 * @param cipherText The byte[] of encrypted data
	 * @param ivSpec The IV to use for decryption
	 * @return byte[] containng the decrypted payload
	 */
	private byte[] decryptPayload(byte[] cipherText, IvParameterSpec ivSpec) {
		Cipher outCipher = null;
		byte[] plainText = null;

		try {
			outCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			outCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
			plainText = outCipher.doFinal(cipherText);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return plainText;
	}

	/**
	 * Turns a list into a byte[] for encryption.
	 * @param list The list to convert to a byte[]
	 * @return byte[] of the converted list
	 */
	protected byte[] listToByteArray(ArrayList<Object> list) {
		byte[] returnBytes = null;

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = null;
		try {
			out = new ObjectOutputStream(bos);   
			out.writeObject(list);
			returnBytes = bos.toByteArray();
			out.close();
			bos.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return returnBytes;
	}

	/**
	 * Turns a byte[] back into an ArrayList<Object>.
	 * @param byteArray The byte[] to convert to a ArrayList<Object>
	 * @return ArrayList<Object> of the converted list
	 */
	private ArrayList<Object> byteArrayToList(byte[] byteArray) {
		ArrayList<Object> list = null;

		ByteArrayInputStream bis = new ByteArrayInputStream(byteArray);
		ObjectInput in = null;
		try {
			in = new ObjectInputStream(bis);
			Object object = in.readObject();
			list = (ArrayList<Object>)object;
			bis.close();
			in.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

		return list;
	}

}
