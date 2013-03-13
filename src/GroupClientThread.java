import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupClientThread extends Thread {
	
	//private final Socket socket;
	private GroupClient my_gc;
	private ObjectOutputStream output;
	private ObjectInputStream input;
	
	private volatile boolean proceed;
	
	public GroupClientThread (ObjectOutputStream _output, ObjectInputStream _input, GroupClient _gc)
	{
		my_gc = _gc;
		output = _output;
		input = _input;
		proceed = true;
	}
	
	public void run() {
		Security.addProvider(new BouncyCastleProvider());
		
		try {
			do {
				SecureEnvelope secureMessage = null;
				try {
					secureMessage = (SecureEnvelope)input.readObject();
					System.out.println("GroupClientThread message received: " + secureMessage.getMessage());
				} catch (EOFException e) {
					System.out.println("Thread shutting down...");
					break;
				}
				
				SecureEnvelope secureResponse = null;
				
				if ((secureMessage.getMessage().equals("OK")) || (secureMessage.getMessage().contains("FAIL"))) {
					// If it is an OK or FAIL message, pass it to the main GroupClient thread via queue
					my_gc.inputQueue.put(secureMessage);
				}
				else if(secureMessage.getMessage().equals("UPDATE-TOKEN")) { // If the server is pushing an updated token
					ArrayList<Object> list = getDecryptedPayload(secureMessage);
					if(list.size() == 1) {
						updateToken((Token)list.get(0));
						secureResponse = new SecureEnvelope("OK-TOKEN");
					}
					else {
						secureResponse = new SecureEnvelope("FAIL-TOKEN"); // Bad new token
					}
					
					output.writeObject(secureResponse);
				}
				else {
					secureResponse = new SecureEnvelope("FAIL-UNKNOWN"); // Client does not understand server request
					output.writeObject(secureResponse);
				}
			}while(proceed);	
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	// Update the token in the controller. Done by calling up to the GroupClient.
	private boolean updateToken(Token _token) {
		return my_gc.updateToken(_token);
	}
	
	/* Crypto Related Methods
	 * 
	 * These methods will abstract the whole secure session process.
	 * 
	 */
 
	private SecureEnvelope makeSecureEnvelope(String msg, ArrayList<Object> list) {
		// Make a new envelope
		SecureEnvelope envelope = new SecureEnvelope(msg);
		
		// Create new ivSpec
		IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
		
		// Set the ivSpec in the envelope
		envelope.setIV(ivSpec.getIV());
		
		// Set the payload using the encrypted ArrayList
		envelope.setPayload(encryptPayload(listToByteArray(list), true, ivSpec));
		
		return envelope;
		
	}
	
	private byte[] encryptPayload(byte[] plainText, boolean useSessionKey, IvParameterSpec ivSpec) {
		byte[] cipherText = null;
		Cipher inCipher;
		
		if (useSessionKey) {
			// TODO
			try {
				inCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				inCipher.init(Cipher.ENCRYPT_MODE, my_gc.sessionKey, ivSpec);
				cipherText = inCipher.doFinal(plainText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else { // Use public key RSA
			try {
				inCipher = Cipher.getInstance("RSA", "BC");
				inCipher.init(Cipher.ENCRYPT_MODE, my_gc.publicKey, new SecureRandom());
				System.out.println("plainText length: " + plainText.length);
				cipherText = inCipher.doFinal(plainText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		return cipherText;
	}
	
	private ArrayList<Object> getDecryptedPayload(SecureEnvelope envelope) {
		// Using this wrapper method in case the envelope changes at all :)
		return byteArrayToList(decryptPayload(envelope.getPayload(), new IvParameterSpec(envelope.getIV())));
	}
	
	private byte[] decryptPayload(byte[] cipherText, IvParameterSpec ivSpec) {
		Cipher outCipher = null;
		byte[] plainText = null;
		
		try {
			outCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			outCipher.init(Cipher.DECRYPT_MODE, my_gc.sessionKey, ivSpec);
			plainText = outCipher.doFinal(cipherText);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return plainText;
	}
	
	private byte[] listToByteArray(ArrayList<Object> list) {
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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return returnBytes;
	}
	
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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return list;
	}
	
	
}
