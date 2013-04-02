package cs1653.termproject.clients;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cs1653.termproject.shared.SecureEnvelope;
import cs1653.termproject.shared.SecurityUtils;

public class FileClientThread extends Thread {
	private FileClient my_fc;
	private ObjectOutputStream output;
	private ObjectInputStream input;
	
	private volatile boolean proceed;
	
	public FileClientThread (ObjectOutputStream _output, ObjectInputStream _input, FileClient _fc)
	{
		my_fc = _fc;
		output = _output;
		input = _input;
		proceed = true;
	}
	
	public void run() {
		Security.addProvider(new BouncyCastleProvider());
		
		try {
			do {
				SecureEnvelope secureMessage = null;
				ArrayList<Object> contents = null;
				byte[] hmac = null;
				String msg = null;
				try {
					secureMessage = (SecureEnvelope)input.readObject();
					contents = getDecryptedPayload(secureMessage);
					hmac = secureMessage.getHMAC();
					msg = (String)contents.get(0);
					System.out.println("FileClientThread message received: " + msg);
				} catch (EOFException e) {
					System.out.println("Thread shutting down...");
					break;
				}
				
				if ((Integer)contents.get(1) == (my_fc.sequenceNumber + 1)) {
					my_fc.sequenceNumber++;
				}
				else {
					my_fc.tamperedConnection = true;
					System.out.println("CONNECTION TAMPERING DETECTED!");
				}
				
				//System.out.println("hmac is: " + Arrays.toString(hmac));
				//System.out.println("contents is: "+ Arrays.toString(listToByteArray(contents)));
				//System.out.println("Key is..." + Arrays.toString(my_fc.integrityKey.getEncoded()));
				if(hmac == null || !SecurityUtils.checkHMAC(listToByteArray(contents), hmac, my_fc.integrityKey)){
					my_fc.tamperedConnection = true;
					System.out.println("CONNECTION TAMPERING DETECTED -- HMAC FAIL!");
					if(hmac == null){
						System.out.println("NO HMAC DETECTED");
					}
				}
				
				// Put the contents in the queue.
				my_fc.inputQueue.put(contents);
				
				/* This isn't needed most likely.
				 * There probably won't be a case where the file server pushes to the client without a request.
				SecureEnvelope secureResponse = null;
				
				if ((msg.equals("OK")) || (msg.contains("FAIL"))) {
					// If it is an OK or FAIL message, pass it to the main FileClient thread via queue
					my_fc.inputQueue.put(contents);
				}
				else {
					secureResponse = makeSecureEnvelope("FAIL-UNKNOWN"); // Client does not understand server request
					output.writeObject(secureResponse);
				}
				*/
			}while(proceed);	
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	/* Crypto Related Methods
	 * 
	 * These methods will abstract the whole secure session process.
	 * 
	 */
 
	// Wrap the other makeSecureEnvelope message by passing an empty list
	protected SecureEnvelope makeSecureEnvelope(String msg) {
		ArrayList<Object> list = new ArrayList<Object>();
		return makeSecureEnvelope(msg, list);
	}
	 
	protected SecureEnvelope makeSecureEnvelope(String msg, ArrayList<Object> list) {
		// Make a new envelope
		SecureEnvelope envelope = new SecureEnvelope();
		
		// Create new ivSpec
		IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
		
		// Set the ivSpec in the envelope
		envelope.setIV(ivSpec.getIV());
		
		// Increment the sequenceNumber
		my_fc.sequenceNumber++;
		
		// Add the msg and sequenceNumber to the list
		list.add(0, my_fc.sequenceNumber);
		list.add(0, msg);
		
		// Set the payload using the encrypted ArrayList
		byte[] payloadBytes = listToByteArray(list);
		byte[] hmac = SecurityUtils.createHMAC(payloadBytes, my_fc.integrityKey);
		envelope.setHMAC(hmac);
		envelope.setPayload(encryptPayload(payloadBytes, true, ivSpec));		
		return envelope;
	}
	
	private byte[] encryptPayload(byte[] plainText, boolean useSessionKey, IvParameterSpec ivSpec) {
		byte[] cipherText = null;
		Cipher inCipher;
		
		if (useSessionKey) {
			// TODO
			try {
				inCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				inCipher.init(Cipher.ENCRYPT_MODE, my_fc.sessionKey, ivSpec);
				cipherText = inCipher.doFinal(plainText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else { // Use public key RSA
			try {
				inCipher = Cipher.getInstance("RSA", "BC");
				inCipher.init(Cipher.ENCRYPT_MODE, my_fc.publicKey, new SecureRandom());
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
			outCipher.init(Cipher.DECRYPT_MODE, my_fc.sessionKey, ivSpec);
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
