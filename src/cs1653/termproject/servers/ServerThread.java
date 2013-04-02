package cs1653.termproject.servers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import cs1653.termproject.shared.SecureEnvelope;
import cs1653.termproject.shared.SecurityUtils;

/**
 * ServerThread is the base class for GroupThread and FileThread. It holds the encryption/decryption/envelope methods.
 * @author Sean and Matt
 *
 */
public abstract class ServerThread extends Thread {
	// Session key to be used for the specific session only
	protected Key sessionKey;
	// Integrity key to use for HMACs in this session
	protected Key integrityKey;
	// Integer to keep track of this session's sequence numbers
	protected int sequenceNumber;
	// Flag to set if the connection is tampered with
	protected boolean tamperedConnection;
	// Flag to set if a token is replaced or tampered with
	protected boolean tamperedToken;
	
	/**
	 * Hash+Sign the bytes passed in using the specified PrivateKey.
	 * @param text The byte[] to sign
	 * @param privateKey The PrivateKey to use for the signing process
	 * @return byte[] containing the signed hash
	 */
	protected byte[] signBytes(byte[] text, PrivateKey privateKey) {
		byte[] sigBytes = null;
		Signature sig = null;
		
		System.out.println("Signing bytes...");
		
		try {
			sig = Signature.getInstance("SHA512WithRSAEncryption", "BC");
			sig.initSign(privateKey);
			sig.update(text);
			sigBytes = sig.sign();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return sigBytes;
	}
	
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
		
		// Set the payload using the encrypted ArrayList
		// Set the payload using the encrypted ArrayList
		byte[] payloadBytes = listToByteArray(list);
		byte[] hmac = SecurityUtils.createHMAC(payloadBytes, integrityKey);
		envelope.setHMAC(hmac);
		System.out.println("hmac is: " + Arrays.toString(hmac));
		System.out.println("contents is: "+ Arrays.toString(listToByteArray(list)));
		//System.out.println("Contents are..." + list);
		envelope.setPayload(encryptPayload(payloadBytes, true, ivSpec, null));
		
		return envelope;
	}
	
	/**
	 * Helper method to encrypt a payload of a SecureEnvelope.
	 * @param plainText Unencrypted byte[] plain text payload
	 * @param useSessionKey True to use the session key, false to use the PrivateKey provided (NOT recommended)
	 * @param ivSpec The random IV to use for the session key option
	 * @param privateKey The PrivateKey if the use is desired (NOT recommended)
	 * @return byte[] of encrypted payload data
	 */
	protected byte[] encryptPayload(byte[] plainText, boolean useSessionKey, IvParameterSpec ivSpec, PrivateKey privateKey) {
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
				inCipher.init(Cipher.ENCRYPT_MODE, privateKey, new SecureRandom());
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
	 * @param useSessionKey True to use the sessionKey, false to use the PrivateKey specified (i.e. for SESSIONINIT)
	 * @param privateKey PrivateKey to use if the option was chosen
	 * @return ArrayList<Object> containing the decrypted payload
	 */
	protected ArrayList<Object> getDecryptedPayload(SecureEnvelope envelope, boolean useSessionKey, PrivateKey privateKey) {
		// Using this wrapper method in case the envelope changes at all :)
		IvParameterSpec iv = null;
		if (envelope.getIV() != null) {
			iv = new IvParameterSpec(envelope.getIV());
		}
		
		return byteArrayToList(decryptPayload(envelope.getPayload(), iv, useSessionKey, privateKey));
	}
	
	/**
	 * Decrypts a payload of encrypted data into a plain text byte[].
	 * @param cipherText The byte[] of encrypted data
	 * @param ivSpec The IV to use for decryption
	 * @param useSessionKey True to use the session key, false to use the PrivateKey specified (i.e. for SESSIONINIT)
	 * @param privateKey PrivateKey to use if the option was chosen
	 * @return byte[] containng the decrypted payload
	 */
	protected byte[] decryptPayload(byte[] cipherText, IvParameterSpec ivSpec, boolean useSessionKey, PrivateKey privateKey) {
		Cipher outCipher = null;
		byte[] plainText = null;
		
		if (useSessionKey) {
			try {
				outCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				outCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
				plainText = outCipher.doFinal(cipherText);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		else {
			try {
				outCipher = Cipher.getInstance("RSA", "BC");
				outCipher.init(Cipher.DECRYPT_MODE, privateKey, new SecureRandom());
				plainText = outCipher.doFinal(cipherText);
			} catch (Exception e) {
				e.printStackTrace();
			}
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
	 * @param byteArray The byte[] to conver to a ArrayList<Object>
	 * @return ArrayList<Object> of the converted list
	 */
	protected ArrayList<Object> byteArrayToList(byte[] byteArray) {
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
