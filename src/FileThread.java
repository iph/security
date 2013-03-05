/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.List;
import java.util.ArrayList;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class FileThread extends Thread
{
	private final Socket socket;
	private FileServer my_fs;
	private Key sessionKey;

	public FileThread(Socket _socket, FileServer _fs)
	{
		socket = _socket;
		my_fs = _fs;
	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			
			// Announce the public key to the client in an unsecured envelope
			Envelope response;
			response = new Envelope("KEYANNOUNCE");
			response.addObject(my_fs.publicKey);
			output.writeObject(response);

			do
			{
				SecureEnvelope secureMessage = (SecureEnvelope)input.readObject();
				System.out.println("Request received: " + secureMessage.getMessage());
				
				SecureEnvelope secureResponse;
				SecureEnvelope secureEnv = null;

				// Handler to list files that this user is allowed to see
				if(secureMessage.getMessage().equals("SESSIONINIT")) // Client wants to initialize a secure session
				{
					// ONLY USE UNSECURE ENVELOPE FOR RETURNING THE NONCE!!!
					// NOWHERE ELSE!
					if(secureMessage.getPayload() == null)
					{
						response = new Envelope("FAIL");
						output.writeObject(response);
					}
					else {
						// Get the list from the SecureEnvelope, false because it's NOT using the session key
						ArrayList<Object> objectList = getDecryptedPayload(secureMessage, false);
						// Make sure it doesn't return null and it has two elements in the list
						if (!(objectList == null) && (objectList.size() == 2)) {
							// Grab the session 
							sessionKey = (Key)objectList.get(0);
							int nonce = (Integer)objectList.get(1);
							nonce = nonce - 1; // nonce - 1 to return
							response = new Envelope("OK");
							response.addObject(nonce);
							output.writeObject(response);
							// Reset the input stream for a secure connection
							
						}
					}
				}
				else if(secureMessage.getMessage().equals("LFILES"))
				{
					// Need dat token
					
					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
					
					if(list.size() < 1)
					{
						secureResponse = new SecureEnvelope("FAIL-BADCONTENTS");
						output.writeObject(secureResponse);
					}
					else {
						Token yourToken = (Token)list.get(0);
						if (verifyToken(yourToken)) {
							List<String> fileNames = new ArrayList<String>();
							
							// Add all files that you can touch.
							for(ShareFile file: FileServer.fileList.getFiles()){
		
								//WE GOOD GUYS, DIS OUR FILE
								if(yourToken.getGroups().contains(file.getGroup())){
									fileNames.add(file.getPath());
								}
							}
							
							ArrayList<Object> tempList = new ArrayList<Object>();
							tempList.add(fileNames);
							secureResponse = makeSecureEnvelope("OK", tempList);
						}
						else {
							secureResponse = new SecureEnvelope("FAIL-MODIFIEDTOKEN");
							System.out.println("User is trying to use a modified token!");
						}
						
						output.writeObject(secureResponse);
					}
				}
				if(secureMessage.getMessage().equals("UPLOADF"))
				{
					
					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);

					if(list.size() < 3)
					{
						secureResponse = new SecureEnvelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(list.get(0) == null) {
							secureResponse = new SecureEnvelope("FAIL-BADPATH");
						}
						if(list.get(1) == null) {
							secureResponse = new SecureEnvelope("FAIL-BADGROUP");
						}
						if(list.get(2) == null) {
							secureResponse = new SecureEnvelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)list.get(0);
							String group = (String)list.get(1);
							Token yourToken = (Token)list.get(2); //Extract token
							
							if (!verifyToken(yourToken)) {
								secureResponse = new SecureEnvelope("FAIL-MODIFIEDTOKEN");
							}
							else if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								secureResponse = new SecureEnvelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								secureResponse = new SecureEnvelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								secureResponse = new SecureEnvelope("READY"); //Success
								output.writeObject(secureResponse);

								secureMessage = (SecureEnvelope)input.readObject();
								while (secureMessage.getMessage().compareTo("CHUNK")==0) {
									// Get new secureMessage contents
									list = getDecryptedPayload(secureMessage, true);
									
									fos.write((byte[])list.get(0), 0, (Integer)list.get(1));
									secureResponse = new SecureEnvelope("READY"); //Success
									output.writeObject(secureResponse);
									secureMessage = (SecureEnvelope)input.readObject();
								}

								if(secureMessage.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									secureResponse = new SecureEnvelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									secureResponse = new SecureEnvelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(secureResponse);
				}
				else if (secureMessage.getMessage().compareTo("DOWNLOADF")==0) {
					
					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
					
					String remotePath = (String)list.get(0);
					Token t = (Token)list.get(1);
					if (!verifyToken(t)) {
						secureEnv = new SecureEnvelope("FAIL-MODIFIEDTOKEN");
						System.out.println("User is trying to use a modified token!");
						output.writeObject(secureEnv);
					}
					else {
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							secureEnv = new SecureEnvelope("ERROR_FILEMISSING");
							output.writeObject(secureEnv);
	
						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							secureEnv = new SecureEnvelope("ERROR_PERMISSION");
							output.writeObject(secureEnv);
						}
						else {
	
							try
							{
								File f = new File("shared_files/_"+remotePath.replace('/', '_'));
								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									secureEnv = new SecureEnvelope("ERROR_NOTONDISK");
									output.writeObject(secureEnv);
		
								}
								else {
									FileInputStream fis = new FileInputStream(f);
		
									do {
										byte[] buf = new byte[4096];
										if (secureMessage.getMessage().compareTo("DOWNLOADF")!=0) {
											System.out.printf("Server error: %s\n", secureMessage.getMessage());
											break;
										}
										int n = fis.read(buf); //can throw an IOException
										if (n > 0) {
											System.out.printf(".");
										} else if (n < 0) {
											System.out.println("Read error");
		
										}
										
										ArrayList<Object> tempList = new ArrayList<Object>();
										tempList.add(buf);
										tempList.add(new Integer(n));
										
										secureEnv = makeSecureEnvelope("CHUNK", tempList);
		
										output.writeObject(secureEnv);
		
										secureMessage = (SecureEnvelope)input.readObject();
		
		
									}
									while (fis.available()>0);
		
									//If server indicates success, return the member list
									if(secureMessage.getMessage().compareTo("DOWNLOADF")==0)
									{
										secureEnv = new SecureEnvelope("EOF");
										output.writeObject(secureEnv);
		
										secureEnv = (SecureEnvelope)input.readObject();
										if(secureEnv.getMessage().compareTo("OK")==0) {
											System.out.printf("File data upload successful\n");
										}
										else {
											System.out.printf("Upload failed: %s\n", secureEnv.getMessage());
										}
									}
									else {
		
										System.out.printf("Upload failed: %s\n", secureEnv.getMessage());
		
									}
									fis.close();
								}
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e1.getMessage());
								e1.printStackTrace(System.err);
	
							}
						}
					}
				}
				else if (secureMessage.getMessage().compareTo("DELETEF")==0) {

					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
					
					String remotePath = (String)list.get(0);
					Token t = (Token)list.get(1);
					
					if (!verifyToken(t)) {
						System.out.println("User is trying to use a modified token!");
						secureEnv = new SecureEnvelope("FAIL-MODIFIEDTOKEN");
					}
					else {
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							secureEnv = new SecureEnvelope("ERROR_DOESNTEXIST");
						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							secureEnv = new SecureEnvelope("ERROR_PERMISSION");
						}
						else {
							try
							{
								File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));
	
								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									secureEnv = new SecureEnvelope("ERROR_FILEMISSING");
								}
								else if (f.delete()) {
									System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
									FileServer.fileList.removeFile("/"+remotePath);
									secureEnv = new SecureEnvelope("OK");
								}
								else {
									System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
									secureEnv = new SecureEnvelope("ERROR_DELETE");
								}
	
	
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e1.getMessage());
								e1.printStackTrace(System.err);
								secureEnv = new SecureEnvelope(e1.getMessage());
							}
						}
					}
					
					output.writeObject(secureEnv);
					
				}
				else if(secureMessage.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
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
				inCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
				cipherText = inCipher.doFinal(plainText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else { // Use public key RSA
			try {
				inCipher = Cipher.getInstance("RSA", "BC");
				inCipher.init(Cipher.ENCRYPT_MODE, my_fs.privateKey, new SecureRandom());
				System.out.println("plainText length: " + plainText.length);
				cipherText = inCipher.doFinal(plainText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		return cipherText;
	}
	
	private ArrayList<Object> getDecryptedPayload(SecureEnvelope envelope, boolean useSessionKey) {
		// Using this wrapper method in case the envelope changes at all :)
		IvParameterSpec iv = null;
		if (envelope.getIV() != null) {
			iv = new IvParameterSpec(envelope.getIV());
		}
		
		return byteArrayToList(decryptPayload(envelope.getPayload(), iv, useSessionKey));
	}
	
	private byte[] decryptPayload(byte[] cipherText, IvParameterSpec ivSpec, boolean useSessionKey) {
		Cipher outCipher = null;
		byte[] plainText = null;
		
		if (useSessionKey) {
			try {
				outCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				outCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
				plainText = outCipher.doFinal(cipherText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else {
			try {
				outCipher = Cipher.getInstance("RSA", "BC");
				outCipher.init(Cipher.DECRYPT_MODE, my_fs.privateKey, new SecureRandom());
				plainText = outCipher.doFinal(cipherText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
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
	
	private boolean verifyToken(Token token) {
		boolean verified = false;
		
		byte[] sigBytes = null;
		byte[] tokenBytes = null;
		Signature sig = null;
		
		tokenBytes = token.toByteArray();
		sigBytes = token.getSignature();
		
		System.out.println("Verifying token...");
		
		try {
			sig = Signature.getInstance("SHA512WithRSAEncryption", "BC");
			sig.initVerify(my_fs.publicKeyGS);
			sig.update(tokenBytes);
			verified = sig.verify(sigBytes);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("Token verified: " + verified);
		
		return verified;
	}

}
