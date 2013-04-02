package cs1653.termproject.servers;
/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.net.Socket;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.KeyGenerator;
import cs1653.termproject.shared.Envelope;
import cs1653.termproject.shared.SecureEnvelope;
import cs1653.termproject.shared.SecurityUtils;
import cs1653.termproject.shared.Ticket;
import cs1653.termproject.shared.Token;

public class FileThread extends ServerThread
{
	private final Socket socket;
	private FileServer my_fs;
	private boolean tamperedTicket;
	private final int threadID;

	public FileThread(Socket _socket, FileServer _fs)
	{
		socket = _socket;
		my_fs = _fs;
		
		// Create a secure random number generator
		SecureRandom rand = new SecureRandom();

		// Get random int and set the threadID for later use
		threadID = rand.nextInt();
	}

	public void run()
	{
		boolean proceed = true;
		try {
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			
			// Announce the public key to the client in an unsecured envelope
			Envelope response;
			response = new Envelope("KEYANNOUNCE");
			response.addObject(my_fs.publicKey);
			output.writeObject(response);

			do {
				SecureEnvelope secureMessage = (SecureEnvelope)input.readObject();
				SecureEnvelope secureResponse = null;
				
				
				// Only initializing the session uses a plaintext msg in the SecureEnvelope
				if ((secureMessage.getMessage() != null) && (secureMessage.getMessage().equals("SESSIONINIT"))) {
					System.out.println("Request received: " + secureMessage.getMessage());
					
					// If there is no payload
					if(secureMessage.getPayload() == null) {
						secureResponse = new SecureEnvelope("FAIL");
						output.writeObject(secureResponse);
					}
					else {
						// Get the list from the SecureEnvelope, false because it's NOT using the session key
						ArrayList<Object> objectList = getDecryptedPayload(secureMessage, false, my_fs.privateKey);
						// Make sure it doesn't return null and it has two elements in the list
						if (!(objectList == null) && (objectList.size() == 2)) {
							// Grab the session 
							sessionKey = (Key)objectList.get(0);
							int nonce = (Integer)objectList.get(1);
							nonce = nonce - 1; // nonce - 1 to return
							
							// Create a secure random number generator
							SecureRandom rand = new SecureRandom();

							// Get random int sequenceNumber and set it
							sequenceNumber = rand.nextInt();
							// Key generation for HMAC
							KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
							integrityKey = keyGen.generateKey();
							
							ArrayList<Object> list = new ArrayList<Object>();
							list.add(nonce);
							
							// Create a new Ticket for this session, and add it to the message
							Ticket yourTicket = createTicket();
							list.add(yourTicket);
							list.add(integrityKey);
							secureResponse = makeSecureEnvelope("OK", list);
							
							output.writeObject(secureResponse);
						}
						else {
							secureResponse = new SecureEnvelope("FAIL");
							output.writeObject(secureResponse);
						}
					}
				}
				else {
					ArrayList<Object> contents = getDecryptedPayload(secureMessage, true, null);
					String msg = (String)contents.get(0);
					
					System.out.println("Request received: " + msg);
					
					if ((Integer)contents.get(1) == (sequenceNumber + 1)) {
						sequenceNumber++;
					}
					else {
						tamperedConnection = true;
						System.out.println("CONNECTION TAMPERING DETECTED!");
					}
					verifyHMAC(listToByteArray(contents), secureMessage.getHMAC());

					if(msg.equals("LFILES")) {
						// Need dat token
						if(contents.size() < 4) {
							secureResponse = makeSecureEnvelope("FAIL-BADCONTENTS");
							output.writeObject(secureResponse);
						}
						else {
							Token yourToken = (Token)contents.get(2);
							Ticket yourTicket = (Ticket)contents.get(3);
							if (verifyToken(yourToken)) {
								if (verifyTicket(yourTicket)) {
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
									secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTICKET");
									System.out.println("User is trying to use a modified ticket!");
								}
							}
							else {
								secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
								System.out.println("User is trying to use a modified token!");
							}
							
							output.writeObject(secureResponse);
						}
					}
					if(msg.equals("UPLOADF")) {
						if(contents.size() < 6) {
							secureResponse = makeSecureEnvelope("FAIL-BADCONTENTS");
						}
						else {
							if(contents.get(2) == null) {
								secureResponse = makeSecureEnvelope("FAIL-BADPATH");
							}
							else if(contents.get(3) == null) {
								secureResponse = makeSecureEnvelope("FAIL-BADGROUP");
							}
							else if(contents.get(4) == null) {
								secureResponse = makeSecureEnvelope("FAIL-BADTOKEN");
							}
							else if (contents.get(5) == null) {
								secureResponse = makeSecureEnvelope("FAIL-BADTICKET");
							}
							else {
								String remotePath = (String)contents.get(2);
								String group = (String)contents.get(3);
								Token yourToken = (Token)contents.get(4); // Extract token
								Ticket yourTicket = (Ticket)contents.get(5); // Extract ticket
								
								if (!verifyToken(yourToken)) {
									secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
								}
								else if (!verifyTicket(yourTicket)) {
									secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTICKET");
								}
								else if (FileServer.fileList.checkFile(remotePath)) {
									System.out.printf("Error: file already exists at %s\n", remotePath);
									secureResponse = makeSecureEnvelope("FAIL-FILEEXISTS"); //Success
								}
								else if (!yourToken.getGroups().contains(group)) {
									System.out.printf("Error: user missing valid token for group %s\n", group);
									secureResponse = makeSecureEnvelope("FAIL-UNAUTHORIZED"); //Success
								}
								else  {
									File file = new File("shared_files/"+remotePath.replace('/', '_'));
									file.createNewFile();
									FileOutputStream fos = new FileOutputStream(file);
									System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

									secureResponse = makeSecureEnvelope("READY"); //Success
									output.writeObject(secureResponse);

									secureMessage = (SecureEnvelope)input.readObject();
									contents = getDecryptedPayload(secureMessage, true, null);
									msg = (String)contents.get(0);
									
									if ((Integer)contents.get(1) == (sequenceNumber + 1)) {
										sequenceNumber++;
									}
									else {
										tamperedConnection = true;
										System.out.println("CONNECTION TAMPERING DETECTED!");
									}
									
									while (msg.equals("CHUNK")) {
										fos.write((byte[])contents.get(2), 0, (Integer)contents.get(3));
										secureResponse = makeSecureEnvelope("READY"); // Success
										output.writeObject(secureResponse);
										// Read new SecureEnvelope
										secureMessage = (SecureEnvelope)input.readObject();
										contents = getDecryptedPayload(secureMessage, true, null);
										msg = (String)contents.get(0);
										
										if ((Integer)contents.get(1) == (sequenceNumber + 1)) {
											sequenceNumber++;
										}
										else {
											tamperedConnection = true;
											System.out.println("CONNECTION TAMPERING DETECTED!");
										}
									}

									if(msg.equals("EOF")) {
										byte[] iv = (byte[])contents.get(2);
										byte[] seed = (byte[]) contents.get(3);
										int keyId = (Integer) contents.get(4); 
										System.out.printf("Transfer successful file %s\n", remotePath);
										FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, iv, seed, keyId);
										secureResponse = makeSecureEnvelope("OK"); // Success
									}
									else {
										System.out.printf("Error reading file %s from client\n", remotePath);
										secureResponse = makeSecureEnvelope("FAIL-ERROR-TRANSFER"); // Fail
									}
									fos.close();
								}
							}
						}

						output.writeObject(secureResponse);
					}
					else if (msg.compareTo("DOWNLOADF")==0) {
						String remotePath = (String)contents.get(2);
						Token t = (Token)contents.get(3);
						Ticket yourTicket = (Ticket)contents.get(4);
						
						if (!verifyToken(t)) {
							secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
							System.out.println("User is trying to use a modified token!");
							output.writeObject(secureResponse);
						}
						else if (!verifyTicket(yourTicket)) {
							secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTICKET");
							System.out.println("User is trying to use a modified ticket!");
							output.writeObject(secureResponse);
						}
						else {
							ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
							if (sf == null) {
								System.out.printf("Error: File %s doesn't exist\n", remotePath);
								secureResponse = makeSecureEnvelope("FAIL-ERROR_FILEMISSING");
								output.writeObject(secureResponse);
		
							}
							else if (!t.getGroups().contains(sf.getGroup())){
								System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
								secureResponse = makeSecureEnvelope("FAIL-ERROR_PERMISSION");
								output.writeObject(secureResponse);
							}
							else {
								try {
									File f = new File("shared_files/_"+remotePath.replace('/', '_'));
									if (!f.exists()) {
										System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
										secureResponse = makeSecureEnvelope("FAIL-ERROR_NOTONDISK");
										output.writeObject(secureResponse);
			
									}
									else {
										FileInputStream fis = new FileInputStream(f);
			
										do {
											byte[] buf = new byte[4096];
											if (msg.compareTo("DOWNLOADF")!=0) {
												System.out.printf("Server error: %s\n", msg);
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
											
											secureResponse = makeSecureEnvelope("CHUNK", tempList);
			
											output.writeObject(secureResponse);
			
											secureMessage = (SecureEnvelope)input.readObject();
											contents = getDecryptedPayload(secureMessage, true, null);
											msg = (String)contents.get(0);
											
											if ((Integer)contents.get(1) == (sequenceNumber + 1)) {
												sequenceNumber++;
											}
											else {
												tamperedConnection = true;
												System.out.println("CONNECTION TAMPERING DETECTED!");
											}
			
										}
										while (fis.available()>0);
			
										//If server indicates success, return the member list
										if(msg.equals("DOWNLOADF")) {
											secureResponse = makeSecureEnvelope("EOF");
											output.writeObject(secureResponse);
			
											secureMessage = (SecureEnvelope)input.readObject();
											contents = getDecryptedPayload(secureMessage, true, null);
											msg = (String)contents.get(0);
											
											if ((Integer)contents.get(1) == (sequenceNumber + 1)) {
												sequenceNumber++;
											}
											else {
												tamperedConnection = true;
												System.out.println("CONNECTION TAMPERING DETECTED!");
											}
											
											
											if(msg.equals("OK")) {
												System.out.printf("File data upload successful\n");
											}
											else {
												System.out.printf("Upload failed: %s\n", secureMessage.getMessage());
											}
										}
										else {
											System.out.printf("Upload failed: %s\n", secureMessage.getMessage());
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
					else if (msg.equals("DELETEF")) {
						String remotePath = (String)contents.get(2);
						Token t = (Token)contents.get(3);
						Ticket yourTicket = (Ticket)contents.get(4);
						
						if (!verifyToken(t)) {
							System.out.println("User is trying to use a modified token!");
							secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
						}
						else if (!verifyTicket(yourTicket)) {
							System.out.println("User is trying to use a modified ticket!");
							secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTICKET");
						}
						else {
							ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
							if (sf == null) {
								System.out.printf("Error: File %s doesn't exist\n", remotePath);
								secureResponse = makeSecureEnvelope("FAIL-ERROR_DOESNTEXIST");
							}
							else if (!t.getGroups().contains(sf.getGroup())){
								System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
								secureResponse = makeSecureEnvelope("FAIL-ERROR_PERMISSION");
							}
							else {
								try
								{
									File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));
		
									if (!f.exists()) {
										System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
										secureResponse = makeSecureEnvelope("FAIL-ERROR_FILEMISSING");
									}
									else if (f.delete()) {
										System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
										FileServer.fileList.removeFile("/"+remotePath);
										secureResponse = makeSecureEnvelope("OK");
									}
									else {
										System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
										secureResponse = makeSecureEnvelope("FAIL-ERROR_DELETE");
									}
		
		
								}
								catch(Exception e1) {
									System.err.println("Error: " + e1.getMessage());
									e1.printStackTrace(System.err);
									secureResponse = makeSecureEnvelope("FAIL-UNKNOWN");
								}
							}
						}
						
						output.writeObject(secureResponse);
						
					}
					else if(msg.equals("DISCONNECT"))
					{
						socket.close();
						proceed = false;
					}
					else if (msg.equals("FILEINFO")) {
						if(contents.size() < 5) {
							secureResponse = makeSecureEnvelope("FAIL-BADCONTENTS");
						}
						if(contents.get(2) == null) {
							secureResponse = makeSecureEnvelope("FAIL-BADPATH");
						}
						else if(contents.get(3) == null) {
							secureResponse = makeSecureEnvelope("FAIL-BADTOKEN");
						}
						else if (contents.get(4) == null) {
							secureResponse = makeSecureEnvelope("FAIL-BADTICKET");
						}
						else {
							String remotePath = (String)contents.get(2);
							Token yourToken = (Token)contents.get(3); // Extract token
							Ticket yourTicket = (Ticket)contents.get(4); // Extract ticket
							
							if (!verifyToken(yourToken)) {
								secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
							}
							else if (!verifyTicket(yourTicket)) {
								secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTICKET");
							}
							else if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								secureResponse = makeSecureEnvelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(FileServer.fileList.getFile("/"+remotePath).getGroup())) {
								System.out.printf("Error: user missing valid token for group %s\n", FileServer.fileList.getFile(remotePath).getGroup());
								secureResponse = makeSecureEnvelope("FAIL-UNAUTHORIZED"); //Success
							}
							else{

								ShareFile file = FileServer.fileList.getFile("/"+remotePath);
								ArrayList<Object> list = new ArrayList<Object>();
								list.add(file.getIV());
								list.add(file.getSeed());
								list.add(file.getKeyId());
								list.add(file.getGroup());
								System.out.println("Sending file info..." + list);
								secureResponse = makeSecureEnvelope("OK", list);

							}
						}
						output.writeObject(secureResponse);
					}
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	// Method to create tickets
	private Ticket createTicket() {
		System.out.println("Creating a ticket...");
		Ticket newTicket = new Ticket("FileServer", threadID);
		
		byte[] ticketBytes = newTicket.toByteArray();
		byte[] signedTicketBytes = signBytes(ticketBytes, my_fs.privateKey);
		
		newTicket.setSignature(signedTicketBytes);
		
		return newTicket;
	}
	
	/*
	 * Check hmac here.
	 * 
	 */
	private boolean verifyHMAC(byte[] hmac, byte[] contents) {
		tamperedConnection = SecurityUtils.checkHMAC(contents, hmac, integrityKey);
		if(tamperedConnection){
			System.out.println("CONNECTION TAMPERING DETECTED--WRONG HMAC");
		}
		return tamperedConnection;
	}
	
	private boolean verifyTicket(Ticket ticket) {
		boolean verified = false;
		
		byte[] sigBytes = null;
		byte[] ticketBytes = null;
		Signature sig = null;
		
		ticketBytes = ticket.toByteArray();
		sigBytes = ticket.getSignature();
		
		System.out.println("Verifying token...");
		
		if (ticket.getThreadID() == threadID) {
			
			try {
				sig = Signature.getInstance("SHA512WithRSAEncryption", "BC");
				sig.initVerify(my_fs.publicKey);
				sig.update(ticketBytes);
				verified = sig.verify(sigBytes);
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			if (!verified) {
				tamperedTicket = true;
				System.out.println("Ticket tampered with!");
			}
			System.out.println("Ticket verified? " + verified);
			
		}
		else {
			System.out.println("Wrong ticket!");
			tamperedTicket = true;
			verified = false;
		}
		
		return verified;
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
			e.printStackTrace();
		}
		
		if (!verified) {
			tamperedToken = true;
			System.out.println("Token tampered with!");
		}
		
		System.out.println("Token verified? " + verified);
		
		return verified;
	}

}
