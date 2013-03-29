/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	private Key sessionKey;
	private int sequenceNumber;
	private boolean tamperedConnection;
	private boolean tamperedToken;
	private final int threadID;
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
		
		// Create a secure random number generator
		SecureRandom rand = new SecureRandom();

		// Get random int and set the threadID for later use
		threadID = rand.nextInt();
	}
	
	public void run()
	{
		boolean proceed = true;
		tamperedConnection = false;
		Security.addProvider(new BouncyCastleProvider());

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do {
				SecureEnvelope secureMessage = (SecureEnvelope)input.readObject();
				SecureEnvelope secureResponse = null;
				
				// Only initializing the session uses a plaintext msg in the SecureEnvelope
				if ((secureMessage.getMessage() != null) && (secureMessage.getMessage().equals("SESSIONINIT"))) {
					System.out.println("Request received: " + secureMessage.getMessage());
					// Client wants to initialize a secure session
					
					// ONLY USE UNSECURE MSG FOR WHEN THERE IS A PROBLEM!!!
					// NOWHERE ELSE!
					// If there is no payload
					if(secureMessage.getPayload() == null) {
						secureResponse = new SecureEnvelope("FAIL");
						output.writeObject(secureResponse);
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
							
							// Create a secure random number generator
							SecureRandom rand = new SecureRandom();

							// Get random int sequenceNumber and set it
							sequenceNumber = rand.nextInt();
							
							ArrayList<Object> list = new ArrayList<Object>();
							list.add(nonce);
							
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
					ArrayList<Object> contents = getDecryptedPayload(secureMessage, true);
					String msg = (String)contents.get(0);
					
					System.out.println("Request received: " + msg);
					
					if ((Integer)contents.get(1) == (sequenceNumber + 1)) {
						sequenceNumber++;
					}
					else {
						tamperedConnection = true;
						System.out.println("CONNECTION TAMPERING DETECTED!");
					}
					
					if(msg.equals("GET")) {
						//Client wants a token
						//String username = (String)list.get(0); //Get the username
						
						String username = null;
						
						if(secureMessage.getPayload() == null)
						{
							secureResponse = makeSecureEnvelope("FAIL");
							output.writeObject(secureResponse);
						}
						else {
							// Get the decrypted payload, TRUE because it's using the session key
							//ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
							// Get the username from the object list
							if(contents.size() < 4) {
								secureResponse = makeSecureEnvelope("FAIL");
								output.writeObject(secureResponse);
							}
							username = (String)contents.get(2);
							String password = (String)contents.get(3);
							// If the username is null, send a FAIL message
							if ((username == null) || (!my_gs.userList.checkUser(username))) {
								//System.out.println("username: " + username);
								secureResponse = makeSecureEnvelope("FAIL");
								output.writeObject(secureResponse);
							}
							else {
								// Create the token for the user specified
								UserToken yourToken = createToken(username, password);
								ArrayList<Object> newList = new ArrayList<Object>();
								newList.add(yourToken);
								// Respond to the client. On error, the client will receive a null token
								secureResponse = makeSecureEnvelope("OK", newList);
								//secureResponse.addObject(yourToken);
								output.writeObject(secureResponse);
							}
						}
					}
					else if(msg.equals("CUSER")) //Client wants to create a user
					{
						if(contents.size() < 5)
						{
							secureResponse = makeSecureEnvelope("FAIL");
						}
						else
						{
							secureResponse = makeSecureEnvelope("FAIL");
							
							if(contents.get(2) != null && contents.get(3) != null && contents.get(4) != null)
							{
							    String username = (String)contents.get(2); //Extract the username
							    String password = (String)contents.get(3);
							    Token yourToken = (Token)contents.get(4); //Extract the token

							    System.out.println("Create user: " + username + ", password: " + password);
							    if (!verifyToken(yourToken)) {
								    secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
							    }
							    else {
							    	if(createUser(username, password, yourToken)) {
									secureResponse = makeSecureEnvelope("OK"); //Success
									}
							    }
							}
						}
						
						output.writeObject(secureResponse);
					}
					else if(msg.equals("DUSER")) //Client wants to delete a user
					{
						if(contents.size() < 4) {
							secureResponse = makeSecureEnvelope("FAIL");
						}
						else {
							secureResponse = makeSecureEnvelope("FAIL");
							
							if(contents.get(2) != null) {
								if(contents.get(3) != null) {
									String username = (String)contents.get(2); //Extract the username
									Token yourToken = (Token)contents.get(3); //Extract the token
									
									if (!verifyToken(yourToken)) {
										secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
									}
									else {
										if(deleteUser(username, yourToken)) {
											secureResponse = makeSecureEnvelope("OK"); //Success
										}
									}
								}
							}
						}
						
						output.writeObject(secureResponse);
					}
					else if(msg.equals("CGROUP")) //Client wants to create a group
					{
					    /* Create Group:
							Any user can create a group
							Owner of the group.
					    */
						// Make sure contents are correct
						if(contents.size() < 4){
							secureResponse = makeSecureEnvelope("FAIL");
							output.writeObject(secureResponse);
							return;
						}
						String groupname = (String)contents.get(2);
						Token yourToken = (Token)contents.get(3); //Extract the token
						if (!verifyToken(yourToken)) {
							secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
							output.writeObject(secureResponse);
						}
						else {
							if (createGroup(groupname, yourToken)) {
								secureResponse = makeSecureEnvelope("OK");
							}
							else {
								secureResponse = makeSecureEnvelope("FAIL");
							}
							
							output.writeObject(secureResponse);
						}
					}
					else if(msg.equals("DGROUP")) //Client wants to delete a group
					{
					    /*
							boolean deleteGroup(String groupname, UserToken token)
							This method allows the owner of token to delete the specified group, provided that
							they are the owner of that group. After deleting a group, no user should be a member
							of that group.
					    */
						if(contents.size() < 4) {
							secureResponse = makeSecureEnvelope("FAIL");
							output.writeObject(secureResponse);
						}
						else {
							String groupname = (String)contents.get(2);
							Token yourToken = (Token)contents.get(3); //Extract the token

							// deleteGroup method does all the work
							if (deleteGroup(groupname, yourToken)) {
								secureResponse = makeSecureEnvelope("OK");
							}
							else {
								secureResponse = makeSecureEnvelope("FAIL");
							}
								
							output.writeObject(secureResponse);
						}
					}
					else if(msg.equals("LMEMBERS")) { // Client wants a list of members in a group
					    /*
							List<String> listMembers(String group, UserToken token)
							Provided that the owner of token is also the owner of group, this method will return
							a list of all users that are currently members of group
					    */
						if(contents.size() < 4){
							secureResponse = makeSecureEnvelope("FAIL");
							output.writeObject(secureResponse);
							return;
						}

						String groupname = (String)contents.get(2);
						Token yourToken = (Token)contents.get(3); //Extract the token
						String username = yourToken.getSubject();
						
						if (!verifyToken(yourToken)) {
							secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
							output.writeObject(secureResponse);
						}
						else {
							if(!my_gs.groupList.isMember(groupname, username)) {
								secureResponse = makeSecureEnvelope("FAIL");
								output.writeObject(secureResponse);
							}
							else {
								ArrayList<Object> newList = new ArrayList<Object>();
								newList.add(new ArrayList<String>(my_gs.groupList.getMembers(groupname)));
								secureResponse = makeSecureEnvelope("OK", newList);
								output.writeObject(secureResponse);
		
							}
						}
					}
					else if(msg.equals("AUSERTOGROUP")) { // Client wants to add user to a group
					    /*
							boolean addUserToGroup(String user, String group, UserToken token)
							This method enables the owner of token to add the user user to the group group.
							This operation requires that the owner of token is also the owner of group.
					    */
						if(contents.size() < 5){
							secureResponse = makeSecureEnvelope("FAIL");
							output.writeObject(secureResponse);
							return;
						}

						String userToAdd = (String)contents.get(2);
						String groupname = (String)contents.get(3);
						Token yourToken = (Token)contents.get(4); //Extract the token
						if (!verifyToken(yourToken)) {
							secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
							output.writeObject(secureResponse);
						}
						else {
							if (addUserToGroup(groupname, userToAdd, yourToken)) {
								secureResponse = makeSecureEnvelope("OK");
							}
							else {
								secureResponse = makeSecureEnvelope("FAIL");
							}
							
							output.writeObject(secureResponse);	
						}
					}
					else if(msg.equals("AOWNERTOGROUP")) { // Client wants to add owner to a group
						if(contents.size() < 5) {
							secureResponse = makeSecureEnvelope("FAIL");
							output.writeObject(secureResponse);
							return;
						}

						String userToAdd = (String)contents.get(2);
						String groupname = (String)contents.get(3);
						Token yourToken = (Token)contents.get(4); //Extract the token
						if (!verifyToken(yourToken)) {
							secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
							output.writeObject(secureResponse);
						}
						else {
							if (addOwnerToGroup(groupname, userToAdd, yourToken)) {
								secureResponse = makeSecureEnvelope("OK");
							}
							else {
								secureResponse = makeSecureEnvelope("FAIL");
							}
							
							output.writeObject(secureResponse);	
						}
					}
					else if(msg.equals("RUSERFROMGROUP")) { // Client wants to remove user from a group
					    /*
							boolean deleteUserFromGroup(String user, String group, UserToken token)
							This method enables the owner of token to remove the user user from the group
							group. This operation requires that the owner of token is also the owner of group.
					    */
						if(contents.size() < 5) {
							secureResponse = makeSecureEnvelope("FAIL");
							output.writeObject(secureResponse);
							return;
						}

						String userToRemove = (String)contents.get(2);
						String groupname = (String)contents.get(3);
						Token yourToken = (Token)contents.get(4); //Extract the token
						
						if (!verifyToken(yourToken)) {
							secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
							output.writeObject(secureResponse);
						}
						else {
							if (removeUserFromGroup(groupname, userToRemove, yourToken)) {
								secureResponse = makeSecureEnvelope("OK");
							}
							else {
								secureResponse = makeSecureEnvelope("FAIL");
							}
							
							output.writeObject(secureResponse);	
						}
					}
					else if(msg.equals("DISCONNECT")) { // Client wants to disconnect
						socket.close(); //Close the socket
						proceed = false; //End this communication loop
					}
					else { // Server does not understand client request
						secureResponse = makeSecureEnvelope("FAIL");
						output.writeObject(secureResponse);
					}
				}
			}while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	//Method to create tokens
	private UserToken createToken(String username, String password) 
	{
		//Check that user exists
		System.out.println(password);
		if(my_gs.userList.checkUserPassword(username, password))
		{
			//Issue a new token with server's name, user's name, and user's groups
			// Now adding a signature as well
			// Phase4: Including threadID now :)
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), threadID);
			
			byte[] tokenBytes = yourToken.toByteArray();
			byte[] signedTokenBytes = signBytes(tokenBytes);
			
			yourToken.setSignature(signedTokenBytes);

			return yourToken;
		}
		else
		{
			return null;
		}
	}
	
	// Sign bytes (for token)
	public byte[] signBytes(byte[] text) {
		byte[] sigBytes = null;
		Signature sig = null;
		
		System.out.println("Signing bytes...");
		
		try {
			sig = Signature.getInstance("SHA512WithRSAEncryption", "BC");
			sig.initSign(my_gs.privateKey);
			sig.update(text);
			sigBytes = sig.sign();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return sigBytes;
	}
	
	private boolean addOwnerToGroup(String groupname, String username, Token yourToken) {
		String requester = yourToken.getSubject();
		// For this to work, the requester must already be an owner
		if ((my_gs.groupList.isOwner(groupname, requester)) && 
		(my_gs.userList.checkUser(username)) && 
		!(my_gs.groupList.isOwner(groupname, username))) {
			// Add the user as an owner
			my_gs.userList.addOwnership(username, groupname);
			my_gs.groupList.addOwner(groupname, username);
			// If they are not a member, add them as one
			if (!my_gs.groupList.isMember(groupname, username)) {
				my_gs.userList.addGroup(username, groupname);
				my_gs.groupList.addMember(groupname, username);
			}
			return true;
		}
		else {
			return false;
		}
	}
	
	
	private boolean addUserToGroup(String groupname, String username, Token yourToken) {
		String requester = yourToken.getSubject();
		
		if ((my_gs.groupList.isOwner(groupname, requester)) && 
		(my_gs.userList.checkUser(username)) && 
		!(my_gs.groupList.isMember(groupname, username))) {
			my_gs.userList.addGroup(username, groupname);
			my_gs.groupList.addMember(groupname, username);
			return true;
		}
		else {
			return false;
		}
	}
	
	private boolean removeUserFromGroup(String groupname, String username, Token yourToken) {
		String requester = yourToken.getSubject();
		
		if ((my_gs.groupList.isOwner(groupname, requester)) && 
		(my_gs.userList.checkUser(username)) && 
		(my_gs.groupList.isMember(groupname, username))) {
			my_gs.userList.removeGroup(username, groupname);
			my_gs.groupList.removeMember(groupname, username);
			return true;
		}
		else {
			return false;
		}
	}
	
	//Method to create a user
    private boolean createUser(String username, String password, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		// Check if requester exists
		if(my_gs.userList.checkUser(requester)) {
			//requester needs to be an administrator
			if(my_gs.userList.getUserGroups(requester).contains("ADMIN")) {
				//Does user already exist?
				if(my_gs.userList.checkUser(username)) {
					return false; // User already exists
				}
				else {
					return my_gs.userList.addUser(username, password); // Return if the user was added successfully
				}
			}
			else {
				return false; //requester not an administrator
			}
		}
		else {
			return false; //requester does not exist
		}
	}
	
	private boolean deleteUser (String username, Token yourToken) {
		String requester = yourToken.getSubject();
		
		if ((my_gs.userList.checkUser(requester)) && 
		(my_gs.userList.getUserGroups(requester).contains("ADMIN")) && 
		(my_gs.userList.checkUser(username))) {
			// Get the user's groups for ownership checking later
			ArrayList<String> groupsOwned = new ArrayList<String>(my_gs.userList.getUserOwnership(username));
			ArrayList<String> groupsMember = new ArrayList<String>(my_gs.userList.getUserGroups(username));
			
			my_gs.userList.deleteUser(username);
			
			// Remove user from all groups which they are a member
			for (String groupname : groupsMember) {
				my_gs.groupList.removeMember(groupname, username);
			}
			
			// Delete groups where they are the only owner; remove them as an owner where they are not.
			for (String groupname : groupsOwned) {
				if (my_gs.groupList.isOnlyOwner(groupname, username)) {
					// Use the existing method, so just create a basic token
					deleteGroup(groupname, new Token(null, username, null));
				}
				else {
					// Just remove them as an owner if they are not the only one
					my_gs.groupList.removeOwner(groupname, username);
				}
			}
			
			return true;
		}
		else {
			return false;
		}
	}
	
	private boolean createGroup(String groupname, Token yourToken) {
		String username = yourToken.getSubject();
		if (my_gs.groupList.checkGroup(groupname)) {
			return false; // Group already exists
		}
		else {
			my_gs.userList.addGroup(username, groupname);
			my_gs.userList.addOwnership(username, groupname);

			my_gs.groupList.addGroup(groupname);
			my_gs.groupList.addOwner(groupname, username);
			my_gs.groupList.addMember(groupname, username);
		}
		
		return true;
	}
	
	private boolean deleteGroup(String groupname, Token yourToken) {
		// Only permitted if the user is an owner
		if (my_gs.groupList.isOwner(groupname, yourToken.getSubject())) {
			my_gs.userList.removeGroupFromAllUsers(groupname);
			my_gs.userList.removeOwnershipFromAllUsers(groupname);
			return my_gs.groupList.deleteGroup(groupname);
		}
		else {
			return false;
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
		sequenceNumber++;
		
		// Add the msg and sequenceNumber to the list
		list.add(0, sequenceNumber);
		list.add(0, msg);
		
		// Set the payload using the encrypted ArrayList
		envelope.setPayload(encryptPayload(listToByteArray(list), true, ivSpec));
		
		return envelope;
	}
	
	private byte[] encryptPayload(byte[] plainText, boolean useSessionKey, IvParameterSpec ivSpec) {
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
				inCipher.init(Cipher.ENCRYPT_MODE, my_gs.privateKey, new SecureRandom());
				System.out.println("plainText length: " + plainText.length);
				cipherText = inCipher.doFinal(plainText);
			} catch (Exception e) {
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
				e.printStackTrace();
			}
		}
		else {
			try {
				outCipher = Cipher.getInstance("RSA", "BC");
				outCipher.init(Cipher.DECRYPT_MODE, my_gs.privateKey, new SecureRandom());
				plainText = outCipher.doFinal(cipherText);
			} catch (Exception e) {
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
		
		if (token.getThreadID() == threadID) {
			
			try {
				sig = Signature.getInstance("SHA512WithRSAEncryption", "BC");
				sig.initVerify(my_gs.publicKey);
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
			
		}
		else {
			System.out.println("Wrong token!");
			verified = false;
		}
		
		return verified;
	}
}
