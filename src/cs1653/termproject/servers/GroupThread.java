package cs1653.termproject.servers;

import java.net.Socket;
import java.io.*;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cs1653.termproject.shared.SecureEnvelope;
import cs1653.termproject.shared.SecurityUtils;
import cs1653.termproject.shared.Token;
import cs1653.termproject.shared.UserToken;

public class GroupThread extends ServerThread 
{
	private final Socket socket;
	private GroupServer my_gs;
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
					
					// ONLY USE UNSECURE MSG FOR WHEN THERE IS A PROBLEM WITH SESSIONINIT!!!
					// NOWHERE ELSE!
					// If there is no payload
					if(secureMessage.getPayload() == null) {
						secureResponse = new SecureEnvelope("FAIL");
						output.writeObject(secureResponse);
					}
					else {
						// Get the list from the SecureEnvelope, false because it's NOT using the session key
						ArrayList<Object> objectList = getDecryptedPayload(secureMessage, false, my_gs.privateKey);
						// Make sure it doesn't return null and it has two elements in the list
						if (!(objectList == null) && (objectList.size() == 2)) {
							// Grab the session 
							sessionKey = (Key)objectList.get(0);
							
							int nonce = (Integer)objectList.get(1);
							nonce = nonce - 1; // nonce - 1 to return
							
							// Key generation for HMAC
							KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
							integrityKey = keyGen.generateKey();
							// Create a secure random number generator
							SecureRandom rand = new SecureRandom();

							// Get random int sequenceNumber and set it
							sequenceNumber = rand.nextInt();
							
							ArrayList<Object> list = new ArrayList<Object>();
							list.add(nonce);
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
				else if (secureMessage.getPayload() == null) { // If there is no payload and its not SESSION INIT
					secureResponse = makeSecureEnvelope("FAIL");
					output.writeObject(secureResponse);
				}
				else { // Any case other than SESSION INIT and there is a payload
					// Get the decrypted payload
					ArrayList<Object> contents = getDecryptedPayload(secureMessage, true, null);
					// Get the msg from the payload
					String msg = (String)contents.get(0);
					// Print the message that was received
					System.out.println("Request received: " + msg);
					// Verify the sequence number
					verifySequenceNumber((Integer)contents.get(1));
					verifyHMAC(listToByteArray(contents), secureMessage.getHMAC());
					
					if(msg.equals("GET")) { // Client wants to obtain a token
						// Declare variables
						String username = null;
						String password = null;
						
						if(contents.size() < 4) { // Verify that the payload has the required number of items
							secureResponse = makeSecureEnvelope("FAIL-BADARGS");
						}
						else {
							// Set the variables
							username = (String)contents.get(2);
							password = (String)contents.get(3);
							
							// Verify that the username is not null and that the user exists
							if (username == null || (!my_gs.userList.checkUser(username))) { 
								secureResponse = makeSecureEnvelope("FAIL-BADUSER");
							}
							else if (password == null) { // Verify that the password is not null
								secureResponse = makeSecureEnvelope("FAIL-BADPASS");
							}
							else {
								// Create the token for the user specified. If the password is invalid, it is a null token
								UserToken yourToken = createToken(username, password);
								// Create a list for the SecureEnvelope
								ArrayList<Object> newList = new ArrayList<Object>();
								// Add the token to the list
								newList.add(yourToken);
								// Make the SecureEnvelope
								secureResponse = makeSecureEnvelope("OK", newList);
							}
						}
						// Respond to the client. On error, the client will receive a null token
						output.writeObject(secureResponse);
					}
					else if(msg.equals("CUSER")) { //Client wants to create a user
						String username = null;
						String password = null;
						Token yourToken = null;
						
						if(contents.size() < 5) {
							secureResponse = makeSecureEnvelope("FAIL-BADARGS");
						}
						else {
							username = (String)contents.get(2); // Extract the username
						    password = (String)contents.get(3); // Extract the password
						    yourToken = (Token)contents.get(4); // Extract the token
							
						    if (username == null) { // Verify no null username
						    	secureResponse = makeSecureEnvelope("FAIL-BADUSER");
						    }
						    else if (password == null || password.equals("")) { // Verify no null or blank password
						    	secureResponse = makeSecureEnvelope("FAIL-BADPASS");
						    }
						    else if (yourToken == null) { // Verify no null token
						    	secureResponse = makeSecureEnvelope("FAIL-NOTOKEN");
						    }
						    else if (!verifyToken(yourToken)) { // Verify good token
							    secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
						    }
						    else {
						    	System.out.println("Create user: " + username + ", password: " + password);
						    	if(createUser(username, password, yourToken)) {
						    		secureResponse = makeSecureEnvelope("OK"); // Success
						    	}
						    	else { // Failed for some reason, probably user already exists
						    		secureResponse = makeSecureEnvelope("FAIL-CUSER");
						    	}
						    }
						}
						// Respond to the client
						output.writeObject(secureResponse);
					}
					else if(msg.equals("DUSER")) { //Client wants to delete a user
						// Declare variables
						String username = null;
						Token yourToken = null;
						
						if(contents.size() < 4) { // Verify that the payload has the required number of items
							secureResponse = makeSecureEnvelope("FAIL-BADARGS");
						}
						else {
							// Set the variables
							username = (String)contents.get(2);
							yourToken = (Token)contents.get(3);
							
							// Verify that the username is not null and that the user exists
							if (username == null || (!my_gs.userList.checkUser(username))) { 
								secureResponse = makeSecureEnvelope("FAIL-BADUSER");
							}
							else if (yourToken == null) { // Verify that the token is not null
								secureResponse = makeSecureEnvelope("FAIL-NOTOKEN");
							}
							else if (!verifyToken(yourToken)) { // Verify good token
							    secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
						    }
						    else {
						    	if(deleteUser(username, yourToken)) {
									secureResponse = makeSecureEnvelope("OK"); //Success
								}
						    	else { // Failed to delete user. Probably didn't exist or no permission
						    		secureResponse = makeSecureEnvelope("FAIL-DUSER");
						    	}
						    }
						}
						// Respond to client
						output.writeObject(secureResponse);
					}
					else if(msg.equals("CGROUP")) { // Client wants to create a group
						// Declare variables
						String groupname = null;
						Token yourToken = null;
						
						if(contents.size() < 4) { // Verify that the payload has the required number of items
							secureResponse = makeSecureEnvelope("FAIL-BADARGS");
						}
						else {
							// Set the variables
							groupname = (String)contents.get(2);
							yourToken = (Token)contents.get(3);
							
							// Verify that the group is not null and that it exists
							if ((groupname == null) || (my_gs.groupList.checkGroup(groupname))){ 
								secureResponse = makeSecureEnvelope("FAIL-BADGROUP");
							}
							else if (yourToken == null) { // Verify that the token is not null
								secureResponse = makeSecureEnvelope("FAIL-NOTOKEN");
							}
							else if (!verifyToken(yourToken)) { // Verify good token
							    secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
						    }
						    else {
						    	if (createGroup(groupname, yourToken)) {
									secureResponse = makeSecureEnvelope("OK"); //Success
								}
						    	else { // Failed to create group. Probably didn't exist or no permission
						    		secureResponse = makeSecureEnvelope("FAIL-CGROUP");
						    	}
						    }
						}
						// Respond to client
						output.writeObject(secureResponse);
					}
					else if(msg.equals("DGROUP")) { //Client wants to delete a group
						// Declare variables
						String groupname = null;
						Token yourToken = null;
						
						if(contents.size() < 4) { // Verify that the payload has the required number of items
							secureResponse = makeSecureEnvelope("FAIL-BADARGS");
						}
						else {
							// Set the variables
							groupname = (String)contents.get(2);
							yourToken = (Token)contents.get(3);
							
							// Verify that the group is not null and that it exists
							if ((groupname == null) || (!my_gs.groupList.checkGroup(groupname))){ 
								secureResponse = makeSecureEnvelope("FAIL-BADGROUP");
							}
							else if (yourToken == null) { // Verify that the token is not null
								secureResponse = makeSecureEnvelope("FAIL-NOTOKEN");
							}
							else if (!verifyToken(yourToken)) { // Verify good token
							    secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
						    }
						    else {
						    	if (deleteGroup(groupname, yourToken)) {
									secureResponse = makeSecureEnvelope("OK"); //Success
								}
						    	else { // Failed to delete group. Probably didn't exist or no permission
						    		secureResponse = makeSecureEnvelope("FAIL-DGROUP");
						    	}
						    }
						}
						// Respond to client
						output.writeObject(secureResponse);
					}
					else if(msg.equals("LMEMBERS")) { // Client wants a list of members in a group
						// Declare variables
						String groupname = null;
						Token yourToken = null;
						
						if(contents.size() < 4) { // Verify that the payload has the required number of items
							secureResponse = makeSecureEnvelope("FAIL-BADARGS");
						}
						else {
							// Set the variables
							groupname = (String)contents.get(2);
							yourToken = (Token)contents.get(3);
							
							// Verify that the group is not null and that it exists
							if ((groupname == null) || (!my_gs.groupList.checkGroup(groupname))) { 
								secureResponse = makeSecureEnvelope("FAIL-BADGROUP");
							}
							else if (yourToken == null) { // Verify that the token is not null
								secureResponse = makeSecureEnvelope("FAIL-NOTOKEN");
							}
							else if (!verifyToken(yourToken)) { // Verify good token
							    secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
						    }
							else if (!my_gs.groupList.isMember(groupname, yourToken.getSubject())) { // If not a member of the group
								secureResponse = makeSecureEnvelope("FAIL-LMEMBERS");
							}
						    else {
						    	// Get the list of members
						    	ArrayList<Object> newList = new ArrayList<Object>();
								newList.add(new ArrayList<String>(my_gs.groupList.getMembers(groupname)));
								// Make response with list of members included
								secureResponse = makeSecureEnvelope("OK", newList);
						    }
						}
						// Respond to client
						output.writeObject(secureResponse);
					}
					else if(msg.equals("AUSERTOGROUP")) { // Client wants to add user to a group
						String userToAdd = null;
						String groupname = null;
						Token yourToken = null;
						
						if(contents.size() < 5) {
							secureResponse = makeSecureEnvelope("FAIL-BADARGS");
						}
						else {
							userToAdd = (String)contents.get(2); // Extract the user to add to the group
							groupname = (String)contents.get(3); // Extract the groupname
							yourToken = (Token)contents.get(4); // Extract the token
							
							// Verify that the userToAdd is not null and that the user exists
							if (userToAdd == null || (!my_gs.userList.checkUser(userToAdd))) { 
								secureResponse = makeSecureEnvelope("FAIL-BADUSER");
							}
							else if ((groupname == null) || (!my_gs.groupList.checkGroup(groupname))) { // Verify that the group is not null and exists
								secureResponse = makeSecureEnvelope("FAIL-BADGROUP");
							}
						    else if (yourToken == null) { // Verify no null token
						    	secureResponse = makeSecureEnvelope("FAIL-NOTOKEN");
						    }
						    else if (!verifyToken(yourToken)) { // Verify good token
							    secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
						    }
						    else {
						    	if (addUserToGroup(groupname, userToAdd, yourToken)) {
									secureResponse = makeSecureEnvelope("OK");
								}
								else { // Failed for some reason, user doesn't exists, requester is not owner, etc
									secureResponse = makeSecureEnvelope("FAIL-AUSERTOGROUP");
								}
						    }
						}
						// Respond to the client
						output.writeObject(secureResponse);
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
						String userToRemove = null;
						String groupname = null;
						Token yourToken = null;
						
						if(contents.size() < 5) {
							secureResponse = makeSecureEnvelope("FAIL-BADARGS");
						}
						else {
							userToRemove = (String)contents.get(2); // Extract the user to remove from the group
							groupname = (String)contents.get(3); // Extract the groupname
							yourToken = (Token)contents.get(4); // Extract the token
							
							// Verify that the userToRemove is not null and that the user exists
							if (userToRemove == null || (!my_gs.userList.checkUser(userToRemove))) { 
								secureResponse = makeSecureEnvelope("FAIL-BADUSER");
							}
							else if ((groupname == null) || (!my_gs.groupList.checkGroup(groupname))) { // Verify that the group is not null and exists
								secureResponse = makeSecureEnvelope("FAIL-BADGROUP");
							}
						    else if (yourToken == null) { // Verify no null token
						    	secureResponse = makeSecureEnvelope("FAIL-NOTOKEN");
						    }
						    else if (!verifyToken(yourToken)) { // Verify good token
							    secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
						    }
						    else {
						    	if (removeUserFromGroup(groupname, userToRemove, yourToken)) {
									secureResponse = makeSecureEnvelope("OK");
								}
								else { // Failed for some reason, user doesn't exists, requester is not owner, etc
									secureResponse = makeSecureEnvelope("FAIL-AUSERTOGROUP");
								}
						    }
						}
						// Respond to the client
						output.writeObject(secureResponse);
					}
					else if(msg.equals("NEWFILEKEY")) { // Client needs a new file key for encryption
						
						if(contents.size() < 4) { // Verify there are 4 items in the payload
							secureResponse = makeSecureEnvelope("FAIL");
						}
						else if (contents.get(2) == null) { // Verify that the group name is not null
							secureResponse = makeSecureEnvelope("FAIL");
						}
						else if (contents.get(3) == null) { // Verify that the token is not null
							secureResponse = makeSecureEnvelope("FAIL");
						}
						else {
							String groupName = (String)contents.get(2); // Extract the groupName
							Token yourToken = (Token)contents.get(3); // Extract the token
							
							if (!verifyToken(yourToken)) { // Verify the token is not modified
								secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
							}
							else {
								// Generate the new key info based on the groupname, with token to verify membership
								ArrayList<Object> keyInfo = newFileKeyInfo(groupName, yourToken);
								// If the key info was generated successfully
								if (keyInfo != null) {
									ArrayList<Object> newList = new ArrayList<Object>();
									newList.addAll(keyInfo);
									secureResponse = makeSecureEnvelope("OK", newList);
								}
								else { // If the key info was not generated successfully
									secureResponse = makeSecureEnvelope("FAIL");
								}
							}
						}
						// Send the response
						output.writeObject(secureResponse);
					}
					else if(msg.equals("RETRIEVEFILEKEY")) { // Client needs a file key for decryption
						
						if(contents.size() < 6) { // Verify there are 6 items in the payload
							secureResponse = makeSecureEnvelope("FAIL");
						}
						else if (contents.get(2) == null) { // Verify that the group name is not null
							secureResponse = makeSecureEnvelope("FAIL");
						}
						else if (contents.get(3) == null) { // Verify that the seed is not null
							secureResponse = makeSecureEnvelope("FAIL");
						}
						else if (contents.get(4) == null) { // Verify that the keyID is not null
							secureResponse = makeSecureEnvelope("FAIL");
						}
						else if (contents.get(5) == null) { // Verify that the token is not null
							secureResponse = makeSecureEnvelope("FAIL");
						}
						else {
							String groupName = (String)contents.get(2); // Extract the groupName
							byte[] seed = (byte[])contents.get(3); // Extract the seed
							int keyID = (Integer)contents.get(4); // Extract the keyID
							Token yourToken = (Token)contents.get(5); // Extract the token
							
							if (!verifyToken(yourToken)) { // Verify the token is not modified
								secureResponse = makeSecureEnvelope("FAIL-MODIFIEDTOKEN");
							}
							else {
								// Get the file key based on the provided information
								SecretKeySpec fileKey = retrieveFileKey(groupName, seed, keyID, yourToken);
								// If the key was retrieved successfully
								if (fileKey != null) {
									ArrayList<Object> newList = new ArrayList<Object>();
									newList.add(fileKey);
									secureResponse = makeSecureEnvelope("OK", newList);
								}
								else { // If the key info was not generated successfully
									secureResponse = makeSecureEnvelope("FAIL");
								}
							}
						}
						// Send the response
						output.writeObject(secureResponse);
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
			byte[] signedTokenBytes = signBytes(tokenBytes, my_gs.privateKey);
			
			yourToken.setSignature(signedTokenBytes);

			return yourToken;
		}
		else
		{
			return null;
		}
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
	
	/*
	 * Message integrity related
	 * 
	 */
	
	private boolean verifySequenceNumber(int verifyNumber) {
		if (verifyNumber == (sequenceNumber + 1)) {
			sequenceNumber++;
			return true;
		}
		else {
			tamperedConnection = true;
			System.out.println("CONNECTION TAMPERING DETECTED!");
			return false;
		}
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
	
	
	/*
	 * File Encryption Related
	 * 
	 * These will be used for dealing with file keys.
	 */
	
	private ArrayList<Object> newFileKeyInfo(String groupName, Token yourToken) {
		// Get the requester
		String requester = yourToken.getSubject();
		// Seed is 8 bytes
		byte[] seed = new byte[8];
		// Groupname array is undetermined length (that's okay)
		byte[] groupBytes = null;
		// If the groupName is null, don't try anything
		if (groupName != null) {
			// Check if the requester is the member of the group
			if (!my_gs.groupList.isMember(groupName, requester)) {
				return null;
			}
			
			try {
				groupBytes = groupName.getBytes("UTF-8"); // Use UTF-8 for portability
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			} 
		}
		else {
			System.out.println("A group name is required!");
			return null;
		}
		
		// Use the latest keyID
		int keyID = my_gs.masterKeyList.size() - 1;
		
		// Create a secure random number generator
		SecureRandom rand = new SecureRandom();

		// Get random bytes seed
		rand.nextBytes(seed);
		// Generate a SecretKeySpec
		SecretKeySpec fileKey = generateFileKey(groupBytes, seed, keyID);
		// Create a return list
		ArrayList<Object> returnList = new ArrayList<Object>();
		// Set the appropriate values
		returnList.add(fileKey);
		returnList.add(seed);
		returnList.add(keyID);
		
		return returnList;
	}
	
	private SecretKeySpec generateFileKey(byte[] groupBytes, byte[] seed, int keyID) {
		// Master file key is 256 bytes
		byte[] masterKey;
		
		// Get the latest master key from the list
		masterKey = my_gs.masterKeyList.get(keyID);
		
		// Create a new array of combined length
		byte[] combinedBytes = new byte[seed.length + masterKey.length + groupBytes.length];

		// Merge the three byte arrays into combinedBytes
		System.arraycopy(seed,0,combinedBytes,0,seed.length);
		System.arraycopy(masterKey,0,combinedBytes,seed.length,masterKey.length);
		System.arraycopy(groupBytes,0,combinedBytes,seed.length + masterKey.length, groupBytes.length);
		
		MessageDigest md = null;
		
		try {
			md = MessageDigest.getInstance("SHA-256", "BC");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		byte[] hash = md.digest(combinedBytes);
		
		
		
		// Generate the secret key specs.
		SecretKeySpec keySpec = new SecretKeySpec(hash, "AES");
		
		return keySpec;
	}
	
	private SecretKeySpec retrieveFileKey(String groupName, byte[] seed, int keyID, Token yourToken) {
		String requester = yourToken.getSubject();
		byte[] groupBytes = null;
		
		// If the groupName is null, don't try anything
		if (groupName != null) {
			try {
				groupBytes = groupName.getBytes("UTF-8"); // Use UTF-8 for portability
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			} 
		}
		else {
			System.out.println("A group name is required!");
			return null;
		}
		
		// Create new SecretKeySpec
		SecretKeySpec spec = null;
		
		// Check if the requester is the member of the group
		if (my_gs.groupList.isMember(groupName, requester)) {
			// Generate the key based on the provided information
			spec = generateFileKey(groupBytes, seed, keyID);
		}
		
		return spec;
	}
	
	
	
	
	/* Crypto Related Methods
	 * 
	 * These methods will abstract the whole secure session process.
	 * 
	 */
	
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
			tamperedToken = true;
			verified = false;
		}
		
		return verified;
	}
}
