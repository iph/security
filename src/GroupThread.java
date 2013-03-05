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
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{
		boolean proceed = true;
		Security.addProvider(new BouncyCastleProvider());

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				SecureEnvelope secureMessage = (SecureEnvelope)input.readObject();
				SecureEnvelope secureResponse = null;
				
				System.out.println("Request received: " + secureMessage.getMessage());

				if(secureMessage.getMessage().equals("SESSIONINIT")) // Client wants to initialize a secure session
				{
					// ONLY USE UNSECURE ENVELOPE FOR RETURNING THE NONCE!!!
					// NOWHERE ELSE!
					Envelope response;
					if(secureMessage.getPayload() == null)
					{
						response = new SecureEnvelope("FAIL");
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
				else if(secureMessage.getMessage().equals("GET"))//Client wants a token
				{
					//String username = (String)list.get(0); //Get the username
					
					String username = null;
					
					if(secureMessage.getPayload() == null)
					{
						secureResponse = new SecureEnvelope("FAIL");
						output.writeObject(secureResponse);
					}
					else {
						// Get the decrypted payload, TRUE because it's using the session key
						ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
						// Get the username from the object list
						username = (String)list.get(0);
						
						// If the username is null, send a FAIL message
						if ((username == null) || (!my_gs.userList.checkUser(username))) {
							//System.out.println("username: " + username);
							secureResponse = new SecureEnvelope("FAIL");
							output.writeObject(secureResponse);
						}
						else {
							// Create the token for the user specified
							UserToken yourToken = createToken(username);
							ArrayList<Object> newList = new ArrayList<Object>();
							newList.add(yourToken);
							// Respond to the client. On error, the client will receive a null token
							secureResponse = makeSecureEnvelope("OK", newList);
							secureResponse.addObject(yourToken);
							output.writeObject(secureResponse);
						}
					}
				}
				else if(secureMessage.getMessage().equals("CUSER")) //Client wants to create a user
				{
					
					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
					
					if(list.size() < 2)
					{
						secureResponse = new SecureEnvelope("FAIL");
					}
					else
					{
						secureResponse = new SecureEnvelope("FAIL");
						
						if(list.get(0) != null)
						{
							if(list.get(1) != null)
							{
								String username = (String)list.get(0); //Extract the username
								Token yourToken = (Token)list.get(1); //Extract the token
								
								System.out.println("Create user: " + username);
								if (!verifyToken(yourToken)) {
									secureResponse = new SecureEnvelope("FAIL-MODIFIEDTOKEN");
								}
								else {
									if(createUser(username, yourToken))
									{
										secureResponse = new SecureEnvelope("OK"); //Success
									}
								}
							}
						}
					}
					
					output.writeObject(secureResponse);
				}
				else if(secureMessage.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
					
					if(list.size() < 2)
					{
						secureResponse = new SecureEnvelope("FAIL");
					}
					else
					{
						secureResponse = new SecureEnvelope("FAIL");
						
						if(list.get(0) != null)
						{
							if(list.get(1) != null)
							{
								String username = (String)list.get(0); //Extract the username
								Token yourToken = (Token)list.get(1); //Extract the token
								
								if (!verifyToken(yourToken)) {
									secureResponse = new SecureEnvelope("FAIL-MODIFIEDTOKEN");
								}
								else {
									if(deleteUser(username, yourToken))
									{
										secureResponse = new SecureEnvelope("OK"); //Success
									}
								}
							}
						}
					}
					
					output.writeObject(secureResponse);
				}
				else if(secureMessage.getMessage().equals("CGROUP")) //Client wants to create a group
				{
				    /* Create Group:
						Any user can create a group
						Owner of the group.
				    */
					
					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
					
					// Make sure contents are correct
					if(list.size() < 2){
						secureResponse = new SecureEnvelope("FAIL");
						output.writeObject(secureResponse);
						return;
					}
					String groupname = (String)list.get(0);
					Token yourToken = (Token)list.get(1); //Extract the token
					if (!verifyToken(yourToken)) {
						secureResponse = new SecureEnvelope("FAIL-MODIFIEDTOKEN");
						output.writeObject(secureResponse);
					}
					else {
						String username = yourToken.getSubject();
	
						my_gs.userList.addGroup(username, groupname);
						my_gs.userList.addOwnership(username, groupname);
	
						my_gs.groupList.addGroup(groupname);
						my_gs.groupList.addOwner(groupname, username);
	
						secureResponse = new SecureEnvelope("OK");
						output.writeObject(secureResponse);
					}
				}
				else if(secureMessage.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				    /*
						boolean deleteGroup(String groupname, UserToken token)
						This method allows the owner of token to delete the specified group, provided that
						they are the owner of that group. After deleting a group, no user should be a member
						of that group.
				    */
					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);

					if(list.size() < 2){
						secureResponse = new SecureEnvelope("FAIL");
						output.writeObject(secureResponse);
						return;
					}

					String groupname = (String)list.get(0);
					Token yourToken = (Token)list.get(1); //Extract the token
					String username = yourToken.getSubject();

					if(!my_gs.groupList.isOwner(groupname, username)){
						secureResponse = new SecureEnvelope("FAIL");
						output.writeObject(secureResponse);
					}
					else{
						my_gs.userList.removeGroup(username, groupname);	

						//Go through all the group members and remove them!
						for(String user: my_gs.groupList.getMembers(groupname)){
							my_gs.userList.removeGroup(user, groupname);
						}
						// @FIXME: Is there more than one user as an owner? If yes, fix this to remove all groups
						my_gs.groupList.deleteGroup(groupname);
						secureResponse = new SecureEnvelope("OK");
						output.writeObject(secureResponse);

					}
				}
				else if(secureMessage.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
				    /*
						List<String> listMembers(String group, UserToken token)
						Provided that the owner of token is also the owner of group, this method will return
						a list of all users that are currently members of group
				    */
					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
					
					if(list.size() < 2){
						secureResponse = new SecureEnvelope("FAIL");
						output.writeObject(secureResponse);
						return;
					}

					String groupname = (String)list.get(0);
					Token yourToken = (Token)list.get(1); //Extract the token
					String username = yourToken.getSubject();
					
					if (!verifyToken(yourToken)) {
						secureResponse = new SecureEnvelope("FAIL-MODIFIEDTOKEN");
						output.writeObject(secureResponse);
					}
					else {
						if(!my_gs.groupList.isOwner(groupname, username)) {
							secureResponse = new SecureEnvelope("FAIL");
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
				else if(secureMessage.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    /*
						boolean addUserToGroup(String user, String group, UserToken token)
						This method enables the owner of token to add the user user to the group group.
						This operation requires that the owner of token is also the owner of group.
				    */
					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
					
					if(list.size() < 2){
						secureResponse = new SecureEnvelope("FAIL");
						output.writeObject(secureResponse);
						return;
					}

					String userToAdd = (String)list.get(0);
					String groupname = (String)list.get(1);
					Token yourToken = (Token)list.get(2); //Extract the token
					String username = yourToken.getSubject();
					
					if (!verifyToken(yourToken)) {
						secureResponse = new SecureEnvelope("FAIL-MODIFIEDTOKEN");
						output.writeObject(secureResponse);
					}
					else {
	
						if(!my_gs.groupList.isOwner(groupname, username)){
							secureResponse = new SecureEnvelope("FAIL");
							output.writeObject(secureResponse);
						}
						else if (!my_gs.userList.checkUser(userToAdd)) {
							System.out.println("Trying to add " + userToAdd + " to group " + groupname);
							secureResponse = new SecureEnvelope("FAIL");
							output.writeObject(secureResponse);
						}
						else{
							my_gs.userList.addGroup(userToAdd, groupname);
							my_gs.groupList.addMember(groupname, userToAdd);
	
							secureResponse = new SecureEnvelope("OK");
							output.writeObject(secureResponse);
						}
					}

				}
				else if(secureMessage.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    /*
						boolean deleteUserFromGroup(String user, String group, UserToken token)
						This method enables the owner of token to remove the user user from the group
						group. This operation requires that the owner of token is also the owner of group.
				    */
					ArrayList<Object> list = getDecryptedPayload(secureMessage, true);
					
					if(list.size() < 3){
						secureResponse = new SecureEnvelope("FAIL");
						output.writeObject(secureResponse);
						return;
					}

					String userToDelete = (String) list.get(0);
					String groupname = (String)list.get(1);
					Token yourToken = (Token)list.get(2); //Extract the token
					String username = yourToken.getSubject();
					
					if (!verifyToken(yourToken)) {
						secureResponse = new SecureEnvelope("FAIL-MODIFIEDTOKEN");
						output.writeObject(secureResponse);
					}
					else {
						if( userToDelete.equals(username) || !my_gs.groupList.isOwner(groupname, username)){
							secureResponse = new SecureEnvelope("FAIL");
							output.writeObject(secureResponse);
						}
						else{
							my_gs.userList.removeGroup(userToDelete, groupname);
							my_gs.groupList.removeMember(groupname, userToDelete);
	
							secureResponse = new SecureEnvelope("OK");
							output.writeObject(secureResponse);
						}
					}

				}
				else if(secureMessage.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					secureResponse = new SecureEnvelope("FAIL"); //Server does not understand client request
					output.writeObject(secureResponse);
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
	private UserToken createToken(String username) 
	{
		//Check that user exists
		// TODO: Checking password
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			// Now adding a signature as well
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			
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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return sigBytes;
	}
	
	
	//Method to create a user
	private boolean createUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}
					
					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
					}
					
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					return false; //User does not exist
					
				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	private void deleteGroup(String groupname, UserToken token){
		String username = token.getSubject();
		my_gs.userList.removeGroup(username, groupname);	

		//Go through all the group members and remove them!
		for(String user: my_gs.groupList.getMembers(groupname)){
			my_gs.userList.removeGroup(user, groupname);
		}
		// @FIXME: Is there more than one user as an owner? If yes, fix this to remove all groups
		my_gs.groupList.deleteGroup(groupname);

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
				inCipher.init(Cipher.ENCRYPT_MODE, my_gs.privateKey, new SecureRandom());
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
				outCipher.init(Cipher.DECRYPT_MODE, my_gs.privateKey, new SecureRandom());
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
			sig.initVerify(my_gs.publicKey);
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
