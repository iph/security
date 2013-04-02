package cs1653.termproject.clients;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import cs1653.termproject.shared.Token;

/**
 * The ClientController is the layer between the clients and the interface that sits on top.
 * It allows communication between the GroupClient and FileClient, holds the state of both, and maintains token information.
 * This way the frontend/GUI/CLI is interchangeable, and the clients are access through a specific API, so to speak.
 * 
 * @author Matt and Sean
 *
 */
public class ClientController {
	// Hold the GroupClient state.
	private GroupClient gClient;
	// Hold the FileClient state.
	private FileClient fClient;
	// Hold the token information.
	private Token token;
	
	/**
	 * Default constructor. Set all fields to null.
	 */
	public ClientController() {
		gClient = null;
		fClient = null;
		token = null;
	}
	
	/**
	 * Check to see if the token exists.
	 * @return True if the token exists, false if it is null.
	 */
	public boolean checkToken() {
		if (token == null) {
			return false;
		}
		else {
			return true;
		}
	}
	
	/**
	 * Update the token in this controller.
	 * This method should not be used for nullifying a token! Thus, null values are not accepted.
	 * @param _token The token to update with.
	 * @return True if the token was updated successfully, false if it was a null value.
	 */
	public boolean updateToken(Token _token) {
		// Check to make sure a null value was not passed.
		if (_token == null) {
			return false;
		}
		else {
			token = _token;
			return true;
		}
	}
	
	/**
	 * Initialize a new GroupClient.
	 * @param server Server to connect to.
	 * @param port Port to connect to.
	 * @return True if the values were valid and the instance was created, false if not.
	 */
	public boolean initGroupClient(String server, int port) {
		boolean clientInit = false;
		
		// First verify no bad values were passed
		if ((server != null) && (port != 0)) {
			gClient = new GroupClient(server, port, this);
			clientInit = true;
		}
		
		return clientInit;
	}
	
	/**
	 * Connect to the group server.
	 * @return True if the connection was established, false if there was no group client instance or the values for server or port did not work.
	 */
	public boolean connectGroupClient () {
		boolean clientConnect = false;
		
		// First verify the group client has been instantiated.
		if (gClient != null) {
			clientConnect = gClient.connect();
		}
		
		return clientConnect;
	}
	
	/**
	 * Gets a token from the group server.
	 * @return True if a token was obtained successfully, false if it was not.
	 */
	public boolean getToken (String username, String password) {
		// First verify no null values were passed
		if ((username != null) && (password != null)) {
			token = gClient.getToken(username, password);
			if (token != null) {
				System.out.println("Token received!\n" + token.toString());
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Disconnect from the group server. Also disconnects from the file server, if any.
	 * @return True if all disconnects were successful.
	 */
	public boolean disconnectGroupClient() {
		if ((gClient != null) && (gClient.isConnected())) {
			gClient.secureDisconnect();
		}
		
		// Also disconnect file client.
		disconnectFileClient();
		
		gClient = null;
		
		return true;
	}
	
	/**
	 * Creates a new users on the group server.
	 * @param username Username of the new user.
	 * @param password Password of the new user.
	 * @return True if the user was created successfully, false if the input was null or the user was not created successfully.
	 */
	public boolean createUser(String username, String password) {
		boolean userCreated = false;
		
		// First verify no null values were passed
		if ((username != null) && (password != null)) {
			userCreated = gClient.createUser(username, password, token);
		}
		
		return userCreated;
	}
	
	/**
	 * Delete the specified user from the group server.
	 * @param username Username of the user to delete.
	 * @return True if the user was deleted successfully, false if the input was null or the user was not deleted successfully.
	 */
	public boolean deleteUser(String username) {
		boolean userDeleted = false;
		
		// First verify no null value was passed
		if (username != null) {
			userDeleted = gClient.deleteUser(username, token);
		}
		
		return userDeleted;
	}
	
	/**
	 * Create a group.
	 * @param groupname Name of the group to create.
	 * @return True if the group was created successfully, false if not.
	 */
	public boolean createGroup(String groupname) {
		boolean groupCreated = false;
		
		// First verify no null value was passed
		if (groupname != null) {
			groupCreated = gClient.createGroup(groupname, token);
		}
		
		return groupCreated;
	}
	
	/**
	 * Delete a group.
	 * @param groupname Name of the group to delete.
	 * @return True if the group was deleted successfully, false if not.
	 */
	public boolean deleteGroup(String groupname) {
		boolean groupDeleted = false;
		
		// First verify no null value was passed
		if (groupname != null) {
			groupDeleted = gClient.deleteGroup(groupname, token);
		}
		
		return groupDeleted;
	}
	
	/**
	 * Get the list of members of a group.
	 * @param groupname The name of the group for which the list of members is desired.
	 * @return The list of members of the group. The value will be null if the request could not be completed.
	 */
	public List<String> listMembers(String groupname) {
		// First verify no null value was passed
		if (groupname != null) {
			return gClient.listMembers(groupname, token);
		}
		else {
			return null;
		}
	}
	
	/**
	 * Add a user to a group.
	 * @param username Username of the user to add to a group.
	 * @param groupname Group to add the user to.
	 * @return True if the user was successfully added to the group, false if they were not for some reason.
	 */
	public boolean addUserToGroup(String username, String groupname) {
		boolean userAdded = false;
		
		// First verify no null values were passed
		if ((username != null) && (groupname != null)) {
			userAdded = gClient.addUserToGroup(username, groupname, token);
		}
		
		return userAdded;
	}
	
	/**
	 * Delete a user from a group.
	 * @param username Username of the user to delete from a group.
	 * @param groupname Group to delete the user from.
	 * @return True if the user was successfully deleted from the group, false if they were not for some reason.
	 */
	public boolean deleteUserFromGroup(String username, String groupname) {
		boolean userAdded = false;
		
		// First verify no null values were passed
		if ((username != null) && (groupname != null)) {
			userAdded = gClient.deleteUserFromGroup(username, groupname, token);
		}
		
		return userAdded;
	}
	
	/**
	 * Add an owner to a group.
	 * @param username Username of the user to add as an owner of a group.
	 * @param groupname Group to add the user as an owner of.
	 * @return True if the user was successfully added as an owner of the group, false if they were not for some reason.
	 */
	public boolean addOwnerToGroup(String username, String groupname) {
		boolean ownerAdded = false;
		
		// First verify no null values were passed
		if ((username != null) && (groupname != null)) {
			ownerAdded = gClient.addOwnerToGroup(username, groupname, token);
		}
		
		return ownerAdded;
	}
	
	
	/*
	 * ++++++++++++++++++++++++++++++++++++++++++++++++
	 * ++++++++++++++++++++++++++++++++++++++++++++++++
	 * ++++++++++		File Client Methods	 ++++++++++
	 * ++++++++++++++++++++++++++++++++++++++++++++++++
	 * ++++++++++++++++++++++++++++++++++++++++++++++++
	 */
	
	/**
	 * Initialize a new FileClient.
	 * @param server Server to connect to.
	 * @param port Port to connect to.
	 * @return True if the values were valid and the instance was created, false if not.
	 */
	public boolean initFileClient(String server, int port) {
		boolean clientInit = false;
		
		// First verify no bad values were passed
		if ((server != null) && (port != 0)) {
			fClient = new FileClient(server, port, this);
			clientInit = true;
		}
		
		return clientInit;
	}
	
	/**
	 * Connect to the file server.
	 * @return True if the connection was established, false if there was no file client instance or the values for server or port did not work.
	 */
	public boolean connectFileClient () {
		boolean clientConnect = false;
		
		// First verify the file client has been instantiated.
		if (fClient != null) {
			clientConnect = fClient.connect();
		}
		
		return clientConnect;
	}
	
	/**
	 * Disconnect from the file server.
	 * @return True if all disconnects were successful.
	 */
	public boolean disconnectFileClient() {
		if ((fClient != null) && (fClient.isConnected())) {
			fClient.secureDisconnect();
		}
		
		fClient = null;
		
		return true;
	}
	
	/**
	 * Set up the secure file client channel. This is after the user accepts the fingerprint of the server.
	 * @return True if the group client was set up already and the secure channel was set up successfully, false if not.
	 */
	public boolean setupFileClientChannel() {
		boolean channelSet = false;
		
		// Verify the file client is initialized and connected first.
		if ((fClient != null) && (fClient.isConnected())) {
			channelSet = fClient.setupChannel();
		}
		
		return channelSet;
	}
	
	public boolean deleteFile(String filename) {
		boolean fileDeleted = false;
		
		// First verify no null value was passed
		if (filename != null) {
			fileDeleted = fClient.delete(filename, token);
		}
		
		return fileDeleted;
	}
	
	public boolean uploadFile(String sourceFile, String destFile, String group) {
		boolean fileUploaded = false;
		
		// First verify no null values were passed
		if ((sourceFile != null) && (destFile != null) && (group != null)){
	
			// Need to first get group server keys.
			
			// TODO: save seed, keyid and key
			ArrayList<Object> list = gClient.getNewFileKey(group, token);
			System.out.println(list.get(2).toString());

			// Make sure that the list is correct.
			if (list != null && (!((String)(list.get(0))).equals("OK")) && list.size() != 5) {
				return false;
			}
			fileUploaded = fClient.upload(sourceFile, destFile, group, token, (SecretKeySpec) list.get(2), (byte[]) list.get(3), (Integer) list.get(4));
		}
		
		return fileUploaded;
	}
	
	public List<String> listFiles() {
		return fClient.listFiles(token);
	}
	
	public boolean downloadFile(String sourceFile, String destFile) {
		boolean fileDownloaded = false;
		
		if ((sourceFile != null) && (destFile != null)){
			List<Object> list= fClient.getFileInfo(sourceFile, token);
			if(list != null && list.size() != 6){
				return false;
			}
			SecretKeySpec key = gClient.getFileKey((byte[])list.get(3), (Integer)list.get(4), (String)list.get(5), token);
			System.out.println(key.toString());
			fileDownloaded = fClient.download(sourceFile, destFile, token, key, (byte[])list.get(2));
		}
		
		return fileDownloaded;
	}
	
	public String getFingerprint() {
		return fClient.getFingerprint();
	}
	
}
