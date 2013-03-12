import java.util.List;


public class ClientController {

	private GroupClient gClient;
	private FileClient fClient;
	private Token token;
	
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
		token = gClient.getToken(username, password);
		
		if (token != null) {
			System.out.println("Token received!\n" + token.toString());
			return true;
		}
		else {
			return false;
		}
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
			userAdded = gClient.addUserToGroup(username, groupname, token);
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
			fileUploaded = fClient.upload(sourceFile, destFile, group, token);
		}
		
		return fileUploaded;
	}
	
	public List<String> listFiles() {
		return fClient.listFiles(token);
	}
	
	public boolean downloadFile(String sourceFile, String destFile) {
		boolean fileDownloaded = false;
		
		if ((sourceFile != null) && (destFile != null)){
			fileDownloaded = fClient.download(sourceFile, destFile, token);
		}
		
		return fileDownloaded;
	}
	
	public String getFingerprint() {
		return fClient.getFingerprint();
	}
	
}
