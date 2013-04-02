package cs1653.termproject.clients;
import java.security.Security;
import java.util.ArrayList;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class CLI {
	protected ClientController controller;
	private Scanner input;
	private final String groupMenu = "Group Server Menu:\n" +
			"1) Create User\n" +
			"2) Delete User\n" +
			"3) Create Group\n" +
			"4) Delete Group\n" +
			"5) Add User to Group\n" +
			"6) Delete User from Group\n" +
			"7) List Members of Group\n" +
			"8) Disconnect\n";
	
	public CLI() {
		System.out.println("Instantiated a new CLI!");
	}
	
	public void run() {
		Security.addProvider(new BouncyCastleProvider());
		input = new Scanner(System.in);
		String address, port;
		int portInt = 0;
		boolean loop = true;
		
		// Initialize the controller.
		controller = new ClientController();
		
		System.out.println("Welcome to the file sharing system!\n");
		//You can press \'d\' during any menu to disconnect, or \'x\' to quit.
		
		// Group Server connection loop
		do {
			System.out.println("Enter information to connect!");
			
			System.out.print("Server Address: ");
			
			address = input.nextLine();
			
			System.out.print("Server Port: ");
			do {
				port = input.nextLine();
				
				portInt = Integer.parseInt(port);
			} while(!(portInt > 0));
			
			// Initialize the GroupClient with the info
			controller.initGroupClient(address, portInt);
			
			if (controller.connectGroupClient()) { // If the GroupClient connected successfully
				System.out.println("Connected to the Group Server successfully!");
				loop = false;
			}
		} while (loop);

		// Reset loop variable
		loop = true;
		// Get token loop
		do {
			System.out.println("Please enter your credentials: ");
			System.out.print("Username: ");
			
			String username = input.nextLine();
			System.out.print("Password");
			
			String password = input.nextLine();
			
			if (controller.getToken(username, password)) {
				System.out.println("Login successful!");
				loop = false;
			}
			else {
				System.out.println("Login failed!");
			}
		} while(loop);
		
		// Reset loop variable
		loop = true;
		
		// Group Server menu
		do {
			String choice;
			int choiceInt = 0;
			System.out.print(groupMenu);
			
			choice = input.nextLine();
			
			choiceInt = Integer.parseInt(choice);
			
			if (!(choiceInt > 0) && !(choiceInt <= 8)) { // If bad option
				System.out.println("Bad choice! Try again.");
			}
			else if (choiceInt != 8) { // Options 1-7
				groupChoice(choiceInt);
			}
			else { // Choice 8 (disconnect)
				System.out.println("Disconnecting...goodbye!");
				groupChoice(choiceInt);
				loop = false;
			}
		} while(loop);
		
	}
	
	private void groupChoice(int choice) {
		String username, password, groupname;
		
		switch(choice) {
		case 1:
			System.out.println("You picked: Create User");
			System.out.print("New Username: ");
			username = input.nextLine();
			System.out.print("New Password: ");
			password = input.nextLine();
			
			if (controller.createUser(username, password)) {
				System.out.println("Created user " + username + " successfully!");
			}
			else {
				System.out.println("Failed to created user!");
			}
			
			System.out.println("Returning to menu...");
			
			break;
		case 2:
			System.out.println("You picked: Delete User");
			System.out.print("Username: ");
			username = input.nextLine();
			
			if (controller.deleteUser(username)) {
				System.out.println("Deleted user " + username + " successfully!");
			}
			else {
				System.out.println("Failed to delete user!");
			}
			
			System.out.println("Returning to menu...");
			
			break;
		case 3:
			System.out.println("You picked: Create Group");
			System.out.print("New Group Name: ");
			groupname = input.nextLine();
			
			if (controller.createGroup(groupname)) {
				System.out.println("Created group " + groupname + " successfully!");
			}
			else {
				System.out.println("Failed to create group!");
			}
			
			System.out.println("Returning to menu...");
			
			break;
		case 4:
			System.out.println("You picked: Delete Group");
			System.out.print("Group Name: ");
			groupname = input.nextLine();
			
			if (controller.deleteGroup(groupname)) {
				System.out.println("Deleted group " + groupname + " successfully!");
			}
			else {
				System.out.println("Failed to delete group!");
			}
			
			System.out.println("Returning to menu...");
			
			break;
		case 5:
			System.out.println("You picked: Add User to Group");
			System.out.print("Username: ");
			username = input.nextLine();
			System.out.print("Group Name: ");
			groupname = input.nextLine();
			
			if (controller.addUserToGroup(username, groupname)) {
				System.out.println("Added " + username + " to " + groupname + " successfully!");
			}
			else {
				System.out.println("Failed to add user to group!");
			}
			
			System.out.println("Returning to menu...");
			
			break;
		case 6:
			System.out.println("You picked: Delete User to Group");
			System.out.print("Username: ");
			username = input.nextLine();
			System.out.print("Group Name: ");
			groupname = input.nextLine();
			
			if (controller.deleteUserFromGroup(username, groupname)) {
				System.out.println("Deleted " + username + " from " + groupname + " successfully!");
			}
			else {
				System.out.println("Failed to delete user from group!");
			}
			
			System.out.println("Returning to menu...");
			
			break;
		case 7:
			System.out.println("You picked: List Members of Group");
			System.out.print("Group Name: ");
			groupname = input.nextLine();
			
			ArrayList<String> members = (ArrayList<String>) controller.listMembers(groupname);
			if (!(members == null)) {
				System.out.println("Members of " + groupname + ":");
				
				for (int i = 0; i < members.size(); i++) {
					System.out.println(members.get(i));
				}
				
				System.out.println("Done listing members!");
			}
			else {
				System.out.println("Failed to list members of group!");
			}
			
			System.out.println("Returning to menu...");
			
			break;
		case 8:
			System.out.println("Disconnecting....goodbye!");
			controller.disconnectGroupClient();
			break;
		default:
			System.out.println("Invalid param!");
			break;
		}
	}
	
	
}
