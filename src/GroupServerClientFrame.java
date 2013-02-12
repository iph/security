import java.awt.*;
import javax.swing.*;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;


public class GroupServerClientFrame extends JInternalFrame {

	private ClientApplication parentApp;
	
	private JTextField usernameField;
	private JLabel lblUser;
	private JTextField userField;
	private JLabel lblModifyUsersAnd;
	private JLabel lblGroup;
	private JButton btnCreateUser;
	private JButton btnDeleteUser;
	private JTextField groupField;
	private JButton btnCreateGroup;
	private JButton btnNewButton_1;
	private JButton btnAddUserTo;
	private JButton btnListMembersOf;
	private JTextPane membersTextPane;
	private JLabel lblListOfMembers;
	private JButton btnDisconnect;
	private JLabel lblServer_1;
	private JLabel lblPort_1;
	private JTextField fileserverField;
	private JTextField fileserverportField;
	private JPanel connectFileServerPanel;
	
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					//GroupServerClientFrame frame = new GroupServerClientFrame();
					//frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public GroupServerClientFrame(ClientApplication parentApp_) {
		parentApp = parentApp_;
		
		setIconifiable(true);
		setResizable(true);
		setMaximizable(true);
		setBounds(25, 69, 630, 400);
		
		getContentPane().setLayout(null);
		
		JLabel lblUsername = new JLabel("Username:");
		lblUsername.setBounds(10, 11, 52, 14);
		getContentPane().add(lblUsername);
		
		usernameField = new JTextField();
		usernameField.setBounds(72, 8, 86, 20);
		getContentPane().add(usernameField);
		usernameField.setColumns(10);
		
		JButton btnGetToken = new JButton("Get Token!");
		btnGetToken.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				boolean returned = getTokenAction();
				if (returned == true) {
					userField.setEnabled(true);
					groupField.setEnabled(true);
					
					connectFileServerPanel.setVisible(true);
				}
			}
		});
		btnGetToken.setBounds(10, 36, 148, 23);
		getContentPane().add(btnGetToken);
		
		JPanel groupActionsPanel = new JPanel();
		groupActionsPanel.setBounds(168, 11, 300, 349);
		getContentPane().add(groupActionsPanel);
		GridBagLayout gbl_groupActionsPanel = new GridBagLayout();
		gbl_groupActionsPanel.columnWidths = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_groupActionsPanel.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_groupActionsPanel.columnWeights = new double[]{0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gbl_groupActionsPanel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		groupActionsPanel.setLayout(gbl_groupActionsPanel);
		
		lblModifyUsersAnd = new JLabel("Users and Groups");
		GridBagConstraints gbc_lblModifyUsersAnd = new GridBagConstraints();
		gbc_lblModifyUsersAnd.gridwidth = 8;
		gbc_lblModifyUsersAnd.insets = new Insets(0, 0, 5, 5);
		gbc_lblModifyUsersAnd.gridx = 2;
		gbc_lblModifyUsersAnd.gridy = 0;
		groupActionsPanel.add(lblModifyUsersAnd, gbc_lblModifyUsersAnd);
		
		lblUser = new JLabel("User:");
		GridBagConstraints gbc_lblUser = new GridBagConstraints();
		gbc_lblUser.anchor = GridBagConstraints.EAST;
		gbc_lblUser.gridwidth = 3;
		gbc_lblUser.insets = new Insets(0, 0, 5, 5);
		gbc_lblUser.gridx = 2;
		gbc_lblUser.gridy = 2;
		groupActionsPanel.add(lblUser, gbc_lblUser);
		
		userField = new JTextField();
		userField.setEnabled(false);
		GridBagConstraints gbc_userField = new GridBagConstraints();
		gbc_userField.gridwidth = 5;
		gbc_userField.insets = new Insets(0, 0, 5, 5);
		gbc_userField.fill = GridBagConstraints.HORIZONTAL;
		gbc_userField.gridx = 5;
		gbc_userField.gridy = 2;
		groupActionsPanel.add(userField, gbc_userField);
		userField.setColumns(10);
		
		lblGroup = new JLabel("Group:");
		GridBagConstraints gbc_lblGroup = new GridBagConstraints();
		gbc_lblGroup.anchor = GridBagConstraints.EAST;
		gbc_lblGroup.gridwidth = 3;
		gbc_lblGroup.insets = new Insets(0, 0, 5, 5);
		gbc_lblGroup.gridx = 2;
		gbc_lblGroup.gridy = 3;
		groupActionsPanel.add(lblGroup, gbc_lblGroup);
		
		groupField = new JTextField();
		groupField.setEnabled(false);
		GridBagConstraints gbc_groupField = new GridBagConstraints();
		gbc_groupField.gridwidth = 5;
		gbc_groupField.insets = new Insets(0, 0, 5, 5);
		gbc_groupField.fill = GridBagConstraints.HORIZONTAL;
		gbc_groupField.gridx = 5;
		gbc_groupField.gridy = 3;
		groupActionsPanel.add(groupField, gbc_groupField);
		groupField.setColumns(10);
		
		btnCreateUser = new JButton("Create User");
		btnCreateUser.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				createUserAction();
			}
		});
		GridBagConstraints gbc_btnCreateUser = new GridBagConstraints();
		gbc_btnCreateUser.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnCreateUser.gridwidth = 5;
		gbc_btnCreateUser.insets = new Insets(0, 0, 5, 5);
		gbc_btnCreateUser.gridx = 1;
		gbc_btnCreateUser.gridy = 4;
		groupActionsPanel.add(btnCreateUser, gbc_btnCreateUser);
		
		btnDeleteUser = new JButton("Delete User");
		btnDeleteUser.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				deleteUserAction();
			}
		});
		GridBagConstraints gbc_btnDeleteUser = new GridBagConstraints();
		gbc_btnDeleteUser.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnDeleteUser.gridwidth = 5;
		gbc_btnDeleteUser.insets = new Insets(0, 0, 5, 5);
		gbc_btnDeleteUser.gridx = 6;
		gbc_btnDeleteUser.gridy = 4;
		groupActionsPanel.add(btnDeleteUser, gbc_btnDeleteUser);
		
		btnCreateGroup = new JButton("Create Group");
		btnCreateGroup.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				createGroupAction();
			}
		});
		GridBagConstraints gbc_btnCreateGroup = new GridBagConstraints();
		gbc_btnCreateGroup.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnCreateGroup.gridwidth = 5;
		gbc_btnCreateGroup.insets = new Insets(0, 0, 5, 5);
		gbc_btnCreateGroup.gridx = 1;
		gbc_btnCreateGroup.gridy = 5;
		groupActionsPanel.add(btnCreateGroup, gbc_btnCreateGroup);
		
		btnNewButton_1 = new JButton("Delete Group");
		btnNewButton_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				deleteGroupAction();
			}
		});
		GridBagConstraints gbc_btnNewButton_1 = new GridBagConstraints();
		gbc_btnNewButton_1.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnNewButton_1.gridwidth = 5;
		gbc_btnNewButton_1.insets = new Insets(0, 0, 5, 5);
		gbc_btnNewButton_1.gridx = 6;
		gbc_btnNewButton_1.gridy = 5;
		groupActionsPanel.add(btnNewButton_1, gbc_btnNewButton_1);
		
		btnAddUserTo = new JButton("Add User to Group");
		btnAddUserTo.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				addUserToGroupAction();
			}
		});
		GridBagConstraints gbc_btnAddUserTo = new GridBagConstraints();
		gbc_btnAddUserTo.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnAddUserTo.gridwidth = 10;
		gbc_btnAddUserTo.insets = new Insets(0, 0, 5, 5);
		gbc_btnAddUserTo.gridx = 1;
		gbc_btnAddUserTo.gridy = 6;
		groupActionsPanel.add(btnAddUserTo, gbc_btnAddUserTo);
		
		btnListMembersOf = new JButton("List Members of Group");
		btnListMembersOf.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				boolean returned = listMembersAction();
			}
		});
		GridBagConstraints gbc_btnListMembersOf = new GridBagConstraints();
		gbc_btnListMembersOf.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnListMembersOf.gridwidth = 10;
		gbc_btnListMembersOf.insets = new Insets(0, 0, 5, 5);
		gbc_btnListMembersOf.gridx = 1;
		gbc_btnListMembersOf.gridy = 7;
		groupActionsPanel.add(btnListMembersOf, gbc_btnListMembersOf);
		
		lblListOfMembers = new JLabel("List of Members");
		GridBagConstraints gbc_lblListOfMembers = new GridBagConstraints();
		gbc_lblListOfMembers.gridwidth = 5;
		gbc_lblListOfMembers.insets = new Insets(0, 0, 5, 5);
		gbc_lblListOfMembers.gridx = 4;
		gbc_lblListOfMembers.gridy = 8;
		groupActionsPanel.add(lblListOfMembers, gbc_lblListOfMembers);
		
		membersTextPane = new JTextPane();
		GridBagConstraints gbc_membersTextPane = new GridBagConstraints();
		gbc_membersTextPane.gridheight = 4;
		gbc_membersTextPane.gridwidth = 10;
		gbc_membersTextPane.insets = new Insets(0, 0, 0, 5);
		gbc_membersTextPane.fill = GridBagConstraints.BOTH;
		gbc_membersTextPane.gridx = 1;
		gbc_membersTextPane.gridy = 9;
		groupActionsPanel.add(membersTextPane, gbc_membersTextPane);
		
		btnDisconnect = new JButton("Disconnect");
		btnDisconnect.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				disconnectAction();
				
			}
		});
		btnDisconnect.setBounds(10, 91, 148, 23);
		getContentPane().add(btnDisconnect);
		
		connectFileServerPanel = new JPanel();
		connectFileServerPanel.setBounds(10, 126, 148, 243);
		getContentPane().add(connectFileServerPanel);
		connectFileServerPanel.setLayout(null);
		connectFileServerPanel.setVisible(false);
		
		JLabel lblFileServer = new JLabel("File Server");
		lblFileServer.setHorizontalAlignment(SwingConstants.CENTER);
		lblFileServer.setBounds(6, 6, 136, 15);
		connectFileServerPanel.add(lblFileServer);
		
		lblServer_1 = new JLabel("Server:");
		lblServer_1.setBounds(0, 33, 60, 15);
		connectFileServerPanel.add(lblServer_1);
		
		lblPort_1 = new JLabel("Port:");
		lblPort_1.setBounds(0, 58, 60, 15);
		connectFileServerPanel.add(lblPort_1);
		
		fileserverField = new JTextField();
		fileserverField.setBounds(49, 27, 93, 27);
		connectFileServerPanel.add(fileserverField);
		fileserverField.setColumns(10);
		
		fileserverportField = new JTextField();
		fileserverportField.setBounds(49, 52, 93, 27);
		connectFileServerPanel.add(fileserverportField);
		fileserverportField.setColumns(10);
		
		JButton btnConnectFileServer = new JButton("Connect");
		btnConnectFileServer.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if (connectFileServerAction() == true) {
					parentApp.initializeFileClientWindow();
				}
			}
		});
		btnConnectFileServer.setBounds(0, 91, 142, 27);
		connectFileServerPanel.add(btnConnectFileServer);
		

	}
	
	private boolean connectFileServerAction() {
		String tempServer;
		int tempPort;
		boolean tempBool = false;
		
		//JOptionPane.showMessageDialog(null, "Test Dialog:\n" + serverField.getText());
		
		if (!(fileserverField.getText().equals("")) && !(fileserverportField.getText().equals(""))) {
			tempServer = fileserverField.getText();
			try {
				tempPort = Integer.parseInt(fileserverportField.getText());
				parentApp.fClient = new FileClient(tempServer, tempPort);
				tempBool = parentApp.fClient.connect();
				return tempBool;
			}
			catch (Exception e) {
				JOptionPane.showMessageDialog(null, "Enter a number for the port!");
			}
			
		}
		else {
			JOptionPane.showMessageDialog(null, "Enter both a server and a port!");
		}
		
		return false;
		
	}
	
	private boolean getTokenAction() {
		parentApp.myToken = parentApp.gClient.getToken(usernameField.getText());
		if (parentApp.myToken != null) {
			return true;
		}
		else {
			return false;
		}
		
	}
	
	private void disconnectAction() {
		parentApp.gClient.disconnect();
		parentApp.fClient.disconnect();
		connectFileServerPanel.setVisible(false);
		parentApp.fileClientFrame.setVisible(false);
		parentApp.groupClientFrame.setVisible(false);
		parentApp.connectFrame.setVisible(true);
	}
	
	private boolean createUserAction() {
		if (userField.getText().equals("")) {
			JOptionPane.showMessageDialog(null, "Enter a user to create one!");
		}
		else {
			return parentApp.gClient.createUser(userField.getText(), parentApp.myToken);
		}
		
		return false;
	}
	
	private boolean deleteUserAction() {
		if (userField.getText().equals("")) {
			JOptionPane.showMessageDialog(null, "Enter a user to delete one!");
		}
		else {
			return parentApp.gClient.deleteUser(userField.getText(), parentApp.myToken);
		}
		
		return false;
	}
	
	private boolean createGroupAction() {
		if (groupField.getText().equals("")) {
			JOptionPane.showMessageDialog(null, "Enter a group to create one!");
		}
		else {
			return parentApp.gClient.createGroup(groupField.getText(), parentApp.myToken);
		}
		
		return false;
	}
	
	private boolean deleteGroupAction() {
		if (groupField.getText().equals("")) {
			JOptionPane.showMessageDialog(null, "Enter a group to delete one!");
		}
		else {
			return parentApp.gClient.deleteGroup(groupField.getText(), parentApp.myToken);
		}
		
		return false;
	}
	
	private boolean addUserToGroupAction() {
		if ((groupField.getText().equals("")) || (userField.getText().equals(""))) {
			JOptionPane.showMessageDialog(null, "Enter a user AND group!");
		}
		else {
			return parentApp.gClient.addUserToGroup(userField.getText(), groupField.getText(), parentApp.myToken);
		}
		
		return false;
	}
	
	private boolean deleteUserFromGroupAction() {
		if ((groupField.getText().equals("")) || (userField.getText().equals(""))) {
			JOptionPane.showMessageDialog(null, "Enter a user AND group!");
		}
		else {
			return parentApp.gClient.deleteUserFromGroup(userField.getText(), groupField.getText(), parentApp.myToken);
		}
		
		return false;
	}
	
	private boolean listMembersAction() {
		if (groupField.getText().equals("")) {
			JOptionPane.showMessageDialog(null, "Enter a group to list members!");
		}
		else {
			String temp = "";
			for (String member : parentApp.gClient.listMembers(groupField.getText(), parentApp.myToken)) {
				temp += member;
				temp += ", ";
			}
			membersTextPane.setText(temp);
			return true;
		}
		
		return false;
	}

}
