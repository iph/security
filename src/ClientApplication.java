import java.awt.EventQueue;

import javax.swing.JFrame;
import java.awt.GridLayout;

import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import javax.swing.JLabel;
import javax.swing.JButton;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.BoxLayout;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.RowSpec;
import com.jgoodies.forms.factories.FormFactory;
import javax.swing.SwingConstants;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;
import javax.swing.JInternalFrame;
import javax.swing.event.InternalFrameAdapter;
import javax.swing.event.InternalFrameEvent;
import javax.swing.JSeparator;
import net.miginfocom.swing.MigLayout;
import javax.swing.DropMode;
import javax.swing.JTextPane;


public class ClientApplication {

	private JFrame frame;
	private JTextField serverField;
	private JTextField portField;
	private JDesktopPane desktopPane;
	private JInternalFrame groupClientFrame;
	private JInternalFrame connectFrame;
	
	// Custom variables
	private GroupClient gClient;
	private FileClient fClient;
	private UserToken myToken;
	
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

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ClientApplication window = new ClientApplication();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public ClientApplication() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 700, 500);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(new GridLayout(1, 0, 0, 0));
		
		desktopPane = new JDesktopPane();
		frame.getContentPane().add(desktopPane);
		
		connectFrame = new JInternalFrame("Connect");
		connectFrame.setBounds(10, 11, 210, 135);
		desktopPane.add(connectFrame);
		connectFrame.getContentPane().setLayout(null);
		
		JLabel lblServer = new JLabel("Server");
		lblServer.setBounds(10, 11, 46, 14);
		connectFrame.getContentPane().add(lblServer);
		
		JLabel lblPort = new JLabel("Port");
		lblPort.setBounds(10, 36, 46, 14);
		connectFrame.getContentPane().add(lblPort);
		
		serverField = new JTextField();
		serverField.setBounds(60, 8, 86, 20);
		connectFrame.getContentPane().add(serverField);
		serverField.setColumns(10);
		
		portField = new JTextField();
		portField.setBounds(60, 36, 86, 20);
		connectFrame.getContentPane().add(portField);
		portField.setColumns(10);
		
		JButton btnConnect = new JButton("Connect");
		btnConnect.setBounds(60, 67, 89, 23);
		connectFrame.getContentPane().add(btnConnect);
		
		
		btnConnect.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (connectAction() == true) {
					System.out.println("here");
					initializeGroupClientWindow();
				}
				else {
					JOptionPane.showMessageDialog(null, "Invalid server or port.");
				}
			}
		});
		connectFrame.setVisible(true);
		
		groupClientFrame = new JInternalFrame("Group Server Client");
		groupClientFrame.setIconifiable(true);
		groupClientFrame.setResizable(true);
		groupClientFrame.setMaximizable(true);
		groupClientFrame.setBounds(54, 32, 630, 400);
		desktopPane.add(groupClientFrame);
		groupClientFrame.getContentPane().setLayout(null);
		
		JLabel lblUsername = new JLabel("Username:");
		lblUsername.setBounds(10, 11, 52, 14);
		groupClientFrame.getContentPane().add(lblUsername);
		
		usernameField = new JTextField();
		usernameField.setBounds(72, 8, 86, 20);
		groupClientFrame.getContentPane().add(usernameField);
		usernameField.setColumns(10);
		
		JButton btnGetToken = new JButton("Get Token!");
		btnGetToken.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				boolean returned = getTokenAction();
				if (returned == true) {
					userField.setEnabled(true);
					groupField.setEnabled(true);
				}
			}
		});
		btnGetToken.setBounds(10, 36, 148, 23);
		groupClientFrame.getContentPane().add(btnGetToken);
		
		JPanel groupActionsPanel = new JPanel();
		groupActionsPanel.setBounds(168, 11, 300, 349);
		groupClientFrame.getContentPane().add(groupActionsPanel);
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
		groupClientFrame.getContentPane().add(btnDisconnect);
		
		//setupClient();
	}
	
	private void initializeGroupClientWindow() {
		
		
		
		groupClientFrame.setVisible(true);
		connectFrame.setVisible(false);
		
	}
	
	private boolean getTokenAction() {
		myToken = gClient.getToken(usernameField.getText());
		if (myToken != null) {
			return true;
		}
		else {
			return false;
		}
		
	}
	
	private void disconnectAction() {
		gClient.disconnect();
		groupClientFrame.setVisible(false);
	}
	
	private boolean createUserAction() {
		if (userField.getText().equals("")) {
			JOptionPane.showMessageDialog(null, "Enter a user to create one!");
		}
		else {
			return gClient.createUser(userField.getText(), myToken);
		}
		
		return false;
	}
	
	private boolean deleteUserAction() {
		if (userField.getText().equals("")) {
			JOptionPane.showMessageDialog(null, "Enter a user to delete one!");
		}
		else {
			return gClient.deleteUser(userField.getText(), myToken);
		}
		
		return false;
	}
	
	private boolean createGroupAction() {
		if (groupField.getText().equals("")) {
			JOptionPane.showMessageDialog(null, "Enter a group to create one!");
		}
		else {
			return gClient.createGroup(groupField.getText(), myToken);
		}
		
		return false;
	}
	
	private boolean deleteGroupAction() {
		if (groupField.getText().equals("")) {
			JOptionPane.showMessageDialog(null, "Enter a group to delete one!");
		}
		else {
			return gClient.deleteGroup(groupField.getText(), myToken);
		}
		
		return false;
	}
	
	private boolean addUserToGroupAction() {
		if ((groupField.getText().equals("")) || (userField.getText().equals(""))) {
			JOptionPane.showMessageDialog(null, "Enter a user AND group!");
		}
		else {
			return gClient.addUserToGroup(userField.getText(), groupField.getText(), myToken);
		}
		
		return false;
	}
	
	private boolean deleteUserFromGroupAction() {
		if ((groupField.getText().equals("")) || (userField.getText().equals(""))) {
			JOptionPane.showMessageDialog(null, "Enter a user AND group!");
		}
		else {
			return gClient.deleteUserFromGroup(userField.getText(), groupField.getText(), myToken);
		}
		
		return false;
	}
	
	private boolean listMembersAction() {
		if (groupField.getText().equals("")) {
			JOptionPane.showMessageDialog(null, "Enter a group to list members!");
		}
		else {
			String temp = "";
			for (String member : gClient.listMembers(groupField.getText(), myToken)) {
				temp += member;
				temp += "\n";
			}
			membersTextPane.setText(temp);
			return true;
		}
		
		return false;
	}
	
	
	private boolean connectAction() {
		String tempServer;
		int tempPort;
		boolean tempBool = false;
		
		//JOptionPane.showMessageDialog(null, "Test Dialog:\n" + serverField.getText());
		
		if (!(serverField.getText().equals("")) && !(portField.getText().equals(""))) {
			tempServer = serverField.getText();
			try {
				tempPort = Integer.parseInt(portField.getText());
				gClient = new GroupClient(tempServer, tempPort);
				tempBool = gClient.connect();
				System.out.println("tempBool: " + tempBool);
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
}
