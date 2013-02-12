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
import javax.swing.SwingConstants;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;
import javax.swing.JInternalFrame;
import javax.swing.event.InternalFrameAdapter;
import javax.swing.event.InternalFrameEvent;
import javax.swing.JSeparator;
import javax.swing.DropMode;
import javax.swing.JTextPane;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.RowSpec;
import com.jgoodies.forms.factories.FormFactory;
import javax.swing.JList;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;


public class ClientApplication {

	private JFrame frame;
	private JTextField serverField;
	private JTextField portField;
	private JDesktopPane desktopPane;
	protected JInternalFrame groupClientFrame;
	protected JInternalFrame connectFrame;
	protected JInternalFrame fileClientFrame;
	
	// Custom variables
	protected GroupClient gClient;
	protected FileClient fClient;
	protected UserToken myToken;
	
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
	private JButton btnDownloadFile;
	private JButton btnUploadFile;
	private JButton btnDeleteFile;
	private JPanel panel_1;
	private JButton btnDisconnectFileServer;
	

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
		frame.addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				// To avoid connection resets.
				gClient.disconnect();
				fClient.disconnect();
			}
		});
		frame.setBounds(100, 100, 700, 500);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(new GridLayout(1, 0, 0, 0));
		
		desktopPane = new JDesktopPane();
		frame.getContentPane().add(desktopPane);
		
		connectFrame = new JInternalFrame("Connect");
		connectFrame.setBounds(25, 33, 210, 135);
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
		
		fileClientFrame = new FileServerClientFrame();
		desktopPane.add(fileClientFrame);
		
		groupClientFrame = new GroupServerClientFrame(this);
		desktopPane.add(groupClientFrame);
		
		
		//setupClient();
	}
	
	protected void initializeGroupClientWindow() {
		groupClientFrame.setVisible(true);
		connectFrame.setVisible(false);
	}
	
	protected void initializeFileClientWindow() {
		fileClientFrame.setVisible(true);
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
