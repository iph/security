import java.awt.*;
import javax.swing.*;


public class FileServerClientFrame extends JInternalFrame {

	
	private JFrame frame;
	private JTextField serverField;
	private JTextField portField;
	private JDesktopPane desktopPane;
	private JInternalFrame groupClientFrame;
	private JInternalFrame connectFrame;
	private JInternalFrame fileClientFrame;
	
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
					FileServerClientFrame frame = new FileServerClientFrame();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public FileServerClientFrame() {
		setTitle("File Server Client");
		
		
		setIconifiable(true);
		setResizable(true);
		setMaximizable(true);
		setBounds(329, 69, 400, 400);
		getContentPane().setLayout(new BorderLayout(0, 0));
		
		JLabel lblNewLabel_3 = new JLabel("File List:");
		lblNewLabel_3.setHorizontalAlignment(SwingConstants.CENTER);
		getContentPane().add(lblNewLabel_3, BorderLayout.NORTH);
		
		JList fileList = new JList();
		getContentPane().add(fileList, BorderLayout.CENTER);
		
		JPanel panel = new JPanel();
		getContentPane().add(panel, BorderLayout.WEST);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{100, 0};
		gbl_panel.rowHeights = new int[]{27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel.setLayout(gbl_panel);
		
		JButton btnListFiles = new JButton("List Files");
		GridBagConstraints gbc_btnListFiles = new GridBagConstraints();
		gbc_btnListFiles.insets = new Insets(0, 0, 5, 0);
		gbc_btnListFiles.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnListFiles.anchor = GridBagConstraints.NORTH;
		gbc_btnListFiles.gridx = 0;
		gbc_btnListFiles.gridy = 2;
		panel.add(btnListFiles, gbc_btnListFiles);
		
		btnDownloadFile = new JButton("Download File");
		GridBagConstraints gbc_btnDownloadFile = new GridBagConstraints();
		gbc_btnDownloadFile.insets = new Insets(0, 0, 5, 0);
		gbc_btnDownloadFile.gridx = 0;
		gbc_btnDownloadFile.gridy = 4;
		panel.add(btnDownloadFile, gbc_btnDownloadFile);
		
		btnDeleteFile = new JButton("Delete File");
		GridBagConstraints gbc_btnDeleteFile = new GridBagConstraints();
		gbc_btnDeleteFile.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnDeleteFile.insets = new Insets(0, 0, 5, 0);
		gbc_btnDeleteFile.gridx = 0;
		gbc_btnDeleteFile.gridy = 6;
		panel.add(btnDeleteFile, gbc_btnDeleteFile);
		
		btnUploadFile = new JButton("Upload File");
		GridBagConstraints gbc_btnUploadFile = new GridBagConstraints();
		gbc_btnUploadFile.insets = new Insets(0, 0, 5, 0);
		gbc_btnUploadFile.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnUploadFile.gridx = 0;
		gbc_btnUploadFile.gridy = 8;
		panel.add(btnUploadFile, gbc_btnUploadFile);
		
		panel_1 = new JPanel();
		getContentPane().add(panel_1, BorderLayout.EAST);
		GridBagLayout gbl_panel_1 = new GridBagLayout();
		gbl_panel_1.columnWidths = new int[]{60, 0};
		gbl_panel_1.rowHeights = new int[]{15, 0, 0, 0, 0, 0};
		gbl_panel_1.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);
		
		btnDisconnectFileServer = new JButton("Disconnect");
		GridBagConstraints gbc_btnDisconnectFileServer = new GridBagConstraints();
		gbc_btnDisconnectFileServer.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnDisconnectFileServer.gridx = 0;
		gbc_btnDisconnectFileServer.gridy = 4;
		panel_1.add(btnDisconnectFileServer, gbc_btnDisconnectFileServer);
	}

}
