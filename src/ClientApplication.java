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
				if (fClient != null) {
					if (fClient.isConnected()) {
						fClient.disconnect();
					}
				}
				if (gClient != null) {
					if (gClient.isConnected()) {
						gClient.disconnect();
					}
				}
			}
		});
		frame.setBounds(100, 100, 700, 500);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(new GridLayout(1, 0, 0, 0));
		
		desktopPane = new JDesktopPane();
		frame.getContentPane().add(desktopPane);
		
		groupClientFrame = new GroupServerClientFrame(this);
		groupClientFrame.setLocation(29, 39);
		desktopPane.add(groupClientFrame);
		
		fileClientFrame = new FileServerClientFrame(this);
		fileClientFrame.setLocation(135, 11);
		desktopPane.add(fileClientFrame);
		
		connectFrame = new JInternalFrame("Connect");
		connectFrame.setBounds(247, 160, 210, 135);
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
					initializeGroupClientWindow();
				}
				else {
					JOptionPane.showMessageDialog(null, "Invalid server or port.");
				}
			}
		});
		connectFrame.setVisible(true);
		
		
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
		
		if (!(serverField.getText().equals("")) && !(portField.getText().equals(""))) {
			tempServer = serverField.getText();
			try {
				tempPort = Integer.parseInt(portField.getText());
				gClient = new GroupClient(tempServer, tempPort);
				tempBool = gClient.connect();
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
