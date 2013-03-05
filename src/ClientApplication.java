import javax.swing.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.Security;


public class ClientApplication {

	private JFrame frame;
	private JDesktopPane desktopPane;
	protected GroupServerClientFrame groupClientFrame;
	protected ConnectFrame connectFrame;
	protected FileServerClientFrame fileClientFrame;
	
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
					Security.addProvider(new BouncyCastleProvider());
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
						fClient.secureDisconnect();
					}
				}
				if (gClient != null) {
					if (gClient.isConnected()) {
						gClient.secureDisconnect();
					}
				}
			}
		});
		frame.setBounds(100, 100, 750, 580);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(new GridLayout(1, 0, 0, 0));
		
		desktopPane = new JDesktopPane();
		frame.getContentPane().add(desktopPane);
		
		groupClientFrame = new GroupServerClientFrame(this);
		groupClientFrame.setLocation(61, 17);
		desktopPane.add(groupClientFrame);
		
		fileClientFrame = new FileServerClientFrame(this);
		desktopPane.add(fileClientFrame);
		
		connectFrame = new ConnectFrame(this);
		desktopPane.add(connectFrame);
		connectFrame.setVisible(true);
	}
	
	protected void initializeFileClientWindow() {
		fileClientFrame.setVisible(true);
	}
}
