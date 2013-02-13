import java.awt.event.*;
import javax.swing.*;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;


public class ConnectFrame extends JInternalFrame {
	
	private static final long serialVersionUID = -422925463211565384L;
	
	private ClientApplication parentApp;
	private JTextField serverField;
	private JTextField portField;

	/**
	 * Create the frame.
	 */
	public ConnectFrame(ClientApplication parentApp_) {
		parentApp = parentApp_;
		
		setTitle("Connect");
		setBounds(247, 160, 220, 150);
		
		JLabel lblServer = new JLabel("Server:");
		
		JLabel lblPort = new JLabel("Port:");
		lblPort.setHorizontalAlignment(SwingConstants.CENTER);
		
		serverField = new JTextField();
		serverField.setColumns(10);
		
		portField = new JTextField();
		portField.setColumns(10);
		
		JButton btnConnect = new JButton("Connect");
		GroupLayout groupLayout = new GroupLayout(getContentPane());
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING)
						.addComponent(lblServer, GroupLayout.PREFERRED_SIZE, 53, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblPort, GroupLayout.DEFAULT_SIZE, 56, Short.MAX_VALUE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING, false)
						.addComponent(portField, 0, 0, Short.MAX_VALUE)
						.addComponent(serverField, GroupLayout.DEFAULT_SIZE, 98, Short.MAX_VALUE))
					.addGap(32))
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(47)
					.addComponent(btnConnect, GroupLayout.PREFERRED_SIZE, 112, GroupLayout.PREFERRED_SIZE)
					.addContainerGap(51, Short.MAX_VALUE))
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(11)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(serverField, GroupLayout.PREFERRED_SIZE, 20, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblServer, GroupLayout.PREFERRED_SIZE, 14, GroupLayout.PREFERRED_SIZE))
					.addGap(11)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(portField, GroupLayout.PREFERRED_SIZE, 20, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblPort, GroupLayout.PREFERRED_SIZE, 14, GroupLayout.PREFERRED_SIZE))
					.addGap(18)
					.addComponent(btnConnect, GroupLayout.PREFERRED_SIZE, 23, GroupLayout.PREFERRED_SIZE)
					.addGap(15))
		);
		getContentPane().setLayout(groupLayout);
		
		btnConnect.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				connectAction();
			}
		});
		setVisible(true);
	}
	
	private void connectAction() {
		String tempServer;
		int tempPort;
		
		if (!(serverField.getText().equals("")) && !(portField.getText().equals(""))) {
			tempServer = serverField.getText();
			try {
				tempPort = Integer.parseInt(portField.getText());
				parentApp.gClient = new GroupClient(tempServer, tempPort);
				if(parentApp.gClient.connect() == true) {
					initializeGroupClientWindow();
				}
				else {
					JOptionPane.showMessageDialog(null, "Invalid server or port, or host down.");
				}
			}
			catch (Exception e) {
				JOptionPane.showMessageDialog(null, "Enter a number for the port!");
			}
		}
		else {
			JOptionPane.showMessageDialog(null, "Enter both a server and a port!");
		}
	}
	
	private void initializeGroupClientWindow() {
		parentApp.groupClientFrame.setVisible(true);
		setVisible(false);
	}
}
