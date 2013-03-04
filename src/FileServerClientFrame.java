import java.awt.*;
import java.io.File;
import java.util.List;
import javax.swing.*;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;


public class FileServerClientFrame extends JInternalFrame {
	
	private static final long serialVersionUID = -2501440867428581412L;
	
	private ClientApplication parentApp;
	private JFileChooser fileChooser;
	private JFileChooser saveChooser;
	
	private JButton btnDownloadFile;
	private JButton btnUploadFile;
	private JButton btnDeleteFile;
	private JPanel panel_1;
	private JButton btnDisconnectFileServer;
	private JList fileList;
	
	private JLabel lblEnterGroup;
	private JTextField groupUploadField;
	private JLabel lblOrderToUpload;
	

	/**
	 * Create the frame.
	 */
	public FileServerClientFrame(ClientApplication parentApp_) {
		super();
		parentApp = parentApp_;
		fileChooser = new JFileChooser();
		saveChooser = new JFileChooser();
		saveChooser.setDialogTitle("Choose a file to save as...");
        saveChooser.setDialogType(javax.swing.JFileChooser.SAVE_DIALOG);
		
		setTitle("File Server Client");
		setIconifiable(true);
		setResizable(true);
		setMaximizable(true);
		setBounds(329, 69, 400, 400);
		setLocation(135, 11);
		getContentPane().setLayout(new BorderLayout(0, 0));
		
		JLabel lblNewLabel_3 = new JLabel("File List:");
		lblNewLabel_3.setHorizontalAlignment(SwingConstants.CENTER);
		getContentPane().add(lblNewLabel_3, BorderLayout.NORTH);
		
		// This does a warning in JavaSE 7. It isn't parameterized in SE 6.
		fileList = new JList();
		
		getContentPane().add(fileList, BorderLayout.CENTER);
		
		JPanel panel = new JPanel();
		getContentPane().add(panel, BorderLayout.WEST);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{100, 0};
		gbl_panel.rowHeights = new int[]{27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel.setLayout(gbl_panel);
		
		JButton btnListFiles = new JButton("List Files");
		btnListFiles.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				listFilesAction();
			}
		});
		GridBagConstraints gbc_btnListFiles = new GridBagConstraints();
		gbc_btnListFiles.insets = new Insets(0, 0, 5, 0);
		gbc_btnListFiles.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnListFiles.anchor = GridBagConstraints.NORTH;
		gbc_btnListFiles.gridx = 0;
		gbc_btnListFiles.gridy = 2;
		panel.add(btnListFiles, gbc_btnListFiles);
		
		btnDownloadFile = new JButton("Download File");
		btnDownloadFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				downloadAction();
			}
		});
		GridBagConstraints gbc_btnDownloadFile = new GridBagConstraints();
		gbc_btnDownloadFile.insets = new Insets(0, 0, 5, 0);
		gbc_btnDownloadFile.gridx = 0;
		gbc_btnDownloadFile.gridy = 4;
		panel.add(btnDownloadFile, gbc_btnDownloadFile);
		
		btnDeleteFile = new JButton("Delete File");
		btnDeleteFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				deleteAction();
			}
		});
		GridBagConstraints gbc_btnDeleteFile = new GridBagConstraints();
		gbc_btnDeleteFile.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnDeleteFile.insets = new Insets(0, 0, 5, 0);
		gbc_btnDeleteFile.gridx = 0;
		gbc_btnDeleteFile.gridy = 6;
		panel.add(btnDeleteFile, gbc_btnDeleteFile);
		
		lblEnterGroup = new JLabel("Enter group in");
		GridBagConstraints gbc_lblEnterGroup = new GridBagConstraints();
		gbc_lblEnterGroup.insets = new Insets(0, 0, 5, 0);
		gbc_lblEnterGroup.gridx = 0;
		gbc_lblEnterGroup.gridy = 8;
		panel.add(lblEnterGroup, gbc_lblEnterGroup);
		
		lblOrderToUpload = new JLabel("order to upload:");
		GridBagConstraints gbc_lblOrderToUpload = new GridBagConstraints();
		gbc_lblOrderToUpload.insets = new Insets(0, 0, 5, 0);
		gbc_lblOrderToUpload.gridx = 0;
		gbc_lblOrderToUpload.gridy = 9;
		panel.add(lblOrderToUpload, gbc_lblOrderToUpload);
		
		groupUploadField = new JTextField();
		groupUploadField.setToolTipText("");
		groupUploadField.setHorizontalAlignment(SwingConstants.CENTER);
		GridBagConstraints gbc_groupUploadField = new GridBagConstraints();
		gbc_groupUploadField.insets = new Insets(0, 0, 5, 0);
		gbc_groupUploadField.fill = GridBagConstraints.HORIZONTAL;
		gbc_groupUploadField.gridx = 0;
		gbc_groupUploadField.gridy = 10;
		panel.add(groupUploadField, gbc_groupUploadField);
		groupUploadField.setColumns(10);
		
		btnUploadFile = new JButton("Upload File");
		btnUploadFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				uploadAction();
			}
		});
		GridBagConstraints gbc_btnUploadFile = new GridBagConstraints();
		gbc_btnUploadFile.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnUploadFile.gridx = 0;
		gbc_btnUploadFile.gridy = 11;
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
		btnDisconnectFileServer.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				disconnectAction();
			}
		});
		GridBagConstraints gbc_btnDisconnectFileServer = new GridBagConstraints();
		gbc_btnDisconnectFileServer.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnDisconnectFileServer.gridx = 0;
		gbc_btnDisconnectFileServer.gridy = 4;
		panel_1.add(btnDisconnectFileServer, gbc_btnDisconnectFileServer);
	}

	
	private void disconnectAction() {
		parentApp.fClient.secureDisconnect();
		parentApp.fClient = null;
		parentApp.fileClientFrame.setVisible(false);
	}
	
	private boolean listFilesAction() {
		List<String> tempList = parentApp.fClient.listFiles(parentApp.myToken);
		
		if ((tempList != null)) {
			String[] tempArray = tempList.toArray(new String[tempList.size()]);
			fileList.setListData(tempArray);
			return true;
		}
		else {
			return false;
		}
	}
	
	private void uploadAction() {
		String group;
		String sourceFile;
		String destFile;
		File openFile;
		
		if (groupUploadField.getText().equals("")) {
			JOptionPane.showMessageDialog(this, "Enter a group to upload a file!");
		}
		else {
			group = groupUploadField.getText();
			
			int returnValue = fileChooser.showOpenDialog(FileServerClientFrame.this);
			if (returnValue == JFileChooser.APPROVE_OPTION) {
				openFile = fileChooser.getSelectedFile();
				sourceFile = openFile.getAbsolutePath();
				destFile = openFile.getName(); 
				if ((parentApp.fClient.upload(sourceFile, destFile, group, parentApp.myToken)) == true) {
					JOptionPane.showMessageDialog(this, "Upload success!");
				}
				else {
					JOptionPane.showMessageDialog(this, "Upload failed!");
				}
			}
		}
	}
	
	private void deleteAction() {
		String filename;
		
		filename = (String)fileList.getSelectedValue();
		
		if (filename == null) {
			JOptionPane.showMessageDialog(this, "Select a file to delete!");
		}
		else {
			if ((parentApp.fClient.delete(filename, parentApp.myToken)) == true) {
				JOptionPane.showMessageDialog(this, "Delete success!");
			}
			else {
				JOptionPane.showMessageDialog(this, "Delete failed!");
			}
			// Re-populate just in case...
			listFilesAction();
		}
	}
	
	private void downloadAction() {
		String sourceFile;
		String destFile = "";
		File saveFile;
		
		sourceFile = (String)fileList.getSelectedValue();
		
		if (sourceFile == null) {
			JOptionPane.showMessageDialog(this, "Select a file to download!");
		}
		else {
			int returnValue = saveChooser.showSaveDialog(this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
            	saveFile = saveChooser.getSelectedFile();
            	destFile = saveFile.getAbsolutePath();
            	if ((parentApp.fClient.download(sourceFile, destFile, parentApp.myToken)) == true) {
    				JOptionPane.showMessageDialog(this, "Download success!");
    			}
    			else {
    				JOptionPane.showMessageDialog(this, "Download failed!");
    			}
            }
		}
	}
}
