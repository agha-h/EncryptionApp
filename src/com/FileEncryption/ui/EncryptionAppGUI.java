package com.FileEncryption.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.FileEncryption.encryption.AESDecryption;
import com.FileEncryption.encryption.AESEncryption;
import com.FileEncryption.encryption.RSADecryption;
import com.FileEncryption.encryption.RSAEncryption;

public class EncryptionAppGUI extends JFrame {
    private JTextField encryptionKeyTextField;
    private JTextField decryptionKeyTextField;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton selectFileButton;
    private JLabel selectedFileLabel;
    private JComboBox<String> encryptionAlgorithmComboBox;

    public EncryptionAppGUI() {
        setTitle("File Encryption Application");
        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null); // Center the frame on the screen

        // Initialize components
        initComponents();

        // Add components to the frame
        addComponents();

        // Display the frame
        setVisible(true);
    }

    private void initComponents() {
        // Initialize text fields, buttons, and combo box
        encryptionKeyTextField = new JTextField(20);
        decryptionKeyTextField = new JTextField(20);
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");
        selectFileButton = new JButton("Select File");
        selectedFileLabel = new JLabel("No file selected");
        encryptionAlgorithmComboBox = new JComboBox<>(new String[] { "AES", "RSA" });

        // Add action listeners for buttons
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedAlgorithm = (String) encryptionAlgorithmComboBox.getSelectedItem();

                if (selectedAlgorithm.equals("AES")) {
                    try {
                        String filePath = selectedFileLabel.getText();
                        String plaintext = readFile(filePath);
                        String key = encryptionKeyTextField.getText();
                        byte[] encryptedBytes = AESEncryption.encrypt(plaintext, key);
                        writeFile(filePath, encryptedBytes);
                        System.out.println("AES Encrypted and replaced file: " + filePath);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                } else if (selectedAlgorithm.equals("RSA")) {
                    try {
                        String filePath = selectedFileLabel.getText();
                        String plaintext = readFile(filePath);
                        KeyPair keyPair = RSAEncryption.generateRSAKeyPair();
                        PublicKey publicKey = keyPair.getPublic();
                        byte[] encryptedBytes = RSAEncryption.encrypt(plaintext, publicKey);
                        writeFile(filePath, encryptedBytes);
                        System.out.println("RSA Encrypted and replaced file: " + filePath);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                } else {
                    System.err.println("Invalid encryption algorithm selected.");
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedAlgorithm = (String) encryptionAlgorithmComboBox.getSelectedItem();
                String filePath = selectedFileLabel.getText();

                try {
                    byte[] encryptedBytes = AESDecryption.readFile(filePath);
                    String key = decryptionKeyTextField.getText();
                    String decryptedText;

                    if (selectedAlgorithm.equals("AES")) {
                        decryptedText = AESDecryption.decrypt(encryptedBytes, key);
                    } else if (selectedAlgorithm.equals("RSA")) {
                        String privateKeyStr = ""; // Load RSA private key from somewhere
                        PrivateKey privateKey = RSADecryption.decodePrivateKey(privateKeyStr);
                        decryptedText = RSADecryption.decrypt(encryptedBytes, privateKey);
                    } else {
                        throw new IllegalArgumentException("Invalid encryption algorithm selected.");
                    }

                    JTextArea decryptedTextArea = new JTextArea(10, 40);
                    decryptedTextArea.setText(decryptedText);
                    JOptionPane.showMessageDialog(EncryptionAppGUI.this, new JScrollPane(decryptedTextArea),
                            "Decrypted Text", JOptionPane.PLAIN_MESSAGE);
                } catch (Exception ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(EncryptionAppGUI.this, "Error decrypting file: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        selectFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int result = fileChooser.showOpenDialog(EncryptionAppGUI.this);
                if (result == JFileChooser.APPROVE_OPTION) {
                    String selectedFilePath = fileChooser.getSelectedFile().getAbsolutePath();
                    selectedFileLabel.setText(selectedFilePath);
                }
            }
        });
    }

    private void addComponents() {
        JPanel mainPanel = new JPanel(new GridLayout(8, 1));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel encryptionKeyPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        encryptionKeyPanel.add(new JLabel("Enter Encryption Key: "));
        encryptionKeyPanel.add(encryptionKeyTextField);

        JPanel decryptionKeyPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        decryptionKeyPanel.add(new JLabel("Enter Decryption Key: "));
        decryptionKeyPanel.add(decryptionKeyTextField);

        JPanel filePanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        filePanel.add(selectFileButton);
        filePanel.add(selectedFileLabel);

        JPanel algorithmPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        algorithmPanel.add(new JLabel("Select Encryption Algorithm: "));
        algorithmPanel.add(encryptionAlgorithmComboBox);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        mainPanel.add(encryptionKeyPanel);
        mainPanel.add(decryptionKeyPanel);
        mainPanel.add(filePanel);
        mainPanel.add(algorithmPanel);
        mainPanel.add(buttonPanel);

        getContentPane().add(mainPanel);
    }

    private String readFile(String filePath) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }

    private void writeFile(String filePath, byte[] encryptedBytes) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(encryptedBytes);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new EncryptionAppGUI());
    }
}
