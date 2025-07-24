package com.thana.client;

import com.thana.core.AuthRequest;
import com.thana.core.CryptoUtils;
import com.thana.core.Message;
import com.thana.core.PublicKeyUpdate;
import com.thana.core.UserLeft;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

public class SecureChatClientGUI extends JFrame {

  private JTextArea chatArea;
  private JTextField messageField;
  private JComboBox<String> userList;
  private JButton sendButton;

  private ObjectOutputStream out;
  private ObjectInputStream in;

  private String myName;
  private PrivateKey myPrivateKey;
  private PublicKey myPublicKey;

  private final Map<String, PublicKey> clientPublicKeys = new ConcurrentHashMap<>();
  private final Set<String> seenNonces = Collections.synchronizedSet(new HashSet<>());

  public SecureChatClientGUI() {
    setupLogin();
  }

  private void setupLogin() {
    String[] options = {"Login", "Signup"};
    int action = JOptionPane.showOptionDialog(null, "Select an option:", "Authentication",
        JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0]);

    if (action == -1) {
      System.exit(0); // Cancel
    }

    JPanel panel = new JPanel(new BorderLayout(5, 5));
    JPanel labels = new JPanel(new GridLayout(0, 1));
    labels.add(new JLabel("Username:"));
    labels.add(new JLabel("Password:"));
    panel.add(labels, BorderLayout.WEST);

    JPanel controls = new JPanel(new GridLayout(0, 1));
    JTextField usernameField = new JTextField();
    JPasswordField passwordField = new JPasswordField();
    controls.add(usernameField);
    controls.add(passwordField);
    panel.add(controls, BorderLayout.CENTER);

    int result = JOptionPane.showConfirmDialog(null, panel,
        options[action], JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

    if (result != JOptionPane.OK_OPTION) {
      System.exit(0);
    }

    String username = usernameField.getText().trim();
    String password = new String(passwordField.getPassword()).trim();

    if (username.isEmpty() || password.isEmpty()) {
      showError("Username and password cannot be empty.");
      System.exit(0);
    }

    setupSocket(username, password, options[action].equals("Login")
        ? AuthRequest.Type.LOGIN : AuthRequest.Type.SIGNUP);
  }

  private void setupSocket(String username, String password, AuthRequest.Type type) {
    try {
      Socket socket = new Socket("localhost", 1257);
      out = new ObjectOutputStream(socket.getOutputStream());
      in = new ObjectInputStream(socket.getInputStream());

      // Send authentication request
      out.writeObject(new AuthRequest(username, password, type));
      out.flush();

      // Read server response
      String response = (String) in.readObject();
      if (!response.equals("AUTH_SUCCESS")) {
        showError("Authentication failed: " + response);
        System.exit(0);
      }

      this.myName = username;

      // Generate RSA keys after authentication
      KeyPair myKeys = CryptoUtils.generateRSAKeyPair();
      myPrivateKey = myKeys.getPrivate();
      myPublicKey = myKeys.getPublic();

      // Send keys
      out.writeObject(myName);
      out.writeObject(myPublicKey);
      out.flush();

      setupGUI();
      listenForMessages();

    } catch (Exception e) {
      showError("Connection error: " + e.getMessage());
      System.exit(1);
    }
  }

  private void setupGUI() {
    setTitle("🔐 Secure Chat - " + myName);
    setSize(600, 500);
    setDefaultCloseOperation(EXIT_ON_CLOSE);
    setLayout(new BorderLayout());

    chatArea = new JTextArea();
    chatArea.setEditable(false);
    JScrollPane scroll = new JScrollPane(chatArea);

    messageField = new JTextField();
    sendButton = new JButton("Send");
    userList = new JComboBox<>();
    JPanel bottomPanel = new JPanel(new BorderLayout());
    bottomPanel.add(userList, BorderLayout.WEST);
    bottomPanel.add(messageField, BorderLayout.CENTER);
    bottomPanel.add(sendButton, BorderLayout.EAST);

    add(scroll, BorderLayout.CENTER);
    add(bottomPanel, BorderLayout.SOUTH);

    sendButton.addActionListener(e -> sendMessage());
    messageField.addActionListener(e -> sendMessage());

    setVisible(true);
  }

  private void listenForMessages() {
    new Thread(() -> {
      try {
        while (true) {
          Object obj = in.readObject();

          if (obj instanceof PublicKeyUpdate update) {
            clientPublicKeys.put(update.getClientName(), update.getPublicKey());
            if (!update.getClientName().equals(myName)) {
              SwingUtilities.invokeLater(() -> {
                if (((DefaultComboBoxModel<String>) userList.getModel()).getIndexOf(
                    update.getClientName()) == -1) {
                  userList.addItem(update.getClientName());
                }
              });
            }
            continue;
          }

          if (obj instanceof Message msg) {
            byte[] aesKeyBytes = CryptoUtils.rsaDecrypt(msg.getEncryptedAesKey(), myPrivateKey);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            byte[] decrypted = CryptoUtils.aesDecrypt(msg.getEncryptedMessage(), aesKey);
            String combined = new String(decrypted);

            String[] split1 = combined.split("::NONCE::");
            if (split1.length != 2) {
              continue;
            }
            String msgText = split1[0];

            String[] split2 = split1[1].split("::SIGN::");
            if (split2.length != 2) {
              continue;
            }
            String nonce = split2[0];
            byte[] sig = Base64.getDecoder().decode(split2[1]);

            if (seenNonces.contains(nonce)) {
              appendText("[⚠️] Replay attack detected! Message discarded.\n");
              continue;
            }
            seenNonces.add(nonce);

            PublicKey senderKey = clientPublicKeys.get(msg.getSender());
            if (senderKey == null) {
              continue;
            }

            boolean valid = CryptoUtils.verifySignature(msgText, sig, senderKey);
            appendText("[📨] " + msg.getSender() + ": " + msgText + (valid ? " ✅" : " ❌") + "\n");
          }
          if (obj instanceof UserLeft left) {
            String user = left.getClientName();
            clientPublicKeys.remove(user);

            SwingUtilities.invokeLater(() -> {
              userList.removeItem(user);
              appendText("[👋] " + user + " has left the chat.\n");
            });
            continue;
          }

        }
      } catch (Exception e) {
        appendText("[X] Disconnected from server.\n");
      }
    }).start();
  }

  private void sendMessage() {
    String msg = messageField.getText().trim();
    String recipient = (String) userList.getSelectedItem();

    if (msg.isEmpty() || recipient == null) {
      return;
    }

    try {
      PublicKey recipientKey = clientPublicKeys.get(recipient);
      if (recipientKey == null) {
        appendText("[!] No public key for " + recipient + "\n");
        return;
      }

      String nonce = UUID.randomUUID().toString();
      byte[] signature = CryptoUtils.signMessage(msg, myPrivateKey);
      String combined =
          msg + "::NONCE::" + nonce + "::SIGN::" + Base64.getEncoder().encodeToString(signature);
      byte[] combinedBytes = combined.getBytes();

      SecretKey aesKey = CryptoUtils.generateAESKey();
      byte[] encMsg = CryptoUtils.aesEncrypt(combinedBytes, aesKey);
      byte[] encKey = CryptoUtils.rsaEncrypt(aesKey.getEncoded(), recipientKey);

      Message message = new Message(myName, recipient, encMsg, encKey, nonce);
      out.writeObject(message);
      out.flush();

      appendText("[You → " + recipient + "]: " + msg + "\n");
      messageField.setText("");
    } catch (Exception e) {
      appendText("[X] Failed to send message.\n");
    }
  }

  private void appendText(String text) {
    SwingUtilities.invokeLater(() -> chatArea.append(text));
  }

  private void showError(String msg) {
    JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
  }

  public static void main(String[] args) {
    SwingUtilities.invokeLater(SecureChatClientGUI::new);
  }
}
