package com.thana.server;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.util.Set;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public class ServerGUI extends JFrame implements ServerLogger {

  private final JTextPane logPane;
  private final StyledDocument logDoc;
  private final DefaultListModel<String> userListModel;
  private final JLabel userCountLabel;

  public ServerGUI() {
    setTitle("\uD83D\uDD12 Secure Chat Server Monitor");
    setSize(700, 500);
    setDefaultCloseOperation(EXIT_ON_CLOSE);
    setLayout(new BorderLayout());

    // Log area (Styled for colored logs)
    logPane = new JTextPane();
    logPane.setEditable(false);
    logDoc = logPane.getStyledDocument();
    JScrollPane scrollPane = new JScrollPane(logPane);

    // Define styles
    Style def = logPane.addStyle("default", null);
    Style info = logPane.addStyle("info", def);
    StyleConstants.setForeground(info, Color.BLUE);
    Style error = logPane.addStyle("error", def);
    StyleConstants.setForeground(error, Color.RED);
    Style success = logPane.addStyle("success", def);
    StyleConstants.setForeground(success, new Color(0, 128, 0));

    // Connected user list
    userListModel = new DefaultListModel<>();
    JList<String> userList = new JList<>(userListModel);
    JScrollPane userScroll = new JScrollPane(userList);
    userScroll.setPreferredSize(new Dimension(150, 0));

    // User count label
    userCountLabel = new JLabel("Connected Users: 0");
    add(userCountLabel, BorderLayout.NORTH);

    // Control panel with buttons
    JPanel controlPanel = new JPanel();
    JButton shutdownButton = new JButton("Shutdown Server");
    JButton restartButton = new JButton("Restart Server");
    restartButton.setEnabled(false); // Restart disabled for now

    controlPanel.add(shutdownButton);
//    controlPanel.add(restartButton);

    // Add components to layout
    add(scrollPane, BorderLayout.CENTER);
    add(userScroll, BorderLayout.EAST);
    add(controlPanel, BorderLayout.SOUTH);

    // Button listeners
    shutdownButton.addActionListener(e -> {
      int choice = JOptionPane.showConfirmDialog(this, "Are you sure you want to stop the server?",
          "Shutdown Server", JOptionPane.YES_NO_OPTION);
      if (choice == JOptionPane.YES_OPTION) {
        System.exit(0);
      }
    });

    // Register this GUI as the logger
    Server.setLogger(this);
    setVisible(true);
  }

  @Override
  public void log(String message) {
    SwingUtilities.invokeLater(() -> {
      Style style = logPane.getStyle("info");
      if (message.contains("[X]")) {
        style = logPane.getStyle("error");
      } else if (message.contains("[✔]") || message.contains("[+]") || message.contains("[-]")) {
        style = logPane.getStyle("success");
      }

      try {
        logDoc.insertString(logDoc.getLength(), message + "\n", style);
      } catch (BadLocationException ignored) {
      }
    });
  }

  @Override
  public void updateUserList() {
    SwingUtilities.invokeLater(() -> {
      userListModel.clear();
      Set<String> users = Server.getConnectedUsernames();
      for (String user : users) {
        userListModel.addElement(user);
      }
      userCountLabel.setText("Connected Users: " + users.size());
    });
  }

  public static void main(String[] args) {
    SwingUtilities.invokeLater(ServerGUI::new);
    Server.main(null);
  }
}
