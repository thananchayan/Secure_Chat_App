package com.thana;

import java.io.IOException;
import javax.swing.*;
import java.awt.*;
import java.util.Set;

public class ServerGUI extends JFrame implements ServerLogger {

  private final JTextArea logArea;
  private final DefaultListModel<String> userListModel;

  public ServerGUI() {
    setTitle("🔒 Secure Chat Server Monitor");
    setSize(600, 400);
    setDefaultCloseOperation(EXIT_ON_CLOSE);
    setLayout(new BorderLayout());

    logArea = new JTextArea();
    logArea.setEditable(false);
    JScrollPane scrollPane = new JScrollPane(logArea);

    userListModel = new DefaultListModel<>();
    JList<String> userList = new JList<>(userListModel);
    JScrollPane userScroll = new JScrollPane(userList);
    userScroll.setPreferredSize(new Dimension(150, 0));

    add(scrollPane, BorderLayout.CENTER);
    add(userScroll, BorderLayout.EAST);

    Server.setLogger(this); // Register as logger
    setVisible(true);
  }

  @Override
  public void log(String message) {
    SwingUtilities.invokeLater(() -> logArea.append(message + "\n"));
  }

  @Override
  public void updateUserList() {
    SwingUtilities.invokeLater(() -> {
      userListModel.clear();
      Set<String> users = Server.getConnectedUsernames();
      for (String user : users) userListModel.addElement(user);
    });
  }

  public static void main(String[] args) throws IOException {
    SwingUtilities.invokeLater(ServerGUI::new);
    Server.main(null); // Start server thread
  }
}
