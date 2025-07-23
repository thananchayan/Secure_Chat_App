package com.thana;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Server {

  // Store client name → ClientHandler
  private static final Map<String, ClientHandler> clients = new ConcurrentHashMap<>();
  private static final Map<String, PublicKey> publicKeys = new ConcurrentHashMap<>();

  public static void main(String[] args) throws IOException {
    ServerSocket serverSocket = new ServerSocket(1257);
    System.out.println("[✔] Secure Chat Server started on port 1257...");

    while (true) {
      Socket clientSocket = serverSocket.accept();
      System.out.println("[+] New client connected: " + clientSocket.getInetAddress());

      // Handle client in a new thread
      new Thread(new ClientHandler(clientSocket)).start();
    }
  }

  static class ClientHandler implements Runnable {

    private final Socket socket;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private String clientName;
    private PublicKey publicKey;

    public ClientHandler(Socket socket) {
      this.socket = socket;
    }

    public void sendMessage(Message msg) {
      try {
        out.writeObject(msg);
        out.flush();
      } catch (IOException e) {
        System.out.println("[X] Failed to send message to " + clientName);
      }
    }

    public void sendUserLeftNotification(String leftClient) {
      try {
        out.writeObject(new UserLeft(leftClient));
        out.flush();
      } catch (IOException e) {
        System.out.println("[X] Failed to send UserLeft notification to " + clientName);
      }
    }

    @Override
    public void run() {
      try {
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());

        // Receive name and public key
        clientName = (String) in.readObject();
        publicKey = (PublicKey) in.readObject();

        clients.put(clientName, this);
        publicKeys.put(clientName, publicKey);
        System.out.println("[↑] " + clientName + " joined the chat.");

        // Notify existing clients about this one
        for (ClientHandler handler : clients.values()) {
          if (!handler.clientName.equals(clientName)) {
            handler.out.writeObject(new PublicKeyUpdate(clientName, publicKey));
            handler.out.flush();

            // Send existing keys to this client
            out.writeObject(new PublicKeyUpdate(handler.clientName, handler.publicKey));
            out.flush();
          }
        }

        // Handle messages from client
        while (true) {
          Message message = (Message) in.readObject();
          String recipient = message.getRecipient();

          ClientHandler targetClient = clients.get(recipient);
          if (targetClient != null) {
            targetClient.sendMessage(message);
          } else {
            System.out.println("[!] Recipient " + recipient + " not found.");
          }
        }

      } catch (Exception e) {
        System.out.println("[X] Client " + clientName + " disconnected.");
      } finally {
        try {
          if (clientName != null) {
            clients.remove(clientName);
            publicKeys.remove(clientName);
            System.out.println("[-] " + clientName + " left the chat.");

            // Notify all remaining clients
            for (ClientHandler handler : clients.values()) {
              handler.sendUserLeftNotification(clientName);
            }
          }
          socket.close();
        } catch (IOException ignored) {
        }
      }
    }
  }
}
