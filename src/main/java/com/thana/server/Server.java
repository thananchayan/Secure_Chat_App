package com.thana.server;

import com.thana.core.AuthRequest;
import com.thana.core.Message;
import com.thana.core.PublicKeyUpdate;
import com.thana.core.UserLeft;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import lombok.Setter;

public class Server {

  private static final Map<String, ClientHandler> clients = new ConcurrentHashMap<>();
  private static final Map<String, PublicKey> publicKeys = new ConcurrentHashMap<>();

  @Setter
  private static ServerLogger logger;

  public static Set<String> getConnectedUsernames() {
    return new HashSet<>(clients.keySet());
  }

  public static void main(String[] args) {
    new Thread(() -> {
      try {
        ServerSocket serverSocket = new ServerSocket(1257);
        log("[✔] Secure Chat Server started on port 1257...");

        while (true) {
          Socket clientSocket = serverSocket.accept();
          log("[+] New client connected: " + clientSocket.getInetAddress());
          new Thread(new ClientHandler(clientSocket)).start();
        }
      } catch (IOException e) {
        log("[X] Server error: " + e.getMessage());
      }
    }).start();
  }

  private static void log(String msg) {
    if (logger != null) {
      logger.log(msg);
    } else {
      System.out.println(msg);
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
        log("[X] Failed to send message to " + clientName);
      }
    }

    public void sendUserLeftNotification(String leftClient) {
      try {
        out.writeObject(new UserLeft(leftClient));
        out.flush();
      } catch (IOException e) {
        log("[X] Failed to notify user left: " + clientName);
      }
    }

    @Override
    public void run() {
      try {
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());

        // Step 1: Authenticate the client
        AuthRequest auth = (AuthRequest) in.readObject();
        String username = auth.getUsername();
        String password = auth.getPassword();

        boolean success = switch (auth.getType()) {
          case LOGIN -> UserStore.login(username, password);
          case SIGNUP -> UserStore.register(username, password);
        };

        if (!success) {
          out.writeObject("AUTH_FAILED");
          socket.close();
          return;
        }

        out.writeObject("AUTH_SUCCESS");

        // Step 2: Proceed with key exchange
        clientName = (String) in.readObject();
        publicKey = (PublicKey) in.readObject();

        clients.put(clientName, this);
        publicKeys.put(clientName, publicKey);

        log("[↑] " + clientName + " joined the chat.");
        if (logger != null) {
          logger.updateUserList();
        }

        for (ClientHandler handler : clients.values()) {
          if (!handler.clientName.equals(clientName)) {
            handler.out.writeObject(new PublicKeyUpdate(clientName, publicKey));
            handler.out.flush();

            out.writeObject(new PublicKeyUpdate(handler.clientName, handler.publicKey));
            out.flush();
          }
        }

        while (true) {
          Message message = (Message) in.readObject();
          ClientHandler recipient = clients.get(message.getRecipient());
          if (recipient != null) {
            recipient.sendMessage(message);
          } else {
            log("[!] Recipient not found: " + message.getRecipient());
          }
        }

      } catch (Exception e) {
        log("[X] Client " + clientName + " disconnected.");
      } finally {
        try {
          if (clientName != null) {
            clients.remove(clientName);
            publicKeys.remove(clientName);
            log("[-] " + clientName + " left the chat.");
            if (logger != null) {
              logger.updateUserList();
            }

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
