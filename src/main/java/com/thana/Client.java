package com.thana;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client {

  private static PrivateKey myPrivateKey;
  private static PublicKey myPublicKey;
  private static final Map<String, PublicKey> clientPublicKeys = new HashMap<>();
  private static final Set<String> seenNonces = Collections.synchronizedSet(new HashSet<>());

  public static void main(String[] args) throws Exception {
    Scanner scanner = new Scanner(System.in);

    // Connect to server
    Socket socket = new Socket("localhost", 1257);
    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
    ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

    // Prompt for user name
    System.out.print("Enter your name: ");
    String myName = scanner.nextLine();

    // Generate RSA key pair
    KeyPair myKeys = CryptoUtils.generateRSAKeyPair();
    myPrivateKey = myKeys.getPrivate();
    myPublicKey = myKeys.getPublic();

    // Register with server
    out.writeObject(myName);
    out.writeObject(myPublicKey);
    out.flush();

    // Start a thread to listen for incoming messages
    Thread reader = new Thread(() -> {
      try {
        while (true) {
          Object obj = in.readObject();

          // Public key update
          if (obj instanceof PublicKeyUpdate) {
            PublicKeyUpdate update = (PublicKeyUpdate) obj;
            clientPublicKeys.put(update.getClientName(), update.getPublicKey());
            System.out.println("[🔑] Public key received for " + update.getClientName());
            continue;
          }

          // Encrypted message
          if (obj instanceof Message) {
            Message message = (Message) obj;

            // Decrypt AES key
            byte[] aesKeyBytes = CryptoUtils.rsaDecrypt(message.getEncryptedAesKey(), myPrivateKey);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // Decrypt message (includes IV)
            byte[] decrypted = CryptoUtils.aesDecrypt(message.getEncryptedMessage(), aesKey);
            String combined = new String(decrypted);

            // Extract message text, nonce, and signature
            String[] split1 = combined.split("::NONCE::");
            if (split1.length != 2) {
              System.out.println("[!] Invalid message format.");
              continue;
            }
            String msgText = split1[0];
            String[] split2 = split1[1].split("::SIGN::");
            if (split2.length != 2) {
              System.out.println("[!] Signature missing or malformed.");
              continue;
            }

            String nonce = split2[0];
            byte[] sig = Base64.getDecoder().decode(split2[1]);

            // Check for replay attack
            if (seenNonces.contains(nonce)) {
              System.out.println("[⚠️] Replay attack detected! Nonce reused: " + nonce);
              continue;
            }
            seenNonces.add(nonce);

            // Verify sender
            PublicKey senderKey = clientPublicKeys.get(message.getSender());
            if (senderKey == null) {
              System.out.println("[!] Unknown sender: " + message.getSender());
              continue;
            }

            boolean valid = CryptoUtils.verifySignature(msgText, sig, senderKey);
            System.out.println("\n[📨] From " + message.getSender() + ": " + msgText +
                (valid ? " ✅" : " ❌ Invalid Signature"));
          }
        }
      } catch (Exception e) {
        System.out.println("[X] Disconnected from server.");
      }
    });

    reader.start();

    // Chat input
    System.out.println("\n💬 You can now chat! Format: recipient::message");
    while (true) {
      String line = scanner.nextLine();
      if (!line.contains("::")) continue;

      String[] split = line.split("::", 2);
      String recipient = split[0];
      String msg = split[1];

      PublicKey recipientKey = clientPublicKeys.get(recipient);
      if (recipientKey == null) {
        System.out.println("[!] Unknown recipient (no public key): " + recipient);
        continue;
      }

      // Generate a nonce
      String nonce = UUID.randomUUID().toString();

      // Sign the message
      byte[] signature = CryptoUtils.signMessage(msg, myPrivateKey);
      String combined = msg + "::NONCE::" + nonce + "::SIGN::" + Base64.getEncoder().encodeToString(signature);
      byte[] combinedBytes = combined.getBytes();

      // Encrypt the message with AES (CBC + IV inside)
      SecretKey aesKey = CryptoUtils.generateAESKey();
      byte[] encMsg = CryptoUtils.aesEncrypt(combinedBytes, aesKey);

      // Encrypt the AES key with recipient’s public RSA key
      byte[] encKey = CryptoUtils.rsaEncrypt(aesKey.getEncoded(), recipientKey);

      // Create and send message
      Message message = new Message(myName, recipient, encMsg, encKey, nonce);
      out.writeObject(message);
      out.flush();
    }
  }
}
