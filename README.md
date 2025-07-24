# 🔐 Secure Encrypted Chat Application (Java + Swing)

This is a **secure multi-client chat system** built using Java and Swing, implementing **hybrid encryption (AES + RSA)**, **digital signatures**, **mutual authentication**, and **replay attack prevention**. It includes both **client and server GUIs** and is suitable for academic and learning purposes in secure communication.

---

## 🧩 Features

- 🔐 **Only authenticated users** can access the chat
- ✉️ **AES-128 (CBC mode)** for message encryption
- 🔑 **RSA 2048-bit** used for key exchange and digital signatures
- ✅ **Digital signature verification** for authenticity
- 🔁 **Replay attack prevention** using UUID nonces
- 🧑‍🤝‍🧑 Dynamic user list with key sharing
- 📋 Server shows logs and connected users in real time
- 🧹 Users removed automatically on disconnect
- 🖥️ GUI for both **Server** and **Client**
- 🧱 Login/Signup authentication with in-memory credential store

---

## 📁 Project Structure

```bash
secure-chat-app/
├── client/
│   └── SecureChatClientGUI.java       # Swing-based chat client
│
├── core/
│   ├── AuthRequest.java               # Used for login/signup requests
│   ├── CryptoUtils.java               # AES/RSA encryption, signature logic
│   ├── Message.java                   # Encrypted message format with nonce
│   ├── PublicKeyUpdate.java           # Used to broadcast new user's public key
│   └── UserLeft.java                  # Used to notify client of disconnecting users
│
└── server/
    ├── Server.java                    # Multi-client server logic
    ├── ServerGUI.java                 # Swing GUI for server logs/user list
    ├── ServerLogger.java              # Logging interface
    └── UserStore.java                 # In-memory user store for login/signup
