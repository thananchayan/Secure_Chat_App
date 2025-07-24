# 🔐 Secure Encrypted Chat Application (Java + Swing)

This is a **secure multi-client chat system** built using Java and Swing, implementing **hybrid encryption (AES + RSA)**, **digital signatures**, **mutual authentication**, and **replay attack prevention**. It includes both **client and server GUIs** and is suitable for academic and learning purposes in secure communication.

---

## 🧩 Features

- 🔐 **Only authenticated users** can access the chat
- ✉️ **AES-128 CBC** mode encryption for messages
- 🔑 **RSA 2048-bit** for key exchange and digital signatures
- ✅ **Digital signature verification** for message authenticity
- 🔄 **Replay attack prevention** using **UUID nonce**
- 🧑‍🤝‍🧑 Dynamic user list and public key distribution
- 📋 Server maintains **logs** and shows connected users
- 🧹 Users automatically removed on disconnect
- 🖥️ **Swing GUI** for both **Server** and **Clients**
- 🧱 Supports **login/signup** (authentication service)

---

## 🧱 Project Structure

```bash
secure-chat-app/
├── core/
│   ├── CryptoUtils.java         # AES/RSA encryption, signature logic
│   ├── Message.java             # Serializable encrypted message with nonce
│   ├── PublicKeyUpdate.java     # Shared object to update public keys
│   ├── UserLeft.java            # Notification when a user disconnects
│   └── ServerLogger.java        # Interface for server logging
│
├── server/
│   ├── Server.java              # Core server logic and client threads
│   └── ServerGUI.java           # Swing GUI to monitor server logs and users
│
├── client/
│   └── SecureChatClientGUI.java # Full-featured Swing-based chat client
