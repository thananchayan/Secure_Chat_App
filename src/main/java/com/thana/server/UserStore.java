package com.thana.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class UserStore {

  private static final File FILE = new File("users.db");
  private static final Map<String, String> userMap = new HashMap<>();

  static {
    loadUsers();
  }

  public static boolean register(String username, String password) {
    if (userMap.containsKey(username)) {
      return false;
    }
    userMap.put(username, hash(password));
    saveUsers();
    return true;
  }

  public static boolean login(String username, String password) {
    return userMap.containsKey(username) &&
        userMap.get(username).equals(hash(password));
  }

  private static void loadUsers() {
    if (!FILE.exists()) {
      return;
    }
    try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(FILE))) {
      Object o = ois.readObject();
      if (o instanceof Map<?, ?> map) {
        for (Object k : map.keySet()) {
          if (k instanceof String key && map.get(k) instanceof String val) {
            userMap.put(key, val);
          }
        }
      }
    } catch (Exception ignored) {
    }
  }

  private static void saveUsers() {
    try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE))) {
      oos.writeObject(userMap);
    } catch (Exception ignored) {
    }
  }

  private static String hash(String password) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return Base64.getEncoder().encodeToString(digest.digest(password.getBytes()));
    } catch (Exception e) {
      return "";
    }
  }
}
