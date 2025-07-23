package com.thana;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptoUtils {

  private static final String RSA_ALGORITHM = "RSA";
  private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
  private static final int AES_KEY_SIZE = 128; // bits
  private static final int IV_SIZE = 16;       // bytes for AES

  public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
    generator.initialize(2048);
    return generator.generateKeyPair();
  }

  public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(AES_KEY_SIZE);
    return generator.generateKey();
  }

  public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
    Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
    signature.initSign(privateKey);
    signature.update(message.getBytes());
    return signature.sign();
  }

  public static boolean verifySignature(String message, byte[] signature, PublicKey publicKey)
      throws Exception {
    Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
    verifier.initVerify(publicKey);
    verifier.update(message.getBytes());
    return verifier.verify(signature);
  }

  public static byte[] aesEncrypt(byte[] data, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

    // Generate a random IV
    byte[] ivBytes = new byte[IV_SIZE];
    SecureRandom random = new SecureRandom();
    random.nextBytes(ivBytes);
    IvParameterSpec iv = new IvParameterSpec(ivBytes);

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    byte[] encrypted = cipher.doFinal(data);

    // Prepend IV to the ciphertext
    byte[] encryptedWithIv = new byte[IV_SIZE + encrypted.length];
    System.arraycopy(ivBytes, 0, encryptedWithIv, 0, IV_SIZE);
    System.arraycopy(encrypted, 0, encryptedWithIv, IV_SIZE, encrypted.length);

    return encryptedWithIv;
  }

  public static byte[] aesDecrypt(byte[] encryptedWithIv, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

    // Extract IV
    byte[] ivBytes = Arrays.copyOfRange(encryptedWithIv, 0, IV_SIZE);
    IvParameterSpec iv = new IvParameterSpec(ivBytes);

    // Extract encrypted content
    byte[] encrypted = Arrays.copyOfRange(encryptedWithIv, IV_SIZE, encryptedWithIv.length);

    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    return cipher.doFinal(encrypted);
  }

  public static byte[] rsaEncrypt(byte[] data, PublicKey key) throws Exception {
    Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(data);
  }

  public static byte[] rsaDecrypt(byte[] encrypted, PrivateKey key) throws Exception {
    Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, key);
    return cipher.doFinal(encrypted);
  }
}
