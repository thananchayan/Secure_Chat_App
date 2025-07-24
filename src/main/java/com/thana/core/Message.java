package com.thana.core;

import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class Message implements Serializable {

  private static final long serialVersionUID = 1L;

  private String sender;
  private String recipient;
  private byte[] encryptedMessage;
  private byte[] encryptedAesKey;
  private String nonce;
}
