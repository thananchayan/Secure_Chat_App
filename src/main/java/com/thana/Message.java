package com.thana;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.Serializable;

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
