package com.thana;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.Serializable;
import java.security.PublicKey;

@Getter
@AllArgsConstructor
public class PublicKeyUpdate implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String clientName;
    private final PublicKey publicKey;
}
