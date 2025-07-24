package com.thana.core;

import java.io.Serializable;
import java.security.PublicKey;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class PublicKeyUpdate implements Serializable {

  private static final long serialVersionUID = 1L;

  private final String clientName;
  private final PublicKey publicKey;
}
