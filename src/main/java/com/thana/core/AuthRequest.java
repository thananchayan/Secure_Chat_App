package com.thana.core;

import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AuthRequest implements Serializable {

  public enum Type {LOGIN, SIGNUP}

  private final String username;
  private final String password;
  private final Type type;

}
