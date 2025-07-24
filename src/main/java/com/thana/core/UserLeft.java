package com.thana.core;

import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserLeft implements Serializable {

  private static final long serialVersionUID = 1L;
  private final String clientName;
}
