package com.pheonix.security.saml.api;

import java.io.Serializable;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class User implements Serializable {

  private String name;
  private String password;
  private List<String> authorities;
}
