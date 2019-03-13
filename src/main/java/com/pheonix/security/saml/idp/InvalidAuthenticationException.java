package com.pheonix.security.saml.idp;

import org.springframework.security.core.AuthenticationException;

public class InvalidAuthenticationException extends AuthenticationException {

  public InvalidAuthenticationException(String msg) {
    super(msg);
  }
}
