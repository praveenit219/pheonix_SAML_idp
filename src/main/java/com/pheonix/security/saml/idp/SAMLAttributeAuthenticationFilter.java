package com.pheonix.security.saml.idp;

import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class SAMLAttributeAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


  @Override
  protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
    Map<String, String[]> parameterMap = request.getParameterMap().entrySet().stream()
      .filter(e -> !getPasswordParameter().equals(e.getKey()) && !getUsernameParameter().equals(e.getKey()))
      .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    authRequest.setDetails(parameterMap);
  }
}
