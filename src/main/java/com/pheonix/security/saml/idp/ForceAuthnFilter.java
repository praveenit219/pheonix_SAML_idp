package com.pheonix.security.saml.idp;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class ForceAuthnFilter extends OncePerRequestFilter {

  private SAMLMessageHandler samlMessageHandler;

  public ForceAuthnFilter(SAMLMessageHandler samlMessageHandler) {
    this.samlMessageHandler = samlMessageHandler;
  }
  
 
  public  void getHeadersInfo(HttpServletRequest request) {

		
      Map<String, String> map = new HashMap<String, String>();
      Enumeration headerNames = request.getHeaderNames();
      while (headerNames.hasMoreElements()) {
          String key = (String) headerNames.nextElement();
          String value = request.getHeader(key);
          map.put(key, value);
          //logger.debug(key, value);
          System.out.println(  key+" "+value);
      }

   
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
    String servletPath = request.getServletPath();
    getHeadersInfo(request);
    System.out.println("inside forceidp filter----"+servletPath);
    /*if (servletPath == null || !servletPath.endsWith("SingleSignOnService") || request.getMethod().equalsIgnoreCase("GET")) {
      chain.doFilter(request, response);
      return;
    }*/
    
    if (servletPath == null || !servletPath.endsWith("SingleSignOnService") || request.getMethod().equalsIgnoreCase("GET")) {
        chain.doFilter(request, response);
        return;
      }
    
    SAMLMessageContext messageContext;
    try {
      messageContext = samlMessageHandler.extractSAMLMessageContext(request, response, request.getMethod().equalsIgnoreCase("POST"), true);
  	samlMessageHandler.buildAndResolveArtifactResponseFromFilter(request,messageContext,response);
    } catch (Exception e) {
      throw new IllegalArgumentException(e);
    }
    AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();
    if (authnRequest.isForceAuthn()) {
      SecurityContextHolder.getContext().setAuthentication(null);
    }
    chain.doFilter(request, response);
  }
}
