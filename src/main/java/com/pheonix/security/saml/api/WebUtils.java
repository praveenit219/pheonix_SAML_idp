package com.pheonix.security.saml.api;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.LoggerFactory;


public class WebUtils  {
	
	 org.slf4j.Logger logger = LoggerFactory.getLogger(WebUtils.class);
	
	
	public  void getHeadersInfo(HttpServletRequest request) {

		
        Map<String, String> map = new HashMap<String, String>();
		

        Enumeration headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            String value = request.getHeader(key);
            map.put(key, value);
            //logger.debug(key, value);
        }

        logger.debug(map.toString());
    }
}

