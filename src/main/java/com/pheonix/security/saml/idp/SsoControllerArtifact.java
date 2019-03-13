package com.pheonix.security.saml.idp;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.impl.ArtifactResolveImpl;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import com.pheonix.security.saml.SAMLAttribute;
import com.pheonix.security.saml.SAMLPrincipal;
import com.pheonix.security.saml.api.IdpConfiguration;

@Controller
public class SsoControllerArtifact {

	@Autowired
	private SAMLMessageHandler samlMessageHandler;

	@Autowired
	private IdpConfiguration idpConfiguration;


	@GetMapping(path = "/SingleSignOnServicePost/alias/pheonix/artifactResolver", consumes = {"text/xml", "application/xml"})
	public void singleSignOnServiceGet(HttpServletRequest request, HttpServletResponse response,Authentication authentication)
			throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
		System.out.println("/idp/artifactResolver get--------------");
		doArtifactResolve(request, response,authentication,false,true);
	}


	/*@GetMapping("/idp/artifactResolver")
	public void singleSignOnServiceGet(HttpServletRequest request, HttpServletResponse response, Authentication  authentication)
			throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
		 System.out.println("/idp/artifactResolver get--------------");
		doArtifactResolve(request, response, authentication, false);
	}*/

	@PostMapping(path = "/SingleSignOnServicePost/alias/pheonix/artifactResolver", consumes = {"text/xml", "application/xml"})
	public void singleSignOnServicePost(HttpServletRequest request, HttpServletResponse response,Authentication authentication)
			throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
		System.out.println("/idp/artifactResolver post--------------");
		if(null!=authentication) {
			doArtifactResolve(request, response,authentication,true,true);
		} else {
			SecurityContext context = SecurityContextHolder.getContext();
			Authentication auth = context.getAuthentication();

			if(null!=auth) {
				doArtifactResolve(request, response,auth,true,true);
			} else {
				doArtifactResolve(request, response,null,true,true);
			}
		}

	}

	/*@PostMapping("/idp/artifactResolver")
	public void singleSignOnServicePost(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
		System.out.println("/idp/artifactResolver post--------------");
		doArtifactResolve(request, response, authentication, true);
	}*/



	@SuppressWarnings("unchecked")
	private void doArtifactResolve(HttpServletRequest request, HttpServletResponse response, Authentication authentication, 
			boolean postRequest,boolean soapRequest) throws ValidationException, SecurityException, MessageDecodingException, MarshallingException, SignatureException, MessageEncodingException, MetadataProviderException, IOException, ServletException {


		SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContextSoap(request, response, postRequest,soapRequest);		
		ArtifactResolveImpl artifactResolve = (ArtifactResolveImpl) messageContext.getInboundSAMLMessage();
		//String assertionConsumerServiceURL = idpConfiguration.getAcsEndpoint() != null ? idpConfiguration.getAcsEndpoint() : artifactResolve.getDestination();
		String assertionConsumerServiceURL = "http://localhost:9090/sp/consumer";
		List<SAMLAttribute> attributes = attributes(authentication);
		SAMLPrincipal principal = new SAMLPrincipal(
				authentication.getName(),
				attributes.stream().filter(attr -> "urn:oasis:names:tc:SAML:1.1:nameid-format".equals(attr.getName()))
				.findFirst().map(attr -> attr.getValue()).orElse(NameIDType.UNSPECIFIED),
				attributes,
				artifactResolve.getIssuer().getValue(),
				artifactResolve.getID(),
				assertionConsumerServiceURL,
				messageContext.getRelayState());

		samlMessageHandler.buildAndResolveArtifactResponse(principal,messageContext,response);
	}


	@SuppressWarnings("unchecked")
	private List<SAMLAttribute> attributes(Authentication authentication) {
		String uid = authentication.getName();
		Map<String, List<String>> result = new HashMap<>(idpConfiguration.getAttributes());


		
		//Provide the ability to limit the list attributes returned to the SP
		return result.entrySet().stream()				
				.map(entry -> 
							new SAMLAttribute(entry.getKey(), entry.getValue()))
				.collect(toList());
	}

}
