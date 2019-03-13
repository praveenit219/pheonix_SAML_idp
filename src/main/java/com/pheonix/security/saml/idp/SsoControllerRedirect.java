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
import org.opensaml.common.binding.artifact.BasicSAMLArtifactMap;
import org.opensaml.common.binding.artifact.BasicSAMLArtifactMapEntryFactory;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004Builder;
import org.opensaml.saml2.binding.encoding.HTTPArtifactEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.StorageService;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import com.pheonix.security.saml.SAMLAttribute;
import com.pheonix.security.saml.SAMLPrincipal;
import com.pheonix.security.saml.api.IdpConfiguration;

@Controller
public class SsoControllerRedirect {

	@Autowired
	private SAMLMessageHandler samlMessageHandler;

	@Autowired
	private IdpConfiguration idpConfiguration;

	@GetMapping("/SingleSignOnServiceRedirect/alias/pheonix/idp")
	public void singleSignOnServiceGet(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
		 System.out.println("/SingleSignOnServiceRedirect/alias/pheonix/idp get--------------");
		doSSOForArtifactResolveRequest(request, response, authentication, false,false);
		
		//response.sendRedirect(SPConstants.ASSERTION_CONSUMER_SERVICE + "?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D");
	}

	@PostMapping("/SingleSignOnServiceRedirect/alias/pheonix/idp")
	public void singleSignOnServicePost(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
		//doSSO(request, response, authentication, true);
		 System.out.println("/SingleSignOnServiceRedirect/alias/pheonix/idp post--------------");
		doSSOForArtifactResolveRequest(request, response, authentication, true, false);
		
	}

	@SuppressWarnings("unchecked")
	private void doSSOForArtifactResolveRequest(HttpServletRequest request, HttpServletResponse response, Authentication authentication, 
			boolean postRequest, boolean soapRequest) throws ValidationException, SecurityException, MessageDecodingException, MarshallingException, SignatureException, MessageEncodingException, MetadataProviderException, IOException, ServletException {
		SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(request, response, postRequest, soapRequest);
		AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

		String assertionConsumerServiceURL = idpConfiguration.getAcsEndpoint() != null ? idpConfiguration.getAcsEndpoint() : authnRequest.getAssertionConsumerServiceURL();
		List<SAMLAttribute> attributes = attributes(authentication);

		SAMLPrincipal principal = new SAMLPrincipal(
				authentication.getName(),
				attributes.stream().filter(attr -> "urn:oasis:names:tc:SAML:1.1:nameid-format".equals(attr.getName()))
				.findFirst().map(attr -> attr.getValue()).orElse(NameIDType.UNSPECIFIED),
				attributes,
				authnRequest.getIssuer().getValue(),
				authnRequest.getID(),
				assertionConsumerServiceURL,
				messageContext.getRelayState());

		/*	SAML2ArtifactType0004 sam2artifact = new SAML2ArtifactType0004Builder().buildArtifact(messageContext);

		String SamlArtifact = sam2artifact.base64Encode();
		System.out.println("SamlArtifact"+SamlArtifact);

		long lifetime = 120000;
		SAMLArtifactMapEntry obj = new BasicSAMLArtifactMapEntryFactory().newEntry(SamlArtifact, authnRequest.getIssuer().getValue(), idpConfiguration.getEntityId(), authnRequest, lifetime);

		final StorageService<String, SAMLArtifactMapEntry> storageEngine = new MapBasedStorageService<String, SAMLArtifactMapEntry>();
		storageEngine.put("artifact", authnRequest.getID(), obj);

		SAMLArtifactMap sam=  new BasicSAMLArtifactMap(storageEngine, lifetime);

		HTTPArtifactEncoder encoder = new HTTPArtifactEncoder(VelocityFactory.getEngine(), "/templates/saml2-post-artifact-binding.vm",sam);

		

		encoder.getBindingURI();
		encoder.encode(messageContext);*/

		samlMessageHandler.sendAuthnResponse(principal, response,messageContext);
	}

	@SuppressWarnings("unchecked")
	private List<SAMLAttribute> attributes(Authentication authentication) {
		String uid = authentication.getName();
		Map<String, List<String>> result = new HashMap<>(idpConfiguration.getAttributes());


		Optional<Map<String, List<String>>> optionalMap = idpConfiguration.getUsers().stream().filter(user -> user
				.getPrincipal()
				.equals(uid)).findAny().map(FederatedUserAuthenticationToken::getAttributes);
		optionalMap.ifPresent(result::putAll);

		//See SAMLAttributeAuthenticationFilter#setDetails
		Map<String, String[]> parameterMap = (Map<String, String[]>) authentication.getDetails();
		parameterMap.forEach((key, values) -> {
			result.put(key, Arrays.asList(values));
		});

		//Provide the ability to limit the list attributes returned to the SP
		return result.entrySet().stream()
				.filter(entry -> !entry.getValue().stream().allMatch(StringUtils::isEmpty))
				.map(entry -> entry.getKey().equals("urn:mace:dir:attribute-def:uid") ?
						new SAMLAttribute(entry.getKey(), singletonList(uid)) :
							new SAMLAttribute(entry.getKey(), entry.getValue()))
				.collect(toList());
	}

}
