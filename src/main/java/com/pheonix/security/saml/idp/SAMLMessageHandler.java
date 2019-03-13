package com.pheonix.security.saml.idp;

import static com.pheonix.security.saml.SAMLBuilder.buildAssertion;
import static com.pheonix.security.saml.SAMLBuilder.buildIssuer;
import static com.pheonix.security.saml.SAMLBuilder.buildSAMLObject;
import static com.pheonix.security.saml.SAMLBuilder.buildStatus;
import static com.pheonix.security.saml.SAMLBuilder.signAssertion;
import static com.pheonix.security.saml.SAMLBuilder.encryptAssertion;


import static java.util.Arrays.asList;
import static org.opensaml.xml.Configuration.getValidatorSuite;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.artifact.BasicSAMLArtifactMap;
import org.opensaml.common.binding.artifact.BasicSAMLArtifactMapEntryFactory;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004Builder;
import org.opensaml.saml2.binding.encoding.HTTPArtifactEncoder;
import org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.EncryptedAssertionBuilder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.StorageService;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.util.VelocityFactory;

import com.pheonix.security.saml.ProxiedSAMLContextProviderLB;
import com.pheonix.security.saml.SAMLAttribute;
import com.pheonix.security.saml.SAMLBuilder;
import com.pheonix.security.saml.SAMLPrincipal;
import com.pheonix.security.saml.api.IdpConfiguration;



public class SAMLMessageHandler {

	private final KeyManager keyManager;
	private final Collection<SAMLMessageDecoder> decoders;
	private final SAMLMessageEncoder encoder;
	private final SecurityPolicyResolver resolver;
	private final IdpConfiguration idpConfiguration;

	private final List<ValidatorSuite> validatorSuites;
	private final ProxiedSAMLContextProviderLB proxiedSAMLContextProviderLB;
	private final StorageService<String, SAMLArtifactMapEntry> storageEngine;


	public SAMLMessageHandler(KeyManager keyManager, Collection<SAMLMessageDecoder> decoders,
			SAMLMessageEncoder encoder, SecurityPolicyResolver securityPolicyResolver,
			IdpConfiguration idpConfiguration, String idpBaseUrl,StorageService<String, SAMLArtifactMapEntry> storageEngine) throws URISyntaxException {
		this.keyManager = keyManager;
		this.encoder = encoder;
		this.decoders = decoders;
		this.resolver = securityPolicyResolver;
		this.idpConfiguration = idpConfiguration;
		this.validatorSuites = asList(
				getValidatorSuite("saml2-core-schema-validator"),
				getValidatorSuite("saml2-core-spec-validator"));
		this.proxiedSAMLContextProviderLB = new ProxiedSAMLContextProviderLB(new URI(idpBaseUrl));
		//this.proxiedSAMLContextProviderLB.setMetadata(metadata);
		this.storageEngine = storageEngine; 
	}

	@Value("${idp.base_url}") 
	String idpBaseUrl;

	@Autowired 
	private  CachingMetadataManager metadata;


	public SAMLMessageContext extractSAMLMessageContextSoap(HttpServletRequest request, HttpServletResponse response, boolean postRequest, boolean soapRequestURI) throws ValidationException, SecurityException, MessageDecodingException, MetadataProviderException {
		SAMLMessageContext messageContext = new SAMLMessageContext();


		proxiedSAMLContextProviderLB.setMetadata(metadata);
		proxiedSAMLContextProviderLB.setKeyManager(keyManager);
		proxiedSAMLContextProviderLB.setMetadataResolver(new org.springframework.security.saml.trust.MetadataCredentialResolver(metadata, keyManager));

		proxiedSAMLContextProviderLB.populateGenericContext(request, response, messageContext);

		messageContext = proxiedSAMLContextProviderLB.getLocalEntity(request, response);

		messageContext.setSecurityPolicyResolver(resolver);



		SAMLMessageDecoder samlMessageDecoder = samlMessageDecoder(postRequest,soapRequestURI);
		samlMessageDecoder.decode(messageContext);


		return messageContext;
	}

	public SAMLMessageContext extractSAMLMessageContext(HttpServletRequest request, HttpServletResponse response, boolean postRequest, boolean soapRequestURI) throws ValidationException, SecurityException, MessageDecodingException, MetadataProviderException {
		SAMLMessageContext messageContext = new SAMLMessageContext();

		proxiedSAMLContextProviderLB.setMetadata(metadata);
		proxiedSAMLContextProviderLB.setKeyManager(keyManager);
		proxiedSAMLContextProviderLB.setMetadataResolver(new org.springframework.security.saml.trust.MetadataCredentialResolver(metadata, keyManager));

		proxiedSAMLContextProviderLB.populateGenericContext(request, response, messageContext);

		messageContext = proxiedSAMLContextProviderLB.getLocalEntity(request, response);

		messageContext.setSecurityPolicyResolver(resolver);



		SAMLMessageDecoder samlMessageDecoder = samlMessageDecoder(postRequest, soapRequestURI);
		samlMessageDecoder.decode(messageContext);

		SAMLObject inboundSAMLMessage = messageContext.getInboundSAMLMessage();


		AuthnRequest authnRequest = (AuthnRequest) inboundSAMLMessage;
		//lambda is poor with Exceptions



		for (ValidatorSuite validatorSuite : validatorSuites) {
			validatorSuite.validate(authnRequest);
		}
		return messageContext;
	}

	private SAMLMessageDecoder samlMessageDecoder(boolean postRequest, boolean soapBindingURI) {


		return decoders.stream().filter(samlMessageDecoder -> (postRequest ) ? (soapBindingURI ? samlMessageDecoder.getBindingURI().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI) : 
			samlMessageDecoder.getBindingURI().equals(SAMLConstants.SAML2_POST_BINDING_URI) ) :
				samlMessageDecoder.getBindingURI().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI))
				.findAny()
				.orElseThrow(() -> new RuntimeException(String.format("Only %s and %s are supported",
						SAMLConstants.SAML2_REDIRECT_BINDING_URI,
						SAMLConstants.SAML2_POST_BINDING_URI)));
	}



	@SuppressWarnings("unchecked")
	public void sendAuthnResponse(SAMLPrincipal principal, HttpServletResponse response, org.opensaml.common.binding.SAMLMessageContext requesetMessageContext) throws MarshallingException, SignatureException, MessageEncodingException {
		Status status = buildStatus(StatusCode.SUCCESS_URI);

		String entityId = idpConfiguration.getEntityId();
		Credential signingCredential = resolveCredential(entityId);

		Response authResponse = buildSAMLObject(Response.class, Response.DEFAULT_ELEMENT_NAME);
		Issuer issuer = buildIssuer(entityId);

		authResponse.setIssuer(issuer);
		authResponse.setID(SAMLBuilder.randomSAMLId());
		authResponse.setIssueInstant(new DateTime());
		authResponse.setInResponseTo(principal.getRequestID());

		Assertion assertion = buildAssertion(principal, status, entityId);
		signAssertion(assertion, signingCredential);

		authResponse.getAssertions().add(assertion);
		authResponse.setDestination(principal.getAssertionConsumerServiceURL());

		authResponse.setStatus(status);

		Endpoint endpoint = buildSAMLObject(Endpoint.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
		endpoint.setLocation(principal.getAssertionConsumerServiceURL());

		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

		//BasicSAMLMessageContext messageContext = requesetMessageContext;

		requesetMessageContext.setOutboundMessageTransport(outTransport);
		requesetMessageContext.setPeerEntityEndpoint(endpoint);
		requesetMessageContext.setOutboundSAMLMessage(authResponse);
		requesetMessageContext.setOutboundSAMLMessageSigningCredential(signingCredential);

		requesetMessageContext.setOutboundMessageIssuer(entityId);
		requesetMessageContext.setRelayState(principal.getRelayState());

		//requesetMessageContext.setMetadataProvider(provider);

		long lifetime = 120000;

		SAML2ArtifactType0004 sam2artifact = new SAML2ArtifactType0004Builder().buildArtifact(requesetMessageContext);

		String SamlArtifact = sam2artifact.base64Encode();

		System.out.println("SamlArtifact"+SamlArtifact);

		SAMLArtifactMapEntry obj = new BasicSAMLArtifactMapEntryFactory().newEntry(SamlArtifact, authResponse.getIssuer().getValue(), idpConfiguration.getEntityId(), authResponse, lifetime);


		storageEngine.put("artifact_"+authResponse.getID(), authResponse.getID(), obj);

		System.out.println("authresponse for samlartifact------------"+authResponse.getID());


		SAMLArtifactMap sam=  new BasicSAMLArtifactMap(storageEngine, lifetime);

		HTTPArtifactEncoder encoder = new HTTPArtifactEncoder(VelocityFactory.getEngine(), "/templates/saml2-post-artifact-binding.vm",sam);


		encoder.getBindingURI();
		encoder.encode(requesetMessageContext);
	}


	@SuppressWarnings("unchecked")
	public void sendAuthnResponse(SAMLPrincipal principal, HttpServletResponse response) throws MarshallingException, SignatureException, MessageEncodingException {
		Status status = buildStatus(StatusCode.SUCCESS_URI);

		String entityId = idpConfiguration.getEntityId();
		Credential signingCredential = resolveCredential(entityId);

		Response authResponse = buildSAMLObject(Response.class, Response.DEFAULT_ELEMENT_NAME);
		Issuer issuer = buildIssuer(entityId);

		authResponse.setIssuer(issuer);
		authResponse.setID(SAMLBuilder.randomSAMLId());
		authResponse.setIssueInstant(new DateTime());
		authResponse.setInResponseTo(principal.getRequestID());

		Assertion assertion = buildAssertion(principal, status, entityId);
		signAssertion(assertion, signingCredential);

		authResponse.getAssertions().add(assertion);
		authResponse.setDestination(principal.getAssertionConsumerServiceURL());

		authResponse.setStatus(status);

		Endpoint endpoint = buildSAMLObject(Endpoint.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
		endpoint.setLocation(principal.getAssertionConsumerServiceURL());

		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();

		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setPeerEntityEndpoint(endpoint);
		messageContext.setOutboundSAMLMessage(authResponse);
		messageContext.setOutboundSAMLMessageSigningCredential(signingCredential);

		messageContext.setOutboundMessageIssuer(entityId);
		messageContext.setRelayState(principal.getRelayState());

		encoder.encode(messageContext);

	}


	public void buildAndResolveArtifactResponse(SAMLPrincipal principal,org.opensaml.common.binding.SAMLMessageContext messageContext,HttpServletResponse response) throws MarshallingException, SignatureException, MessageEncodingException {
		ArtifactResponse artifactResponse = buildArtifactResponse(principal,messageContext);

		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

		//BasicSAMLMessageContext mc = new BasicSAMLMessageContext();
		String entityId = idpConfiguration.getEntityId();
		Credential signingCredential = resolveCredential(entityId);

		messageContext.setOutboundMessageTransport(outTransport);
		//messageContext.setPeerEntityEndpoint(endpoint);
		messageContext.setOutboundSAMLMessage(artifactResponse);
		messageContext.setOutboundSAMLMessageSigningCredential(signingCredential);

		messageContext.setOutboundMessageIssuer(entityId);
		messageContext.setRelayState(principal.getRelayState());

		HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();

		//encoder.getBindingURI();
		encoder.encode(messageContext);
		

	}


	public void buildAndResolveArtifactResponseDummy(org.opensaml.common.binding.SAMLMessageContext messageContext,HttpServletResponse response) throws MarshallingException, SignatureException, MessageEncodingException {
		ArtifactResponse artifactResponse = buildArtifactResponse(null,messageContext);

		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

		//BasicSAMLMessageContext mc = new BasicSAMLMessageContext();
		String entityId = idpConfiguration.getEntityId();
		Credential signingCredential = resolveCredential(entityId);

		messageContext.setOutboundMessageTransport(outTransport);
		//messageContext.setPeerEntityEndpoint(endpoint);
		messageContext.setOutboundSAMLMessage(artifactResponse);
		messageContext.setOutboundSAMLMessageSigningCredential(signingCredential);

		messageContext.setOutboundMessageIssuer(entityId);
		messageContext.setRelayState("testing");

		org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder encoder = new org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder();

		encoder.getBindingURI();
		encoder.encode(messageContext);

	}




	private ArtifactResponse buildArtifactResponse(SAMLPrincipal principal,org.opensaml.common.binding.SAMLMessageContext messageContext) {

		ArtifactResponse artifactResponse = buildSAMLObject(ArtifactResponse.class, ArtifactResponse.DEFAULT_ELEMENT_NAME);

		String entityId = idpConfiguration.getEntityId();
		Credential signingCredential = resolveCredential(entityId);

		Issuer issuer = buildIssuer(entityId);
		artifactResponse.setID(SAMLBuilder.randomSAMLId());		
		
		artifactResponse.setIssuer(issuer);
		artifactResponse.setIssueInstant(new DateTime());

		Status status = buildStatus(StatusCode.SUCCESS_URI);   
		artifactResponse.setStatus(status);
		artifactResponse.setDestination(idpConfiguration.getAcsEndpoint());

		Response response = buildSAMLObject(Response.class, Response.DEFAULT_ELEMENT_NAME);		
		response.setDestination(idpConfiguration.getAcsEndpoint());
		response.setID(SAMLBuilder.randomSAMLId());				
		response.setIssueInstant(new DateTime());

		Issuer issuer2 = buildIssuer(entityId);
		response.setIssuer(issuer2);


		Status status2 = buildStatus(StatusCode.SUCCESS_URI);
		response.setStatus(status2);



		Assertion assertion = buildAssertion(principal, status, entityId); 
		EncryptedAssertion encryptedAssertion = null;
		try {
			signAssertion(assertion, signingCredential);
			encryptedAssertion =  encryptAssertion(assertion, signingCredential);
		} catch (MarshallingException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		response.getEncryptedAssertions().add(encryptedAssertion);
		artifactResponse.setMessage(response);

		return artifactResponse;
	}


	private Credential resolveCredential(String entityId) {
		try {
			return keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(entityId)));
		} catch (SecurityException e) {
			throw new RuntimeException(e);
		}
	}

	public void buildAndResolveArtifactResponseFromFilter(HttpServletRequest request,
			org.opensaml.common.binding.SAMLMessageContext messageContext, HttpServletResponse response) throws MessageEncodingException {


		AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();
		String assertionConsumerServiceURL = idpConfiguration.getAcsEndpoint() != null ? idpConfiguration.getAcsEndpoint() : authnRequest.getAssertionConsumerServiceURL();


		SAMLPrincipal principal = new SAMLPrincipal(
				null,
				null,
				null,
				authnRequest.getIssuer().getValue(),
				authnRequest.getID(),
				assertionConsumerServiceURL,
				messageContext.getRelayState());


		ArtifactResponse artifactResponse = buildArtifactResponse(principal,messageContext);

		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

		//BasicSAMLMessageContext mc = new BasicSAMLMessageContext();
		String entityId = idpConfiguration.getEntityId();
		Credential signingCredential = resolveCredential(entityId);

		messageContext.setOutboundMessageTransport(outTransport);
		//messageContext.setPeerEntityEndpoint(endpoint);
		messageContext.setOutboundSAMLMessage(artifactResponse);
		messageContext.setOutboundSAMLMessageSigningCredential(signingCredential);

		messageContext.setOutboundMessageIssuer(entityId);
		messageContext.setRelayState(principal.getRelayState());

		org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder encoder = new org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder();

		encoder.getBindingURI();
		encoder.encode(messageContext);

	}

}
