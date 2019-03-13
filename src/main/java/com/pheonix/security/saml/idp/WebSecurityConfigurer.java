package com.pheonix.security.saml.idp;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.stream.XMLStreamException;

import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.common.binding.decoding.URIComparator;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.StorageService;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import com.pheonix.security.saml.UpgradedSAMLBootstrap;
import com.pheonix.security.saml.api.IdpConfiguration;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigurer extends WebMvcConfigurerAdapter {

	@Autowired
	private Environment environment;


	@Value("${idp.entity_id}")
	private String idpEntityId;


	@Value("${idp.private_key}")
	private String idpPrivateKey;

	@Value("${idp.certificate}")
	private String idpCertificate;

	@Value("${idp.passphrase}")
	private String idpPassphrase;

	@Bean(initMethod = "initialize")
	@Autowired
	public ParserPool parserPool() {
		return new StaticBasicParserPool();
	}


	@Bean
	@Autowired
	public SAMLMessageHandler samlMessageHandler(@Value("${idp.clock_skew}") int clockSkew,
			@Value("${idp.expires}") int expires,
			@Value("${idp.base_url}") String idpBaseUrl,
			@Value("${idp.compare_endpoints}") boolean compareEndpoints,
			IdpConfiguration idpConfiguration,
			JKSKeyManager keyManager,StorageService<String, SAMLArtifactMapEntry> storageEngine)
					throws XMLParserException, URISyntaxException {
		// StaticBasicParserPool parserPool = new StaticBasicParserPool();
		BasicSecurityPolicy securityPolicy = new BasicSecurityPolicy();
		securityPolicy.getPolicyRules().addAll(Arrays.asList(new IssueInstantRule(clockSkew, expires)));

		HTTPRedirectDeflateDecoder httpRedirectDeflateDecoder = new HTTPRedirectDeflateDecoder(parserPool());
		HTTPPostDecoder httpPostDecoder = new HTTPPostDecoder(parserPool());
		
		if (!compareEndpoints) {
			URIComparator noopComparator = (uri1, uri2) -> true;
			httpPostDecoder.setURIComparator(noopComparator);
			httpRedirectDeflateDecoder.setURIComparator(noopComparator);
		}
		
		HTTPSOAP11Decoder httpSoapDecoder = new HTTPSOAP11Decoder(parserPool());

		//parserPool.initialize();

		HTTPPostSimpleSignEncoder httpPostSimpleSignEncoder = new HTTPPostSimpleSignEncoder(VelocityFactory.getEngine(), "/templates/saml2-post-simplesign-binding.vm", true);

		return new SAMLMessageHandler(
				keyManager,
				Arrays.asList(httpRedirectDeflateDecoder, httpPostDecoder,httpSoapDecoder),
				httpPostSimpleSignEncoder,
				new StaticSecurityPolicyResolver(securityPolicy),
				idpConfiguration,
				idpBaseUrl,storageEngine);
	}

	@Bean
	public static SAMLBootstrap sAMLBootstrap() {
		return new UpgradedSAMLBootstrap();
	}

	@Value("${idp.alias}")
	private String ALIAS;

	@Value("${idp.passphrase}")
	private String STORE_PASS;

	@Autowired
	@Bean
	public JKSKeyManager keyManager() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, XMLStreamException {


		DefaultResourceLoader loader = new DefaultResourceLoader();
		Resource storeFile = loader.getResource("classpath:server.jks");
		Map<String, String> passwords = new HashMap<>();
		passwords.put(ALIAS, STORE_PASS);
		passwords.put(idpEntityId, STORE_PASS);
		return new JKSKeyManager(storeFile, STORE_PASS, passwords, idpEntityId);

		/*KeyStore keyStore = KeyStoreLocator.createKeyStore(idpPassphrase);
    KeyStoreLocator.addPrivateKey(keyStore, idpEntityId, idpPrivateKey, idpCertificate, idpPassphrase);
    return new JKSKeyManager(keyStore, Collections.singletonMap(idpEntityId, idpPassphrase), idpEntityId);*/
	}

	@Bean
	public ServletContextInitializer servletContextInitializer() {
		//otherwise the two localhost instances override each other session
		return servletContext -> servletContext.getSessionCookieConfig().setName("pheonixIdpSessionId");
	}

	@Value("${idp.idp_metadata_url}")
	private String identityProviderMetadataUrl;

	
	
	private DefaultResourceLoader defaultResourceLoader = new DefaultResourceLoader();

	@Bean
	public MetadataProvider identityProvider() throws MetadataProviderException, XMLParserException {
		Resource resource = defaultResourceLoader.getResource(identityProviderMetadataUrl);
		ResourceMetadataProvider resourceMetadataProvider = new ResourceMetadataProvider(resource);
		resourceMetadataProvider.setParserPool(parserPool());
		ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(resourceMetadataProvider, extendedMetadata());
		extendedMetadataDelegate.setMetadataTrustCheck(false);
		extendedMetadataDelegate.setMetadataRequireSignature(false);
		
		return extendedMetadataDelegate;
	}
	
	@Bean
	public ExtendedMetadata extendedMetadata() { 
		ExtendedMetadata extendedMetadata = new ExtendedMetadata();
		extendedMetadata.setAlias("pheonix");
		extendedMetadata.setLocal(true);
		extendedMetadata.setSigningKey(idpEntityId);
		extendedMetadata.setEncryptionKey(idpEntityId);
		extendedMetadata.setSigningAlgorithm("RSA");
		extendedMetadata.setSslSecurityProfile(null);
		//extendedMetadata.setSigningAlgorithm("RSA");
		return extendedMetadata;
	}

	@Bean
	@Qualifier("metadata")
	public CachingMetadataManager metadata() throws MetadataProviderException, XMLParserException {
		List<MetadataProvider> providers = new ArrayList<>();
		providers.add(identityProvider());
		
		return new CachingMetadataManager(providers);
	}
	
	
	@Configuration
	@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
	protected static class ApplicationSecurity extends WebSecurityConfigurerAdapter {

		@Autowired
		private IdpConfiguration idpConfiguration;

		@Autowired
		private SAMLMessageHandler samlMessageHandler;
		
		@Autowired
		private JKSKeyManager keyManager;
		
		@Autowired
		private  ExtendedMetadata extendedMetadata;

		@Value("${idp.acs_resolve_path}")
		private String assertionResolveURL;
		
		private SAMLAttributeAuthenticationFilter authenticationFilter() throws Exception {
			SAMLAttributeAuthenticationFilter filter = new SAMLAttributeAuthenticationFilter();
			filter.setAuthenticationManager(authenticationManagerBean());
			
			filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error=true"));
			return filter;
		}
		
		/*	@Bean
		public FilterChainProxy samlFilter() throws Exception {
			List<SecurityFilterChain> chains = new ArrayList<>();
		
			chains.add(chain(assertionResolveURL + "/**", samlWebSSOProcessingFilter()));
			return new FilterChainProxy(chains);
		}
		private DefaultSecurityFilterChain chain(String pattern, Filter entryPoint) {
			return new DefaultSecurityFilterChain(new AntPathRequestMatcher(pattern), entryPoint);
		}

		@Bean
		public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
			SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
			samlWebSSOProcessingFilter.setFilterProcessesUrl(assertionResolveURL);
			samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
	
			return samlWebSSOProcessingFilter;
		}*/
		
		@Bean
		@Autowired
		public  StorageService<String, SAMLArtifactMapEntry> storageEngine(){ 
			return new MapBasedStorageService<String, SAMLArtifactMapEntry>();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
			.csrf().disable()
			.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
			.addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(new ForceAuthnFilter(samlMessageHandler), SAMLAttributeAuthenticationFilter.class)
			.authorizeRequests()
			.antMatchers("/", "/metadata", "/favicon.ico", "/api/**", "/*.css", "/*.js", assertionResolveURL + "/**").permitAll()
			.antMatchers("/admin/**").hasRole("ADMIN")
			.anyRequest().hasRole("USER")
			.and()
			.formLogin()
			.loginPage("/login")
			.permitAll()
			.failureUrl("/login?error=true")
			.permitAll()
			.and()
			.logout()
			.logoutSuccessUrl("/");
		}

		@Value("${idp.base_url}")
		private String idpBaseUrl;

		@Value("${idp.entity_id}")
		private String idpEntityId;

		@Bean
		public MetadataGeneratorFilter metadataGeneratorFilter() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, XMLStreamException {
			return new MetadataGeneratorFilter(metadataGenerator());
		}



		@Bean
		public MetadataGenerator metadataGenerator() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
			MetadataGenerator metadataGenerator = new MetadataGenerator();
			metadataGenerator.setEntityId(idpEntityId);
			
			metadataGenerator.setEntityBaseURL(idpBaseUrl);
			metadataGenerator.setExtendedMetadata(extendedMetadata);
			//metadataGenerator.setIncludeDiscoveryExtension(false);
			metadataGenerator.setKeyManager(keyManager);
			//metadataGenerator.setRequestSigned(true);
			return metadataGenerator;
		}



		@Override
		public void configure(AuthenticationManagerBuilder auth) {
			auth.authenticationProvider(new AuthenticationProvider(idpConfiguration));
		}

		@Bean
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}
	}

}
