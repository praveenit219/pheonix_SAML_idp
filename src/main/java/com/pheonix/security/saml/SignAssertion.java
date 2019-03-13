package com.pheonix.security.saml;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
 
public class SignAssertion
{
	 private final static Logger logger = LoggerFactory.getLogger(SignAssertion.class);

	    private static Credential signingCredential = null;
	    final static String password = "secret";
	    final static String certificateAliasName = "localhost";

	    @SuppressWarnings("static-access")
	    private void intializeCredentials() {
	        KeyStore ks = null;
	        char[] password = this.password.toCharArray();
	        FileInputStream fis = null;
	        // Get Default Instance of KeyStore
	        try {
	            ks = KeyStore.getInstance(KeyStore.getDefaultType());
	        } catch (KeyStoreException e) {
	            logger.error("Error while Intializing Keystore", e);
	        }

	        try {
				fis = new FileInputStream("D:\\dev_mine\\singpass-saml\\sp-sample-SP\\src\\main\\resources\\server.jks");
			} catch (FileNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
	        // Read Keystore
	       // InputStream is = getClass().getResourceAsStream("D:\\dev_mine\\singpass-saml\\sp-sample-SP\\src\\main\\resources\\server.jks");

	        // Load KeyStore
	        try {
	            ks.load(fis, password);
	        } catch (Exception e) {
	            logger.error("Failed to Load the KeyStore:: ", e);
	        }


	        // Get Private Key Entry From Certificate
	        KeyStore.PrivateKeyEntry pkEntry = null;
	        try {
	            pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(this.certificateAliasName, new KeyStore.PasswordProtection(
	                    this.password.toCharArray()));
	        } catch (Exception e) {
	            logger.error("Failed to Get Private Entry From the keystore", e);
	        }

	        PrivateKey pk = pkEntry.getPrivateKey();

	        X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
	        BasicX509Credential credential = new BasicX509Credential();
	        credential.setEntityCertificate(certificate);
	        credential.setPrivateKey(pk);
	        signingCredential = credential;

	        logger.info("Private Key loaded");

	    }

	    public static void main(String args[]) throws Exception {
	        SignAssertion sign = new SignAssertion();
	        sign.intializeCredentials();
	        try {
	            DefaultBootstrap.bootstrap();
	        } catch (ConfigurationException e) {
	            logger.error("Configuration exception");
	        }
	        Signature signature = (Signature) Configuration
	                .getBuilderFactory()
	                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
	                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

	        signature.setSigningCredential(signingCredential);

	        // This is also the default if a null SecurityConfiguration is specified
	        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
	        // If null this would result in the default KeyInfoGenerator being used

	        String keyInfoGeneratorProfile = "XMLSignature";

	        try {
	            SecurityHelper.prepareSignatureParams(signature, signingCredential, secConfig, null);
	        } catch (Exception e) {
	            logger.error("Couldn't prepare signature");
	        }

	        Response resp = (Response) Configuration
	                .getBuilderFactory()
	                .getBuilder(Response.DEFAULT_ELEMENT_NAME)
	                .buildObject(Response.DEFAULT_ELEMENT_NAME);

	        resp.getAssertions().add(SAMLWriter.getSamlAssertion());

	        resp.setSignature(signature);

	        try {
	            Configuration.getMarshallerFactory()
	                    .getMarshaller(resp)
	                    .marshall(resp);
	        } catch (MarshallingException e) {
	            logger.error("Couldn't marshall");
	        }

	        try {
	            Signer.signObject(signature);
	        } catch (SignatureException e) {
	            logger.error("Couldn't sign object");
	        }

	        ResponseMarshaller marshaller = new ResponseMarshaller();
	        Element plain = marshaller.marshall(resp);
	        // response.setSignature(sign);
	        String samlResponse = XMLHelper.nodeToString(plain);

	        logger.info("********************\n*\n***********::" + samlResponse);
	    }
}