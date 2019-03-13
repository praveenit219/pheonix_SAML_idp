package com.pheonix.security.saml.idp;

import static com.pheonix.security.saml.SAMLBuilder.buildSAMLObject;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;

import com.pheonix.security.saml.SAMLBuilder;
import com.pheonix.security.saml.api.IdpConfiguration;

@RestController
public class MetadataController {

  @Autowired
  private KeyManager keyManager;

  @Autowired
  private IdpConfiguration idpConfiguration;

  @Autowired
  Environment environment;

  @RequestMapping(method = RequestMethod.GET, value = "/metadata", produces = "application/xml")
  public String metadata() throws SecurityException, ParserConfigurationException, SignatureException, MarshallingException, TransformerException {
    EntityDescriptor entityDescriptor = buildSAMLObject(EntityDescriptor.class, EntityDescriptor.DEFAULT_ELEMENT_NAME);
	 // EntityDescriptor entityDescriptor = buildSAMLObject(EntityDescriptor.class,  EntityDescriptor.ELEMENT_QNAME);
    entityDescriptor.setEntityID(idpConfiguration.getEntityId());
    entityDescriptor.setID(SAMLBuilder.randomSAMLId());
    entityDescriptor.setValidUntil(new DateTime().plusMillis(86400000));

    //Signature signature = buildSAMLObject(Signature.class, Signature.DEFAULT_ELEMENT_NAME);
    Signature signature = buildSAMLObject(Signature.class, Signature.DEFAULT_ELEMENT_NAME);

    Credential credential = keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(idpConfiguration.getEntityId())));
    signature.setSigningCredential(credential);
    //signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
 
    entityDescriptor.setSignature(signature);

    Configuration.getMarshallerFactory().getMarshaller(entityDescriptor).marshall(entityDescriptor);
    Signer.signObject(signature);

    IDPSSODescriptor idpssoDescriptor = buildSAMLObject(IDPSSODescriptor.class, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    idpssoDescriptor.setWantAuthnRequestsSigned(true);
    NameIDFormat nameIDFormat = buildSAMLObject(NameIDFormat.class, NameIDFormat.DEFAULT_ELEMENT_NAME);
    nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
    idpssoDescriptor.getNameIDFormats().add(nameIDFormat);

    idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
    String localPort = environment.getProperty("local.server.port");

    ArtifactResolutionService ars = buildSAMLObject(ArtifactResolutionService.class, ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
    ars.setIndex(0);
    ars.setLocation("http://localhost:" + localPort +"/ArtifactResolver");
    ars.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
    ars.setIsDefault(true);
   
    idpssoDescriptor.getArtifactResolutionServices().add(ars);
    
    SingleSignOnService singleSignOnService_Artifact = buildSAMLObject(SingleSignOnService.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
    singleSignOnService_Artifact.setLocation("http://localhost:" + localPort + "/SingleSignOnServicArtifact");
    singleSignOnService_Artifact.setBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
    
    SingleSignOnService singleSignOnService_REDIRECT = buildSAMLObject(SingleSignOnService.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
    singleSignOnService_REDIRECT.setLocation("http://localhost:" + localPort + "/SingleSignOnServiceRedirect/alias/pheonix/idp");
    singleSignOnService_REDIRECT.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    
    SingleSignOnService singleSignOnService_POST = buildSAMLObject(SingleSignOnService.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
    singleSignOnService_POST.setLocation("http://localhost:" + localPort + "/SingleSignOnServicePost");
    singleSignOnService_POST.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    
    SingleSignOnService singleSignOnService_SOAP = buildSAMLObject(SingleSignOnService.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
    singleSignOnService_SOAP.setLocation("http://localhost:" + localPort + "/SingleSignOnServiceSoap");
    singleSignOnService_SOAP.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);

    idpssoDescriptor.getSingleSignOnServices().add(singleSignOnService_REDIRECT);
    idpssoDescriptor.getSingleSignOnServices().add(singleSignOnService_POST);
    idpssoDescriptor.getSingleSignOnServices().add(singleSignOnService_SOAP);
   
    X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
    keyInfoGeneratorFactory.setEmitEntityCertificate(true);
    KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

    KeyDescriptor encKeyDescriptor = buildSAMLObject(KeyDescriptor.class, KeyDescriptor.DEFAULT_ELEMENT_NAME);
    encKeyDescriptor.setUse(UsageType.SIGNING);

    encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(credential));

    idpssoDescriptor.getKeyDescriptors().add(encKeyDescriptor);

    entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);

    return writeEntityDescriptor(entityDescriptor);
  }

  private String writeEntityDescriptor(EntityDescriptor entityDescriptor) throws ParserConfigurationException, MarshallingException, TransformerException {
    Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(entityDescriptor);
    Element element = marshaller.marshall(entityDescriptor);
    return XMLHelper.nodeToString(element);
  }

}
