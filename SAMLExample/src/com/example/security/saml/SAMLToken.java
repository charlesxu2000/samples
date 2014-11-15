package com.example.security.saml;

import java.io.*;
import java.nio.charset.Charset;
import java.util.*;
import java.util.logging.Logger;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import com.example.security.util.PrettyPrinter;
import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

/**
 * SAMLToken class is a utility class to build, sign, encode a SAML assertion.
 * The normal flow for creating SAML token is:
 * 1) Use keytool to create a keystore which contains public/private key pair used to sign the SAML assertion.
 * 2) Create SAML assertion (by calling buildSAMLAssertion()).
 * 3) Encode (marshell SAML assertion to XML document), then sign the XML document.
 * 4) Compress the SAML assertion to become a SAML token.
 * 5) Put the compressed SAML token to HTTP Authorization header like: Authorization: SAML <SAML token>
 */
public class SAMLToken
{
    private static Logger   log = Logger.getLogger( SAMLToken.class.getName() );

    /* SAMLSigner instance used for signing assertion */
    private SAMLSigner      samlSigner;

    /* Hold OpenSAML builder factory instance */
    private static XMLObjectBuilderFactory  builderFactory;

    /* static block, initialized only once during class load time */
    static
    {
        try {
            DefaultBootstrap.bootstrap();
        } catch ( ConfigurationException e )
        {
            log.severe( e.getStackTrace().toString() );
        }
        builderFactory = Configuration.getBuilderFactory();

    }

    /**
     * Initialization method for SAMLToken instance.
     *
     * @param properties Properties contains signing keystore info.
     */
    public void init( Properties properties )
    {
        // Initialize SAMLSigher

        try {
            samlSigner = new SAMLSigner();
            samlSigner.init( properties );
        } catch ( Exception e )
        {
            log.severe( e.getStackTrace().toString() );
        }
    }



    /**
     * Create a SAML assertion based on attributes values defined in SAMLParams.
     * This is the main method that construct SAML assertion profiles and
     * assemble them together.
     * User can pull out and put in another profile block into here.
     *
     * @param params The assertion attributes value.
     * @return SAML assertion.
     */
    public Assertion buildSAMLAssertion(SAMLParams params)
    {
        try
        {
            /**** Create the NameIdentifier ****/
            /* In this block, it creates the SAML Subject <saml2:Subject> */

            SAMLObjectBuilder nameIdBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
            NameID nameId = (NameID) nameIdBuilder.buildObject();
            nameId.setValue(params.getNameID());
            nameId.setNameQualifier(params.getNameQualifier());
            nameId.setFormat(NameID.EMAIL);

            /**** Create the SubjectConfirmation ****/
            /* In this block, it creates the SAML SubjectConfirmation <saml2:SubjectConfirmation> */

            SAMLObjectBuilder subjectConfirmationBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
            SubjectConfirmation subjectConfirmation = (SubjectConfirmation) subjectConfirmationBuilder.buildObject();
            subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

            /**** Create the Subject ****/
            /* In this block, it creates SAML Subject </saml2:Subject> */

            SAMLObjectBuilder subjectBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
            Subject subject = (Subject) subjectBuilder.buildObject();
            subject.setNameID(nameId);
            subject.getSubjectConfirmations().add(subjectConfirmation);

            /**** Create the Conditions ****/
            /* In this block, it create SAML Conditions <saml2:Conditions> */

            SAMLObjectBuilder conditionsBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
            Conditions conditions = (Conditions) conditionsBuilder.buildObject();

            DateTime now = new DateTime();
            conditions.setNotBefore (now.minusSeconds (10));
            conditions.setNotOnOrAfter (now.plusMinutes(params.getValidationDuration()));

            /**** Create Authentication Statement ****/
            /* In this block, it creates the SAML Authn profile <saml2:AuthnStatement> */

            SAMLObjectBuilder authStatementBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
            AuthnStatement authnStatement = (AuthnStatement) authStatementBuilder.buildObject();

            authnStatement.setAuthnInstant(now);
            authnStatement.setSessionIndex(params.getSessionId());
            authnStatement.setSessionNotOnOrAfter(now.plusMinutes(params.getMaxSessionTimeoutInMinutes()));

            SAMLObjectBuilder authContextBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
            AuthnContext authnContext = (AuthnContext) authContextBuilder.buildObject();

            SAMLObjectBuilder authContextClassRefBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
            AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef) authContextClassRefBuilder.buildObject();
            authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");

            authnContext.setAuthnContextClassRef(authnContextClassRef);
            authnStatement.setAuthnContext(authnContext);

            /**** Create Attributes Statement ****/
            /* In this block, it creates SAML Attribute profile <saml2:AttributeStatement> */

            SAMLObjectBuilder attrStatementBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
            AttributeStatement attrStatement = (AttributeStatement) attrStatementBuilder.buildObject();

            /* Create the attribute statement */

            Map attributes = params.getAttributes();
            if(attributes != null){
                Set keySet = attributes.keySet();
                for (String key : (Set<String>)keySet)
                {
                    Attribute attrFirstName = buildStringAttribute(key, (String)attributes.get(key), builderFactory);
                    attrStatement.getAttributes().add(attrFirstName);
                }
            }


            /**** Create Issuer ****/
            /* In this block, it creates SAML token issuer <saml2:Issuer> */

            SAMLObjectBuilder issuerBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
            Issuer issuer = (Issuer) issuerBuilder.buildObject();
            issuer.setValue(params.getIssuer());

            /**** Create the SAML Assertion ****/
            /* In this block, it assemble all the components constructed above and put in to the assertion. */

            SAMLObjectBuilder assertionBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
            Assertion assertion = (Assertion) assertionBuilder.buildObject();

            assertion.setIssuer(issuer);
            assertion.setIssueInstant(now);
            assertion.setVersion(SAMLVersion.VERSION_20);

            assertion.setSubject(subject);
            assertion.setConditions(conditions);

            assertion.getAuthnStatements().add(authnStatement);
            assertion.getAttributeStatements().add(attrStatement);

            return assertion;
        }
        catch (Exception e)
        {
            log.severe( e.getStackTrace().toString() );
        }
        return null;
    }

    /**
     * Compress SAML token.
     * @param token The token need to be compressed.
     * @return Compressed SAML token.
     */
    public String compressSAMLAssertion( String token )
    {
        String compressedSAMLToken;

        // compress the XML document
        Deflater compressor = new Deflater(Deflater.DEFLATED, true);
        compressor.setInput(token.getBytes());
        compressor.finish();

        byte[] output = new byte[token.getBytes().length];
        int compressedDataLength = compressor.deflate(output);
        byte[] compressedData = new byte[compressedDataLength];
        System.arraycopy(output, 0, compressedData, 0, compressedDataLength);

        Base64 encoder = new Base64(true);
        compressedSAMLToken = new String(encoder.encode(compressedData));

        return compressedSAMLToken;
    }

    /**
     * Decompress SAML token.
     * @param token Compressed token.
     * @return Decompressed SAML token.
     */
    public String decompressSAMLAssertion( String token )
    {
        String decompressedSAMLToken;

        Base64 decoder = new Base64(true);
        byte[] unencodedSource = (byte[]) decoder.decode(token.getBytes());
        Inflater inflater = new Inflater(true);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(
                outputStream, inflater);

        try {
            inflaterOutputStream.write(unencodedSource);
            inflaterOutputStream.close();
        } catch ( IOException e )
        {
            log.severe( e.getStackTrace().toString() );
        }

        decompressedSAMLToken = new String(outputStream.toByteArray());

        return decompressedSAMLToken;
    }

    /**
     * Encode and sign SAML assertion.
     * @param assertion A SAML assertion need to be signed and encoded.
     * @return Encoded SAML token.
     */
    public String encodeAndSignSAMLAssertion( Assertion assertion )
    {
        String      encodedSAMLToken = null;

        try {
            // Marshal the assertion to XML document
            AssertionMarshaller marshaller = new AssertionMarshaller();
            Element plaintextElement = marshaller.marshall(assertion);

            samlSigner.signSAMLObject(plaintextElement);

            // Convert XML DOM to string
            encodedSAMLToken = XMLHelper.nodeToString(plaintextElement);
        } catch ( Exception e )
        {
            log.severe( e.getStackTrace().toString() );
        }

        log.fine("Assertion String: \n" + PrettyPrinter.prettyPrint(new ByteArrayInputStream(encodedSAMLToken.getBytes(Charset.forName("UTF-8")))));

        return encodedSAMLToken;
    }

    /**
     * Encode the SAML assertion (without sign).
     * @param assertion A SAML assertion need to be encoded.
     * @return Encoded SAML assertion.
     */
    public String encodeUnsignedSAMLAssertion( Assertion assertion )
    {
        String encodedSAMLToken = null;

        try {
            // Marshal the assertion to XML document
            AssertionMarshaller marshaller = new AssertionMarshaller();
            Element plaintextElement = marshaller.marshall(assertion);

            // Convert XML DOM to string
            encodedSAMLToken = XMLHelper.nodeToString(plaintextElement);
        } catch ( MarshallingException e )
        {
            log.severe( e.getStackTrace().toString() );
        }

        log.fine("Assertion String: \n" + PrettyPrinter.prettyPrint(new ByteArrayInputStream(encodedSAMLToken.getBytes(Charset.forName("UTF-8")))));

        return encodedSAMLToken;
    }

    /**
     * Builds a SAML Attribute of type String
     * @param name
     * @param value
     * @param builderFactory
     * @return
     * @throws ConfigurationException
     */
    private Attribute buildStringAttribute(String name, String value, XMLObjectBuilderFactory builderFactory) throws ConfigurationException
    {
        SAMLObjectBuilder attrBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        Attribute attrFirstName = (Attribute) attrBuilder.buildObject();
        attrFirstName.setName(name);

        // Set custom Attributes
        XMLObjectBuilder stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);
        XSString attrValueFirstName = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        attrValueFirstName.setValue(value);

        attrFirstName.getAttributeValues().add(attrValueFirstName);
        return attrFirstName;
    }

    /**
     * Get the SAML Signer. Can use to validate the SAML token signature.
     * @return SAMLSigner object.
     */
    public SAMLSigner getSamlSigner() {
        return samlSigner;
    }

    /**
     * The main method is a sample for how to use SAMLToken to construct a SAML token.
     * @param args
     */
    public static void main(String[] args) {

        /* Load configuration properties */
        Properties properties = new Properties();
        try
        {
            properties.load( new FileInputStream( "config.properties" ) );
        } catch ( IOException e )
        {
            log.severe( e.getStackTrace().toString() );
        }

        /* Create SAML assertion attributes info object */
        SAMLParams params = new SAMLParams();
        params.setIssuer(properties.getProperty("ISSUER", "http://www.example.com"));
        params.setValidationDuration(Integer.parseInt(properties.getProperty("VALIDATION_DURATION", "720")));

        params.setNameID("JohnDoe@example.com");
        params.setNameQualifier("example.com");
        params.setSessionId(UUID.randomUUID().toString());

        Map customAttributes = new HashMap();
        customAttributes.put("Identity", "Example Co");
        customAttributes.put("Usage", "Test");

        params.setAttributes(customAttributes);

        /* Use SAMLToken class to create a signed and a unsigned SAML token */
        SAMLToken samlToken = new SAMLToken();
        samlToken.init( properties );
        Assertion assertion = samlToken.buildSAMLAssertion(params);
        String unsignedToken = samlToken.encodeUnsignedSAMLAssertion(assertion);
        String signedToken = samlToken.encodeAndSignSAMLAssertion(assertion);

        System.out.println("Unsigned Token: " + unsignedToken);
        System.out.println("Signed Token:" +  signedToken);
    }
}