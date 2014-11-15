package com.example.security.saml;

import com.example.security.saml.SAMLParams;
import com.example.security.saml.SAMLToken;
import com.example.security.util.PrettyPrinter;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

public class SAMLTokenTest
{
    SAMLParams params;
    SAMLToken samlToken;

    @org.junit.Before
    public void setUp() throws Exception {
        Properties  properties = new Properties();
        properties.load(new FileInputStream("config.properties"));
        samlToken = new SAMLToken();
        samlToken.init(properties);

        params = new SAMLParams();
        params.setIssuer(properties.getProperty("ISSUER", "http://www.example.com"));
        params.setValidationDuration(Integer.parseInt(properties.getProperty("VALIDATION_DURATION", "720")));

        params.setNameID("JohnDoe@example.com");
        params.setNameQualifier("example.com");
        params.setSessionId(UUID.randomUUID().toString());


        Map customAttributes = new HashMap();
        customAttributes.put("Identity", "Example Co");
        customAttributes.put("Usage", "Test");

        params.setAttributes(customAttributes);
    }

    @Test
    public void testEncodeUnsignedSAMLAssertion() throws Exception
    {
        // Create SAML Assertion
        Assertion assertion = samlToken.buildSAMLAssertion(params);

        // Compress the SAML Assertion without sign the assertion
        String token = samlToken.encodeUnsignedSAMLAssertion(assertion);
        String compressedToken = samlToken.compressSAMLAssertion(token);
        System.out.println("Compressed Unsigned Token:\n" + compressedToken);

        // Decompress the SAML Aseertion
        String decompressedToken = samlToken.decompressSAMLAssertion(compressedToken);
        System.out.println("Decompressed Unsigned Token:\n" + decompressedToken);
        System.out.println("SAML Assertion (Unsigned):\n" + PrettyPrinter.prettyPrint(new ByteArrayInputStream(token.getBytes(Charset.forName("UTF-8")))));

        // The decompressed the assertion should be the same as the original assertion
        Assert.assertEquals(token, decompressedToken);
    }

    @Test
    public void testEncodeSignedSAMLAssertion() throws Exception {
        // Create SAML Assertion
        Assertion assertion = samlToken.buildSAMLAssertion(params);

        // Sign the SAML Assertion
        String token = samlToken.encodeAndSignSAMLAssertion(assertion);

        // Compress the SAML Assertion and ready to use
        String compressedToken = samlToken.compressSAMLAssertion(token);
        System.out.println("Compressed Signed Token:\n" + compressedToken);

        // Decompress the SAML Assertion
        String decompressedToken = samlToken.decompressSAMLAssertion(compressedToken);
        System.out.println("Decompressed Signed Token:\n" + decompressedToken);
        System.out.println("SAML Assertion (Signed):\n" + PrettyPrinter.prettyPrint(new ByteArrayInputStream(token.getBytes(Charset.forName("UTF-8")))));

        // Compare the original SAML Assertion and the one decompressed, they should be equal
        Assert.assertEquals(token, decompressedToken);

        // Validate the SAML signature

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder;
        Element assertionElement = null;
        try
        {
            // Rebuild the SAML Assertion from the decompressed token.
            factory.setNamespaceAware(true);
            builder = factory.newDocumentBuilder();
            Document document = builder.parse( new InputSource( new StringReader( decompressedToken ) ) );
            assertionElement = document.getDocumentElement();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Validate the SAML Assertion signature, it should be valid with the original assertion and signing key.
        Assert.assertTrue(samlToken.getSamlSigner().verifySAMLSignature(assertionElement));
    }
}
