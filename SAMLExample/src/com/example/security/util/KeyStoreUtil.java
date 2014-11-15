package com.example.security.util;

import java.io.*;
import java.security.*;
import java.util.*;

/**
 * Utility class for SAML signing certificate and keystore.
 */
public class KeyStoreUtil
{
    /**
     * Get a KeyStore object given the keystore filename and password.
     * @param filename The keystore file name.
     * @param password The keystore password.
     * @return Keystore object.
     * @throws KeyStoreException
     */
    public static KeyStore getKeyStore (String filename, String password)
        throws KeyStoreException
    {
        KeyStore result = KeyStore.getInstance (KeyStore.getDefaultType ());
        
        try
        {
            FileInputStream in = new FileInputStream (filename);
            result.load (in, password.toCharArray ());
            in.close ();
        }
        catch (Exception ex)
        {
            System.out.println ("Failed to read keystore:" + ex.getStackTrace());
        }
        
        return result;
    }

    /**
     * List all the key and certificate aliases in the keystore.
     * @param keystore The keystore that used to list the key alias.
     * @return A list of key alias.
     * @throws KeyStoreException
     */
    public static List getAliases (KeyStore keystore)
        throws KeyStoreException
    {
        return Collections.list (keystore.aliases ());
    }

    /**
     * Get a private key from the keystore by name and password.
     * @param keystore The keystore that the private key stored.
     * @param alias The key alias for the priviate key.
     * @param password The key password.
     * @return A private key.
     * @throws GeneralSecurityException
     */
    public static Key getKey (KeyStore keystore, String alias, String password)
        throws GeneralSecurityException
    {
        return keystore.getKey (alias, password.toCharArray ());
    }

    /**
     * Get a certificate from the keystore by name.
     * @param keystore The keystore that stores the key and certs.
     * @param alias The key alias for the key that certificate generated from.
     * @return Certificate of the key.
     * @throws GeneralSecurityException
     */
    public static java.security.cert.Certificate getCertificate 
            (KeyStore keystore, String alias)
        throws GeneralSecurityException
    {
        return keystore.getCertificate (alias);
    }
    
    /**
    Dump all data about the private key to the console.
    */
    public static String spillBeans (Key key)
    {
        StringBuffer buffer = new StringBuffer 
            ("Algorithm: " + key.getAlgorithm () + endLine +
             "Key value: " + endLine);

        appendHexValue (buffer, key.getEncoded ());

        return buffer.toString ();
    }
    
    /**
    Dump all data about the certificate to the console.
    */
    public static String spillBeans (java.security.cert.Certificate cert)
        throws GeneralSecurityException
    {
        StringBuffer buffer = new StringBuffer 
            ("Certificate type: " + cert.getType () + endLine +
             "Encoded data: " + endLine);
        appendHexValue (buffer, cert.getEncoded ());

        return buffer.toString ();
    }
    
    /**
    Helper method to solicit a line of user input from the console.
    */
    public static String getUserInput (String prompt)
        throws IOException
    {
        System.out.print (prompt);
        BufferedReader reader = new BufferedReader
            (new InputStreamReader (System.in));
        String result = reader.readLine ();
        
        return result;
    }

    /**
     * Helper method that converts a single byte to a hex string representation.
     * @param buffer Holding the output value (with the two-digit hex string).
     * @param b Byte to convert.
     */
    public static void appendHexValue (StringBuffer buffer, byte b)
    {
        int[] digits = { (b >>> 4) & 0x0F, b & 0x0F };
        for (int d = 0; d < digits.length; ++d)
        {
            int increment = (int) ((digits[d] < 10) ? '0' : ('a' - 10));
            buffer.append ((char) (digits[d] + increment));
        }
    }

    /**
     * Helper that appends a hex representation of a byte array to an
     * existing StringBuffer Holding the output value (with the two-digit hex string).
     * @param buffer Holding the output value.
     * @param bytes Byte to append.
     */
    public static void appendHexValue (StringBuffer buffer, byte[] bytes)
    {
        for (int i = 0; i < bytes.length; ++i)
            appendHexValue (buffer, bytes[i]);
    }

    private static final String endLine = 
        System.getProperty ("line.separator");

    /**
     * As an application, this class will operate something like the
     * <b>keytool -list</b> command: it will read out every alias in the
     * keystore, and with the user's provided password for a given key
     * will write out all data on the key and/or certificate.
     * @param args
     * @throws Exception
     */
    public static void main (String[] args)
        throws Exception
    {
        if (args.length < 2)
        {
            System.out.println 
                ("Usage: java KeyStoreUtil <filename> <password>");
            System.exit (-1);
        }
        
        String filename = args[0];
        String password = args[1];
        
        KeyStore keystore = getKeyStore (filename, password);
        Iterator each = getAliases (keystore).iterator ();
        while (each.hasNext ())
            try
            {
                String alias = (String) each.next ();
                System.out.println ("Key or certificate alias: " + alias);
                
                Key key = getKey 
                    (keystore, alias, getUserInput ("Key password: "));
                System.out.println (spillBeans (key));
                
                java.security.cert.Certificate certificate = 
                    getCertificate (keystore, alias);
                System.out.println (spillBeans (certificate));
                System.out.println ();
            }
            catch (Exception ex)
            {
                System.out.println ("Couldn't read key.");
            }
    }
}

