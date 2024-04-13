package com.FileEncryption.encryption;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import javax.crypto.Cipher;
import java.util.Base64;

public class RSAEncryption {

    public static byte[] encrypt(String plaintext, PublicKey publicKey) throws Exception {
        // Initialize the Cipher object for encryption with RSA algorithm
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encrypt the plaintext
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

        return encryptedBytes;
    }

    // Encode a public key to Base64 string
    public static String encodePublicKey(PublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    // Helper method to generate RSA key pair
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048); // Key size of 2048 bits
        return keyPairGen.generateKeyPair();
    }
}
