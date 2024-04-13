package com.FileEncryption.encryption;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class AESEncryption {

    public static byte[] encrypt(String plaintext, String key) throws Exception {
        // Convert the key string into a byte array
        byte[] keyBytes = key.getBytes();

        // Create a SecretKeySpec object representing the AES key
        Key secretKey = new SecretKeySpec(keyBytes, "AES");

        // Initialize the Cipher object for encryption
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt the plaintext
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

        return encryptedBytes;
    }

    public static void main(String[] args) {
        try {
            // Example usage
            String plaintext = "This is a secret message.";
            String key = "thisisakey123456"; // 128-bit key

            // Encrypt the plaintext
            byte[] encryptedBytes = encrypt(plaintext, key);

            // Print the encrypted bytes (in hexadecimal format)
            System.out.println("Encrypted bytes: " + bytesToHex(encryptedBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper method to convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
