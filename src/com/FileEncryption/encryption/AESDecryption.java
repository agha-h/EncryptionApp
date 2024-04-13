package com.FileEncryption.encryption;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class AESDecryption {
    public static String decrypt(byte[] encryptedBytes, String key) throws Exception {
        // Convert the key string into a byte array
        byte[] keyBytes = key.getBytes();

        // Create a SecretKeySpec object representing the AES key
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        // Initialize the Cipher object for decryption
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // Decrypt the bytes
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Convert the decrypted bytes back to plaintext
        return new String(decryptedBytes);
    }

    public static byte[] readFile(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }
}
