package crypto;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * EncryptionManager - Handles AES-256-GCM encryption/decryption with HMAC-SHA256
 * 
 * Features:
 * - AES-256-GCM for authenticated encryption
 * - HMAC-SHA256 for additional integrity verification
 * - Secure random IV generation per packet
 * - RSA-2048 support for key exchange
 */
public class EncryptionManager {
    
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12; // 96 bits recommended for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128 bits authentication tag
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    
    private SecretKey aesKey;
    private SecretKey hmacKey;
    private SecureRandom secureRandom;
    
    /**
     * Constructor - Initializes with AES and HMAC keys
     */
    public EncryptionManager(SecretKey aesKey, SecretKey hmacKey) {
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
        this.secureRandom = new SecureRandom();
    }
    
    /**
     * Generate a random AES-256 key
     */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, new SecureRandom());
        return keyGen.generateKey();
    }
    
    /**
     * Generate a random HMAC key
     */
    public static SecretKey generateHMACKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(HMAC_ALGORITHM);
        keyGen.init(256, new SecureRandom());
        return keyGen.generateKey();
    }
    
    /**
     * Create SecretKey from raw bytes
     */
    public static SecretKey createAESKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }
    
    public static SecretKey createHMACKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, HMAC_ALGORITHM);
    }
    
    /**
     * Encrypt data using AES-256-GCM
     * Returns: [IV (12 bytes)][Encrypted Data + Auth Tag]
     */
    public byte[] encrypt(byte[] plaintext) throws Exception {
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        
        // Setup cipher
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        
        // Encrypt
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        // Combine IV + Ciphertext
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        
        return result;
    }
    
    /**
     * Decrypt data using AES-256-GCM
     * Input: [IV (12 bytes)][Encrypted Data + Auth Tag]
     */
    public byte[] decrypt(byte[] encrypted) throws Exception {
        if (encrypted.length < GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data length");
        }
        
        // Extract IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(encrypted, 0, iv, 0, GCM_IV_LENGTH);
        
        // Extract ciphertext
        byte[] ciphertext = new byte[encrypted.length - GCM_IV_LENGTH];
        System.arraycopy(encrypted, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);
        
        // Setup cipher
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        
        // Decrypt and verify authentication tag
        return cipher.doFinal(ciphertext);
    }
    
    /**
     * Generate RSA-2048 key pair for key exchange
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }
    
    /**
     * Encrypt AES key using RSA public key
     */
    public static byte[] encryptKeyWithRSA(SecretKey key, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(key.getEncoded());
    }
    
    /**
     * Decrypt AES key using RSA private key
     */
    public static SecretKey decryptKeyWithRSA(byte[] encryptedKey, PrivateKey privateKey, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] keyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(keyBytes, algorithm);
    }
    
    /**
     * Compute HMAC-SHA256 for integrity verification
     */
    public byte[] computeHMAC(byte[] data) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(hmacKey);
        return mac.doFinal(data);
    }
    
    /**
     * Verify HMAC-SHA256
     */
    public boolean verifyHMAC(byte[] data, byte[] receivedHMAC) throws Exception {
        byte[] computedHMAC = computeHMAC(data);
        return MessageDigest.isEqual(computedHMAC, receivedHMAC);
    }
    
    /**
     * Hash data using SHA-256
     */
    public static byte[] sha256Hash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
    
    /**
     * Secure comparison to prevent timing attacks
     */
    public static boolean secureCompare(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
    
    // Getters
    public SecretKey getAESKey() {
        return aesKey;
    }
    
    public SecretKey getHMACKey() {
        return hmacKey;
    }
}