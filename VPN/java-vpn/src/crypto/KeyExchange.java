package crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;

import java.security.spec.*;

public class KeyExchange {
    private PublicKey publicKey;    // This side’s RSA public key
    private PrivateKey privateKey;  // This side’s RSA private key
    private SecretKey aesKey;       // Agreed AES key (256-bit)
    private SecretKey hmacKey;      // Agreed HMAC key (for HMAC-SHA256)

    /**
     * Constructor (Client-side). Generates a new RSA-2048 key pair.
     */
    public KeyExchange() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);  // 2048-bit RSA key:contentReference[oaicite:11]{index=11}
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    public SecretKey getAESKey() {
        return aesKey;
    }
    public SecretKey getHMACKey() {
        return hmacKey;
    }

    /**
     * Send this side's RSA public key over the stream (length + bytes).
     */
    public void sendPublicKey(OutputStream out) throws IOException {
        byte[] pubBytes = publicKey.getEncoded();
        DataOutputStream dos = new DataOutputStream(out);
        dos.writeInt(pubBytes.length);
        dos.write(pubBytes);
        dos.flush();
    }

    /**
     * Receive an RSA public key from the stream.
     */
    public void receivePublicKey(InputStream in) throws IOException, GeneralSecurityException {
        DataInputStream dis = new DataInputStream(in);
        int len = dis.readInt();
        byte[] pubBytes = new byte[len];
        dis.readFully(pubBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.publicKey = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
    }

    /**
     * Generate new AES and HMAC keys (256-bit each).
     */
    public void generateSymmetricKeys() throws NoSuchAlgorithmException {
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(256);
        this.aesKey = aesGen.generateKey();  // AES-256 key:contentReference[oaicite:12]{index=12}

        KeyGenerator hmacGen = KeyGenerator.getInstance("HmacSHA256");
        hmacGen.init(256);
        this.hmacKey = hmacGen.generateKey();  // HMAC-SHA256 key:contentReference[oaicite:13]{index=13}
    }

    /**
     * Encrypt the AES and HMAC keys with the other party’s RSA public key and send them.
     */
    public void sendEncryptedKeys(PublicKey otherPubKey, OutputStream out) throws GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, otherPubKey);

        byte[] encAes = cipher.doFinal(aesKey.getEncoded());
        byte[] encHmac = cipher.doFinal(hmacKey.getEncoded());

        DataOutputStream dos = new DataOutputStream(out);
        dos.writeInt(encAes.length);
        dos.write(encAes);
        dos.writeInt(encHmac.length);
        dos.write(encHmac);
        dos.flush();
    }

    /**
     * Receive the encrypted AES and HMAC keys, decrypt with this side’s RSA private key, and store them.
     */
    public void receiveEncryptedKeys(InputStream in) throws GeneralSecurityException, IOException {
        DataInputStream dis = new DataInputStream(in);
        int lenA = dis.readInt();
        byte[] encAes = new byte[lenA];
        dis.readFully(encAes);
        int lenH = dis.readInt();
        byte[] encHmac = new byte[lenH];
        dis.readFully(encHmac);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);

        byte[] aesBytes = cipher.doFinal(encAes);
        byte[] hmacBytes = cipher.doFinal(encHmac);

        this.aesKey = new SecretKeySpec(aesBytes, "AES");
        this.hmacKey = new SecretKeySpec(hmacBytes, "HmacSHA256");
    }
}
