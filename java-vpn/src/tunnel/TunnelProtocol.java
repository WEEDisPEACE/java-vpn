package tunnel;

import crypto.EncryptionManager;

import java.io.*;
import java.util.Arrays;

/**
 * TunnelProtocol
 *
 * Handles:
 * - Framing
 * - Encryption / Decryption
 * - HMAC verification
 *
 * Adapts STRICTLY to EncryptionManager API.
 */
public class TunnelProtocol {

    private static final int IV_LENGTH = 12;

    private final EncryptionManager crypto;

    public TunnelProtocol(EncryptionManager crypto) {
        this.crypto = crypto;
    }

    /* ==========================
       SEND PACKET
       ========================== */

    public synchronized void sendPacket(OutputStream out, VPNPacket packet) throws IOException {
        try {
            byte[] plaintext = packet.getPayload();

            byte[] encryptedWithIv = (plaintext != null && plaintext.length > 0)
                    ? crypto.encrypt(plaintext)
                    : new byte[0];

            byte[] iv = new byte[IV_LENGTH];
            byte[] encrypted;

            if (encryptedWithIv.length >= IV_LENGTH) {
                System.arraycopy(encryptedWithIv, 0, iv, 0, IV_LENGTH);
                encrypted = Arrays.copyOfRange(encryptedWithIv, IV_LENGTH, encryptedWithIv.length);
            } else {
                encrypted = encryptedWithIv;
            }

            byte[] hmac = crypto.computeHMAC(encrypted);

            packet.setIv(iv);
            packet.setHmac(hmac);
            packet.setPayload(encrypted);

            byte[] raw = packet.toBytes();

            DataOutputStream dos = new DataOutputStream(out);
            dos.writeInt(raw.length);
            dos.write(raw);
            dos.flush();

        } catch (Exception e) {
            throw new IOException("Failed to send VPN packet", e);
        }
    }

    /* ==========================
       RECEIVE PACKET
       ========================== */

    public synchronized VPNPacket receivePacket(InputStream in) throws IOException {
        try {
            DataInputStream dis = new DataInputStream(in);

            int length = dis.readInt();
            if (length <= 0) {
                throw new IOException("Invalid packet length");
            }

            byte[] buffer = new byte[length];
            dis.readFully(buffer);

            DataInputStream packetStream =
                    new DataInputStream(new ByteArrayInputStream(buffer));

            VPNPacket packet = VPNPacket.fromStream(packetStream);

            // Control / handshake packets are not encrypted
            if (packet.getType() == VPNPacket.TYPE_HANDSHAKE_INIT ||
                packet.getType() == VPNPacket.TYPE_HANDSHAKE_RESPONSE ||
                packet.getType() == VPNPacket.TYPE_HANDSHAKE_ACK ||
                packet.getType() == VPNPacket.TYPE_DISCONNECT) {

                return packet;
            }

            // Verify HMAC
            byte[] expectedHmac = crypto.computeHMAC(packet.getPayload());
            if (!Arrays.equals(expectedHmac, packet.getHMAC())) {
                throw new IOException("HMAC verification failed");
            }

            // Rebuild encrypted blob: [IV][ciphertext]
            byte[] encryptedWithIv = new byte[IV_LENGTH + packet.getPayload().length];
            System.arraycopy(packet.getIv(), 0, encryptedWithIv, 0, IV_LENGTH);
            System.arraycopy(packet.getPayload(), 0, encryptedWithIv, IV_LENGTH, packet.getPayload().length);

            byte[] decrypted = packet.getPayload().length > 0
                    ? crypto.decrypt(encryptedWithIv)
                    : new byte[0];

            packet.setPayload(decrypted);

            return packet;

        } catch (Exception e) {
            throw new IOException("Failed to receive VPN packet", e);
        }
    }
}
    