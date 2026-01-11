package tunnel;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * VPNPacket
 * Central protocol object used by both client and server.
 */
public class VPNPacket {

    /* =======================
       Packet Type Constants
       ======================= */

    public static final byte TYPE_HANDSHAKE_INIT      = 0x01;
    public static final byte TYPE_HANDSHAKE_RESPONSE  = 0x02;
    public static final byte TYPE_HANDSHAKE_ACK       = 0x03;
    public static final byte TYPE_DATA                = 0x10;
    public static final byte TYPE_HEARTBEAT           = 0x11;
    public static final byte TYPE_DISCONNECT          = 0x12;

    /* =======================
       Packet Fields
       ======================= */

    private byte type;
    private byte[] hmac;
    private byte[] iv;
    private byte[] payload;

    /* =======================
       Constructors
       ======================= */

    public VPNPacket() {}

    private VPNPacket(byte type, byte[] payload) {
        this.type = type;
        this.payload = payload;
    }

    /* =======================
       Factory Methods
       ======================= */

    public static VPNPacket createHandshakeInit(byte[] clientPublicKey) {
        return new VPNPacket(TYPE_HANDSHAKE_INIT, clientPublicKey);
    }

    public static VPNPacket createHandshakeResponse(byte[] encryptedKeys) {
        return new VPNPacket(TYPE_HANDSHAKE_RESPONSE, encryptedKeys);
    }

    public static VPNPacket createHandshakeAck() {
        return new VPNPacket(TYPE_HANDSHAKE_ACK, new byte[0]);
    }

    public static VPNPacket createDataPacket(byte[] encryptedPayload, byte[] hmac) {
        VPNPacket p = new VPNPacket(TYPE_DATA, encryptedPayload);
        p.hmac = hmac;
        return p;
    }

    public static VPNPacket createHeartbeat(byte[] hmac) {
        VPNPacket p = new VPNPacket(TYPE_HEARTBEAT, new byte[0]);
        p.hmac = hmac;
        return p;
    }

    public static VPNPacket createDisconnect() {
        return new VPNPacket(TYPE_DISCONNECT, new byte[0]);
    }

    /* =======================
       Serialization
       ======================= */

    public byte[] toBytes() throws IOException {
        int hmacLen = (hmac != null) ? hmac.length : 0;
        int ivLen   = (iv != null)   ? iv.length   : 0;
        int payLen  = (payload != null) ? payload.length : 0;

        int totalLen = 1 + 4 + hmacLen + 4 + ivLen + 4 + payLen;

        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream(totalLen);
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeByte(type);

        dos.writeInt(hmacLen);
        if (hmacLen > 0) dos.write(hmac);

        dos.writeInt(ivLen);
        if (ivLen > 0) dos.write(iv);

        dos.writeInt(payLen);
        if (payLen > 0) dos.write(payload);

        dos.flush();
        return baos.toByteArray();
    }

    public static VPNPacket fromStream(DataInputStream in) throws IOException {
        VPNPacket p = new VPNPacket();

        p.type = in.readByte();

        int hmacLen = in.readInt();
        if (hmacLen > 0) {
            p.hmac = new byte[hmacLen];
            in.readFully(p.hmac);
        }

        int ivLen = in.readInt();
        if (ivLen > 0) {
            p.iv = new byte[ivLen];
            in.readFully(p.iv);
        }

        int payloadLen = in.readInt();
        if (payloadLen > 0) {
            p.payload = new byte[payloadLen];
            in.readFully(p.payload);
        }

        return p;
    }

    /* =======================
       Getters
       ======================= */

    public byte getType() {
        return type;
    }

    public byte[] getPayload() {
        return payload;
    }

    public byte[] getHMAC() {
        return hmac;
    }

    public byte[] getIv() {
        return iv;
    }

    public String getTypeString() {
        switch (type) {
            case TYPE_HANDSHAKE_INIT:     return "HANDSHAKE_INIT";
            case TYPE_HANDSHAKE_RESPONSE: return "HANDSHAKE_RESPONSE";
            case TYPE_HANDSHAKE_ACK:      return "HANDSHAKE_ACK";
            case TYPE_DATA:               return "DATA";
            case TYPE_HEARTBEAT:          return "HEARTBEAT";
            case TYPE_DISCONNECT:         return "DISCONNECT";
            default:                      return "UNKNOWN(" + type + ")";
        }
    }

    /* =======================
       Setters (used by tunnel)
       ======================= */

    public void setHmac(byte[] hmac) {
        this.hmac = hmac;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    /* =======================
       Debug
       ======================= */

    @Override
    public String toString() {
        return "VPNPacket{" +
                "type=" + getTypeString() +
                ", hmac=" + (hmac == null ? "null" : hmac.length + " bytes") +
                ", iv=" + (iv == null ? "null" : iv.length + " bytes") +
                ", payload=" + (payload == null ? "null" : payload.length + " bytes") +
                '}';
    }
}
