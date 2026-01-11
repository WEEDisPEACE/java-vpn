package client;

import crypto.EncryptionManager;
import logging.VPNLogger;
import tunnel.VPNPacket;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public class VPNClient {
    
    private static final String DEFAULT_SERVER = "localhost";
    private static final int DEFAULT_SERVER_PORT = 8443;
    private static final int SOCKS5_PORT = 1080;
    
    private Socket serverSocket;
    private DataInputStream in;
    private DataOutputStream out;
    private EncryptionManager encryptionManager;
    private SOCKS5Server socks5Server;
    private KillSwitch killSwitch;
    private ExecutorService executor;
    private AtomicLong bytesIn;
    private AtomicLong bytesOut;
    private volatile boolean connected;
    
    // Session management
    private Map<String, VPNSession> activeSessions;
    private AtomicLong sessionCounter;
    
    public VPNClient(String serverHost, int serverPort) throws IOException {
        this.serverSocket = new Socket(serverHost, serverPort);
        this.in = new DataInputStream(new BufferedInputStream(serverSocket.getInputStream()));
        this.out = new DataOutputStream(new BufferedOutputStream(serverSocket.getOutputStream()));
        this.executor = Executors.newCachedThreadPool();
        this.bytesIn = new AtomicLong(0);
        this.bytesOut = new AtomicLong(0);
        this.connected = false;
        this.activeSessions = new ConcurrentHashMap<>();
        this.sessionCounter = new AtomicLong(0);
    }
    
    public boolean connect() {
        try {
            VPNLogger.info("Connecting to VPN Server: " + serverSocket.getRemoteSocketAddress());
            
            if (!performKeyExchange()) {
                VPNLogger.error("Key exchange failed");
                return false;
            }
            
            connected = true;
            VPNLogger.info("VPN Tunnel established!");
            
            startPacketReceiver();
            startHeartbeatSender();
            startSOCKS5Proxy();
            startKillSwitch();
            
            return true;
            
        } catch (Exception e) {
            VPNLogger.error("Connection failed", e);
            return false;
        }
    }
    
    private boolean performKeyExchange() {
        try {
            VPNLogger.info("Performing RSA key exchange...");
            
            KeyPair clientKeyPair = EncryptionManager.generateRSAKeyPair();
            VPNPacket initPacket = VPNPacket.createHandshakeInit(clientKeyPair.getPublic().getEncoded());
            sendPacket(initPacket);
            
            VPNLogger.debug("Sent RSA public key to server");
            
            VPNPacket responsePacket = VPNPacket.fromStream(in);
            if (responsePacket.getType() != VPNPacket.TYPE_HANDSHAKE_RESPONSE) {
                VPNLogger.error("Expected HANDSHAKE_RESPONSE, got: " + responsePacket.getTypeString());
                return false;
            }
            
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(responsePacket.getPayload()));
            int aesLen = dis.readInt();
            byte[] encryptedAES = new byte[aesLen];
            dis.readFully(encryptedAES);
            int hmacLen = dis.readInt();
            byte[] encryptedHMAC = new byte[hmacLen];
            dis.readFully(encryptedHMAC);
            
            SecretKey aesKey = EncryptionManager.decryptKeyWithRSA(
                encryptedAES, clientKeyPair.getPrivate(), "AES");
            SecretKey hmacKey = EncryptionManager.decryptKeyWithRSA(
                encryptedHMAC, clientKeyPair.getPrivate(), "HmacSHA256");
            
            VPNLogger.debug("Decrypted session keys");
            
            VPNPacket ackPacket = VPNPacket.createHandshakeAck();
            sendPacket(ackPacket);
            
            encryptionManager = new EncryptionManager(aesKey, hmacKey);
            
            VPNLogger.info("Establishing encrypted tunnel...");
            return true;
            
        } catch (Exception e) {
            VPNLogger.error("Key exchange error", e);
            return false;
        }
    }
    
    private void startPacketReceiver() {
        executor.submit(() -> {
            while (connected) {
                try {
                    VPNPacket packet = VPNPacket.fromStream(in);
                    handlePacket(packet);
                } catch (EOFException e) {
                    VPNLogger.error("Connection closed by server");
                    disconnect();
                    break;
                } catch (Exception e) {
                    if (connected) {
                        VPNLogger.error("Packet receive error", e);
                        disconnect();
                    }
                    break;
                }
            }
        });
    }
    
    private void handlePacket(VPNPacket packet) throws Exception {
        switch (packet.getType()) {
            case VPNPacket.TYPE_DATA:
                handleDataPacket(packet);
                break;
                
            case VPNPacket.TYPE_HEARTBEAT:
                VPNLogger.debug("Heartbeat received from server");
                break;
                
            case VPNPacket.TYPE_DISCONNECT:
                VPNLogger.info("Disconnect request from server");
                disconnect();
                break;
                
            default:
                VPNLogger.warning("Unknown packet type: " + packet.getTypeString());
        }
    }
    
    private void handleDataPacket(VPNPacket packet) throws Exception {
        byte[] computedHMAC = encryptionManager.computeHMAC(packet.getPayload());
        byte[] truncatedHMAC = Arrays.copyOf(computedHMAC, 16);
        
        if (!Arrays.equals(truncatedHMAC, packet.getHMAC())) {
            VPNLogger.error("HMAC verification failed");
            return;
        }
        
        byte[] decryptedData = encryptionManager.decrypt(packet.getPayload());
        bytesIn.addAndGet(decryptedData.length);
        
        // Parse session ID from response
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(decryptedData));
        int sessionIdLen = dis.readUnsignedByte();
        byte[] sessionIdBytes = new byte[sessionIdLen];
        dis.readFully(sessionIdBytes);
        String sessionId = new String(sessionIdBytes);
        
        // Read actual response data
        byte[] responseData = new byte[dis.available()];
        dis.readFully(responseData);
        
        // Route to correct session
        VPNSession session = activeSessions.get(sessionId);
        if (session != null && session.isActive()) {
            session.queueReceiveData(responseData);
            VPNLogger.debug("Routed " + responseData.length + " bytes to session " + sessionId);
        } else {
            VPNLogger.warning("Received data for unknown/inactive session: " + sessionId);
        }
    }
    
    /**
     * Create a new session for a SOCKS5 connection
     */
    public VPNSession createSession(String host, int port) {
        String sessionId = "S-" + sessionCounter.incrementAndGet();
        VPNSession session = new VPNSession(sessionId, host, port);
        activeSessions.put(sessionId, session);
        VPNLogger.debug("Created session " + sessionId + " for " + host + ":" + port);
        return session;
    }
    
    /**
     * Send data through a specific session
     */
    public void sendSessionData(VPNSession session, byte[] data) throws Exception {
        if (!connected) {
            throw new IOException("VPN tunnel not connected");
        }
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        
        // Write session ID
        byte[] sessionIdBytes = session.getSessionId().getBytes();
        dos.writeByte(sessionIdBytes.length);
        dos.write(sessionIdBytes);
        
        // Write connection info (only needed on first packet, but included for simplicity)
        dos.writeByte(session.getHost().length());
        dos.write(session.getHost().getBytes());
        dos.writeShort(session.getPort());
        
        // Write actual data
        dos.write(data);
        dos.flush();
        
        byte[] requestData = baos.toByteArray();
        
        // Encrypt
        byte[] encrypted = encryptionManager.encrypt(requestData);
        byte[] hmac = encryptionManager.computeHMAC(encrypted);
        byte[] truncatedHMAC = Arrays.copyOf(hmac, 16);
        
        bytesOut.addAndGet(data.length);
        
        // Send packet
        VPNPacket packet = VPNPacket.createDataPacket(encrypted, truncatedHMAC);
        sendPacket(packet);
        
        VPNLogger.debug("Sent " + data.length + " bytes through session " + session.getSessionId());
    }
    
    /**
     * Close a session
     */
    public void closeSession(String sessionId) {
        VPNSession session = activeSessions.remove(sessionId);
        if (session != null) {
            session.close();
            VPNLogger.debug("Closed session " + sessionId);
        }
    }
    
    private void startHeartbeatSender() {
        executor.submit(() -> {
            while (connected) {
                try {
                    Thread.sleep(30000);
                    
                    byte[] timestamp = String.valueOf(System.currentTimeMillis()).getBytes();
                    byte[] hmac = encryptionManager.computeHMAC(timestamp);
                    byte[] truncatedHMAC = Arrays.copyOf(hmac, 16);
                    
                    VPNPacket heartbeat = VPNPacket.createHeartbeat(truncatedHMAC);
                    sendPacket(heartbeat);
                    
                    VPNLogger.debug("Heartbeat sent");
                    
                } catch (InterruptedException e) {
                    break;
                } catch (Exception e) {
                    VPNLogger.error("Heartbeat error", e);
                    disconnect();
                    break;
                }
            }
        });
    }
    
    private void startSOCKS5Proxy() {
        try {
            socks5Server = new SOCKS5Server(SOCKS5_PORT, this);
            executor.submit(() -> socks5Server.start());
            VPNLogger.info("SOCKS5 Proxy started on localhost:" + SOCKS5_PORT);
        } catch (IOException e) {
            VPNLogger.error("Failed to start SOCKS5 proxy", e);
        }
    }
    
    private void startKillSwitch() {
        killSwitch = new KillSwitch(this, socks5Server);
        executor.submit(() -> killSwitch.monitor());
        VPNLogger.info("Kill-switch activated");
    }
    
    private synchronized void sendPacket(VPNPacket packet) throws IOException {
        out.write(packet.toBytes());
        out.flush();
    }
    
    public boolean isConnected() {
        return connected;
    }
    
    public void disconnect() {
        if (!connected) return;
        
        connected = false;
        VPNLogger.info("Disconnecting from VPN...");
        
        try {
            VPNPacket disconnectPacket = VPNPacket.createDisconnect();
            sendPacket(disconnectPacket);
        } catch (Exception e) {
            // Ignore
        }
        
        // Close all sessions
        for (VPNSession session : activeSessions.values()) {
            session.close();
        }
        activeSessions.clear();
        
        try {
            if (socks5Server != null) socks5Server.stop();
            if (in != null) in.close();
            if (out != null) out.close();
            if (serverSocket != null) serverSocket.close();
            executor.shutdownNow();
        } catch (Exception e) {
            VPNLogger.error("Cleanup error", e);
        }
        
        VPNLogger.info("Disconnected");
    }
    
    public static void main(String[] args) {
        String serverHost = DEFAULT_SERVER;
        int serverPort = DEFAULT_SERVER_PORT;
        
        if (args.length >= 1) {
            serverHost = args[0];
        }
        if (args.length >= 2) {
            try {
                serverPort = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number. Using default: " + DEFAULT_SERVER_PORT);
            }
        }
        
        VPNLogger.banner("Java VPN Client v1.0");
        
        try {
            VPNClient client = new VPNClient(serverHost, serverPort);
            
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                client.disconnect();
            }));
            
            if (client.connect()) {
                VPNLogger.separator();
                VPNLogger.info("You can now route applications through the VPN");
                VPNLogger.info("SOCKS5 Proxy: localhost:" + SOCKS5_PORT);
                VPNLogger.info("Press Ctrl+C to disconnect");
                VPNLogger.separator();
                
                while (client.isConnected()) {
                    Thread.sleep(1000);
                }
            } else {
                VPNLogger.error("Failed to establish VPN connection");
                System.exit(1);
            }
            
        } catch (Exception e) {
            VPNLogger.error("Client error", e);
            System.exit(1);
        }
    }
}