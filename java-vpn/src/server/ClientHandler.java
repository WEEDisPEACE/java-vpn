package server;

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

/**
 * ClientHandler - Handles individual client connection on server
 * 
 * Responsibilities:
 * - Perform RSA key exchange
 * - Establish encrypted tunnel
 * - Forward traffic to internet with session management
 * - Monitor traffic statistics
 */
public class ClientHandler implements Runnable {
    
    private Socket clientSocket;
    private String clientId;
    private VPNServer server;
    private EncryptionManager encryptionManager;
    private DataInputStream in;
    private DataOutputStream out;
    private AtomicLong bytesIn;
    private AtomicLong bytesOut;
    private volatile boolean connected;
    
    // Session tracking
    private Map<String, SessionConnection> sessionConnections;
    private ExecutorService sessionExecutor;
    
    public ClientHandler(Socket socket, String clientId, VPNServer server) {
        this.clientSocket = socket;
        this.clientId = clientId;
        this.server = server;
        this.bytesIn = new AtomicLong(0);
        this.bytesOut = new AtomicLong(0);
        this.connected = true;
        this.sessionConnections = new ConcurrentHashMap<>();
        this.sessionExecutor = Executors.newCachedThreadPool();
    }
    
    @Override
    public void run() {
        try {
            in = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
            out = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
            
            if (!performKeyExchange()) {
                VPNLogger.error("Key exchange failed for " + clientId);
                cleanup();
                return;
            }
            
            VPNLogger.info("Session established: " + clientId);
            
            startHeartbeatMonitor();
            
            while (connected) {
                try {
                    VPNPacket packet = VPNPacket.fromStream(in);
                    handlePacket(packet);
                } catch (EOFException e) {
                    VPNLogger.info("Client disconnected: " + clientId);
                    break;
                } catch (Exception e) {
                    VPNLogger.error("Error processing packet for " + clientId, e);
                    break;
                }
            }
            
        } catch (Exception e) {
            VPNLogger.error("Client handler error: " + clientId, e);
        } finally {
            cleanup();
        }
    }
    
    /**
     * Perform RSA key exchange with client
     */
    private boolean performKeyExchange() {
        try {
            KeyPair serverKeyPair = EncryptionManager.generateRSAKeyPair();
            
            VPNPacket initPacket = VPNPacket.fromStream(in);
            if (initPacket.getType() != VPNPacket.TYPE_HANDSHAKE_INIT) {
                VPNLogger.error("Expected HANDSHAKE_INIT, got: " + initPacket.getTypeString());
                return false;
            }
            
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(initPacket.getPayload());
            PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);
            
            VPNLogger.debug("Received client RSA public key");
            
            SecretKey aesKey = EncryptionManager.generateAESKey();
            SecretKey hmacKey = EncryptionManager.generateHMACKey();
            
            byte[] encryptedAES = EncryptionManager.encryptKeyWithRSA(aesKey, clientPublicKey);
            byte[] encryptedHMAC = EncryptionManager.encryptKeyWithRSA(hmacKey, clientPublicKey);
            
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeInt(encryptedAES.length);
            dos.write(encryptedAES);
            dos.writeInt(encryptedHMAC.length);
            dos.write(encryptedHMAC);
            dos.flush();
            
            VPNPacket responsePacket = VPNPacket.createHandshakeResponse(baos.toByteArray());
            sendPacket(responsePacket);
            
            VPNLogger.debug("Sent encrypted session keys to client");
            
            VPNPacket ackPacket = VPNPacket.fromStream(in);
            if (ackPacket.getType() != VPNPacket.TYPE_HANDSHAKE_ACK) {
                VPNLogger.error("Expected HANDSHAKE_ACK, got: " + ackPacket.getTypeString());
                return false;
            }
            
            encryptionManager = new EncryptionManager(aesKey, hmacKey);
            
            VPNLogger.info("RSA key exchange completed for " + clientId);
            return true;
            
        } catch (Exception e) {
            VPNLogger.error("Key exchange error", e);
            return false;
        }
    }
    
    /**
     * Handle incoming VPN packet
     */
    private void handlePacket(VPNPacket packet) throws Exception {
        switch (packet.getType()) {
            case VPNPacket.TYPE_DATA:
                handleDataPacket(packet);
                break;
                
            case VPNPacket.TYPE_HEARTBEAT:
                handleHeartbeat(packet);
                break;
                
            case VPNPacket.TYPE_DISCONNECT:
                VPNLogger.info("Disconnect request from " + clientId);
                connected = false;
                break;
                
            default:
                VPNLogger.warning("Unknown packet type: " + packet.getTypeString());
        }
    }
    
    /**
     * Handle encrypted data packet - forward to internet with session management
     */
    private void handleDataPacket(VPNPacket packet) throws Exception {
        // Verify HMAC
        byte[] computedHMAC = encryptionManager.computeHMAC(packet.getPayload());
        byte[] truncatedHMAC = Arrays.copyOf(computedHMAC, 16);
        
        if (!Arrays.equals(truncatedHMAC, packet.getHMAC())) {
            VPNLogger.error("HMAC verification failed for " + clientId);
            return;
        }
        
        // Decrypt payload
        byte[] decryptedData = encryptionManager.decrypt(packet.getPayload());
        bytesIn.addAndGet(decryptedData.length);
        
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(decryptedData));
        
        // Read session ID
        int sessionIdLen = dis.readUnsignedByte();
        byte[] sessionIdBytes = new byte[sessionIdLen];
        dis.readFully(sessionIdBytes);
        String sessionId = new String(sessionIdBytes);
        
        // Read destination
        int hostLen = dis.readUnsignedByte();
        byte[] hostBytes = new byte[hostLen];
        dis.readFully(hostBytes);
        String host = new String(hostBytes);
        int port = dis.readUnsignedShort();
        
        // Read data to forward
        byte[] dataToForward = new byte[dis.available()];
        dis.readFully(dataToForward);
        
        VPNLogger.request(clientId + "/" + sessionId, host + ":" + port);
        
        // Get or create session connection
        SessionConnection sessionConn = sessionConnections.get(sessionId);
        if (sessionConn == null) {
            sessionConn = new SessionConnection(sessionId, host, port);
            sessionConnections.put(sessionId, sessionConn);
            VPNLogger.debug("Created new session connection: " + sessionId);
        }
        
        // Forward data
        sessionConn.forwardData(dataToForward);
    }
    
    /**
     * Handle heartbeat packet
     */
    private void handleHeartbeat(VPNPacket packet) throws Exception {
        VPNLogger.debug("Heartbeat received from " + clientId);
        
        byte[] heartbeatData = String.valueOf(System.currentTimeMillis()).getBytes();
        byte[] hmac = encryptionManager.computeHMAC(heartbeatData);
        byte[] truncatedHMAC = Arrays.copyOf(hmac, 16);
        
        VPNPacket heartbeatResponse = VPNPacket.createHeartbeat(truncatedHMAC);
        sendPacket(heartbeatResponse);
    }
    
    /**
     * Start heartbeat monitoring thread
     */
    private void startHeartbeatMonitor() {
        Thread monitor = new Thread(() -> {
            long lastHeartbeat = System.currentTimeMillis();
            while (connected) {
                try {
                    Thread.sleep(30000);
                    
                    if (System.currentTimeMillis() - lastHeartbeat > 90000) {
                        VPNLogger.warning("Heartbeat timeout for " + clientId);
                        connected = false;
                        break;
                    }
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        monitor.setDaemon(true);
        monitor.start();
    }
    
    /**
     * Send packet to client
     */
    private synchronized void sendPacket(VPNPacket packet) throws IOException {
        out.write(packet.toBytes());
        out.flush();
    }
    
    /**
     * Send data back to client for a specific session
     */
    private void sendSessionResponse(String sessionId, byte[] data) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            
            // Write session ID
            byte[] sessionIdBytes = sessionId.getBytes();
            dos.writeByte(sessionIdBytes.length);
            dos.write(sessionIdBytes);
            
            // Write response data
            dos.write(data);
            dos.flush();
            
            byte[] responseData = baos.toByteArray();
            
            // Encrypt
            byte[] encrypted = encryptionManager.encrypt(responseData);
            byte[] hmac = encryptionManager.computeHMAC(encrypted);
            byte[] truncatedHMAC = Arrays.copyOf(hmac, 16);
            
            bytesOut.addAndGet(data.length);
            
            // Send packet
            VPNPacket packet = VPNPacket.createDataPacket(encrypted, truncatedHMAC);
            sendPacket(packet);
            
            VPNLogger.debug("Sent " + data.length + " bytes to session " + sessionId);
            
            // Update stats periodically
            if (bytesOut.get() % 10240 == 0) {
                VPNLogger.traffic(clientId, bytesIn.get(), bytesOut.get());
                server.updateStats(bytesIn.get(), bytesOut.get());
            }
            
        } catch (Exception e) {
            VPNLogger.error("Failed to send response for session " + sessionId, e);
        }
    }
    
    /**
     * Cleanup resources
     */
    private void cleanup() {
        connected = false;
        
        // Close all session connections
        for (SessionConnection conn : sessionConnections.values()) {
            conn.close();
        }
        sessionConnections.clear();
        
        try {
            sessionExecutor.shutdownNow();
            if (in != null) in.close();
            if (out != null) out.close();
            if (clientSocket != null) clientSocket.close();
        } catch (IOException e) {
            VPNLogger.error("Cleanup error", e);
        }
        server.removeClient(clientId);
    }
    
    /**
     * Represents a persistent connection to a destination server for a session
     */
    private class SessionConnection {
        private String sessionId;
        private String host;
        private int port;
        private Socket destSocket;
        private OutputStream destOut;
        private InputStream destIn;
        private volatile boolean active;
        private volatile boolean connected;
        
        SessionConnection(String sessionId, String host, int port) {
            this.sessionId = sessionId;
            this.host = host;
            this.port = port;
            this.active = true;
            this.connected = false;
        }
        
        private synchronized void connect() throws IOException {
            if (!connected) {
                destSocket = new Socket();
                destSocket.connect(new InetSocketAddress(host, port), 10000);
                destSocket.setSoTimeout(30000); // 30 second read timeout
                destOut = destSocket.getOutputStream();
                destIn = destSocket.getInputStream();
                connected = true;
                VPNLogger.debug("Connected to " + host + ":" + port + " for session " + sessionId);
                
                // Start receiver AFTER connection is established
                startReceiver();
            }
        }
        
        void forwardData(byte[] data) throws IOException {
            // Ensure connection is established before forwarding
            if (!connected) {
                connect();
            }
            
            if (data.length > 0 && destOut != null) {
                destOut.write(data);
                destOut.flush();
            }
        }
        
        private void startReceiver() {
            sessionExecutor.submit(() -> {
                try {
                    if (!connected || destIn == null) {
                        VPNLogger.error("Cannot start receiver - not connected");
                        return;
                    }
                    
                    VPNLogger.debug("Started receiver for session " + sessionId);
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    
                    // Keep reading until connection closes or error occurs
                    while (active && connected) {
                        try {
                            bytesRead = destIn.read(buffer);
                            if (bytesRead == -1) {
                                VPNLogger.debug("Destination closed connection for session " + sessionId);
                                break;
                            }
                            
                            byte[] responseData = new byte[bytesRead];
                            System.arraycopy(buffer, 0, responseData, 0, bytesRead);
                            
                            // Send back to client through VPN tunnel
                            sendSessionResponse(sessionId, responseData);
                            
                        } catch (SocketTimeoutException e) {
                            // Timeout is OK, just continue reading
                            continue;
                        }
                    }
                    
                    VPNLogger.debug("Receiver loop ended for session " + sessionId);
                    
                } catch (IOException e) {
                    if (active && connected) {
                        VPNLogger.debug("Session " + sessionId + " receiver error: " + e.getMessage());
                    }
                } finally {
                    close();
                }
            });
        }
        
        void close() {
            active = false;
            connected = false;
            try {
                if (destSocket != null && !destSocket.isClosed()) {
                    destSocket.close();
                }
            } catch (IOException e) {
                // Ignore
            }
            sessionConnections.remove(sessionId);
            VPNLogger.debug("Closed session connection: " + sessionId);
        }
    }
}