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
import java.util.concurrent.atomic.AtomicLong;

/**
 * ClientHandler - Handles individual client connection on server
 * 
 * Responsibilities:
 * - Perform RSA key exchange
 * - Establish encrypted tunnel
 * - Forward traffic to internet
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
    
    public ClientHandler(Socket socket, String clientId, VPNServer server) {
        this.clientSocket = socket;
        this.clientId = clientId;
        this.server = server;
        this.bytesIn = new AtomicLong(0);
        this.bytesOut = new AtomicLong(0);
        this.connected = true;
    }
    
    @Override
    public void run() {
        try {
            in = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
            out = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
            
            // Perform key exchange
            if (!performKeyExchange()) {
                VPNLogger.error("Key exchange failed for " + clientId);
                cleanup();
                return;
            }
            
            VPNLogger.info("Session established: " + clientId);
            
            // Start heartbeat monitor
            startHeartbeatMonitor();
            
            // Main packet processing loop
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
            // Step 1: Generate server RSA keys
            KeyPair serverKeyPair = EncryptionManager.generateRSAKeyPair();
            
            // Step 2: Receive client's public key
            VPNPacket initPacket = VPNPacket.fromStream(in);
            if (initPacket.getType() != VPNPacket.TYPE_HANDSHAKE_INIT) {
                VPNLogger.error("Expected HANDSHAKE_INIT, got: " + initPacket.getTypeString());
                return false;
            }
            
            // Parse client public key
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(initPacket.getPayload());
            PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);
            
            VPNLogger.debug("Received client RSA public key");
            
            // Step 3: Generate session keys
            SecretKey aesKey = EncryptionManager.generateAESKey();
            SecretKey hmacKey = EncryptionManager.generateHMACKey();
            
            // Step 4: Encrypt session keys with client's public key
            byte[] encryptedAES = EncryptionManager.encryptKeyWithRSA(aesKey, clientPublicKey);
            byte[] encryptedHMAC = EncryptionManager.encryptKeyWithRSA(hmacKey, clientPublicKey);
            
            // Combine encrypted keys
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeInt(encryptedAES.length);
            dos.write(encryptedAES);
            dos.writeInt(encryptedHMAC.length);
            dos.write(encryptedHMAC);
            dos.flush();
            
            // Step 5: Send encrypted keys to client
            VPNPacket responsePacket = VPNPacket.createHandshakeResponse(baos.toByteArray());
            sendPacket(responsePacket);
            
            VPNLogger.debug("Sent encrypted session keys to client");
            
            // Step 6: Wait for acknowledgment
            VPNPacket ackPacket = VPNPacket.fromStream(in);
            if (ackPacket.getType() != VPNPacket.TYPE_HANDSHAKE_ACK) {
                VPNLogger.error("Expected HANDSHAKE_ACK, got: " + ackPacket.getTypeString());
                return false;
            }
            
            // Initialize encryption manager
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
     * Handle encrypted data packet - forward to internet
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
        
        // Parse SOCKS request (simplified)
        // Format: [1 byte: type][host length][host][2 bytes: port][data]
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(decryptedData));
        
        byte requestType = dis.readByte();
        int hostLen = dis.readUnsignedByte();
        byte[] hostBytes = new byte[hostLen];
        dis.readFully(hostBytes);
        String host = new String(hostBytes);
        int port = dis.readUnsignedShort();
        
        // Read actual data to forward
        byte[] dataToForward = new byte[dis.available()];
        dis.readFully(dataToForward);
        
        VPNLogger.request(clientId, host + ":" + port);
        
        // Forward to destination
        byte[] response = forwardToDestination(host, port, dataToForward);
        
        if (response != null) {
            // Encrypt response
            byte[] encryptedResponse = encryptionManager.encrypt(response);
            byte[] responseHMAC = encryptionManager.computeHMAC(encryptedResponse);
            byte[] truncatedResponseHMAC = Arrays.copyOf(responseHMAC, 16);
            
            // Send back to client
            VPNPacket responsePacket = VPNPacket.createDataPacket(encryptedResponse, truncatedResponseHMAC);
            sendPacket(responsePacket);
            
            bytesOut.addAndGet(response.length);
            
            // Log traffic periodically
            if (bytesOut.get() % 10240 == 0) { // Every ~10KB
                VPNLogger.traffic(clientId, bytesIn.get(), bytesOut.get());
                server.updateStats(bytesIn.get(), bytesOut.get());
            }
        }
    }
    
    /**
     * Forward data to actual destination on the internet
     */
    private byte[] forwardToDestination(String host, int port, byte[] data) {
        try (Socket destSocket = new Socket()) {
            destSocket.connect(new InetSocketAddress(host, port), 5000);
            
            OutputStream destOut = destSocket.getOutputStream();
            InputStream destIn = destSocket.getInputStream();
            
            // Send data
            if (data.length > 0) {
                destOut.write(data);
                destOut.flush();
            }
            
            // Read response (with timeout)
            destSocket.setSoTimeout(10000);
            ByteArrayOutputStream responseBuffer = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            
            while ((bytesRead = destIn.read(buffer)) != -1) {
                responseBuffer.write(buffer, 0, bytesRead);
                if (destIn.available() == 0) break; // No more data immediately available
            }
            
            return responseBuffer.toByteArray();
            
        } catch (IOException e) {
            VPNLogger.error("Failed to forward to " + host + ":" + port, e);
            return null;
        }
    }
    
    /**
     * Handle heartbeat packet
     */
    private void handleHeartbeat(VPNPacket packet) throws Exception {
        VPNLogger.debug("Heartbeat received from " + clientId);
        
        // Send heartbeat response
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
                    Thread.sleep(30000); // Check every 30 seconds
                    
                    if (System.currentTimeMillis() - lastHeartbeat > 90000) { // 90 second timeout
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
     * Cleanup resources
     */
    private void cleanup() {
        connected = false;
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (clientSocket != null) clientSocket.close();
        } catch (IOException e) {
            VPNLogger.error("Cleanup error", e);
        }
        server.removeClient(clientId);
    }
}