package client;

import crypto.EncryptionManager;
import logging.VPNLogger;
import tunnel.VPNPacket;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * VPNClient - Connects to VPN server and provides SOCKS5 proxy
 * 
 * Features:
 * - Connects to VPN server
 * - Performs RSA key exchange
 * - Establishes encrypted tunnel
 * - Runs SOCKS5 proxy for applications
 * - Kill-switch functionality
 */
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
    private BlockingQueue<byte[]> responseQueue;
    private AtomicLong bytesIn;
    private AtomicLong bytesOut;
    private volatile boolean connected;
    
    public VPNClient(String serverHost, int serverPort) throws IOException {
        this.serverSocket = new Socket(serverHost, serverPort);
        this.in = new DataInputStream(new BufferedInputStream(serverSocket.getInputStream()));
        this.out = new DataOutputStream(new BufferedOutputStream(serverSocket.getOutputStream()));
        this.executor = Executors.newCachedThreadPool();
        this.responseQueue = new LinkedBlockingQueue<>();
        this.bytesIn = new AtomicLong(0);
        this.bytesOut = new AtomicLong(0);
        this.connected = false;
    }
    
    /**
     * Connect to VPN server and establish tunnel
     */
    public boolean connect() {
        try {
            VPNLogger.info("Connecting to VPN Server: " + serverSocket.getRemoteSocketAddress());
            
            // Perform key exchange
            if (!performKeyExchange()) {
                VPNLogger.error("Key exchange failed");
                return false;
            }
            
            connected = true;
            VPNLogger.info("VPN Tunnel established!");
            
            // Start packet receiver
            startPacketReceiver();
            
            // Start heartbeat sender
            startHeartbeatSender();
            
            // Start SOCKS5 proxy
            startSOCKS5Proxy();
            
            // Start kill-switch
            startKillSwitch();
            
            return true;
            
        } catch (Exception e) {
            VPNLogger.error("Connection failed", e);
            return false;
        }
    }
    
    /**
     * Perform RSA key exchange with server
     */
    private boolean performKeyExchange() {
        try {
            VPNLogger.info("Performing RSA key exchange...");
            
            // Step 1: Generate client RSA keys
            KeyPair clientKeyPair = EncryptionManager.generateRSAKeyPair();
            
            // Step 2: Send public key to server
            VPNPacket initPacket = VPNPacket.createHandshakeInit(clientKeyPair.getPublic().getEncoded());
            sendPacket(initPacket);
            
            VPNLogger.debug("Sent RSA public key to server");
            
            // Step 3: Receive encrypted session keys from server
            VPNPacket responsePacket = VPNPacket.fromStream(in);
            if (responsePacket.getType() != VPNPacket.TYPE_HANDSHAKE_RESPONSE) {
                VPNLogger.error("Expected HANDSHAKE_RESPONSE, got: " + responsePacket.getTypeString());
                return false;
            }
            
            // Parse encrypted keys
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(responsePacket.getPayload()));
            int aesLen = dis.readInt();
            byte[] encryptedAES = new byte[aesLen];
            dis.readFully(encryptedAES);
            int hmacLen = dis.readInt();
            byte[] encryptedHMAC = new byte[hmacLen];
            dis.readFully(encryptedHMAC);
            
            // Step 4: Decrypt session keys with private key
            SecretKey aesKey = EncryptionManager.decryptKeyWithRSA(
                encryptedAES, clientKeyPair.getPrivate(), "AES");
            SecretKey hmacKey = EncryptionManager.decryptKeyWithRSA(
                encryptedHMAC, clientKeyPair.getPrivate(), "HmacSHA256");
            
            VPNLogger.debug("Decrypted session keys");
            
            // Step 5: Send acknowledgment
            VPNPacket ackPacket = VPNPacket.createHandshakeAck();
            sendPacket(ackPacket);
            
            // Initialize encryption manager
            encryptionManager = new EncryptionManager(aesKey, hmacKey);
            
            VPNLogger.info("Establishing encrypted tunnel...");
            return true;
            
        } catch (Exception e) {
            VPNLogger.error("Key exchange error", e);
            return false;
        }
    }
    
    /**
     * Start packet receiver thread
     */
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
    
    /**
     * Handle incoming packet from server
     */
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
    
    /**
     * Handle data packet from server
     */
    private void handleDataPacket(VPNPacket packet) throws Exception {
        // Verify HMAC
        byte[] computedHMAC = encryptionManager.computeHMAC(packet.getPayload());
        byte[] truncatedHMAC = Arrays.copyOf(computedHMAC, 16);
        
        if (!Arrays.equals(truncatedHMAC, packet.getHMAC())) {
            VPNLogger.error("HMAC verification failed");
            return;
        }
        
        // Decrypt payload
        byte[] decryptedData = encryptionManager.decrypt(packet.getPayload());
        bytesIn.addAndGet(decryptedData.length);
        
        // Add to response queue for SOCKS5 server
        responseQueue.offer(decryptedData);
        
        VPNLogger.debug("Received: " + decryptedData.length + " bytes → Decrypted");
    }
    
    /**
     * Send data through VPN tunnel
     */
    public byte[] sendThroughTunnel(String host, int port, byte[] data) throws Exception {
        if (!connected) {
            throw new IOException("VPN tunnel not connected");
        }
        
        // Build request packet
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        
        dos.writeByte(0x01); // Request type: CONNECT
        dos.writeByte(host.length());
        dos.write(host.getBytes());
        dos.writeShort(port);
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
        
        VPNLogger.debug("Encrypted: " + data.length + " bytes → Sent through tunnel");
        
        // Wait for response (with timeout)
        byte[] response = responseQueue.poll(10, TimeUnit.SECONDS);
        if (response == null) {
            throw new IOException("Response timeout");
        }
        
        return response;
    }
    
    /**
     * Start heartbeat sender
     */
    private void startHeartbeatSender() {
        executor.submit(() -> {
            while (connected) {
                try {
                    Thread.sleep(30000); // Every 30 seconds
                    
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
    
    /**
     * Start SOCKS5 proxy server
     */
    private void startSOCKS5Proxy() {
        try {
            socks5Server = new SOCKS5Server(SOCKS5_PORT, this);
            executor.submit(() -> socks5Server.start());
            VPNLogger.info("SOCKS5 Proxy started on localhost:" + SOCKS5_PORT);
        } catch (IOException e) {
            VPNLogger.error("Failed to start SOCKS5 proxy", e);
        }
    }
    
    /**
     * Start kill-switch
     */
    private void startKillSwitch() {
        killSwitch = new KillSwitch(this, socks5Server);
        executor.submit(() -> killSwitch.monitor());
        VPNLogger.info("Kill-switch activated");
    }
    
    /**
     * Send packet to server
     */
    private synchronized void sendPacket(VPNPacket packet) throws IOException {
        out.write(packet.toBytes());
        out.flush();
    }
    
    /**
     * Check if tunnel is connected
     */
    public boolean isConnected() {
        return connected;
    }
    
    /**
     * Disconnect from VPN server
     */
    public void disconnect() {
        if (!connected) return;
        
        connected = false;
        VPNLogger.info("Disconnecting from VPN...");
        
        try {
            // Send disconnect packet
            VPNPacket disconnectPacket = VPNPacket.createDisconnect();
            sendPacket(disconnectPacket);
        } catch (Exception e) {
            // Ignore
        }
        
        // Cleanup
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
    
    /**
     * Main entry point
     */
    public static void main(String[] args) {
        String serverHost = DEFAULT_SERVER;
        int serverPort = DEFAULT_SERVER_PORT;
        
        // Parse command line arguments
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
            
            // Shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                client.disconnect();
            }));
            
            if (client.connect()) {
                VPNLogger.separator();
                VPNLogger.info("You can now route applications through the VPN");
                VPNLogger.info("SOCKS5 Proxy: localhost:" + SOCKS5_PORT);
                VPNLogger.info("Press Ctrl+C to disconnect");
                VPNLogger.separator();
                
                // Keep main thread alive
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