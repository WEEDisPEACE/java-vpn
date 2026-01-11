package client;

import logging.VPNLogger;

import java.io.*;
import java.net.*;
import java.util.concurrent.*;

/**
 * SOCKS5Server - SOCKS5 proxy server for routing application traffic through VPN
 * 
 * Implements SOCKS5 protocol (RFC 1928)
 * - No authentication required (guest mode)
 * - CONNECT command support
 * - IPv4 and domain name support
 */
public class SOCKS5Server {
    
    private static final byte SOCKS_VERSION = 0x05;
    private static final byte NO_AUTH = 0x00;
    private static final byte CMD_CONNECT = 0x01;
    private static final byte ATYP_IPV4 = 0x01;
    private static final byte ATYP_DOMAIN = 0x03;
    private static final byte REP_SUCCESS = 0x00;
    
    private ServerSocket serverSocket;
    private VPNClient vpnClient;
    private ExecutorService threadPool;
    private volatile boolean running;
    
    public SOCKS5Server(int port, VPNClient vpnClient) throws IOException {
        this.serverSocket = new ServerSocket(port);
        this.vpnClient = vpnClient;
        this.threadPool = Executors.newCachedThreadPool();
        this.running = false;
    }
    
    /**
     * Start accepting SOCKS5 connections
     */
    public void start() {
        running = true;
        VPNLogger.debug("SOCKS5 Server listening on port " + serverSocket.getLocalPort());
        
        while (running) {
            try {
                Socket clientSocket = serverSocket.accept();
                VPNLogger.debug("SOCKS5: New connection from " + clientSocket.getRemoteSocketAddress());
                
                threadPool.submit(() -> handleClient(clientSocket));
                
            } catch (IOException e) {
                if (running) {
                    VPNLogger.error("Error accepting SOCKS5 connection", e);
                }
            }
        }
    }
    
    /**
     * Handle individual SOCKS5 client connection
     */
    private void handleClient(Socket clientSocket) {
        try (InputStream in = clientSocket.getInputStream();
             OutputStream out = clientSocket.getOutputStream()) {
            
            // Step 1: Greeting and authentication negotiation
            if (!handleGreeting(in, out)) {
                VPNLogger.error("SOCKS5: Greeting failed");
                return;
            }
            
            // Step 2: Request handling
            ConnectionInfo connInfo = handleRequest(in, out);
            if (connInfo == null) {
                VPNLogger.error("SOCKS5: Request handling failed");
                return;
            }
            
            VPNLogger.info("REQUEST: CONNECT " + connInfo.host + ":" + connInfo.port);
            
            // Step 3: Establish persistent tunnel and proxy bidirectional data
            proxyDataBidirectional(clientSocket, in, out, connInfo);
            
        } catch (Exception e) {
            VPNLogger.error("SOCKS5 client handler error", e);
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }
    
    /**
     * Handle SOCKS5 greeting
     * Client -> Server: [VER][NMETHODS][METHODS]
     * Server -> Client: [VER][METHOD]
     */
    private boolean handleGreeting(InputStream in, OutputStream out) throws IOException {
        // Read greeting
        int version = in.read();
        if (version != SOCKS_VERSION) {
            VPNLogger.error("Unsupported SOCKS version: " + version);
            return false;
        }
        
        int nMethods = in.read();
        byte[] methods = new byte[nMethods];
        in.read(methods);
        
        // We only support NO_AUTH (0x00)
        boolean noAuthSupported = false;
        for (byte method : methods) {
            if (method == NO_AUTH) {
                noAuthSupported = true;
                break;
            }
        }
        
        if (!noAuthSupported) {
            out.write(new byte[]{SOCKS_VERSION, (byte) 0xFF}); // No acceptable methods
            return false;
        }
        
        // Send selected method: NO_AUTH
        out.write(new byte[]{SOCKS_VERSION, NO_AUTH});
        out.flush();
        
        return true;
    }
    
    /**
     * Handle SOCKS5 request
     * Client -> Server: [VER][CMD][RSV][ATYP][DST.ADDR][DST.PORT]
     * Server -> Client: [VER][REP][RSV][ATYP][BND.ADDR][BND.PORT]
     */
    private ConnectionInfo handleRequest(InputStream in, OutputStream out) throws IOException {
        // Read request
        int version = in.read();
        if (version != SOCKS_VERSION) {
            return null;
        }
        
        int cmd = in.read();
        if (cmd != CMD_CONNECT) {
            sendReply(out, (byte) 0x07); // Command not supported
            return null;
        }
        
        int rsv = in.read(); // Reserved byte
        int atyp = in.read();
        
        String host;
        int port;
        
        // Parse destination address
        if (atyp == ATYP_IPV4) {
            // IPv4 address (4 bytes)
            byte[] addr = new byte[4];
            in.read(addr);
            host = InetAddress.getByAddress(addr).getHostAddress();
            
        } else if (atyp == ATYP_DOMAIN) {
            // Domain name
            int len = in.read();
            byte[] domainBytes = new byte[len];
            in.read(domainBytes);
            host = new String(domainBytes);
            
        } else {
            sendReply(out, (byte) 0x08); // Address type not supported
            return null;
        }
        
        // Read port (2 bytes, big-endian)
        port = (in.read() << 8) | in.read();
        
        // Send success reply
        sendReply(out, REP_SUCCESS);
        
        return new ConnectionInfo(host, port);
    }
    
    /**
     * Send SOCKS5 reply
     */
    private void sendReply(OutputStream out, byte rep) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(SOCKS_VERSION);
        baos.write(rep);
        baos.write(0x00); // Reserved
        baos.write(ATYP_IPV4);
        baos.write(new byte[]{0, 0, 0, 0}); // Bind address (0.0.0.0)
        baos.write(new byte[]{0, 0}); // Bind port (0)
        
        out.write(baos.toByteArray());
        out.flush();
    }
    
    /**
     * Proxy data bidirectionally between client and VPN tunnel
     * This is the key fix - we need bidirectional communication, not request-response
     */
    private void proxyDataBidirectional(Socket clientSocket, InputStream clientIn, 
                                       OutputStream clientOut, ConnectionInfo connInfo) {
        // Create a virtual connection through the VPN tunnel
        VPNTunnelConnection tunnelConn = new VPNTunnelConnection(vpnClient, connInfo.host, connInfo.port);
        
        // Start bidirectional data transfer
        ExecutorService executor = Executors.newFixedThreadPool(2);
        
        try {
            // Thread 1: Client -> VPN Tunnel
            Future<?> clientToTunnel = executor.submit(() -> {
                try {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = clientIn.read(buffer)) != -1) {
                        byte[] dataToSend = new byte[bytesRead];
                        System.arraycopy(buffer, 0, dataToSend, 0, bytesRead);
                        tunnelConn.send(dataToSend);
                    }
                } catch (Exception e) {
                    VPNLogger.debug("Client to tunnel closed: " + e.getMessage());
                } finally {
                    tunnelConn.close();
                }
            });
            
            // Thread 2: VPN Tunnel -> Client
            Future<?> tunnelToClient = executor.submit(() -> {
                try {
                    while (true) {
                        byte[] data = tunnelConn.receive();
                        if (data == null || data.length == 0) {
                            break;
                        }
                        clientOut.write(data);
                        clientOut.flush();
                    }
                } catch (Exception e) {
                    VPNLogger.debug("Tunnel to client closed: " + e.getMessage());
                }
            });
            
            // Wait for both threads to complete
            clientToTunnel.get();
            tunnelToClient.get();
            
        } catch (Exception e) {
            VPNLogger.debug("Proxy connection error: " + e.getMessage());
        } finally {
            executor.shutdownNow();
            tunnelConn.close();
        }
    }
    
    /**
     * Stop SOCKS5 server
     */
    public void stop() {
        running = false;
        try {
            serverSocket.close();
            threadPool.shutdown();
            threadPool.awaitTermination(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            VPNLogger.error("Error stopping SOCKS5 server", e);
        }
        VPNLogger.info("SOCKS5 Proxy stopped");
    }
    
    /**
     * Helper class to store connection information
     */
    private static class ConnectionInfo {
        String host;
        int port;
        
        ConnectionInfo(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }
    
    /**
     * Represents a persistent connection through the VPN tunnel
     */
    private static class VPNTunnelConnection {
        private VPNClient vpnClient;
        private String host;
        private int port;
        private BlockingQueue<byte[]> receiveQueue;
        private volatile boolean closed = false;
        
        VPNTunnelConnection(VPNClient vpnClient, String host, int port) {
            this.vpnClient = vpnClient;
            this.host = host;
            this.port = port;
            this.receiveQueue = new LinkedBlockingQueue<>();
        }
        
        void send(byte[] data) throws Exception {
            if (closed) return;
            byte[] response = vpnClient.sendThroughTunnel(host, port, data);
            if (response != null && response.length > 0) {
                receiveQueue.offer(response);
            }
        }
        
        byte[] receive() throws InterruptedException {
            if (closed) return null;
            return receiveQueue.poll(30, TimeUnit.SECONDS);
        }
        
        void close() {
            closed = true;
        }
    }
}