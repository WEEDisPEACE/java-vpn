package client;

import logging.VPNLogger;

import java.io.*;
import java.net.*;
import java.util.concurrent.*;

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
    
    private void handleClient(Socket clientSocket) {
        VPNSession session = null;
        try {
            InputStream in = clientSocket.getInputStream();
            OutputStream out = clientSocket.getOutputStream();
            
            if (!handleGreeting(in, out)) {
                VPNLogger.error("SOCKS5: Greeting failed");
                return;
            }
            
            ConnectionInfo connInfo = handleRequest(in, out);
            if (connInfo == null) {
                VPNLogger.error("SOCKS5: Request handling failed");
                return;
            }
            
            VPNLogger.info("REQUEST: CONNECT " + connInfo.host + ":" + connInfo.port);
            
            // Create session and proxy bidirectionally (keep alive!)
            session = proxyBidirectional(clientSocket, in, out, connInfo);
            
        } catch (Exception e) {
            VPNLogger.error("SOCKS5 client handler error", e);
        } finally {
            // Clean up session
            if (session != null) {
                vpnClient.closeSession(session.getSessionId());
            }
            try {
                clientSocket.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }
    
    private boolean handleGreeting(InputStream in, OutputStream out) throws IOException {
        int version = in.read();
        if (version != SOCKS_VERSION) {
            VPNLogger.error("Unsupported SOCKS version: " + version);
            return false;
        }
        
        int nMethods = in.read();
        byte[] methods = new byte[nMethods];
        in.read(methods);
        
        boolean noAuthSupported = false;
        for (byte method : methods) {
            if (method == NO_AUTH) {
                noAuthSupported = true;
                break;
            }
        }
        
        if (!noAuthSupported) {
            out.write(new byte[]{SOCKS_VERSION, (byte) 0xFF});
            return false;
        }
        
        out.write(new byte[]{SOCKS_VERSION, NO_AUTH});
        out.flush();
        
        return true;
    }
    
    private ConnectionInfo handleRequest(InputStream in, OutputStream out) throws IOException {
        int version = in.read();
        if (version != SOCKS_VERSION) {
            return null;
        }
        
        int cmd = in.read();
        if (cmd != CMD_CONNECT) {
            sendReply(out, (byte) 0x07);
            return null;
        }
        
        int rsv = in.read();
        int atyp = in.read();
        
        String host;
        int port;
        
        if (atyp == ATYP_IPV4) {
            byte[] addr = new byte[4];
            in.read(addr);
            host = InetAddress.getByAddress(addr).getHostAddress();
            
        } else if (atyp == ATYP_DOMAIN) {
            int len = in.read();
            byte[] domainBytes = new byte[len];
            in.read(domainBytes);
            host = new String(domainBytes);
            
        } else {
            sendReply(out, (byte) 0x08);
            return null;
        }
        
        port = (in.read() << 8) | in.read();
        
        sendReply(out, REP_SUCCESS);
        
        return new ConnectionInfo(host, port);
    }
    
    private void sendReply(OutputStream out, byte rep) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(SOCKS_VERSION);
        baos.write(rep);
        baos.write(0x00);
        baos.write(ATYP_IPV4);
        baos.write(new byte[]{0, 0, 0, 0});
        baos.write(new byte[]{0, 0});
        
        out.write(baos.toByteArray());
        out.flush();
    }
    
    /**
     * Bidirectional proxy using sessions - KEEP ALIVE until socket closes
     */
    private VPNSession proxyBidirectional(Socket clientSocket, InputStream clientIn, 
                                   OutputStream clientOut, ConnectionInfo connInfo) {
        // Create VPN session
        VPNSession session = vpnClient.createSession(connInfo.host, connInfo.port);
        
        ExecutorService executor = Executors.newFixedThreadPool(2);
        
        try {
            // Client → VPN Thread (reads from client, sends through VPN)
            Future<?> clientToVpn = executor.submit(() -> {
                try {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    // Keep reading until client closes connection
                    while ((bytesRead = clientIn.read(buffer)) != -1) {
                        byte[] dataToSend = new byte[bytesRead];
                        System.arraycopy(buffer, 0, dataToSend, 0, bytesRead);
                        vpnClient.sendSessionData(session, dataToSend);
                        VPNLogger.debug("Client→VPN: " + bytesRead + " bytes (session " + session.getSessionId() + ")");
                    }
                    VPNLogger.debug("Client closed connection (session " + session.getSessionId() + ")");
                } catch (Exception e) {
                    VPNLogger.debug("Client→VPN stream error: " + e.getMessage());
                }
            });
            
            // VPN → Client Thread (receives from VPN, writes to client)
            Future<?> vpnToClient = executor.submit(() -> {
                try {
                    // Keep receiving until session is closed
                    while (session.isActive()) {
                        byte[] data = session.receiveData(60, TimeUnit.SECONDS);
                        if (data == null) {
                            // Timeout - check if session still active
                            if (!session.isActive()) {
                                break;
                            }
                            continue; // Keep waiting
                        }
                        clientOut.write(data);
                        clientOut.flush();
                        VPNLogger.debug("VPN→Client: " + data.length + " bytes (session " + session.getSessionId() + ")");
                    }
                    VPNLogger.debug("VPN session closed (session " + session.getSessionId() + ")");
                } catch (Exception e) {
                    VPNLogger.debug("VPN→Client stream error: " + e.getMessage());
                }
            });
            
            // Wait for BOTH threads to complete (when connection closes)
            clientToVpn.get();
            vpnToClient.get();
            
        } catch (Exception e) {
            VPNLogger.debug("Proxy error for session " + session.getSessionId() + ": " + e.getMessage());
        } finally {
            executor.shutdownNow();
        }
        
        return session;
    }
    
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
    
    private static class ConnectionInfo {
        String host;
        int port;
        
        ConnectionInfo(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }
}