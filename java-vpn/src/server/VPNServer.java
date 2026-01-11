package server;
import logging.VPNLogger;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * VPNServer - Multi-client VPN server
 * 
 * Features:
 * - Accepts multiple client connections
 * - RSA key exchange with each client
 * - Per-client encryption
 * - Traffic forwarding to internet
 * - Traffic monitoring and logging
 */
public class VPNServer {
    
    private static final int DEFAULT_PORT = 8443;
    private static final int MAX_CLIENTS = 50;
    
    private ServerSocket serverSocket;
    private ExecutorService threadPool;
    private Map<String, ClientHandler> activeClients;
    private AtomicLong totalBytesIn;
    private AtomicLong totalBytesOut;
    private volatile boolean running;
    
    public VPNServer(int port) throws IOException {
        this.serverSocket = new ServerSocket(port);
        this.threadPool = Executors.newFixedThreadPool(MAX_CLIENTS);
        this.activeClients = new ConcurrentHashMap<>();
        this.totalBytesIn = new AtomicLong(0);
        this.totalBytesOut = new AtomicLong(0);
        this.running = true;
    }
    
    /**
     * Start accepting client connections
     */
    public void start() {
        VPNLogger.banner("Java VPN Server v1.0");
        VPNLogger.info("Initializing VPN Server...");
        VPNLogger.info("Server listening on port " + serverSocket.getLocalPort());
        VPNLogger.info("Max clients: " + MAX_CLIENTS);
        VPNLogger.info("Encryption: AES-256-GCM + RSA-2048");
        VPNLogger.info("Waiting for connections...");
        VPNLogger.separator();
        
        // Start statistics reporter
        startStatsReporter();
        
        // Accept connections
        while (running) {
            try {
                Socket clientSocket = serverSocket.accept();
                String clientId = "CLIENT-" + System.currentTimeMillis();
                
                VPNLogger.info("Client connected from " + clientSocket.getRemoteSocketAddress());
                
                ClientHandler handler = new ClientHandler(clientSocket, clientId, this);
                activeClients.put(clientId, handler);
                threadPool.submit(handler);
                
            } catch (IOException e) {
                if (running) {
                    VPNLogger.error("Error accepting connection", e);
                }
            }
        }
    }
    
    /**
     * Start background thread to report statistics
     */
    private void startStatsReporter() {
        Thread statsThread = new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(60000); // Every 60 seconds
                    VPNLogger.printStats(
                        activeClients.size(),
                        totalBytesIn.get(),
                        totalBytesOut.get()
                    );
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        statsThread.setDaemon(true);
        statsThread.start();
    }
    
    /**
     * Remove client from active list
     */
    public void removeClient(String clientId) {
        activeClients.remove(clientId);
        VPNLogger.info("Client disconnected: " + clientId);
    }
    
    /**
     * Update traffic statistics
     */
    public void updateStats(long bytesIn, long bytesOut) {
        totalBytesIn.addAndGet(bytesIn);
        totalBytesOut.addAndGet(bytesOut);
    }
    
    /**
     * Shutdown server
     */
    public void shutdown() {
        running = false;
        try {
            serverSocket.close();
            threadPool.shutdown();
            threadPool.awaitTermination(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            VPNLogger.error("Error during shutdown", e);
        }
    }
    
    /**
     * Main entry point
     */
    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        
        // Parse command line arguments
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number. Using default: " + DEFAULT_PORT);
            }
        }
        
        try {
            VPNServer server = new VPNServer(port);
            
            // Shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                VPNLogger.info("Shutting down server...");
                server.shutdown();
            }));
            
            server.start();
            
        } catch (IOException e) {
            VPNLogger.error("Failed to start server", e);
            System.exit(1);
        }
    }
}