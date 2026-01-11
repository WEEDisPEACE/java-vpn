package client;

import java.io.*;
import java.util.concurrent.*;

/**
 * VPNSession - Represents a single SOCKS5 connection through the VPN tunnel
 */
public class VPNSession {
    private final String sessionId;
    private final String host;
    private final int port;
    private final BlockingQueue<byte[]> receiveQueue;
    private volatile boolean active;
    
    public VPNSession(String sessionId, String host, int port) {
        this.sessionId = sessionId;
        this.host = host;
        this.port = port;
        this.receiveQueue = new LinkedBlockingQueue<>();
        this.active = true;
    }
    
    public String getSessionId() {
        return sessionId;
    }
    
    public String getHost() {
        return host;
    }
    
    public int getPort() {
        return port;
    }
    
    public void queueReceiveData(byte[] data) {
        if (active) {
            receiveQueue.offer(data);
        }
    }
    
    public byte[] receiveData(long timeout, TimeUnit unit) throws InterruptedException {
        return receiveQueue.poll(timeout, unit);
    }
    
    public boolean isActive() {
        return active;
    }
    
    public void close() {
        active = false;
        receiveQueue.clear();
    }
}