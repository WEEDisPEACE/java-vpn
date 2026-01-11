package client;

import logging.VPNLogger;

/**
 * KillSwitch - Monitors VPN tunnel health and prevents unencrypted traffic leaks
 * 
 * Features:
 * - Monitors tunnel connection status
 * - Automatically stops SOCKS5 proxy if tunnel disconnects
 * - Prevents applications from leaking unencrypted traffic
 * - Periodic health checks
 * 
 * Note: This is a Java-level kill-switch. It can only control the SOCKS5 proxy,
 * not system-level routing. Applications must be configured to use the SOCKS5 proxy.
 */
public class KillSwitch {
    
    private static final int CHECK_INTERVAL_MS = 5000; // Check every 5 seconds
    private static final int FAILURE_THRESHOLD = 3; // Disconnect after 3 failed checks
    
    private VPNClient vpnClient;
    private SOCKS5Server socks5Server;
    private volatile boolean monitoring;
    private int consecutiveFailures;
    
    public KillSwitch(VPNClient vpnClient, SOCKS5Server socks5Server) {
        this.vpnClient = vpnClient;
        this.socks5Server = socks5Server;
        this.monitoring = true;
        this.consecutiveFailures = 0;
    }
    
    /**
     * Start monitoring VPN tunnel health
     */
    public void monitor() {
        VPNLogger.debug("Kill-switch monitoring started");
        
        while (monitoring) {
            try {
                Thread.sleep(CHECK_INTERVAL_MS);
                
                // Check tunnel status
                if (!vpnClient.isConnected()) {
                    consecutiveFailures++;
                    VPNLogger.warning("Kill-switch: VPN tunnel check failed (" + 
                                    consecutiveFailures + "/" + FAILURE_THRESHOLD + ")");
                    
                    if (consecutiveFailures >= FAILURE_THRESHOLD) {
                        triggerKillSwitch();
                        break;
                    }
                } else {
                    // Reset failure counter if tunnel is healthy
                    if (consecutiveFailures > 0) {
                        VPNLogger.debug("Kill-switch: Tunnel recovered");
                        consecutiveFailures = 0;
                    }
                }
                
            } catch (InterruptedException e) {
                VPNLogger.debug("Kill-switch monitoring interrupted");
                break;
            } catch (Exception e) {
                VPNLogger.error("Kill-switch error", e);
            }
        }
        
        VPNLogger.debug("Kill-switch monitoring stopped");
    }
    
    /**
     * Trigger kill-switch: stop SOCKS5 proxy to prevent unencrypted traffic
     */
    private void triggerKillSwitch() {
        VPNLogger.error("╔══════════════════════════════════════╗");
        VPNLogger.error("║     KILL-SWITCH ACTIVATED!           ║");
        VPNLogger.error("║  VPN Tunnel Disconnected             ║");
        VPNLogger.error("║  Stopping SOCKS5 Proxy...            ║");
        VPNLogger.error("╚══════════════════════════════════════╝");
        
        try {
            // Stop SOCKS5 server to prevent unencrypted traffic
            if (socks5Server != null) {
                socks5Server.stop();
            }
            
            VPNLogger.info("SOCKS5 proxy stopped - No traffic will leak");
            VPNLogger.info("All application connections have been terminated");
            VPNLogger.info("Please restart the VPN client to reconnect");
            
        } catch (Exception e) {
            VPNLogger.error("Error activating kill-switch", e);
        }
        
        monitoring = false;
    }
    
    /**
     * Stop kill-switch monitoring
     */
    public void stop() {
        monitoring = false;
    }
    
    /**
     * Check if kill-switch is active (triggered)
     */
    public boolean isTriggered() {
        return consecutiveFailures >= FAILURE_THRESHOLD;
    }
    
    /**
     * Get current health status
     */
    public String getHealthStatus() {
        if (!monitoring) {
            return "STOPPED";
        } else if (consecutiveFailures == 0) {
            return "HEALTHY";
        } else if (consecutiveFailures < FAILURE_THRESHOLD) {
            return "WARNING (" + consecutiveFailures + "/" + FAILURE_THRESHOLD + " failures)";
        } else {
            return "TRIGGERED";
        }
    }
}