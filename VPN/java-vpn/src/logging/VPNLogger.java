package logging;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * VPNLogger - Handles all logging for the VPN system
 * 
 * Features:
 * - Timestamped log messages
 * - Different log levels (INFO, DEBUG, ERROR, TRAFFIC)
 * - Traffic statistics formatting
 * - CMD-based output with color-coded messages
 */
public class VPNLogger {
    
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    // Log levels
    public enum Level {
        INFO, DEBUG, ERROR, TRAFFIC, REQUEST, WARNING
    }
    
    private static boolean verboseMode = false;
    
    /**
     * Enable verbose logging
     */
    public static void setVerbose(boolean verbose) {
        verboseMode = verbose;
    }
    
    /**
     * Log a message with specified level
     */
    public static void log(Level level, String message) {
        String timestamp = DATE_FORMAT.format(new Date());
        String levelStr = String.format("%-8s", "[" + level + "]");
        System.out.println(timestamp + " " + levelStr + " " + message);
    }
    
    /**
     * Log info message
     */
    public static void info(String message) {
        log(Level.INFO, message);
    }
    
    /**
     * Log debug message (only in verbose mode)
     */
    public static void debug(String message) {
        if (verboseMode) {
            log(Level.DEBUG, message);
        }
    }
    
    /**
     * Log error message
     */
    public static void error(String message) {
        log(Level.ERROR, message);
    }
    
    /**
     * Log error with exception
     */
    public static void error(String message, Exception e) {
        log(Level.ERROR, message + ": " + e.getMessage());
        if (verboseMode) {
            e.printStackTrace();
        }
    }
    
    /**
     * Log warning message
     */
    public static void warning(String message) {
        log(Level.WARNING, message);
    }
    
    /**
     * Log traffic statistics
     */
    public static void traffic(String sessionId, long bytesIn, long bytesOut) {
        String message = String.format("Session %s: ↑ %s ↓ %s", 
            sessionId, formatBytes(bytesOut), formatBytes(bytesIn));
        log(Level.TRAFFIC, message);
    }
    
    /**
     * Log connection request
     */
    public static void request(String sessionId, String destination) {
        String message = String.format("Session %s: %s", sessionId, destination);
        log(Level.REQUEST, message);
    }
    
    /**
     * Format bytes to human-readable format
     */
    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        } else {
            return String.format("%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
        }
    }
    
    /**
     * Print a separator line
     */
    public static void separator() {
        System.out.println("========================================");
    }
    
    /**
     * Print a banner
     */
    public static void banner(String title) {
        separator();
        System.out.println("    " + title);
        separator();
    }
    
    /**
     * Print connection statistics
     */
    public static void printStats(int activeConnections, long totalBytesIn, long totalBytesOut) {
        separator();
        System.out.println("VPN Statistics:");
        System.out.println("  Active Connections: " + activeConnections);
        System.out.println("  Total Traffic In:   " + formatBytes(totalBytesIn));
        System.out.println("  Total Traffic Out:  " + formatBytes(totalBytesOut));
        separator();
    }
}