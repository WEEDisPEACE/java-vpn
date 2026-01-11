package utils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public class NetworkUtils {

    /**
     * Parse an endpoint string (hostname:port or [IPv6]:port) into an InetSocketAddress.
     * Example inputs: "example.com:8443", "[2001:db8::1]:443".
     */
    public static InetSocketAddress parseSocketAddress(String endpoint) {
        String host;
        int port;
        try {
            if (endpoint.startsWith("[")) {
                // IPv6 format "[addr]:port"
                int idx = endpoint.indexOf(']');
                host = endpoint.substring(1, idx);
                String portPart = endpoint.substring(idx + 1);
                if (!portPart.startsWith(":")) {
                    throw new IllegalArgumentException("Invalid endpoint format: " + endpoint);
                }
                port = Integer.parseInt(portPart.substring(1));
            } else if (endpoint.contains(":")) {
                // IPv4 or hostname "host:port"
                int idx = endpoint.lastIndexOf(':');
                host = endpoint.substring(0, idx);
                port = Integer.parseInt(endpoint.substring(idx + 1));
            } else {
                throw new IllegalArgumentException("Endpoint must include port: " + endpoint);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse endpoint: " + endpoint, e);
        }
        return new InetSocketAddress(host, port);
    }

    /**
     * Get the local machine's IP address by connecting to a well-known host.
     * This does not send data; it just uses the routing table to find the local IP.
     */
    public static String getLocalIpAddress() {
        try (Socket socket = new Socket("8.8.8.8", 53)) {
            return socket.getLocalAddress().getHostAddress();
        } catch (IOException e) {
            return "127.0.0.1";
        }
    }
}
