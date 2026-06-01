package com.oda.demo;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Serves dashboard.html and JSON telemetry over HTTP so the browser can load data locally.
 */
public final class DashboardServer {

    private static final int PORT = 8765;

    public static void main(String[] args) throws IOException {
        Path root = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        server.createContext("/", exchange -> serve(root, exchange));
        server.setExecutor(null);
        server.start();

        System.out.println("[DASHBOARD] http://localhost:" + PORT + "/dashboard.html");
        System.out.println("[DASHBOARD] Press Ctrl+C to stop.");
    }

    private static void serve(Path root, HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        if ("/".equals(path)) {
            path = "/dashboard.html";
        }

        Path file = root.resolve(path.substring(1)).normalize();
        if (!file.startsWith(root) || !Files.isRegularFile(file)) {
            byte[] msg = "Not found".getBytes();
            exchange.sendResponseHeaders(404, msg.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(msg);
            }
            return;
        }

        String contentType = contentType(file.getFileName().toString());
        byte[] bytes = Files.readAllBytes(file);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Cache-Control", "no-cache");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String contentType(String name) {
        if (name.endsWith(".html")) return "text/html; charset=utf-8";
        if (name.endsWith(".json")) return "application/json; charset=utf-8";
        if (name.endsWith(".css")) return "text/css; charset=utf-8";
        if (name.endsWith(".js")) return "application/javascript; charset=utf-8";
        return "application/octet-stream";
    }
}
