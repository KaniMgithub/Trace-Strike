package com.oda.demo;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Local authorized test harness so STRIKE can confirm findings in demo mode.
 */
public final class MockTargetServer implements AutoCloseable {

    private final HttpServer server;

    public MockTargetServer(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/login", this::handleLogin);
        server.createContext("/", ex -> respond(ex, 404, "Not Found"));
        server.setExecutor(null);
        server.start();
        System.out.println("[DEMO] Mock target listening on http://localhost:" + port + "/login");
    }

    private void handleLogin(HttpExchange ex) throws IOException {
        Map<String, String> params = parseQuery(ex.getRequestURI().getRawQuery());

        String email = params.getOrDefault("email", "");
        String q = params.getOrDefault("q", "");
        String orderId = params.getOrDefault("orderId", "");
        String ip = params.getOrDefault("ip", "");
        String menuPdf = params.getOrDefault("menu_pdf", "");
        String role = params.getOrDefault("role", "");
        String debugMode = params.getOrDefault("debugMode", "");
        String pluginUrl = params.getOrDefault("plugin_url", "");
        String hashType = params.getOrDefault("hash_type", "");
        String discountSeed = params.getOrDefault("discountSeed", "");
        String credentialsToken = params.getOrDefault("credentialsToken", "");
        String cartDataStream = params.getOrDefault("cartDataStream", "");
        String customerEmail = params.getOrDefault("customerEmail", "");
        String exceptionTrigger = params.getOrDefault("exceptionTrigger", "");

        String body;
        if (email.contains("OR") || email.contains("'1'='1")) {
            body = "<html><body>Welcome back, administrator</body></html>";
        } else if (orderId.contains("OR") || orderId.matches(".*\\d+\\s+OR.*")) {
            body = "SQLSyntaxErrorException near 'profiles'";
        } else if (q.contains("<script") || q.contains("onerror=alert") || q.contains("ODA-XSS")) {
            body = "<html><h1>Results for: " + q + "</h1></html>";
        } else if (ip.contains(";") || ip.contains("|") || ip.contains("&&")) {
            body = "uid=0(root) gid=0(root) groups=0(root) env=bash";
        } else if (menuPdf.contains("passwd") || menuPdf.contains("..")) {
            body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin";
        } else if ("admin".equals(role) || "administrator".equals(role)) {
            body = "Welcome to the Admin Panel — Privilege escalation successful!";
        } else if ("true".equals(debugMode)) {
            body = "System debug mode enabled — Directory listing active";
        } else if ("1".equals(pluginUrl)) {
            body = "plugin extension loaded: vulnerable dependency check bypassed";
        } else if ("md5".equals(hashType)) {
            body = "weak crypt hash algorithm: MD5 accepted, Collision confirmed";
        } else if ("12345".equals(discountSeed)) {
            body = "prediction successful: predictable token sequence generated";
        } else if ("true".equals(credentialsToken)) {
            body = "Authentication Bypassed: Logged in as administrator";
        } else if (cartDataStream.length() > 5) {
            body = "deserialization payload successfully executed: touch /tmp/rce_poc";
        } else if ("true".equals(customerEmail)) {
            body = "Security Logging Failure: Log injection successful, audit entry spoofed";
        } else if ("null_pointer".equals(exceptionTrigger)) {
            body = "NullPointerException: stackTrace: admin_db_password=super_secret_pass";
        } else {
            body = "<html><body>Login page — send test payloads via query params: email, q, orderId, ip, menu_pdf, role, debugMode, plugin_url, hash_type, discountSeed, credentialsToken, cartDataStream, customerEmail, exceptionTrigger</body></html>";
        }

        respond(ex, 200, body);
    }

    private static Map<String, String> parseQuery(String raw) {
        if (raw == null || raw.isBlank()) {
            return Map.of();
        }
        return java.util.Arrays.stream(raw.split("&"))
                .map(p -> p.split("=", 2))
                .collect(Collectors.toMap(
                        a -> decode(a[0]),
                        a -> a.length > 1 ? decode(a[1]) : "",
                        (a, b) -> b
                ));
    }

    private static String decode(String s) {
        return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
        System.out.println("[DEMO] Mock target stopped.");
    }
}
