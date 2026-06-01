package com.oda.model;

public final class RemediationLibrary {

    private RemediationLibrary() {}

    public static String forType(Finding.VulnType type) {
        return switch (type) {
            case SQL_INJECTION -> """
                    // FIX: Use parameterized queries — never concatenate user input into SQL.
                    String sql = "SELECT * FROM users WHERE username = ?";
                    PreparedStatement ps = conn.prepareStatement(sql);
                    ps.setString(1, request.getParameter("username"));
                    ps.executeQuery();
                    """;
            case XSS -> """
                    // FIX: Encode output for HTML context before writing to the response.
                    String safe = StringEscapeUtils.escapeHtml4(request.getParameter("query"));
                    out.println("<h1>Results for: " + safe + "</h1>");
                    """;
            case COMMAND_INJECTION -> """
                    // FIX: Avoid shell invocation; use ProcessBuilder with fixed argv, no user strings.
                    ProcessBuilder pb = new ProcessBuilder("fixed-binary", "--flag");
                    pb.start();
                    """;
            case PATH_TRAVERSAL -> """
                    // FIX: Resolve canonical path and verify it stays under an allowed base directory.
                    Path base = Paths.get("/var/app/uploads").toRealPath();
                    Path resolved = base.resolve(safeFileName).normalize();
                    if (!resolved.startsWith(base)) throw new SecurityException();
                    """;
            case BROKEN_ACCESS_CONTROL -> """
                    // FIX: Enforce role-based access checks and verify user session authorization.
                    if (!session.getAttribute("role").equals("admin")) {
                        throw new SecurityException("Unauthorized access to administrative profile.");
                    }
                    """;
            case SECURITY_MISCONFIGURATION -> """
                    // FIX: Enforce secure defaults, disable debugging options, and require HTTPS.
                    System.setProperty("debug", "false");
                    sslConfig.setEnableHostnameVerification(true);
                    """;
            case SUPPLY_CHAIN_FAILURE -> """
                    // FIX: Use trusted package repositories, verify hashes, and use static dependency locking.
                    // Dependency verified and locked to stable release project-oda-core-1.1.0-signed.jar.
                    """;
            case CRYPTOGRAPHIC_FAILURE -> """
                    // FIX: Replace weak/obsolete hash functions (MD5, SHA-1) with secure algorithms like SHA-256 or bcrypt.
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] secureHash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
                    """;
            case INSECURE_DESIGN -> """
                    // FIX: Generate secure random values using SecureRandom, never reuse predictable seeds.
                    SecureRandom secureRandom = new SecureRandom();
                    byte[] tokenBytes = new byte[32];
                    secureRandom.nextBytes(tokenBytes);
                    """;
            case AUTHENTICATION_FAILURE -> """
                    // FIX: Use secure standard password hash comparators (e.g. bcrypt) with constant-time equality checks.
                    if (BCrypt.checkpw(plainPassword, hashedPassword)) {
                        loginSuccess();
                    }
                    """;
            case INTEGRITY_FAILURE -> """
                    // FIX: Avoid deserializing untrusted user inputs; use safe serialization formats like JSON.
                    ObjectMapper mapper = new ObjectMapper();
                    UserData data = mapper.readValue(jsonString, UserData.class);
                    """;
            case LOGGING_ALERTING_FAILURE -> """
                    // FIX: Ensure logs are written correctly, alert security teams on errors, and sanitize logged fields.
                    logger.error("Authentication check failed for user: " + sanitize(userId));
                    alertSecurityTeam("Repeated auth failures detected.");
                    """;
            case EXCEPTIONAL_CONDITIONS -> """
                    // FIX: Always handle checked exceptions and never expose internal error stack traces to clients.
                    try {
                        performAction();
                    } catch (Exception e) {
                        logger.error("Internal processing error", e);
                        response.sendError(500, "An internal error occurred.");
                    }
                    """;
        };
    }
}
