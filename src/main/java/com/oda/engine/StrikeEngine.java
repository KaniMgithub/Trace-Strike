package com.oda.engine;

import com.oda.model.ExploitPoC;
import com.oda.model.Finding;
import com.oda.strike.PayloadGenerator;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * STRIKE — DAST verification engine (context-aware payloads + oracle checks).
 */
public class StrikeEngine {

    private static final Map<Finding.VulnType, List<String>> ORACLE_PATTERNS = Map.ofEntries(
            Map.entry(Finding.VulnType.SQL_INJECTION, List.of(
                    "SQLSyntaxErrorException", "syntax error", "ORA-", "Welcome back",
                    "Login successful", "mysql", "PostgreSQL"
            )),
            Map.entry(Finding.VulnType.XSS, List.of(
                    "ODA-XSS", "alert(1)", "<script>", "onerror=alert"
            )),
            Map.entry(Finding.VulnType.COMMAND_INJECTION, List.of(
                    "root:", "uid=", "www-data"
            )),
            Map.entry(Finding.VulnType.PATH_TRAVERSAL, List.of(
                    "root:x:0:0", "[boot loader]"
            )),
            Map.entry(Finding.VulnType.BROKEN_ACCESS_CONTROL, List.of(
                    "Privilege escalation successful", "Welcome to the Admin Panel", "role mismatch"
            )),
            Map.entry(Finding.VulnType.SECURITY_MISCONFIGURATION, List.of(
                    "System debug mode enabled", "Directory listing", "debugMode active"
            )),
            Map.entry(Finding.VulnType.SUPPLY_CHAIN_FAILURE, List.of(
                    "plugin extension loaded", "untrusted remote host", "vulnerable dependency"
            )),
            Map.entry(Finding.VulnType.CRYPTOGRAPHIC_FAILURE, List.of(
                    "weak crypt hash algorithm", "MD5 accepted", "Collision confirmed"
            )),
            Map.entry(Finding.VulnType.INSECURE_DESIGN, List.of(
                    "prediction successful", "predictable token", "predictable sequence"
            )),
            Map.entry(Finding.VulnType.AUTHENTICATION_FAILURE, List.of(
                    "Authentication Bypassed", "Credentials check skipped", "Logged in as administrator"
            )),
            Map.entry(Finding.VulnType.INTEGRITY_FAILURE, List.of(
                    "deserialization payload", "successfully executed", "touch /tmp/rce_poc"
            )),
            Map.entry(Finding.VulnType.LOGGING_ALERTING_FAILURE, List.of(
                    "Security Logging Failure", "Log injection successful", "audit entry"
            )),
            Map.entry(Finding.VulnType.EXCEPTIONAL_CONDITIONS, List.of(
                    "NullPointerException", "admin_db_password", "stackTrace"
            ))
    );

    private final HttpClient httpClient;

    public StrikeEngine() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        System.out.println("[STRIKE] Engine initialized (context-aware PayloadGenerator).");
    }

    public ExploitPoC verifyVulnerability(Finding finding, String targetBaseUrl) {
        System.out.println("[STRIKE] ─────────────────────────────────────────────────");
        System.out.printf("[STRIKE] %s %s | param='%s' | quoteWrapped=%b | numeric=%b%n",
                finding.getHttpMethod(), targetBaseUrl, finding.getHttpParameter(),
                finding.isSingleQuoteWrapped(), finding.isNumericContext());

        List<String> payloads = PayloadGenerator.generate(finding);
        List<String> oracles = ORACLE_PATTERNS.getOrDefault(finding.getType(), List.of());
        ExploitPoC lastAttempt = ExploitPoC.unreachable("No payloads attempted");

        String base = targetBaseUrl.contains("?")
                ? targetBaseUrl.substring(0, targetBaseUrl.indexOf('?'))
                : targetBaseUrl;

        for (String payload : payloads) {
            System.out.printf("[STRIKE] Trying payload: %s%n", payload);

            String encoded = URLEncoder.encode(payload, StandardCharsets.UTF_8);
            String exploitUrl = base + "?" + finding.getHttpParameter() + "=" + encoded;
            Instant start = Instant.now();

            try {
                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                        .uri(URI.create(exploitUrl))
                        .header("User-Agent", "Project-ODA-StrikeEngine/3.0")
                        .header("Accept", "text/html,application/json,*/*");

                HttpRequest request = "POST".equalsIgnoreCase(finding.getHttpMethod())
                        ? reqBuilder.POST(HttpRequest.BodyPublishers.ofString(
                                finding.getHttpParameter() + "=" + encoded))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .build()
                        : reqBuilder.GET().build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                long latency = Duration.between(start, Instant.now()).toMillis();

                String body = response.body();
                String preview = body.length() > 1200 ? body.substring(0, 1200) + "\n... [truncated]" : body;

                String oracle = checkOracles(body, oracles);
                boolean confirmed = oracle != null
                        || (finding.getType() == Finding.VulnType.XSS && body.contains(payload));

                String rawRequest = buildRequestLog(finding, exploitUrl, payload);
                String rawResponse = buildResponseLog(response.statusCode(), preview, latency);

                lastAttempt = new ExploitPoC(
                        confirmed, payload, rawRequest, rawResponse,
                        confirmed ? (oracle != null ? oracle : "PAYLOAD_REFLECTED") : "NO_ORACLE_TRIGGERED",
                        response.statusCode(), latency
                );

                if (confirmed) {
                    System.out.printf("[STRIKE] ★ EXPLOITATION CONFIRMED — %s%n", lastAttempt.getConfirmationRule());
                    System.out.println("[STRIKE] ─────────────────────────────────────────────────");
                    return lastAttempt;
                }
            } catch (Exception e) {
                System.out.printf("[STRIKE] Connection failed: %s%n", e.getMessage());
                lastAttempt = ExploitPoC.unreachable(e.getMessage());
            }
        }

        System.out.println("[STRIKE] Payloads exhausted — not dynamically confirmed.");
        System.out.println("[STRIKE] ─────────────────────────────────────────────────");
        return lastAttempt;
    }

    private String checkOracles(String body, List<String> patterns) {
        String lower = body.toLowerCase();
        for (String p : patterns) {
            if (lower.contains(p.toLowerCase())) {
                return p;
            }
        }
        return null;
    }

    private String buildRequestLog(Finding f, String url, String payload) {
        return String.format(
                "%s %s HTTP/1.1%nHost: %s%nUser-Agent: Project-ODA-StrikeEngine/3.0%nAccept: */*%n%n[Parameter: %s]%n%s",
                f.getHttpMethod(), url,
                URI.create(url.split("\\?")[0]).getAuthority(),
                f.getHttpParameter(), payload
        );
    }

    private String buildResponseLog(int status, String body, long ms) {
        return String.format("HTTP/1.1 %d%nX-Response-Time: %dms%n%n%s", status, ms, body);
    }
}
