package com.oda;

import com.oda.contract.TraceReportIO;
import com.oda.dashboard.DashboardExporter;
import com.oda.demo.MockTargetServer;
import com.oda.engine.StrikeEngine;
import com.oda.engine.TraceEngine;
import com.oda.model.ExploitPoC;
import com.oda.model.Finding;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Trace & Strike — TRACE → STRIKE → EXPORT → Dashboard pipeline.
 */
public class OdaOrchestrator {

    private static final String DEFAULT_TARGET_FILE = "TargetUserController.java";
    private static final String DEFAULT_TARGET_URL  = "http://localhost:8080/login";
    private static final boolean DEMO_MOCK_SERVER   = true;

    public static void main(String[] args) {
        String targetFile = args.length > 0 ? args[0] : DEFAULT_TARGET_FILE;
        String targetUrl  = args.length > 1 ? args[1] : DEFAULT_TARGET_URL;
        boolean demoMode  = targetFile.equals(DEFAULT_TARGET_FILE);

        printBanner();

        if (demoMode) {
            System.out.println("[ODA]  Demo mode: generating synthetic vulnerable target...");
            seedVulnerableTargetFile(targetFile);
        }

        MockTargetServer mock = null;
        try {
            if (demoMode && DEMO_MOCK_SERVER) {
                mock = new MockTargetServer(8080);
            }

            TraceEngine trace = new TraceEngine();
            List<Finding> findings = trace.analyzeFile(targetFile);

            if (findings.isEmpty()) {
                System.out.println("[ODA]  TRACE: No vulnerabilities detected.");
                return;
            }

            try {
                TraceReportIO.write(targetUrl, findings);
            } catch (IOException e) {
                System.err.println("[ODA]  WARN: Could not write trace-report.json — " + e.getMessage());
            }

            System.out.printf("%n[ODA]  TRACE complete. %d finding(s) → STRIKE (via %s).%n%n",
                    findings.size(), TraceReportIO.TRACE_REPORT_PATH);

            StrikeEngine strike = new StrikeEngine();
            List<DashboardExporter.FindingResult> results = new ArrayList<>();

            for (Finding finding : findings) {
                if (finding.isSanitized()) {
                    System.out.println("[ODA]  Skipping sanitized finding: " + finding);
                    continue;
                }
                System.out.printf("[ODA]  Processing: %s%n", finding);
                ExploitPoC poc = strike.verifyVulnerability(finding, targetUrl);
                results.add(new DashboardExporter.FindingResult(finding, poc));
                System.out.printf("[ODA]  Strike: isExploitable=%b | oracle='%s'%n%n",
                        poc.isExploitable(), poc.getConfirmationRule());
            }

            DashboardExporter exporter = new DashboardExporter();
            try {
                exporter.export(targetFile, results);
            } catch (IOException e) {
                System.err.println("[ODA]  ERROR: Export failed — " + e.getMessage());
            }

            printSummary(results);
            System.out.println();
            System.out.println("[ODA]  ▶ Run run.bat or ./run.sh to open http://localhost:8765/dashboard.html");
            System.out.println("[ODA]  ▶ Contracts: trace-report.json, dashboard-telemetry.json");
        } catch (Exception e) {
            System.err.println("[ODA]  FATAL: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (mock != null) {
                mock.close();
            }
        }
    }

    private static void printSummary(List<DashboardExporter.FindingResult> results) {
        long confirmed = results.stream().filter(r -> r.poc().isExploitable()).count();
        long critical = results.stream()
                .filter(r -> "CRITICAL".equals(r.finding().getSeverity())).count();

        System.out.println();
        System.out.println("[ODA]  ══════════════════════ PIPELINE SUMMARY ══════════════");
        System.out.printf("[ODA]  SAST findings          : %d%n", results.size());
        System.out.printf("[ODA]  DAST confirmed (TP)    : %d%n", confirmed);
        System.out.printf("[ODA]  DAST not confirmed (FP) : %d%n", results.size() - confirmed);
        System.out.printf("[ODA]  Critical               : %d%n", critical);
        System.out.printf("[ODA]  True-positive rate     : %.0f%%%n",
                results.isEmpty() ? 0 : (100.0 * confirmed / results.size()));
        System.out.println("[ODA]  ══════════════════════════════════════════════════════");
    }

    private static void printBanner() {
        System.out.println();
        System.out.println("  ██████╗ ██████╗  █████╗    Project ODA — Trace & Strike");
        System.out.println("  ██╔═══╝ ██╔══██╗██╔══██╗   AppSec Lifecycle Automation v3.0");
        System.out.println("  ██║     ██║  ██║███████║");
        System.out.println("  ██████╗ ██████╔╝██║  ██║   Think · Strike · Present");
        System.out.println("  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝");
        System.out.println();
    }

    private static void seedVulnerableTargetFile(String path) {
        String code = """
                import java.sql.Connection;
                import java.sql.Statement;
                import javax.servlet.http.HttpServletRequest;
                import javax.servlet.http.HttpServletResponse;
                import java.io.PrintWriter;
                import java.io.File;

                public class TargetUserController {

                    public void loginUser(HttpServletRequest request, Connection conn) throws Exception {
                        String email = request.getParameter("email");
                        String rawQuery = "SELECT * FROM users WHERE email = '" + email + "'";
                        Statement stmt = conn.createStatement();
                        stmt.executeQuery(rawQuery);
                    }

                    public void searchJuiceProducts(HttpServletRequest request, HttpServletResponse response) throws Exception {
                        String searchQuery = request.getParameter("q");
                        PrintWriter out = response.getWriter();
                        out.println("<h1>Results for: " + searchQuery + "</h1>");
                    }

                    public void viewJuiceOrder(HttpServletRequest request, Connection conn) throws Exception {
                        String orderId = request.getParameter("orderId");
                        Statement stmt = conn.createStatement();
                        stmt.execute("SELECT * FROM profiles WHERE id = " + orderId);
                    }

                    public void pingServerDiagnostics(HttpServletRequest request) throws Exception {
                        String ip = request.getParameter("ip");
                        Runtime.getRuntime().exec("ping -c 3 " + ip);
                    }

                    public void downloadJuiceMenu(HttpServletRequest request, HttpServletResponse response) throws Exception {
                        String menuPdf = request.getParameter("menu_pdf");
                        File target = new File("/var/app/uploads/" + menuPdf);
                        java.nio.file.Files.copy(target.toPath(), response.getOutputStream());
                    }

                    public void adminUserManagement(HttpServletRequest request) throws Exception {
                        String role = request.getParameter("role");
                        adminUserAccess(role);
                    }

                    private void adminUserAccess(String r) {
                        System.err.println("Privilege role level authorization: " + r);
                    }

                    public void toggleDeveloperDebug(HttpServletRequest request) throws Exception {
                        String debugMode = request.getParameter("debugMode");
                        System.setProperty("debugMode", debugMode);
                    }

                    public void loadJuicePlugin(HttpServletRequest request) throws Exception {
                        String pluginUrl = request.getParameter("plugin_url");
                        loadUntrustedPlugin(pluginUrl);
                    }

                    private void loadUntrustedPlugin(String p) {
                        System.out.println("Loading custom supplier extension: " + p);
                    }

                    public void hashJuiceCoupon(HttpServletRequest request) throws Exception {
                        String hashType = request.getParameter("hash_type");
                        java.security.MessageDigest.getInstance(hashType);
                    }

                    public void generateJuiceDiscountToken(HttpServletRequest request) throws Exception {
                        String discountSeed = request.getParameter("discountSeed");
                        java.util.Random rnd = new java.util.Random();
                        rnd.setSeed(Long.parseLong(discountSeed));
                    }

                    public void bypassJuiceAuth(HttpServletRequest request) throws Exception {
                        String credentialsToken = request.getParameter("credentialsToken");
                        verifyJuiceCredentials(credentialsToken);
                    }

                    private void verifyJuiceCredentials(String t) {
                        System.out.println("Checking active user session credentials: " + t);
                    }

                    public void deserializeBasketData(HttpServletRequest request) throws Exception {
                        String cartDataStream = request.getParameter("cartDataStream");
                        byte[] bytes = java.util.Base64.getDecoder().decode(cartDataStream);
                        java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(bytes);
                        new java.io.ObjectInputStream(bais);
                    }

                    public void logJuiceTransaction(HttpServletRequest request) throws Exception {
                        String customerEmail = request.getParameter("customerEmail");
                        logCustomerPII(customerEmail);
                    }

                    private void logCustomerPII(String e) {
                        System.err.println("Customer email database transaction log: " + e);
                    }

                    public void juiceErrorHandler(HttpServletRequest request) throws Exception {
                        String exceptionTrigger = request.getParameter("exceptionTrigger");
                        if ("null_pointer".equals(exceptionTrigger)) {
                            new NullPointerException().printStackTrace();
                        }
                    }
                }
                """;
        try (FileWriter writer = new FileWriter(path)) {
            writer.write(code);
            System.out.println("[ODA]  Seeded vulnerable target: " + path);
        } catch (IOException e) {
            System.err.println("[ODA]  Failed to seed target: " + e.getMessage());
        }
    }
}
