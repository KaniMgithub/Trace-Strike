package com.oda.engine;

import com.oda.model.Finding;
import com.oda.scanner.*;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * TRACE — SAST engine (Strategy Pattern scanner registry).
 */
public class TraceEngine {

    private final List<VulnerabilityScanner> scannerRegistry = new ArrayList<>();

    public TraceEngine() {
        scannerRegistry.add(new SQLiScanner());
        scannerRegistry.add(new XSSScanner());
        scannerRegistry.add(new CommandInjectionScanner());
        scannerRegistry.add(new PathTraversalScanner());
        scannerRegistry.add(new BrokenAccessControlScanner());
        scannerRegistry.add(new SecurityMisconfigurationScanner());
        scannerRegistry.add(new SupplyChainFailureScanner());
        scannerRegistry.add(new CryptographicFailureScanner());
        scannerRegistry.add(new InsecureDesignScanner());
        scannerRegistry.add(new AuthenticationFailureScanner());
        scannerRegistry.add(new IntegrityFailureScanner());
        scannerRegistry.add(new LoggingAlertingFailureScanner());
        scannerRegistry.add(new ExceptionalConditionsScanner());
        System.out.printf("[TRACE] Engine initialized with %d scanner(s).%n", scannerRegistry.size());
    }

    public List<Finding> analyzeFile(String filePath) throws Exception {
        List<Finding> allFindings = new ArrayList<>();
        File file = new File(filePath);

        if (!file.exists() || !file.isFile()) {
            System.err.println("[TRACE] ERROR: Target file not found: " + filePath);
            return allFindings;
        }

        System.out.println("[TRACE] ─────────────────────────────────────────────────");
        System.out.println("[TRACE] Parsing: " + file.getName());

        CompilationUnit cu = StaticJavaParser.parse(file);
        System.out.println("[TRACE] AST built successfully.");

        for (VulnerabilityScanner scanner : scannerRegistry) {
            System.out.println("[TRACE] Running: " + scanner.getScannerName());
            List<Finding> findings = scanner.scan(cu, file.getName());
            allFindings.addAll(findings);
            System.out.printf("[TRACE] → %d finding(s) from %s%n", findings.size(), scanner.getScannerName());
        }

        System.out.printf("[TRACE] Analysis complete. Total findings: %d%n", allFindings.size());
        System.out.println("[TRACE] ─────────────────────────────────────────────────");

        return allFindings;
    }
}
