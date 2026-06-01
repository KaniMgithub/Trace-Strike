package com.oda.scanner;

import com.oda.analysis.TaintTracker;
import com.oda.model.Finding;
import com.oda.model.RemediationLibrary;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.*;

public class LoggingAlertingFailureScanner implements VulnerabilityScanner {

    @Override
    public String getScannerName() {
        return "Security Logging & Alerting Failures Scanner (A09)";
    }

    @Override
    public List<Finding> scan(CompilationUnit cu, String fileName) {
        List<Finding> findings = new ArrayList<>();
        cu.accept(new LoggingVisitor(findings, fileName), null);
        return findings;
    }

    private static class LoggingVisitor extends VoidVisitorAdapter<Void> {
        private final List<Finding> findings;
        private final String fileName;
        private final TaintTracker tracker = new TaintTracker();

        LoggingVisitor(List<Finding> findings, String fileName) {
            this.findings = findings;
            this.fileName = fileName;
        }

        @Override
        public void visit(VariableDeclarator n, Void arg) {
            super.visit(n, arg);
            if (n.getInitializer().isEmpty()) return;
            var init = n.getInitializer().get();
            if (init.isMethodCallExpr()) {
                var mce = init.asMethodCallExpr();
                if (TaintTracker.SOURCE_METHODS.contains(mce.getNameAsString())) {
                    tracker.recordSource(n, mce);
                }
            }
        }

        @Override
        public void visit(MethodCallExpr n, Void arg) {
            super.visit(n, arg);
            String name = n.getNameAsString();
            if ("logCustomerPII".equals(name) || "logSensitive".equals(name) || "writeLogDirectly".equals(name)) {
                checkSink(n.getArguments().toString(), n.getBegin().map(p -> p.line).orElse(-1), name, n.toString());
            }
        }

        private void checkSink(String argsStr, int sinkLine, String sinkMethod, String sinkSnippet) {
            for (String tainted : tracker.getTaintedVars()) {
                if (!argsStr.contains(tainted) || tracker.isSanitized(tainted)) continue;
                String httpParam = tracker.resolveHttpParam(tainted);
                findings.add(new Finding(
                        Finding.VulnType.LOGGING_ALERTING_FAILURE,
                        fileName,
                        sinkLine,
                        tainted,
                        httpParam,
                        "GET",
                        "/login",
                        sinkMethod,
                        "LoggingSystem",
                        tracker.sourceSnippetFor(tainted).orElse(""),
                        sinkSnippet,
                        "HIGH",
                        false,
                        false,
                        false,
                        List.of("SOURCE: getParameter(" + httpParam + ")", "SINK: " + sinkMethod + "()"),
                        RemediationLibrary.forType(Finding.VulnType.LOGGING_ALERTING_FAILURE)
                ));
                return;
            }
        }
    }
}
