package com.oda.scanner;

import com.oda.analysis.TaintTracker;
import com.oda.model.Finding;
import com.oda.model.RemediationLibrary;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.*;

public class XSSScanner implements VulnerabilityScanner {

    private static final Set<String> SINK_METHODS = Set.of(
            "print", "println", "write", "printf", "append"
    );

    @Override
    public String getScannerName() {
        return "XSS Scanner — Reflected (CWE-79)";
    }

    @Override
    public List<Finding> scan(CompilationUnit cu, String fileName) {
        List<Finding> findings = new ArrayList<>();
        cu.accept(new XSSVisitor(findings, fileName), null);
        return findings;
    }

    private static class XSSVisitor extends VoidVisitorAdapter<Void> {
        private final List<Finding> findings;
        private final String fileName;
        private final TaintTracker tracker = new TaintTracker();

        XSSVisitor(List<Finding> findings, String fileName) {
            this.findings = findings;
            this.fileName = fileName;
        }

        @Override
        public void visit(VariableDeclarator n, Void arg) {
            super.visit(n, arg);
            if (n.getInitializer().isEmpty()) return;

            var init = n.getInitializer().get();
            String varName = n.getNameAsString();

            if (init.isMethodCallExpr()) {
                MethodCallExpr mce = init.asMethodCallExpr();
                if (TaintTracker.SOURCE_METHODS.contains(mce.getNameAsString())) {
                    tracker.recordSource(n, mce);
                    System.out.printf("  [TRACE][XSS] Source → '%s' line %d%n",
                            varName, n.getBegin().map(p -> p.line).orElse(-1));
                }
                if (TaintTracker.SANITIZER_METHODS.contains(mce.getNameAsString())) {
                    tracker.recordSanitizer(mce);
                    String args = mce.getArguments().toString();
                    tracker.getTaintedVars().stream()
                            .filter(args::contains)
                            .forEach(tracker::markSanitized);
                }
            }
        }

        @Override
        public void visit(MethodCallExpr n, Void arg) {
            super.visit(n, arg);
            if (!SINK_METHODS.contains(n.getNameAsString()) || n.getArguments().isEmpty()) {
                return;
            }

            String fullCall = n.toString();
            boolean responseWrite = fullCall.contains("getWriter")
                    || fullCall.contains("writer")
                    || fullCall.contains("out")
                    || fullCall.contains("Writer");
            if (!responseWrite) return;

            int sinkLine = n.getBegin().map(p -> p.line).orElse(-1);
            String argsStr = n.getArguments().toString();

            for (String tainted : tracker.getTaintedVars()) {
                if (tracker.isSanitized(tainted) || !argsStr.contains(tainted)) continue;

                String httpParam = tracker.resolveHttpParam(tainted);
                List<String> flow = List.of(
                        "SOURCE: getParameter(" + httpParam + ")",
                        "SINK: " + n.getNameAsString() + "() — no HTML encoding"
                );

                findings.add(new Finding(
                        Finding.VulnType.XSS,
                        fileName,
                        sinkLine,
                        tainted,
                        httpParam,
                        "GET",
                        "/login",
                        n.getNameAsString(),
                        n.getScope().map(Object::toString).orElse("out"),
                        tracker.sourceSnippetFor(tainted).orElse(tainted + " = request.getParameter(...)"),
                        n.toString(),
                        "HIGH",
                        false,
                        false,
                        false,
                        flow,
                        RemediationLibrary.forType(Finding.VulnType.XSS)
                ));
                System.out.printf("  [TRACE][XSS] ★ CONFIRMED param='%s' line %d%n", httpParam, sinkLine);
                return;
            }
        }
    }
}
