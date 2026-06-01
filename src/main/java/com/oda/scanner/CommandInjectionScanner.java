package com.oda.scanner;

import com.oda.analysis.TaintTracker;
import com.oda.model.Finding;
import com.oda.model.RemediationLibrary;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.*;

public class CommandInjectionScanner implements VulnerabilityScanner {

    @Override
    public String getScannerName() {
        return "Command Injection Scanner (CWE-78)";
    }

    @Override
    public List<Finding> scan(CompilationUnit cu, String fileName) {
        List<Finding> findings = new ArrayList<>();
        cu.accept(new CmdVisitor(findings, fileName), null);
        return findings;
    }

    private static class CmdVisitor extends VoidVisitorAdapter<Void> {
        private final List<Finding> findings;
        private final String fileName;
        private final TaintTracker tracker = new TaintTracker();

        CmdVisitor(List<Finding> findings, String fileName) {
            this.findings = findings;
            this.fileName = fileName;
        }

        @Override
        public void visit(VariableDeclarator n, Void arg) {
            super.visit(n, arg);
            if (n.getInitializer().isEmpty()) return;
            var init = n.getInitializer().get();
            if (init.isMethodCallExpr()) {
                MethodCallExpr mce = init.asMethodCallExpr();
                if (TaintTracker.SOURCE_METHODS.contains(mce.getNameAsString())) {
                    tracker.recordSource(n, mce);
                }
            }
        }

        @Override
        public void visit(MethodCallExpr n, Void arg) {
            super.visit(n, arg);
            if (!"exec".equals(n.getNameAsString()) || n.getArguments().isEmpty()) return;
            checkSink(n, n.getBegin().map(p -> p.line).orElse(-1), "exec", "Runtime");
        }

        @Override
        public void visit(ObjectCreationExpr n, Void arg) {
            super.visit(n, arg);
            if (!"ProcessBuilder".equals(n.getTypeAsString()) || n.getArguments().isEmpty()) return;
            checkSink(n.toString(), n.getBegin().map(p -> p.line).orElse(-1), "ProcessBuilder", "ProcessBuilder", n.toString());
        }

        private void checkSink(MethodCallExpr n, int sinkLine, String sinkMethod, String scope) {
            checkSink(n.getArguments().toString(), sinkLine, sinkMethod, scope, n.toString());
        }

        private void checkSink(String argsStr, int sinkLine, String sinkMethod, String scope, String sinkSnippet) {
            for (String tainted : tracker.getTaintedVars()) {
                if (!argsStr.contains(tainted) || tracker.isSanitized(tainted)) continue;
                String httpParam = tracker.resolveHttpParam(tainted);
                findings.add(new Finding(
                        Finding.VulnType.COMMAND_INJECTION,
                        fileName,
                        sinkLine,
                        tainted,
                        httpParam,
                        "GET",
                        "/login",
                        sinkMethod,
                        scope,
                        tracker.sourceSnippetFor(tainted).orElse(""),
                        sinkSnippet,
                        "CRITICAL",
                        false,
                        false,
                        false,
                        List.of("SOURCE: getParameter(" + httpParam + ")", "SINK: " + sinkMethod),
                        RemediationLibrary.forType(Finding.VulnType.COMMAND_INJECTION)
                ));
                return;
            }
        }
    }
}
