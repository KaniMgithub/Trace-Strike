package com.oda.scanner;

import com.oda.analysis.TaintTracker;
import com.oda.model.Finding;
import com.oda.model.RemediationLibrary;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.*;

public class SQLiScanner implements VulnerabilityScanner {

    private static final Set<String> SINK_METHODS = Set.of(
            "executeQuery", "execute", "executeUpdate",
            "executeLargeUpdate", "prepareStatement", "prepareCall"
    );

    @Override
    public String getScannerName() {
        return "SQL-Injection Scanner (CWE-89)";
    }

    @Override
    public List<Finding> scan(CompilationUnit cu, String fileName) {
        List<Finding> findings = new ArrayList<>();
        cu.accept(new TaintVisitor(findings, fileName), null);
        return findings;
    }

    private static class TaintVisitor extends VoidVisitorAdapter<Void> {
        private final List<Finding> findings;
        private final String fileName;
        private final TaintTracker tracker = new TaintTracker();

        TaintVisitor(List<Finding> findings, String fileName) {
            this.findings = findings;
            this.fileName = fileName;
        }

        @Override
        public void visit(VariableDeclarator n, Void arg) {
            super.visit(n, arg);
            if (n.getInitializer().isEmpty()) return;

            var init = n.getInitializer().get();
            String varName = n.getNameAsString();
            int line = n.getBegin().map(p -> p.line).orElse(-1);

            if (init.isMethodCallExpr()) {
                MethodCallExpr mce = init.asMethodCallExpr();
                if (TaintTracker.SOURCE_METHODS.contains(mce.getNameAsString())) {
                    tracker.recordSource(n, mce);
                    System.out.printf("  [TRACE][SQLi] Source → '%s' param='%s' line %d%n",
                            varName, TaintTracker.extractHttpParamName(mce), line);
                }
                if (TaintTracker.SANITIZER_METHODS.contains(mce.getNameAsString())) {
                    tracker.recordSanitizer(mce);
                }
            }

            if (init.isBinaryExpr() && tracker.containsTaintedInBinary(init.asBinaryExpr())) {
                tracker.recordPropagation(n, n.toString().trim());
                System.out.printf("  [TRACE][SQLi] Propagation → '%s' line %d%n", varName, line);
            }
        }

        @Override
        public void visit(MethodCallExpr n, Void arg) {
            super.visit(n, arg);
            if (!SINK_METHODS.contains(n.getNameAsString()) || n.getArguments().isEmpty()) {
                return;
            }

            int sinkLine = n.getBegin().map(p -> p.line).orElse(-1);
            String argsStr = n.getArguments().toString();

            for (String propagated : tracker.getPropagatedStrings()) {
                if (!argsStr.contains(propagated)) continue;
                if (tracker.isSanitized(propagated)) {
                    System.out.printf("  [TRACE][SQLi] Suppressed (sanitized): '%s'%n", propagated);
                    return;
                }
                String prop = tracker.propagationSnippet(propagated);
                report(n, sinkLine, propagated, tracker.sourceSnippetFor(propagated).orElse(""),
                        prop.isEmpty() ? n.toString() : prop);
                return;
            }

            for (String tainted : tracker.getTaintedVars()) {
                if (!argsStr.contains(tainted) || tracker.isSanitized(tainted)) continue;
                report(n, sinkLine, tainted, tracker.sourceSnippetFor(tainted).orElse(""),
                        n.toString());
                return;
            }
        }

        private void report(MethodCallExpr sink, int sinkLine, String varName,
                            String sourceSnip, String propagationOrSink) {
            String propSnippet = propagationOrSink;
            boolean quoteWrapped = TaintTracker.isSingleQuoteWrapped(propSnippet);
            boolean numeric = TaintTracker.isNumericSqlContext(propSnippet)
                    || propSnippet.contains("WHERE id = ");

            String originVar = resolveOriginVar(varName);
            String httpParam = tracker.resolveHttpParam(originVar);
            String displaySource = tracker.sourceSnippetFor(originVar)
                    .orElse(sourceSnip.isEmpty() ? originVar + " = request.getParameter(...)" : sourceSnip);
            List<String> flow = List.of(
                    "SOURCE: getParameter(" + httpParam + ")",
                    "PROPAGATION: " + (quoteWrapped ? "string concat into SQL" : "direct/numeric SQL"),
                    "SINK: " + sink.getNameAsString() + "()"
            );

            System.out.printf("  [TRACE][SQLi] ★ CONFIRMED param='%s' → %s() line %d%n",
                    httpParam, sink.getNameAsString(), sinkLine);

            findings.add(new Finding(
                    Finding.VulnType.SQL_INJECTION,
                    fileName,
                    sinkLine,
                    originVar,
                    httpParam,
                    "GET",
                    "/login",
                    sink.getNameAsString(),
                    sink.getScope().map(Object::toString).orElse("stmt"),
                    displaySource,
                    sink.toString(),
                    "CRITICAL",
                    quoteWrapped,
                    numeric,
                    false,
                    flow,
                    RemediationLibrary.forType(Finding.VulnType.SQL_INJECTION)
            ));
        }

        private String resolveOriginVar(String propagatedOrDirect) {
            if (tracker.getTaintedVars().contains(propagatedOrDirect)) {
                return propagatedOrDirect;
            }
            String prop = tracker.propagationSnippet(propagatedOrDirect);
            for (String t : tracker.getTaintedVars()) {
                if (prop.contains(t)) {
                    return t;
                }
            }
            return propagatedOrDirect;
        }
    }
}
