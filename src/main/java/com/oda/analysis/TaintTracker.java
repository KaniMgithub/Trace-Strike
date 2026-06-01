package com.oda.analysis;

import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.body.VariableDeclarator;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Intra-procedural taint tracker: sources, propagation, sanitizers, and sink reachability.
 */
public final class TaintTracker {

    public static final Set<String> SOURCE_METHODS = Set.of(
            "getParameter", "getQueryString", "getHeader",
            "getPathInfo", "getRemoteUser", "getCookies"
    );

    public static final Set<String> SANITIZER_METHODS = Set.of(
            "escapeHtml", "escapeHtml4", "encodeForHTML", "htmlEncode", "htmlEscape",
            "sanitize", "stripXSS", "clean", "normalize"
    );

    private final Set<String> taintedVars = new LinkedHashSet<>();
    private final Set<String> propagatedStrings = new LinkedHashSet<>();
    private final Set<String> sanitizedVars = new LinkedHashSet<>();
    private final Map<String, String> sourceSnippets = new LinkedHashMap<>();
    private final Map<String, String> httpParams = new LinkedHashMap<>();
    private final Map<String, String> propagationSnippets = new LinkedHashMap<>();

    public void recordSource(VariableDeclarator n, MethodCallExpr mce) {
        String varName = n.getNameAsString();
        taintedVars.add(varName);
        sourceSnippets.put(varName, n.toString().trim());
        httpParams.put(varName, extractHttpParamName(mce));
    }

    public void recordPropagation(VariableDeclarator n, String snippet) {
        String varName = n.getNameAsString();
        propagatedStrings.add(varName);
        propagationSnippets.put(varName, snippet != null ? snippet : n.toString().trim());
    }

    public String propagationSnippet(String varName) {
        return propagationSnippets.getOrDefault(varName, "");
    }

    public void markSanitized(String varName) {
        sanitizedVars.add(varName);
    }

    public void recordSanitizer(MethodCallExpr mce) {
        String args = mce.getArguments().toString();
        for (String tainted : taintedVars) {
            if (args.contains(tainted)) {
                sanitizedVars.add(tainted);
            }
        }
    }

    public boolean isTainted(String name) {
        return taintedVars.contains(name) || propagatedStrings.contains(name);
    }

    public boolean isSanitized(String name) {
        return sanitizedVars.contains(name);
    }

    public Set<String> getTaintedVars() { return Set.copyOf(taintedVars); }
    public Set<String> getPropagatedStrings() { return Set.copyOf(propagatedStrings); }

    public Optional<String> sourceSnippetFor(String var) {
        return Optional.ofNullable(sourceSnippets.get(var));
    }

    public Optional<String> httpParamFor(String var) {
        return Optional.ofNullable(httpParams.get(var));
    }

    public String resolveHttpParam(String variableOrPropagated) {
        if (httpParams.containsKey(variableOrPropagated)) {
            return httpParams.get(variableOrPropagated);
        }
        String prop = propagationSnippets.getOrDefault(variableOrPropagated, "");
        for (Map.Entry<String, String> e : httpParams.entrySet()) {
            if (prop.contains(e.getKey())) {
                return e.getValue();
            }
        }
        return variableOrPropagated;
    }

    public boolean containsTaintedInBinary(BinaryExpr expr) {
        if (expr.getOperator() != BinaryExpr.Operator.PLUS) {
            return false;
        }
        return isTaintedLeaf(expr.getLeft()) || isTaintedLeaf(expr.getRight());
    }

    private boolean isTaintedLeaf(com.github.javaparser.ast.expr.Expression expr) {
        if (expr.isNameExpr()) {
            return taintedVars.contains(expr.asNameExpr().getNameAsString());
        }
        if (expr.isBinaryExpr()) {
            return containsTaintedInBinary(expr.asBinaryExpr());
        }
        return false;
    }

    public static String extractHttpParamName(MethodCallExpr mce) {
        if (mce.getArguments().isEmpty()) {
            return "param";
        }
        return mce.getArgument(0).toString().replace("\"", "").trim();
    }

    public static boolean isSingleQuoteWrapped(String snippet) {
        return snippet != null && snippet.contains("= '") && snippet.contains("+");
    }

    public static boolean isNumericSqlContext(String snippet) {
        return snippet != null && snippet.matches(".*\\+\\s*\\w+\\s*\\).*")
                || (snippet != null && snippet.contains("WHERE id = ") && !snippet.contains("'"));
    }
}
