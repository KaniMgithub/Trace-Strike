package com.oda.model;

import java.util.List;

/**
 * Canonical SAST finding DTO — handshake artifact between TRACE and STRIKE.
 * Immutable; no setters (production contract).
 */
public final class Finding {

    public enum VulnType {
        SQL_INJECTION,
        XSS,
        PATH_TRAVERSAL,
        COMMAND_INJECTION,
        BROKEN_ACCESS_CONTROL,
        SECURITY_MISCONFIGURATION,
        SUPPLY_CHAIN_FAILURE,
        CRYPTOGRAPHIC_FAILURE,
        INSECURE_DESIGN,
        AUTHENTICATION_FAILURE,
        INTEGRITY_FAILURE,
        LOGGING_ALERTING_FAILURE,
        EXCEPTIONAL_CONDITIONS
    }

    private final VulnType type;
    private final String sourceFile;
    private final int sinkLine;
    private final String variableName;
    private final String httpParameter;
    private final String httpMethod;
    private final String endpointPath;
    private final String sinkMethod;
    private final String sinkScope;
    private final String sourceSnippet;
    private final String sinkSnippet;
    private final String severity;
    private final boolean singleQuoteWrapped;
    private final boolean numericContext;
    private final boolean sanitized;
    private final List<String> taintFlow;
    private final String remediationSnippet;

    public Finding(
            VulnType type,
            String sourceFile,
            int sinkLine,
            String variableName,
            String httpParameter,
            String httpMethod,
            String endpointPath,
            String sinkMethod,
            String sinkScope,
            String sourceSnippet,
            String sinkSnippet,
            String severity,
            boolean singleQuoteWrapped,
            boolean numericContext,
            boolean sanitized,
            List<String> taintFlow,
            String remediationSnippet) {
        this.type = type;
        this.sourceFile = sourceFile;
        this.sinkLine = sinkLine;
        this.variableName = variableName;
        this.httpParameter = httpParameter;
        this.httpMethod = httpMethod;
        this.endpointPath = endpointPath;
        this.sinkMethod = sinkMethod;
        this.sinkScope = sinkScope;
        this.sourceSnippet = sourceSnippet;
        this.sinkSnippet = sinkSnippet;
        this.severity = severity;
        this.singleQuoteWrapped = singleQuoteWrapped;
        this.numericContext = numericContext;
        this.sanitized = sanitized;
        this.taintFlow = List.copyOf(taintFlow);
        this.remediationSnippet = remediationSnippet;
    }

    public VulnType getType() { return type; }
    public String getSourceFile() { return sourceFile; }
    public int getSinkLine() { return sinkLine; }
    public String getVariableName() { return variableName; }
    public String getHttpParameter() { return httpParameter; }
    public String getHttpMethod() { return httpMethod; }
    public String getEndpointPath() { return endpointPath; }
    public String getSinkMethod() { return sinkMethod; }
    public String getSinkScope() { return sinkScope; }
    public String getSourceSnippet() { return sourceSnippet; }
    public String getSinkSnippet() { return sinkSnippet; }
    public String getSeverity() { return severity; }
    public boolean isSingleQuoteWrapped() { return singleQuoteWrapped; }
    public boolean isNumericContext() { return numericContext; }
    public boolean isSanitized() { return sanitized; }
    public List<String> getTaintFlow() { return taintFlow; }
    public String getRemediationSnippet() { return remediationSnippet; }

    /** Backward-compatible alias used by legacy Strike logging. */
    public String getTaintedParameter() { return httpParameter != null ? httpParameter : variableName; }

    @Override
    public String toString() {
        return String.format("[%s] %s → line %d | param='%s' → sink='%s'",
                severity, type, sinkLine, getTaintedParameter(), sinkMethod);
    }
}
