package com.oda.contract;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.oda.model.Finding;

import java.time.Instant;
import java.util.List;

/**
 * JSON contract exported by TRACE and consumed by STRIKE.
 *
 * Sample trace-report.json:
 * <pre>{@code
 * {
 *   "schemaVersion": "3.0",
 *   "generatedAt": "2026-05-31T12:00:00Z",
 *   "targetBaseUrl": "http://localhost:8080/login",
 *   "findings": [{
 *     "id": "finding-0",
 *     "vulnerabilityType": "SQL_INJECTION",
 *     "severity": "CRITICAL",
 *     "sourceFile": "TargetUserController.java",
 *     "sinkLine": 25,
 *     "httpMethod": "GET",
 *     "endpoint": "/login",
 *     "targetParameter": "username",
 *     "variableName": "inputData",
 *     "singleQuoteWrapped": true,
 *     "numericContext": false,
 *     "sanitized": false,
 *     "taintFlow": ["getParameter(username)", "rawQuery concat", "executeQuery"],
 *     "sourceSnippet": "...",
 *     "sinkSnippet": "...",
 *     "remediationSnippet": "Use PreparedStatement with bind parameters."
 *   }]
 * }
 * }</pre>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TraceReport(
        String schemaVersion,
        String generatedAt,
        String targetBaseUrl,
        List<TraceFinding> findings
) {
    public static TraceReport from(String targetBaseUrl, List<Finding> findings) {
        List<TraceFinding> items = findings.stream()
                .map(TraceFinding::from)
                .toList();
        return new TraceReport("3.0", Instant.now().toString(), targetBaseUrl, items);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record TraceFinding(
            String id,
            String vulnerabilityType,
            String severity,
            String sourceFile,
            int sinkLine,
            String httpMethod,
            String endpoint,
            String targetParameter,
            String variableName,
            String sinkMethod,
            String sinkScope,
            boolean singleQuoteWrapped,
            boolean numericContext,
            boolean sanitized,
            List<String> taintFlow,
            String sourceSnippet,
            String sinkSnippet,
            String remediationSnippet
    ) {
        static TraceFinding from(Finding f) {
            return new TraceFinding(
                    "finding-" + f.getSinkLine() + "-" + f.getType().name(),
                    f.getType().name(),
                    f.getSeverity(),
                    f.getSourceFile(),
                    f.getSinkLine(),
                    f.getHttpMethod(),
                    f.getEndpointPath(),
                    f.getHttpParameter(),
                    f.getVariableName(),
                    f.getSinkMethod(),
                    f.getSinkScope(),
                    f.isSingleQuoteWrapped(),
                    f.isNumericContext(),
                    f.isSanitized(),
                    f.getTaintFlow(),
                    f.getSourceSnippet(),
                    f.getSinkSnippet(),
                    f.getRemediationSnippet()
            );
        }

        public Finding toFinding() {
            return new Finding(
                    Finding.VulnType.valueOf(vulnerabilityType),
                    sourceFile,
                    sinkLine,
                    variableName,
                    targetParameter,
                    httpMethod,
                    endpoint,
                    sinkMethod,
                    sinkScope,
                    sourceSnippet,
                    sinkSnippet,
                    severity,
                    singleQuoteWrapped,
                    numericContext,
                    sanitized,
                    taintFlow,
                    remediationSnippet
            );
        }
    }
}
