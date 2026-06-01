package com.oda.contract;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oda.model.Finding;

import java.io.File;
import java.io.IOException;
import java.util.List;

public final class TraceReportIO {

    public static final String TRACE_REPORT_PATH = "trace-report.json";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TraceReportIO() {}

    public static void write(String targetBaseUrl, List<Finding> findings) throws IOException {
        TraceReport report = TraceReport.from(targetBaseUrl, findings);
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(new File(TRACE_REPORT_PATH), report);
        System.out.println("[TRACE] Handoff contract written → " + TRACE_REPORT_PATH);
    }

    public static List<Finding> readFindings() throws IOException {
        TraceReport report = MAPPER.readValue(new File(TRACE_REPORT_PATH), TraceReport.class);
        return report.findings().stream()
                .filter(tf -> !tf.sanitized())
                .map(TraceReport.TraceFinding::toFinding)
                .toList();
    }
}
