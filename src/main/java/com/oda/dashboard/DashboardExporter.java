package com.oda.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.oda.model.ExploitPoC;
import com.oda.model.Finding;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

public class DashboardExporter {

    private static final String OUTPUT_PATH = "dashboard-telemetry.json";
    private final ObjectMapper mapper = new ObjectMapper();

    public void export(String sourceFilePath, List<FindingResult> results) throws IOException {
        ObjectNode root = mapper.createObjectNode();
        root.put("runId", "oda-" + Instant.now().getEpochSecond());
        root.put("generatedAt", Instant.now().toString());
        root.put("schemaVersion", "3.0");

        String sourceCode = "";
        if (!results.isEmpty()) {
            Path p = Path.of(results.get(0).finding().getSourceFile());
            if (Files.exists(p)) {
                sourceCode = Files.readString(p);
            } else if (sourceFilePath != null && Files.exists(Path.of(sourceFilePath))) {
                sourceCode = Files.readString(Path.of(sourceFilePath));
            }
        }
        root.put("sourceCode", sourceCode);

        ArrayNode findingsArray = root.putArray("findings");
        int confirmed = 0, critical = 0, high = 0, falsePositives = 0;

        for (int i = 0; i < results.size(); i++) {
            Finding f = results.get(i).finding();
            ExploitPoC poc = results.get(i).poc();

            ObjectNode item = findingsArray.addObject();
            item.put("id", i);
            item.put("type", f.getType().name());
            item.put("severity", f.getSeverity());
            item.put("file", f.getSourceFile());
            item.put("line", f.getSinkLine());
            item.put("parameter", f.getHttpParameter());
            item.put("variableName", f.getVariableName());
            item.put("httpMethod", f.getHttpMethod());
            item.put("endpoint", f.getEndpointPath());
            item.put("sinkMethod", f.getSinkMethod());
            item.put("singleQuoteWrapped", f.isSingleQuoteWrapped());
            item.put("numericContext", f.isNumericContext());
            item.put("sanitized", f.isSanitized());
            item.put("sourceSnippet", f.getSourceSnippet());
            item.put("sinkSnippet", f.getSinkSnippet());
            item.put("remediationSnippet", f.getRemediationSnippet());
            item.putPOJO("taintFlow", f.getTaintFlow());

            ObjectNode strike = item.putObject("strike");
            strike.put("exploitable", poc.isExploitable());
            strike.put("isExploitable", poc.isExploitable());
            strike.put("payload", poc.getPayload());
            strike.put("httpStatus", poc.getHttpStatusCode());
            strike.put("responseTimeMs", poc.getResponseTimeMs());
            strike.put("confirmationRule", poc.getConfirmationRule());
            strike.put("rawRequest", poc.getRawRequest());
            strike.put("rawResponse", poc.getRawResponse() != null ? poc.getRawResponse() : "");

            if (poc.isExploitable()) confirmed++;
            else falsePositives++;

            switch (f.getSeverity()) {
                case "CRITICAL" -> critical++;
                case "HIGH" -> high++;
            }
        }

        ObjectNode summary = root.putObject("summary");
        summary.put("total", results.size());
        summary.put("confirmed", confirmed);
        summary.put("falsePositives", falsePositives);
        summary.put("truePositiveRate", results.isEmpty() ? 0 : (double) confirmed / results.size());
        summary.put("critical", critical);
        summary.put("high", high);

        mapper.writerWithDefaultPrettyPrinter().writeValue(new File(OUTPUT_PATH), root);
        System.out.println("[EXPORT] Dashboard telemetry → " + OUTPUT_PATH);
    }

    public record FindingResult(Finding finding, ExploitPoC poc) {}
}
