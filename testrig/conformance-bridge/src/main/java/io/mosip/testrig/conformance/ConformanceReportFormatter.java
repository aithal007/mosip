package io.mosip.testrig.conformance;

import java.util.Locale;

/**
 * Helpers that turn a conformance module into testrig-friendly names and the HTML snippet
 * logged through {@code org.testng.Reporter}, which MOSIP's EmailableReport renders inline.
 */
public final class ConformanceReportFormatter {

    private static final int MAX_FINDINGS = 15;

    private ConformanceReportFormatter() {
    }

    /** e.g. InjiVerify_OIDFConformance_oid4vp_1final_verifier_happy_flow */
    public static String testCaseName(String modulePrefix, ConformanceResults.Module module) {
        return modulePrefix + "_OIDFConformance_" + module.module_name.replaceAll("[^A-Za-z0-9]+", "_");
    }

    /** e.g. TC_InjiVerify_OIDFConformance_03 */
    public static String uniqueIdentifier(String modulePrefix, int index) {
        return String.format(Locale.ROOT, "TC_%s_OIDFConformance_%02d", modulePrefix, index);
    }

    public static String description(ConformanceResults.Module module) {
        return "OpenID conformance " + module.plan_name + " / " + module.module_name;
    }

    public static String html(ConformanceResults.Module module, ConformanceResults.Plan plan) {
        StringBuilder html = new StringBuilder(512);
        html.append("<div class='oidf-conformance'><table border='1' cellpadding='4' style='border-collapse:collapse'>");
        row(html, "Conformance module", link(module.log_url, module.module_name));
        row(html, "Test plan", plan == null ? escape(module.plan_name) : link(plan.plan_url, plan.plan_name));
        row(html, "Variant", escape(String.valueOf(module.variant)));
        row(html, "Suite result", escape(module.status) + " / " + escape(module.suite_result));
        row(html, "Gate verdict", "<b>" + escape(module.verdict) + "</b> — " + escape(module.verdict_reason));
        if (module.issue != null && !module.issue.isBlank()) {
            row(html, "Tracked issue", link(module.issue, module.issue));
        }
        if (module.review_evidence != null && !module.review_evidence.isEmpty()) {
            row(html, "Review evidence", "expected " + escape(String.valueOf(module.review_evidence.get("expected")))
                    + ", Inji reported " + escape(String.valueOf(module.review_evidence.get("actual"))));
        }
        html.append("</table>");
        if (!module.findings.isEmpty()) {
            html.append("<p>Findings:</p><ul>");
            module.findings.stream().limit(MAX_FINDINGS).forEach(f -> html.append("<li><b>").append(escape(f.result))
                    .append("</b> <code>").append(escape(f.condition)).append("</code> ")
                    .append(escape(f.message)).append(f.requirements.isEmpty() ? "" : " [" + escape(String.join(", ", f.requirements)) + "]")
                    .append("</li>"));
            if (module.findings.size() > MAX_FINDINGS) {
                html.append("<li>… ").append(module.findings.size() - MAX_FINDINGS).append(" more in the suite log</li>");
            }
            html.append("</ul>");
        }
        return html.append("</div>").toString();
    }

    private static void row(StringBuilder html, String label, String valueHtml) {
        html.append("<tr><th align='left'>").append(escape(label)).append("</th><td>").append(valueHtml).append("</td></tr>");
    }

    private static String link(String url, String text) {
        if (url == null || url.isBlank()) {
            return escape(text);
        }
        return "<a href='" + escape(url) + "' target='_blank'>" + escape(text) + "</a>";
    }

    static String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("'", "&#39;").replace("\"", "&quot;");
    }
}
