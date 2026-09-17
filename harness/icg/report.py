"""Report outputs: consolidated HTML, Markdown summary, SVG badge and JUnit XML."""

from __future__ import annotations

import html
import json
from pathlib import Path
from xml.etree import ElementTree as ET

from .coverage import build_coverage, coverage_by_spec
from .diff import RunDiff
from .manifest import ComponentManifest
from .model import RunResult, Verdict
from .readiness import gap_rows, readiness_markdown

VERDICT_LABEL = {
    Verdict.PASS.value: "Pass",
    Verdict.FAIL.value: "Regression",
    Verdict.KNOWN_ISSUE.value: "Known issue",
    Verdict.STALE_BENCHMARK.value: "Benchmark stale",
    Verdict.SKIP.value: "Skipped",
    Verdict.INCOMPLETE.value: "Incomplete",
}

COMPONENT_LABEL = {"certify": "Inji Certify · OID4VCI issuer", "verify": "Inji Verify · OID4VP verifier"}


# -- Markdown -----------------------------------------------------------------------

def markdown_summary(run: RunResult, diff: RunDiff | None = None, manifests: list[ComponentManifest] | None = None) -> str:
    gate = "✅ PASSED" if run.is_gate_passing() else "❌ FAILED"
    lines = [f"## Inji Conformance Gate — {gate}", "", f"Run `{run.run_id}` · mode `{run.mode}` · suite `{run.suite_version}`", ""]
    lines += ["| Component | Pass | Known issue | Stale | Skip | Regression | Incomplete |", "|---|---|---|---|---|---|---|"]
    for component in run.components:
        mods = [m for m in run.modules if m.component == component]
        count = lambda v: sum(1 for m in mods if m.verdict == v.value)  # noqa: E731
        lines.append(
            f"| {COMPONENT_LABEL.get(component, component)} | {count(Verdict.PASS)} | {count(Verdict.KNOWN_ISSUE)} | "
            f"{count(Verdict.STALE_BENCHMARK)} | {count(Verdict.SKIP)} | {count(Verdict.FAIL)} | {count(Verdict.INCOMPLETE)} |"
        )
    for plan in run.missing_plans():
        lines += ["", f"> ❌ Gating plan `{plan.plan_name}` ({plan.component}) did not produce results — infrastructure error."]
    if run.shims:
        lines += ["", "### ⚠️ Compatibility shims active in this run", "", "| Component | Shim | Why | Issue |", "|---|---|---|---|"]
        lines += [f"| {s.get('component')} | {s.get('name')} | {s.get('reason')} | {s.get('issue') or '—'} |" for s in run.shims]
    blocking = [m for m in run.modules if Verdict(m.verdict).is_blocking]
    if blocking:
        lines += ["", "### Blocking modules", "", "| Component | Module | Verdict | Reason |", "|---|---|---|---|"]
        lines += [
            f"| {m.component} | [`{m.module_name}`]({m.log_url}) | {VERDICT_LABEL[m.verdict]} | {m.verdict_reason} |"
            for m in blocking
        ]
    stale = [m for m in run.modules if m.verdict == Verdict.STALE_BENCHMARK.value]
    if stale:
        lines += ["", "### Benchmark entries to remove (now passing)", ""]
        lines += [f"- `{m.component}` `{m.module_name}` — {m.issue or 'no issue link'}" for m in stale]
    if diff is not None:
        lines += ["", diff.to_markdown()]
    if manifests:
        lines += ["", readiness_markdown(manifests)]
    return "\n".join(lines) + "\n"


# -- Badge --------------------------------------------------------------------------

def badge_svg(run: RunResult) -> str:
    gating = run.summary(gating_only=True)
    passed = run.is_gate_passing()
    label = "OpenID conformance"
    conformant = gating[Verdict.PASS.value] + gating[Verdict.STALE_BENCHMARK.value]
    message = f"{conformant}/{gating['TOTAL']} · " + ("passing" if passed else "failing")
    color = "#16a34a" if passed else "#dc2626"
    lw, mw = int(6.5 * len(label)) + 12, int(6.5 * len(message)) + 14
    total = lw + mw
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{html.escape(label)}: {html.escape(message)}">'
        f'<title>{html.escape(label)}: {html.escape(message)}</title>'
        f'<rect width="{lw}" height="20" fill="#374151"/><rect x="{lw}" width="{mw}" height="20" fill="{color}"/>'
        f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
        f'<text x="{lw / 2}" y="14">{html.escape(label)}</text><text x="{lw + mw / 2}" y="14">{html.escape(message)}</text></g></svg>'
    )


# -- JUnit --------------------------------------------------------------------------

def junit_xml(run: RunResult) -> str:
    suites = ET.Element("testsuites", name="inji-conformance-gate")
    by_plan: dict[str, list] = {}
    for module in run.modules:
        by_plan.setdefault(f"{module.component}.{module.plan_name}", []).append(module)
    for name, modules in by_plan.items():
        suite = ET.SubElement(suites, "testsuite", name=name, tests=str(len(modules)))
        failures = skipped = 0
        for m in modules:
            case = ET.SubElement(suite, "testcase", classname=name, name=m.module_name, time=str(m.duration_seconds))
            if Verdict(m.verdict).is_blocking:
                failures += 1
                ET.SubElement(case, "failure", message=m.verdict_reason).text = m.log_url
            elif m.verdict in (Verdict.SKIP.value, Verdict.KNOWN_ISSUE.value):
                skipped += 1
                ET.SubElement(case, "skipped", message=f"{m.verdict}: {m.verdict_reason} {m.issue}".strip())
        suite.set("failures", str(failures))
        suite.set("skipped", str(skipped))
    return ET.tostring(suites, encoding="unicode")


# -- HTML ---------------------------------------------------------------------------

_CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1c1f24;--muted:#5d6470;--line:#e3e3df;--accent:#1f4fd1;
--pass:#15803d;--pass-bg:#e7f5ec;--fail:#b91c1c;--fail-bg:#fbe9e9;--known:#a16207;--known-bg:#fbf3dc;
--stale:#6d28d9;--stale-bg:#efe9fb;--skip:#4b5563;--skip-bg:#eeeff1;--inc:#c2410c;--inc-bg:#fdeee4}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#111316;--panel:#1a1d21;--ink:#e8e9eb;--muted:#9aa1ab;
--line:#2c3036;--accent:#7aa2ff;--pass:#4ade80;--pass-bg:#16301f;--fail:#f87171;--fail-bg:#3a1b1b;--known:#facc15;--known-bg:#352c10;
--stale:#c4b5fd;--stale-bg:#2a2240;--skip:#b6bcc6;--skip-bg:#262a30;--inc:#fb923c;--inc-bg:#3a2415}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:22px;margin:0}h2{font-size:16px;margin:36px 0 12px}.muted{color:var(--muted)}
header{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;margin-bottom:20px}
.gate{font-weight:600;padding:6px 14px;border-radius:999px}.gate.ok{background:var(--pass-bg);color:var(--pass)}.gate.bad{background:var(--fail-bg);color:var(--fail)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
.card h3{margin:0 0 10px;font-size:14px}.bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--skip-bg)}
.bar span{display:block}.legend{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px;font-size:12px;color:var(--muted)}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.PASS{background:var(--pass-bg);color:var(--pass)}.FAIL{background:var(--fail-bg);color:var(--fail)}.KNOWN_ISSUE{background:var(--known-bg);color:var(--known)}
.STALE_BENCHMARK{background:var(--stale-bg);color:var(--stale)}.SKIP{background:var(--skip-bg);color:var(--skip)}.INCOMPLETE{background:var(--inc-bg);color:var(--inc)}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}.toolbar button{font:inherit;border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:6px;padding:4px 10px;cursor:pointer}
.toolbar button[aria-pressed="true"]{border-color:var(--accent);color:var(--accent)}
.tablewrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}tr:last-child td{border-bottom:0}code{font-size:12.5px}
a{color:var(--accent)}details summary{cursor:pointer;color:var(--muted)}ul.find{margin:6px 0 0;padding-left:18px;font-size:12.5px}
.grid{display:flex;flex-wrap:wrap;gap:3px}.cell{width:14px;height:14px;border-radius:3px}
.cell.passing{background:var(--pass)}.cell.warning{background:var(--known)}.cell.failing{background:var(--fail)}
"""

_JS = """
document.querySelectorAll('.toolbar button').forEach(b=>b.addEventListener('click',()=>{
 document.querySelectorAll('.toolbar button').forEach(x=>x.setAttribute('aria-pressed','false'));b.setAttribute('aria-pressed','true');
 const f=b.dataset.filter;document.querySelectorAll('tbody tr[data-verdict]').forEach(r=>{r.hidden=!(f==='ALL'||r.dataset.verdict===f||(f==='BLOCKING'&&(r.dataset.verdict==='FAIL'||r.dataset.verdict==='INCOMPLETE')))})}));
"""

_BAR_VAR = {
    Verdict.PASS.value: "--pass", Verdict.STALE_BENCHMARK.value: "--stale", Verdict.KNOWN_ISSUE.value: "--known",
    Verdict.SKIP.value: "--skip", Verdict.FAIL.value: "--fail", Verdict.INCOMPLETE.value: "--inc",
}


def html_report(run: RunResult, diff: RunDiff | None = None, manifests: list[ComponentManifest] | None = None) -> str:
    e = html.escape
    passed = run.is_gate_passing()
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>",
        f"<title>Inji Conformance Report</title><style>{_CSS}</style></head><body><main>",
        "<header><div><h1>Inji Conformance Report</h1>",
        f"<div class=muted>Run {e(run.run_id)} · {e(run.mode)} · suite {e(run.suite_version)} · {e(run.finished_at)}</div></div>",
        f"<span class='gate {'ok' if passed else 'bad'}'>Gate {'passed' if passed else 'failed'}</span></header>",
        "<section class=cards>",
    ]
    for component in run.components:
        mods = [m for m in run.modules if m.component == component]
        total = max(len(mods), 1)
        segments = "".join(
            f"<span title='{VERDICT_LABEL[v.value]}' style='width:{100 * sum(1 for m in mods if m.verdict == v.value) / total:.2f}%;background:var({_BAR_VAR[v.value]})'></span>"
            for v in Verdict
        )
        legend = "".join(
            f"<span><span class='chip {v.value}'>{sum(1 for m in mods if m.verdict == v.value)}</span> {VERDICT_LABEL[v.value]}</span>"
            for v in Verdict if any(m.verdict == v.value for m in mods)
        )
        plans = ", ".join(sorted({f"<a href='{e(p.plan_url)}'>{e(p.plan_name)}</a>" for p in run.plans if p.component == component}))
        parts.append(
            f"<article class=card><h3>{e(COMPONENT_LABEL.get(component, component))}</h3><div class=bar>{segments}</div>"
            f"<div class=legend>{legend or 'No modules collected'}</div><p class=muted style='margin:10px 0 0;font-size:12px'>{plans}</p></article>"
        )
    parts.append("</section>")

    if run.shims:
        parts.append("<h2>Compatibility shims active</h2><p class=muted>Workarounds applied by the test environment so the rest of a plan can run. Each one is a conformance gap in its own right.</p>")
        parts.append("<div class=tablewrap><table><thead><tr><th>Component</th><th>Shim</th><th>Why</th><th>Tracking</th></tr></thead><tbody>")
        for s in run.shims:
            issue = s.get("issue", "")
            link = f"<a href='{e(issue)}'>{e(issue.rsplit('/', 1)[-1])}</a>" if issue else "—"
            parts.append(f"<tr><td>{e(s.get('component', ''))}</td><td>{e(s.get('name', ''))}</td><td>{e(s.get('reason', ''))}</td><td>{link}</td></tr>")
        parts.append("</tbody></table></div>")

    parts.append("<h2>Test modules</h2><div class=toolbar>")
    for key, label in (("ALL", "All"), ("BLOCKING", "Blocking"), *((v.value, VERDICT_LABEL[v.value]) for v in Verdict)):
        parts.append(f"<button data-filter='{key}' aria-pressed='{'true' if key == 'ALL' else 'false'}'>{label}</button>")
    parts.append("</div><div class=tablewrap><table><thead><tr><th>Component</th><th>Module</th><th>Suite</th><th>Verdict</th><th>Reason</th><th>Time</th></tr></thead><tbody>")
    for m in sorted(run.modules, key=lambda m: (not Verdict(m.verdict).is_blocking, m.component, m.module_name)):
        findings = "".join(f"<li><b>{e(f.result)}</b> <code>{e(f.condition)}</code> — {e(f.message)}</li>" for f in m.findings[:12])
        details = f"<details><summary>{len(m.findings)} finding(s)</summary><ul class=find>{findings}</ul></details>" if m.findings else ""
        issue = "".join(f" <a href='{e(i.strip())}'>issue</a>" for i in m.issue.split(",") if i.strip())
        name = f"<a href='{e(m.log_url)}'><code>{e(m.module_name)}</code></a>" if m.log_url else f"<code>{e(m.module_name)}</code>"
        parts.append(
            f"<tr data-verdict='{m.verdict}'><td>{e(m.component)}</td><td>{name}{details}</td><td>{e(m.suite_result or m.status)}</td>"
            f"<td><span class='chip {m.verdict}'>{VERDICT_LABEL[m.verdict]}</span></td><td>{e(m.verdict_reason)}{issue}</td><td>{m.duration_seconds:.0f}s</td></tr>"
        )
    parts.append("</tbody></table></div>")

    clauses = build_coverage(run)
    if clauses:
        parts.append("<h2>Specification clauses exercised</h2><p class=muted>Each square is a requirement tag the suite checked during this run. Red: a failing check references it. Amber: warnings only.</p><div class=cards>")
        for spec, counts in coverage_by_spec(clauses).items():
            cells = "".join(
                f"<span class='cell {c.state}' title='{e(c.requirement)} — {len(c.modules)} module(s)'></span>" for c in clauses if c.spec == spec
            )
            parts.append(
                f"<article class=card><h3>{e(spec)}</h3><div class=grid>{cells}</div>"
                f"<div class=legend>{counts['passing']} passing · {counts['warning']} warning · {counts['failing']} failing</div></article>"
            )
        parts.append("</div>")

    if diff is not None:
        parts.append(f"<h2>Changes since {e(diff.baseline_run)}</h2><div class=tablewrap><table><thead><tr><th>Change</th><th>Component</th><th>Module</th><th>Before</th><th>After</th><th>Detail</th></tr></thead><tbody>")
        for label, items in (("Regression", diff.regressions), ("Fix", diff.fixes), ("Changed", diff.changed), ("Added", diff.added), ("Removed", diff.removed)):
            for c in items:
                parts.append(f"<tr><td>{label}</td><td>{e(c.component)}</td><td><code>{e(c.module)}</code></td><td>{e(c.before)}</td><td>{e(c.after)}</td><td>{e(c.detail)}</td></tr>")
        if not (diff.regressions or diff.fixes or diff.changed or diff.added or diff.removed):
            parts.append("<tr><td colspan=6 class=muted>No changes.</td></tr>")
        parts.append("</tbody></table></div>")

    if manifests:
        rows = gap_rows(manifests)
        if rows:
            parts.append("<h2>Certification readiness (HAIP)</h2><p class=muted>OpenID self-certification counts only the HAIP profile plans. These capabilities decide when each plan can run.</p>")
            parts.append("<div class=tablewrap><table><thead><tr><th>Component</th><th>Plan</th><th>Capability</th><th>Status</th><th>Tracking</th></tr></thead><tbody>")
            for r in rows:
                chip = "<span class='chip PASS'>Supported</span>" if r.supported else "<span class='chip FAIL'>Gap</span>"
                link = f"<a href='{e(r.issue)}'>{e(r.issue.rsplit('/', 1)[-1])}</a>" if r.issue else "—"
                parts.append(f"<tr><td>{e(r.component)}</td><td><code>{e(r.plan_name)}</code></td><td>{e(r.capability)}</td><td>{chip}</td><td>{link}</td></tr>")
            parts.append("</tbody></table></div>")

    parts.append(f"<script>{_JS}</script><script type=application/json id=results>{e(json.dumps(run.summary()))}</script></main></body></html>")
    return "".join(parts)


def write_reports(out_dir: Path, run: RunResult, diff: RunDiff | None, manifests: list[ComponentManifest]) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "html": out_dir / "conformance-report.html",
        "markdown": out_dir / "summary.md",
        "badge": out_dir / "badge.svg",
        "junit": out_dir / "junit.xml",
    }
    paths["html"].write_text(html_report(run, diff, manifests), encoding="utf-8")
    paths["markdown"].write_text(markdown_summary(run, diff, manifests), encoding="utf-8")
    paths["badge"].write_text(badge_svg(run), encoding="utf-8")
    paths["junit"].write_text(junit_xml(run), encoding="utf-8")
    return paths
