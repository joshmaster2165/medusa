"""HTML dashboard report generator."""

from __future__ import annotations

import json

from medusa.core.models import ScanResult, Status
from medusa.reporters.base import BaseReporter


class HtmlReporter(BaseReporter):
    """Generate a self-contained HTML dashboard report."""

    def generate(self, result: ScanResult) -> str:
        failed = [f for f in result.findings if f.status == Status.FAIL]
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in failed:
            sev = f.severity.value
            if sev in severity_counts:
                severity_counts[sev] += 1

        total_checks = sum(s.total_checks for s in result.server_scores)
        total_passed = sum(s.passed for s in result.server_scores)
        pass_rate = round(total_passed / total_checks * 100, 1) if total_checks > 0 else 0

        # Build findings JSON for the interactive table
        findings_json = json.dumps(
            [
                {
                    "check_id": f.check_id,
                    "check_title": f.check_title,
                    "severity": f.severity.value,
                    "server": f.server_name,
                    "transport": f.server_transport,
                    "resource": f"{f.resource_type}/{f.resource_name}",
                    "details": f.status_extended,
                    "evidence": f.evidence or "",
                    "remediation": f.remediation,
                    "owasp": ", ".join(f.owasp_mcp),
                }
                for f in failed
            ]
        )

        # Build server scores JSON
        servers_json = json.dumps(
            [
                {
                    "name": s.server_name,
                    "score": s.score,
                    "grade": s.grade,
                    "passed": s.passed,
                    "failed": s.failed,
                    "critical": s.critical_findings,
                    "high": s.high_findings,
                    "medium": s.medium_findings,
                    "low": s.low_findings,
                }
                for s in result.server_scores
            ]
        )

        # Compliance results JSON
        compliance_json = json.dumps(result.compliance_results)

        grade_color = {
            "A": "#22c55e",
            "B": "#84cc16",
            "C": "#eab308",
            "D": "#f97316",
            "F": "#ef4444",
        }.get(result.aggregate_grade, "#6b7280")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Medusa Security Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont,
    'Segoe UI', Roboto, sans-serif;
  background: #0f172a; color: #e2e8f0;
  line-height: 1.6;
}}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
header {{ text-align: center; padding: 40px 0 30px; }}
header h1 {{ font-size: 2rem; color: #f8fafc; margin-bottom: 8px; }}
header .subtitle {{ color: #94a3b8; font-size: 0.9rem; }}
.grade-circle {{
  width: 120px; height: 120px; border-radius: 50%;
  display: flex; align-items: center;
  justify-content: center; margin: 20px auto;
  border: 4px solid {grade_color};
}}
.grade-circle .grade {{
  font-size: 3rem; font-weight: bold;
  color: {grade_color};
}}
.score-label {{ text-align: center; color: #94a3b8; margin-bottom: 30px; }}
.summary {{
  display: grid; gap: 16px; margin-bottom: 30px;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
}}
.stat-card {{ background: #1e293b; border-radius: 12px; padding: 20px; text-align: center; }}
.stat-card .value {{ font-size: 2rem; font-weight: bold; color: #f8fafc; }}
.stat-card .label {{ color: #94a3b8; font-size: 0.85rem; margin-top: 4px; }}
.severity-bar {{ display: flex; gap: 12px; margin-bottom: 30px; flex-wrap: wrap; }}
.sev-badge {{ padding: 8px 16px; border-radius: 8px; font-weight: 600; font-size: 0.9rem; }}
.sev-critical {{
  background: rgba(239,68,68,0.15);
  color: #ef4444; border: 1px solid rgba(239,68,68,0.3);
}}
.sev-high {{
  background: rgba(249,115,22,0.15);
  color: #f97316; border: 1px solid rgba(249,115,22,0.3);
}}
.sev-medium {{
  background: rgba(234,179,8,0.15);
  color: #eab308; border: 1px solid rgba(234,179,8,0.3);
}}
.sev-low {{
  background: rgba(59,130,246,0.15);
  color: #3b82f6; border: 1px solid rgba(59,130,246,0.3);
}}
.section {{ background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
.section h2 {{ font-size: 1.3rem; color: #f8fafc; margin-bottom: 16px; }}
.server-grid {{
  display: grid; gap: 16px;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
}}
.server-card {{
  background: #0f172a; border-radius: 10px;
  padding: 20px; border: 1px solid #334155;
}}
.server-card h3 {{ color: #f8fafc; margin-bottom: 8px; }}
.server-card .server-score {{ font-size: 1.5rem; font-weight: bold; margin-bottom: 4px; }}
.server-card .server-meta {{ color: #94a3b8; font-size: 0.85rem; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
th {{
  text-align: left; padding: 12px; color: #94a3b8;
  font-size: 0.8rem; text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 1px solid #334155;
}}
td {{ padding: 12px; border-bottom: 1px solid #1e293b; font-size: 0.9rem; }}
tr:hover {{ background: rgba(51,65,85,0.3); }}
.finding-row {{ cursor: pointer; }}
.finding-detail {{
  display: none; background: #0f172a;
  padding: 16px; border-radius: 8px; margin: 8px 0;
}}
.finding-detail.open {{ display: block; }}
.finding-detail p {{ margin-bottom: 8px; }}
.finding-detail .label {{ color: #94a3b8; font-weight: 600; }}
.filters {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
.filter-btn {{
  padding: 6px 14px; border-radius: 6px;
  border: 1px solid #334155; background: transparent;
  color: #94a3b8; cursor: pointer; font-size: 0.85rem;
}}
.filter-btn.active {{ background: #334155; color: #f8fafc; }}
.compliance-table td {{ font-size: 0.85rem; }}
.status-pass {{ color: #22c55e; }}
.status-fail {{ color: #ef4444; }}
.status-na {{ color: #6b7280; }}
footer {{ text-align: center; padding: 30px 0; color: #475569; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
<header>
    <h1>Medusa Security Report</h1>
    <p class="subtitle">\
{result.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")} \
| v{result.medusa_version} \
| {result.scan_duration_seconds}s</p>
    <div class="grade-circle"><span class="grade">{result.aggregate_grade}</span></div>
    <p class="score-label">{result.aggregate_score} / 10</p>
</header>

<div class="summary">
    <div class="stat-card">
      <div class="value">{result.servers_scanned}</div>
      <div class="label">Servers Scanned</div>
    </div>
    <div class="stat-card">
      <div class="value">{result.total_findings}</div>
      <div class="label">Findings</div>
    </div>
    <div class="stat-card">
      <div class="value">{pass_rate}%</div>
      <div class="label">Pass Rate</div>
    </div>
    <div class="stat-card">
      <div class="value">{total_checks}</div>
      <div class="label">Checks Run</div>
    </div>
</div>

<div class="severity-bar">
    <span class="sev-badge sev-critical">Critical: {severity_counts["critical"]}</span>
    <span class="sev-badge sev-high">High: {severity_counts["high"]}</span>
    <span class="sev-badge sev-medium">Medium: {severity_counts["medium"]}</span>
    <span class="sev-badge sev-low">Low: {severity_counts["low"]}</span>
</div>

<div class="section">
    <h2>Server Scores</h2>
    <div class="server-grid" id="serverGrid"></div>
</div>

<div class="section">
    <h2>Findings</h2>
    <div class="filters" id="filters">
        <button class="filter-btn active" onclick="filterFindings('all')">All</button>
        <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
        <button class="filter-btn" onclick="filterFindings('high')">High</button>
        <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
        <button class="filter-btn" onclick="filterFindings('low')">Low</button>
    </div>
    <table>
        <thead><tr><th>Severity</th><th>Check</th><th>Server</th><th>Resource</th><th>Details</th></tr></thead>
        <tbody id="findingsTable"></tbody>
    </table>
</div>

<div class="section" id="complianceSection" style="display:none">
    <h2>OWASP MCP Top 10 Compliance</h2>
    <table class="compliance-table">
        <thead><tr><th>Requirement</th><th>Title</th><th>Status</th><th>Passed</th><th>Failed</th></tr></thead>
        <tbody id="complianceTable"></tbody>
    </table>
</div>

<footer>Generated by Medusa - MCP Security Scanner</footer>
</div>

<script>
const findings = {findings_json};
const servers = {servers_json};
const compliance = {compliance_json};

function renderServers() {{
    const grid = document.getElementById('serverGrid');
    grid.innerHTML = servers.map(s => {{
        const g = s.grade;
        const color = g === 'A' ? '#22c55e'
            : g === 'B' ? '#84cc16'
            : g === 'C' ? '#eab308'
            : g === 'D' ? '#f97316' : '#ef4444';
        return `<div class="server-card">
            <h3>${{s.name}}</h3>
            <div class="server-score" style="color:${{color}}">${{s.grade}} (${{s.score}}/10)</div>
            <div class="server-meta">${{s.passed}} passed, ${{s.failed}} failed</div>
            <div class="server-meta" style="margin-top:4px">
                <span style="color:#ef4444">${{s.critical}}C</span>
                <span style="color:#f97316">${{s.high}}H</span>
                <span style="color:#eab308">${{s.medium}}M</span>
                <span style="color:#3b82f6">${{s.low}}L</span>
            </div>
        </div>`;
    }}).join('');
}}

function renderFindings(filter) {{
    const tbody = document.getElementById('findingsTable');
    const filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter);
    tbody.innerHTML = filtered.map((f, i) => {{
        const sevClass = 'sev-' + f.severity;
        return `<tr class="finding-row" onclick="toggleDetail(${{i}})">
            <td><span class="sev-badge ${{sevClass}}">${{f.severity}}</span></td>
            <td>${{f.check_id}}</td>
            <td>${{f.server}}</td>
            <td>${{f.resource}}</td>
            <td>${{f.details.substring(0, 80)}}${{f.details.length > 80 ? '...' : ''}}</td>
        </tr>
        <tr><td colspan="5"><div class="finding-detail" id="detail-${{i}}">
            <p><span class="label">Details: </span>${{f.details}}</p>
            ${{f.evidence
              ? '<p><span class="label">Evidence: </span>'
                + '<code>' + f.evidence.substring(0, 500)
                + '</code></p>' : ''}}
            <p><span class="label">Remediation: </span>${{f.remediation}}</p>
            ${{f.owasp ? '<p><span class="label">OWASP MCP: </span>' + f.owasp + '</p>' : ''}}
        </div></td></tr>`;
    }}).join('');
}}

function toggleDetail(i) {{
    const el = document.getElementById('detail-' + i);
    if (el) el.classList.toggle('open');
}}

function filterFindings(sev) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    renderFindings(sev);
}}

function renderCompliance() {{
    const keys = Object.keys(compliance);
    if (keys.length === 0) return;
    document.getElementById('complianceSection').style.display = 'block';
    const tbody = document.getElementById('complianceTable');
    keys.forEach(framework => {{
        const reqs = compliance[framework];
        Object.entries(reqs).forEach(([id, r]) => {{
            const st = r.status;
            const statusClass = st === 'compliant'
                ? 'status-pass'
                : st === 'non_compliant'
                    ? 'status-fail' : 'status-na';
            const statusText = st === 'compliant'
                ? 'PASS'
                : st === 'non_compliant'
                    ? 'FAIL' : 'N/A';
            tbody.innerHTML += `<tr>
                <td>${{id}}</td>
                <td>${{r.title}}</td>
                <td class="${{statusClass}}">${{statusText}}</td>
                <td>${{r.checks_passed}}</td>
                <td>${{r.checks_failed}}</td>
            </tr>`;
        }});
    }});
}}

renderServers();
renderFindings('all');
renderCompliance();
</script>
</body>
</html>"""
