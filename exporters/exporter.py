import json
from datetime import datetime
from pathlib import Path

from core.models import AnalysisReport, ParseResult


def _default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def export_json(report: AnalysisReport, result: ParseResult, output_path: str | Path) -> None:
    output_path = Path(output_path)
    data = {
        "meta": {
            "generated_at": datetime.utcnow().isoformat(),
            "total_entries": report.total_entries,
            "parse_success_rate": result.success_rate,
            "detected_format": result.detected_format.value,
            "parse_duration_ms": result.parse_duration_ms,
        },
        "summary": report.summary,
        "time_range": {
            "start": report.time_range[0].isoformat() if report.time_range else None,
            "end": report.time_range[1].isoformat() if report.time_range else None,
        },
        "level_distribution": report.level_distribution,
        "throughput_stats": report.throughput_stats,
        "top_sources": [{"source": s, "count": c} for s, c in report.top_sources],
        "top_errors": [{"pattern": p, "count": c} for p, c in report.top_errors],
        "anomalies": [
            {
                "type": a.anomaly_type,
                "score": a.score,
                "line": a.entry.line_number,
                "description": a.description,
                "suggested_action": a.suggested_action,
                "timestamp": a.entry.timestamp.isoformat() if a.entry.timestamp else None,
                "raw": a.entry.raw[:200],
            }
            for a in report.anomalies
        ],
        "patterns": report.patterns[:30],
        "hourly_distribution": {str(h): c for h, c in report.hourly_distribution.items()},
        "error_rate_timeline": report.error_rate_timeline,
        "keyword_frequency": report.keyword_frequency,
        "unique_hosts": report.unique_hosts,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=_default)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log Analysis Report</title>
<style>
  :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
    --green:#3fb950;--yellow:#d29922;--red:#f85149;--blue:#58a6ff;--purple:#bc8cff}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}}
  h1{{color:var(--blue);margin-bottom:.5rem}}
  .meta{{color:var(--muted);margin-bottom:2rem;font-size:.9rem}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin-bottom:2rem}}
  .card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.25rem}}
  .card h3{{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.5rem}}
  .card .val{{font-size:2rem;font-weight:700}}
  .green{{color:var(--green)}}.yellow{{color:var(--yellow)}}.red{{color:var(--red)}}.blue{{color:var(--blue)}}
  section{{margin-bottom:2.5rem}}
  section h2{{color:var(--blue);border-bottom:1px solid var(--border);padding-bottom:.4rem;margin-bottom:1rem}}
  table{{width:100%;border-collapse:collapse;font-size:.9rem}}
  th{{background:var(--card);color:var(--muted);text-align:left;padding:.6rem .8rem;border-bottom:2px solid var(--border)}}
  td{{padding:.5rem .8rem;border-bottom:1px solid var(--border)}}
  tr:hover td{{background:rgba(48,54,61,.5)}}
  .badge{{display:inline-block;padding:.1rem .5rem;border-radius:4px;font-size:.75rem;font-weight:700}}
  .badge-error{{background:#3d1b1b;color:var(--red)}}
  .badge-warn{{background:#3d2b00;color:var(--yellow)}}
  .badge-info{{background:#1b3d1b;color:var(--green)}}
  .badge-sec{{background:#4d0000;color:#ff6b6b}}
  .bar-track{{background:#21262d;border-radius:4px;overflow:hidden;height:16px}}
  .bar-fill{{height:100%;border-radius:4px;background:var(--blue);transition:.3s}}
  .summary-box{{background:var(--card);border-left:4px solid var(--green);padding:1rem 1.5rem;border-radius:0 8px 8px 0;font-size:1rem;line-height:1.6}}
  .anomaly-high{{color:var(--red)}} .anomaly-med{{color:var(--yellow)}}
</style>
</head>
<body>
<h1>🔍 Log Analysis Report</h1>
<div class="meta">Generated {generated_at} | {total_entries:,} entries | Format: {fmt} | Parse rate: {parse_rate:.1f}%</div>

<div class="grid">
  <div class="card"><h3>Total Entries</h3><div class="val blue">{total_entries:,}</div></div>
  <div class="card"><h3>Error Rate</h3><div class="val {health_class}">{error_pct:.2f}%</div></div>
  <div class="card"><h3>Anomalies</h3><div class="val yellow">{anomaly_count}</div></div>
  <div class="card"><h3>Security Issues</h3><div class="val red">{security_count}</div></div>
  <div class="card"><h3>Peak Rate</h3><div class="val blue">{peak_rate}/min</div></div>
  <div class="card"><h3>Unique Hosts</h3><div class="val blue">{host_count}</div></div>
</div>

<section>
  <h2>Summary</h2>
  <div class="summary-box">{summary}</div>
</section>

<section>
  <h2>Level Distribution</h2>
  <table>
    <tr><th>Level</th><th>Count</th><th>%</th><th>Distribution</th></tr>
    {level_rows}
  </table>
</section>

<section>
  <h2>Anomalies ({anomaly_count})</h2>
  <table>
    <tr><th>Score</th><th>Type</th><th>Line</th><th>Description</th><th>Action</th></tr>
    {anomaly_rows}
  </table>
</section>

<section>
  <h2>Top Error Patterns</h2>
  <table>
    <tr><th>Count</th><th>Pattern</th></tr>
    {error_rows}
  </table>
</section>

<section>
  <h2>Top Sources</h2>
  <table>
    <tr><th>Source</th><th>Count</th><th>Share</th></tr>
    {source_rows}
  </table>
</section>

<section>
  <h2>Keyword Frequency</h2>
  <table>
    <tr><th>Keyword</th><th>Hits</th></tr>
    {kw_rows}
  </table>
</section>
</body>
</html>"""


def export_html(report: AnalysisReport, result: ParseResult, output_path: str | Path) -> None:
    total = report.total_entries or 1
    errors = (report.level_distribution.get("ERROR", 0) +
              report.level_distribution.get("CRITICAL", 0) +
              report.level_distribution.get("FATAL", 0))
    error_pct = errors / total * 100

    level_rows = ""
    for lvl, count in sorted(report.level_distribution.items()):
        pct = count / total * 100
        level_rows += (
            f"<tr><td>{lvl}</td><td>{count:,}</td><td>{pct:.1f}%</td>"
            f"<td><div class='bar-track'><div class='bar-fill' style='width:{pct:.1f}%'></div></div></td></tr>\n"
        )

    anomaly_rows = ""
    for a in report.anomalies[:30]:
        badge_cls = "badge-sec" if a.anomaly_type == "security" else ("badge-error" if a.score >= 7 else "badge-warn")
        anomaly_rows += (
            f"<tr><td class='{'anomaly-high' if a.score>=7 else 'anomaly-med'}'>{a.score:.1f}</td>"
            f"<td><span class='badge {badge_cls}'>{a.anomaly_type}</span></td>"
            f"<td>{a.entry.line_number}</td><td>{a.description[:100]}</td><td>{a.suggested_action[:80]}</td></tr>\n"
        )

    error_rows = "".join(
        f"<tr><td>{c:,}</td><td>{p[:130]}</td></tr>\n"
        for p, c in report.top_errors[:20]
    )
    top_count = report.top_sources[0][1] if report.top_sources else 1
    source_rows = "".join(
        f"<tr><td>{s or '<unknown>'}</td><td>{c:,}</td>"
        f"<td><div class='bar-track'><div class='bar-fill' style='width:{c/top_count*100:.0f}%'></div></div></td></tr>\n"
        for s, c in report.top_sources[:15]
    )
    kw_rows = "".join(
        f"<tr><td>{kw}</td><td>{cnt:,}</td></tr>\n"
        for kw, cnt in list(report.keyword_frequency.items())[:15]
    )

    health_class = "green" if error_pct < 1 else ("yellow" if error_pct < 5 else "red")
    tp = report.throughput_stats

    html = HTML_TEMPLATE.format(
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        total_entries=report.total_entries,
        fmt=result.detected_format.value,
        parse_rate=result.success_rate,
        error_pct=error_pct,
        health_class=health_class,
        anomaly_count=len(report.anomalies),
        security_count=sum(1 for a in report.anomalies if a.anomaly_type == "security"),
        peak_rate=tp.get("peak_rate_per_min", 0),
        host_count=len(report.unique_hosts),
        summary=report.summary,
        level_rows=level_rows,
        anomaly_rows=anomaly_rows,
        error_rows=error_rows,
        source_rows=source_rows,
        kw_rows=kw_rows,
    )
    Path(output_path).write_text(html, encoding="utf-8")
